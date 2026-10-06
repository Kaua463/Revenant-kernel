#!/usr/bin/env python3
"""Compare stock sysfs dispatcher, input mutation and stats writes to recovered C."""
import argparse
import ctypes
import hashlib
import importlib.util
from pathlib import Path
import random
import struct
import subprocess
import tempfile


def load(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


HELPERS=r'''
#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
typedef int64_t s64;
struct kobject { unsigned char opaque[96]; };
struct attribute { const char *name; unsigned short mode; };
struct erofs_attr { struct attribute attr; short attr_id; int struct_type,offset; };
#define container_of(p,t,m) ((t *)((unsigned char *)(p)-offsetof(t,m)))
static int sysfs_emit_at(char *buffer,int offset,const char *fmt,...) {
 if(offset<0 || offset>=4096) return 0;
 va_list ap;va_start(ap,fmt);int result=vsnprintf(buffer+offset,4096-offset,fmt,ap);va_end(ap);
 return result>=4096-offset ? 4095-offset : result;
}
static int sysfs_emit(char *buffer,const char *fmt,...) {
 va_list ap;va_start(ap,fmt);int result=vsnprintf(buffer,4096,fmt,ap);va_end(ap);
 return result>=4096 ? 4095 : result;
}
static const char *skip_spaces(const char *p) { while(ascii_space(*p)) p++;return p; }
static int mock_kstrtoul(const char *p,unsigned base,unsigned long *value) {
 if(*p=='+') p++;
 if(!base) { base=10; if(*p=='0') { base=8; if(p[1]=='x' || p[1]=='X') {base=16;p+=2;} } }
 unsigned count=0;unsigned long result=0;
 while(*p) {
  unsigned digit=*p>='0' && *p<='9' ? *p-'0' :
   *p>='a' && *p<='f' ? *p-'a'+10 : *p>='A' && *p<='F' ? *p-'A'+10 : 99;
  if(digit>=base) break;
  if(result>(UINT64_MAX-digit)/base) return -ERANGE;
  result=result*base+digit;count++;p++;
 }
 if(!count) return -EINVAL;
 if(*p=='\n') p++;
 if(*p) return -EINVAL;
 *value=result;return 0;
}
#define kstrtoul mock_kstrtoul
'''


WRAPPER=r'''
long host_dispatch(unsigned char *io_bytes,unsigned char *data,char *text,char *out,
 unsigned mask,int enabled,int attr_id,int struct_type,int store,const char *name) {
 struct erofs_iostat io;memcpy(&io,io_bytes,sizeof(io));io.stats=(void *)data;
 io.iostat_enable=enabled;
 struct erofs_sb_info sbi={.iostat=&io};
 struct erofs_attr attr={.attr={.name=name},.attr_id=attr_id,.struct_type=struct_type};
 possible_cpus=mask;fake_now=100000000000000ULL;
 long ret=store ? erofs_attr_store(&sbi.s_kobj,&attr.attr,text,strlen(text)) :
  erofs_attr_show(&sbi.s_kobj,&attr.attr,out);
 io.stats=NULL;memcpy(io_bytes,&io,sizeof(io));return ret;
}
'''


def run(args):
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
    from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X30,UC_ARM64_REG_SP,UC_ARM64_REG_SP_EL0,UC_ARM64_REG_PC
    diff=load('test-erofs-stock-differential.py');controls=load('test-erofs-stock-controls.py')
    contract=load('verify-stock-recovered-contracts.py')
    image=args.image.read_bytes();assert hashlib.sha256(image).hexdigest()==contract.IMAGE_SHA
    assert hashlib.sha256(args.symbols.read_bytes()).hexdigest()==contract.SYMBOL_SHA
    kernel=load('stock-binary-evidence.py').Kernel(args.image,args.symbols)
    records=kernel.btf.records()
    for name,fields in {'erofs_attr':{'attr':0,'attr_id':16,'struct_type':20,'offset':24},
                       'erofs_sb_info':{'opt':0,'s_kobj':280,'iostat':448}}.items():
        actual={m['name']:m['offset_bits']//8 for m in records['struct '+name][0]['members']}
        for member,offset in fields.items():assert actual[member]==offset
    fixture=diff.FIXTURE.replace('struct erofs_sb_info { unsigned char before[0x1c0]; struct erofs_iostat *iostat; };',
        'struct kobject { unsigned char opaque[96]; };\nstruct erofs_sb_info { unsigned char opt[16], before[264]; struct kobject s_kobj; unsigned char gap[72]; struct erofs_iostat *iostat; };')
    helpers=HELPERS.replace('struct kobject { unsigned char opaque[96]; };','')
    helpers=controls.HELPERS[:controls.HELPERS.index('int host_parse')]+helpers
    root=Path(__file__).parents[1]/'tools/stock-recovery'
    code=fixture+helpers+''.join((root/f'erofs_iostat_{part}.recovered.c').read_text()
        for part in ('update','controls','show','sysfs'))+WRAPPER
    with tempfile.TemporaryDirectory(prefix='erofs-sysfs-') as folder:
        library=Path(folder)/'sysfs.dylib'
        subprocess.run(['clang','-x','c','-std=c11','-Wall','-Wextra','-Werror','-dynamiclib','-o',str(library),'-'],input=code,text=True,check=True)
        host=ctypes.CDLL(str(library));host.host_dispatch.restype=ctypes.c_long
        host.host_dispatch.argtypes=[ctypes.c_void_p]*4+[ctypes.c_uint]+[ctypes.c_int]*4+[ctypes.c_char_p]
        emu=Uc(UC_ARCH_ARM64,UC_MODE_ARM);emu.mem_map(kernel.base,(len(image)+4095)&~4095);emu.mem_write(kernel.base,image)
        ram=0x1000000;emu.mem_map(ram,0x60000)
        sbi,io,attr,text,out,name_addr,task,stack,stop,stats=[ram+x for x in (0,0x1000,0x2000,0x3000,0x4000,0x5000,0x6000,0xf000,0x10000,0x20000)]
        def clock(uc,address,size,user):
            uc.reg_write(UC_ARM64_REG_X0,100000000000000);uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_X30))
        address=kernel.address('ktime_get');emu.hook_add(UC_HOOK_CODE,clock,begin=address,end=address)
        for cpu in range(8):emu.mem_write(kernel.address('__per_cpu_offset')+8*cpu,struct.pack('<Q',cpu*4096))
        rng=random.Random(0x304f);count=0
        names={0:'zero_padding',1:'sync_decompress',2:'iostat_enable',3:'iostat_config',4:'iostat_window_latency',5:'iostat_daily_latency'}
        cases=[(False,i,'') for i in range(6)]
        cases += [(True,2,v) for v in ('0','1','2','-1','+1','0x1','01',' 0\n','','18446744073709551616')]
        cases += [(True,3,v) for v in ('60,100,100,100,100,100','1,2,3,4,5,6','0,0,0,0,0,0','-1,1,1,1,1,1','60,1,2,3,4','60,1,2,3,4,5,6')]
        cases += [(True,5,v) for v in ('reset','reset-extra','bad',' reset\n')]
        cases += [(True,1,v) for v in ('0','1','2','3','4294967295','4294967296','0x2','02','09','-1')]
        cases += [(True,0,'1'),(True,4,'reset')]
        for mask in (0,1,0x89,0xff):
            for enabled in (False,True):
                for store,ident,value in cases:
                    initial_io=bytearray(rng.randbytes(64));initial_io[0]=enabled
                    struct.pack_into('<Q',initial_io,8,60000000000);struct.pack_into('<Q',initial_io,56,0)
                    initial_stats=bytearray(rng.randbytes(8*4096))
                    for cpu in range(8):
                        struct.pack_into('<I',initial_stats,cpu*4096,cpu&1)
                        struct.pack_into('<Q',initial_stats,cpu*4096+8,100000000000000)
                    ni=(ctypes.c_ubyte*64).from_buffer_copy(initial_io);ns=(ctypes.c_ubyte*len(initial_stats)).from_buffer_copy(initial_stats)
                    text_bytes=value.encode()+b'\0';nt=ctypes.create_string_buffer(text_bytes,len(text_bytes));no=ctypes.create_string_buffer(4096)
                    expected=host.host_dispatch(ni,ns,nt,no,mask,enabled,ident,2 if ident==2 else 0,store,names[ident].encode())
                    emu.mem_write(sbi,bytes(456));emu.mem_write(sbi+448,struct.pack('<Q',io))
                    emu.mem_write(io,bytes(initial_io));emu.mem_write(io+56,struct.pack('<Q',stats));emu.mem_write(stats,bytes(initial_stats))
                    emu.mem_write(attr,struct.pack('<QH6xh2xii4x',name_addr,0o644,ident,2 if ident==2 else 0,0))
                    emu.mem_write(name_addr,names[ident].encode()+b'\0');emu.mem_write(text,text_bytes);emu.mem_write(out,bytes(4096))
                    emu.mem_write(kernel.address('__cpu_possible_mask'),struct.pack('<I',mask))
                    for register,v in ((UC_ARM64_REG_X0,sbi+280),(UC_ARM64_REG_X1,attr),(UC_ARM64_REG_X2,text if store else out),(UC_ARM64_REG_X3,len(value)),(UC_ARM64_REG_X30,stop),(UC_ARM64_REG_SP,stack),(UC_ARM64_REG_SP_EL0,task)):emu.reg_write(register,v)
                    emu.emu_start(kernel.address('erofs_attr_store' if store else 'erofs_attr_show'),stop,count=2000000)
                    assert emu.reg_read(UC_ARM64_REG_PC)==stop,'instruction limit'
                    actual=ctypes.c_int64(emu.reg_read(UC_ARM64_REG_X0)).value
                    assert actual==expected,('return',mask,enabled,ident,value,actual,expected)
                    actual_io=bytearray(emu.mem_read(io,64));struct.pack_into('<Q',actual_io,56,0)
                    assert bytes(actual_io)==bytes(ni),('io',mask,enabled,ident,value)
                    assert bytes(emu.mem_read(stats,len(initial_stats)))==bytes(ns),('stats',mask,enabled,ident,value)
                    assert bytes(emu.mem_read(text,len(text_bytes)))==nt.raw,('input',ident,value)
                    assert bytes(emu.mem_read(out,4096))==no.raw,('output',ident,value)
                    count+=1
        print(f'PASS: {count} exact-stock sysfs dispatch cases; return values, input mutation, config and per-CPU stats writes, output bytes')
        print('Valid stock attribute routes; not lifetime, concurrent sysfs access or hardware proof.')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',type=Path,required=True);parser.add_argument('--symbols',type=Path,required=True)
    run(parser.parse_args())
