#!/usr/bin/env python3
"""Actual stock ARM64 parser/reset execution vs recovered C with modeled per-CPU RAM."""
import argparse
import ctypes
import hashlib
import importlib.util
from pathlib import Path
import random
import struct
import subprocess
import tempfile

HELPERS = r'''
#include <errno.h>
static unsigned possible_cpus;
#define for_each_possible_cpu(cpu) for((cpu)=0;(cpu)<8;(cpu)++) if(possible_cpus & (1U<<(cpu)))
#define per_cpu_ptr(p,cpu) ((struct erofs_iostat_stats *)((unsigned char *)(p)+(cpu)*4096))
static int ascii_space(unsigned char c) { return c==' ' || (c>=9 && c<=13); }
static char *mock_strim(char *p) {
 while(ascii_space(*p)) p++;
 char *end=p+strlen(p); while(end>p && ascii_space(end[-1])) end--;
 *end=0; return p;
}
static char *mock_strsep(char **cursor,const char *delim) {
 if(!*cursor) return NULL;
 char *head=*cursor,*p=head; while(*p && !strchr(delim,*p)) p++;
 if(*p) { *p=0; *cursor=p+1; } else *cursor=NULL;
 return head;
}
static int mock_kstrtoull(const char *p,unsigned int base,unsigned long long *out) {
 unsigned long long value=0; unsigned count=0;
 assert(base==10); if(*p=='+') p++;
 while(*p>='0' && *p<='9') {
  unsigned n=(unsigned)(*p-'0');
  if(value>(UINT64_MAX-n)/10) return -ERANGE;
  value=value*10+n; count++; p++;
 }
 if(!count) return -EINVAL;
 if(*p=='\n') p++;
 if(*p) return -EINVAL;
 *out=value; return 0;
}
#define strim mock_strim
#define strsep mock_strsep
#define kstrtoull mock_kstrtoull
int host_parse(unsigned char *io_bytes,char *input,int present) {
 struct erofs_iostat io; memcpy(&io,io_bytes,sizeof(io));
 struct erofs_sb_info sbi={.iostat=present?&io:NULL};
 int result=erofs_iostat_config_parse(&sbi,input);
 memcpy(io_bytes,&io,sizeof(io)); return result;
}
'''


def load_script(name):
    path=Path(__file__).with_name(name)
    spec=importlib.util.spec_from_file_location(name.replace('.','_'),path)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result)
    return result


def run(args):
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM
    from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X30,UC_ARM64_REG_PC,UC_ARM64_REG_SP,UC_ARM64_REG_SP_EL0
    diff=load_script('test-erofs-stock-differential.py')
    compare=load_script('stock-binary-evidence.py')
    contracts=load_script('verify-stock-recovered-contracts.py')
    image=args.image.read_bytes()
    assert hashlib.sha256(image).hexdigest()==contracts.IMAGE_SHA
    assert hashlib.sha256(args.symbols.read_bytes()).hexdigest()==contracts.SYMBOL_SHA
    kernel=compare.Kernel(args.image,args.symbols)
    root=Path(__file__).parents[1]/'tools/stock-recovery'
    core=(root/'erofs_iostat_update.recovered.c').read_text()
    controls=(root/'erofs_iostat_controls.recovered.c').read_text()
    # Helpers must precede their users; prototypes precede host wrapper.
    declarations='int erofs_iostat_config_parse(struct erofs_sb_info *,char *);\n'
    wrapper=r'''
int host_reset(unsigned char *data,unsigned mask,bool enabled,char *input,int daily) {
 struct erofs_iostat io={.iostat_enable=enabled,.stats=(void *)data};
 struct erofs_sb_info sbi={.iostat=&io}; possible_cpus=mask;
 if(daily) return erofs_iostat_daily_stats_reset(&sbi,input);
 erofs_iostat_latency_stats_reset(&sbi); return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='erofs-controls-') as folder:
        library=Path(folder)/'controls.dylib'
        subprocess.run(['clang','-x','c','-std=c11','-Wall','-Wextra','-Werror','-dynamiclib','-o',str(library),'-'],
                       input=diff.FIXTURE+core+declarations+HELPERS+controls+wrapper,text=True,check=True)
        host=ctypes.CDLL(str(library))
        host.host_parse.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_int]
        host.host_reset.argtypes=[ctypes.c_void_p,ctypes.c_uint,ctypes.c_bool,ctypes.c_void_p,ctypes.c_int]
        emulator=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        emulator.mem_map(kernel.base,(len(image)+4095)&~4095);emulator.mem_write(kernel.base,image)
        ram=0x1000000;emulator.mem_map(ram,0x60000)
        sbi,text,io,task,stack,stop,stats=[ram+n for n in (0,0x1000,0x2000,0x4000,0xf000,0x10000,0x20000)]
        def execute(name,arg1=text):
            emulator.reg_write(UC_ARM64_REG_X0,sbi);emulator.reg_write(UC_ARM64_REG_X1,arg1)
            emulator.reg_write(UC_ARM64_REG_X30,stop);emulator.reg_write(UC_ARM64_REG_SP,stack)
            emulator.reg_write(UC_ARM64_REG_SP_EL0,task)
            emulator.emu_start(kernel.address(name),stop,count=50000)
            assert emulator.reg_read(UC_ARM64_REG_PC)==stop,'instruction bound exceeded'
            return ctypes.c_int32(emulator.reg_read(UC_ARM64_REG_X0)&0xffffffff).value
        rng=random.Random(0x304c)
        cases=['60,100,100,100,100,100','  60,1,2,3,4,5 \n','0,0,0,0,0,0',
               '4294967295,18446744073709551615,1,2,3,4',
               '4294967296,1,2,3,4,5','60,1,2,3,4','60,1,2,3,4,5,6',
               '60,1,2,3,4,5,','60,,2,3,4,5','60,1,2,3,4,-5',
               '60,1,2,3,4,+5','60,1,2,3,4,18446744073709551616',
               '60,1,2,3,4,0x10','60,1,2,3,4, 5','','reset',
               '60\n,1,2,3,4,5','+60,1,2,3,4,5']
        cases += [','.join(str(rng.randrange(1<<64)) for _ in range(6)) for _ in range(50)]
        parser_count=0
        for present in (False,True):
            for value in cases:
                initial=rng.randbytes(64)
                native=(ctypes.c_ubyte*64).from_buffer_copy(initial)
                input_bytes=value.encode()+b'\0'
                native_text=ctypes.create_string_buffer(input_bytes,len(input_bytes))
                emulator.mem_write(io,initial);emulator.mem_write(text,input_bytes)
                emulator.mem_write(sbi+448,struct.pack('<Q',io if present else 0))
                result=execute('erofs_iostat_config_parse')
                expected=host.host_parse(native,native_text,present)
                assert result==expected,('parser result',value,result,expected)
                assert bytes(emulator.mem_read(io,64))==bytes(native),('parser writes',value)
                assert bytes(emulator.mem_read(text,len(input_bytes)))==native_text.raw,('parser mutation',value)
                parser_count+=1
        mask_address=kernel.address('__cpu_possible_mask')
        offsets_address=kernel.address('__per_cpu_offset')
        for cpu in range(8): emulator.mem_write(offsets_address+cpu*8,struct.pack('<Q',cpu*4096))
        reset_count=0
        for mask in (0,1,0b10001001,0xff):
            emulator.mem_write(mask_address,struct.pack('<I',mask))
            for enabled in (False,True):
                for daily in (False,True):
                    for value in ('reset',' reset\n','reset-extra','bad',''):
                        initial=rng.randbytes(8*4096)
                        native=(ctypes.c_ubyte*len(initial)).from_buffer_copy(initial)
                        input_bytes=value.encode()+b'\0'
                        native_text=ctypes.create_string_buffer(input_bytes,len(input_bytes))
                        emulator.mem_write(stats,initial)
                        emulator.mem_write(text,input_bytes)
                        emulator.mem_write(sbi+448,struct.pack('<Q',io))
                        emulator.mem_write(io,struct.pack('<B7xQ5QQ',enabled,0,*([0]*5),stats))
                        name='erofs_iostat_daily_stats_reset' if daily else 'erofs_iostat_latency_stats_reset'
                        result=execute(name)
                        expected=host.host_reset(native,mask,enabled,native_text,daily)
                        if daily: assert result==expected,('reset result',mask,enabled,value,result,expected)
                        assert bytes(emulator.mem_read(stats,len(initial)))==bytes(native),('reset writes',mask,enabled,daily,value)
                        if daily: assert bytes(emulator.mem_read(text,len(input_bytes)))==native_text.raw
                        reset_count+=1
        print(f'PASS: {parser_count} exact-stock ARM64 parser cases and {reset_count} per-CPU reset cases vs recovered C')
        print('Modeled helpers/context; not SMP, sysfs integration or hardware validation.')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',type=Path,required=True);parser.add_argument('--symbols',type=Path,required=True)
    run(parser.parse_args())
