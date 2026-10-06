#!/usr/bin/env python3
"""Compare complete stock ARM64 sysfs output with recovered C aggregation/formatting."""
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
    spec=importlib.util.spec_from_file_location(name.replace('.','_'),Path(__file__).with_name(name))
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result


def run(args):
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
    from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X30,UC_ARM64_REG_PC,UC_ARM64_REG_SP,UC_ARM64_REG_SP_EL0
    diff=load('test-erofs-stock-differential.py');controls=load('test-erofs-stock-controls.py')
    compare=load('stock-binary-evidence.py');contract=load('verify-stock-recovered-contracts.py')
    image=args.image.read_bytes();assert hashlib.sha256(image).hexdigest()==contract.IMAGE_SHA
    assert hashlib.sha256(args.symbols.read_bytes()).hexdigest()==contract.SYMBOL_SHA
    kernel=compare.Kernel(args.image,args.symbols)
    root=Path(__file__).parents[1]/'tools/stock-recovery'
    core=(root/'erofs_iostat_update.recovered.c').read_text()
    show=(root/'erofs_iostat_show.recovered.c').read_text()
    helpers=controls.HELPERS[:controls.HELPERS.index('static int ascii_space')]
    helpers+=r'''
#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
typedef int64_t s64;
static int sysfs_emit_at(char *buffer,int offset,const char *fmt,...) {
 if(offset<0 || offset>=4096) return 0;
 va_list ap;va_start(ap,fmt); int result=vsnprintf(buffer+offset,4096-offset,fmt,ap);va_end(ap);
 return result>=4096-offset ? 4095-offset : result;
}
static int sysfs_emit(char *buffer,const char *fmt,...) {
 va_list ap;va_start(ap,fmt);int result=vsnprintf(buffer,4096,fmt,ap);va_end(ap);
 return result>=4096 ? 4095 : result;
}
'''
    wrapper=r'''
long host_show(unsigned char *data,unsigned mask,bool enabled,int present,u64 period,
 u64 *limits,u64 now,char *buffer,int daily) {
 struct erofs_iostat io={.iostat_enable=enabled,.window_period_ns=period,.stats=(void *)data};
 memcpy(io.latency_threshold_ns,limits,sizeof(io.latency_threshold_ns));
 struct erofs_sb_info sbi={.iostat=present?&io:NULL};possible_cpus=mask;fake_now=now;
 return daily ? erofs_iostat_daily_latency_show(&sbi,buffer) : erofs_iostat_window_latency_show(&sbi,buffer);
}
'''
    with tempfile.TemporaryDirectory(prefix='erofs-show-') as folder:
        library=Path(folder)/'show.dylib'
        subprocess.run(['clang','-x','c','-std=c11','-Wall','-Wextra','-Werror','-dynamiclib','-o',str(library),'-'],
                       input=diff.FIXTURE+core+helpers+show+wrapper,text=True,check=True)
        host=ctypes.CDLL(str(library));host.host_show.restype=ctypes.c_long
        host.host_show.argtypes=[ctypes.c_void_p,ctypes.c_uint,ctypes.c_bool,ctypes.c_int,ctypes.c_uint64,
                               ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_int]
        emulator=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        emulator.mem_map(kernel.base,(len(image)+4095)&~4095);emulator.mem_write(kernel.base,image)
        ram=0x1000000;emulator.mem_map(ram,0x60000)
        sbi,output,io,task,stack,stop,stats=[ram+n for n in (0,0x1000,0x2000,0x4000,0xf000,0x10000,0x20000)]
        clock={'now':0}
        def ktime(uc,address,size,user):
            uc.reg_write(UC_ARM64_REG_X0,clock['now']);uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_X30))
        address=kernel.address('ktime_get');emulator.hook_add(UC_HOOK_CODE,ktime,begin=address,end=address)
        for cpu in range(8):emulator.mem_write(kernel.address('__per_cpu_offset')+cpu*8,struct.pack('<Q',cpu*4096))
        rng=random.Random(0x3045);count=0
        for case in range(args.cases):
            mask=(0,1,0x89,0xff)[case%4]
            enabled=case%7!=0;present=case%11!=0
            period=(1,60000000000,(1<<64)-1)[case%3];now=100000000000000
            initial=bytearray(rng.randbytes(8*4096))
            for cpu in range(8):
                struct.pack_into('<I',initial,cpu*4096,(case+cpu)&1)
                age=(0,period,period*2,period*2+1,period*3,period*3+1,(1<<64)-1)[(case+cpu)%7]
                struct.pack_into('<Q',initial,cpu*4096+8,(now-age)&((1<<64)-1))
            limits=tuple(rng.randrange(1<<64) for _ in range(5))
            emulator.mem_write(stats,bytes(initial))
            emulator.mem_write(kernel.address('__cpu_possible_mask'),struct.pack('<I',mask))
            emulator.mem_write(sbi+448,struct.pack('<Q',io if present else 0))
            emulator.mem_write(io,struct.pack('<B7xQ5QQ',enabled,period,*limits,stats))
            clock['now']=now
            for daily in (False,True):
                emulator.mem_write(output,bytes(4096))
                emulator.reg_write(UC_ARM64_REG_X0,sbi);emulator.reg_write(UC_ARM64_REG_X1,output)
                emulator.reg_write(UC_ARM64_REG_X30,stop);emulator.reg_write(UC_ARM64_REG_SP,stack)
                emulator.reg_write(UC_ARM64_REG_SP_EL0,task)
                name='erofs_iostat_daily_latency_show' if daily else 'erofs_iostat_window_latency_show'
                emulator.emu_start(kernel.address(name),stop,count=1000000)
                assert emulator.reg_read(UC_ARM64_REG_PC)==stop,'instruction limit exceeded'
                actual_size=emulator.reg_read(UC_ARM64_REG_X0)
                native=(ctypes.c_ubyte*len(initial)).from_buffer_copy(initial)
                native_limits=(ctypes.c_uint64*5)(*limits);native_output=ctypes.create_string_buffer(4096)
                expected=host.host_show(native,mask,enabled,present,period,native_limits,now,native_output,daily)
                actual=bytes(emulator.mem_read(output,4096))
                assert actual_size==expected,('show size',case,daily,actual_size,expected)
                assert actual==native_output.raw,('show bytes',case,daily,actual.split(b'\0')[0],native_output.value)
                assert bytes(emulator.mem_read(stats,len(initial)))==bytes(initial),'show unexpectedly changes stats'
                count+=1
        print(f'PASS: {count} actual stock ARM64 sysfs output cases vs recovered C, exact bytes and length')
        print('Per-CPU/time modeled; no concurrency, filesystem integration or device validation.')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',type=Path,required=True);parser.add_argument('--symbols',type=Path,required=True)
    parser.add_argument('--cases',type=int,default=40)
    run(parser.parse_args())
