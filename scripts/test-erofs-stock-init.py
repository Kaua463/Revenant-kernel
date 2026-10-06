#!/usr/bin/env python3
"""Differential stock ARM64 init/destroy, with explicit allocation failure models.

No actual allocation/free, device, SMP or kernel lifetime is simulated. Original
instructions run with intercepted allocator/clock calls and private RAM only.
"""
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
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HELPERS = r'''
#include <errno.h>
static unsigned possible_cpus, fail_stage, clock_calls;
static unsigned char *io_buffer, *stats_buffer;
#define GFP_KERNEL 0xdc0
#define for_each_possible_cpu(cpu) for((cpu)=0;(cpu)<32;(cpu)++) if(possible_cpus & (1U<<(cpu)))
#define per_cpu_ptr(p,cpu) ((struct erofs_iostat_stats *)((unsigned char *)(p)+(cpu)*4096))
static void *mock_kzalloc(size_t bytes, unsigned flags) {
 assert(bytes==64 && flags==0xdc0);
 if(fail_stage==1) return NULL;
 memset(io_buffer,0,bytes); return io_buffer;
}
static void *mock_alloc_percpu(size_t bytes, size_t alignment) {
 assert(bytes==856 && alignment==8);
 return fail_stage==2 ? NULL : stats_buffer;
}
static u64 clock_step(void) { return ktime_get() + clock_calls++; }
#define ktime_get clock_step
#define kzalloc mock_kzalloc
#define alloc_percpu(type) mock_alloc_percpu(sizeof(type),_Alignof(type))
'''


WRAPPER = r'''
int host_init(unsigned char *io, unsigned char *stats, unsigned mask,
 unsigned failure, u64 now, unsigned *meta) {
 struct erofs_sb_info sbi={.iostat=(void *)1};
 io_buffer=io; stats_buffer=stats; possible_cpus=mask;
 fail_stage=failure; fake_now=now; clock_calls=0; kfree_calls=0;
 int ret=erofs_init_iostat(&sbi);
 meta[0]=sbi.iostat==NULL ? 0 : (sbi.iostat==(void *)io ? 1 : 2);
 meta[1]=kfree_calls; meta[2]=clock_calls;
 if(sbi.iostat) sbi.iostat->stats = sbi.iostat->stats ? (void *)2 : NULL;
 return ret;
}
unsigned host_destroy(int present, int stats_present) {
 struct erofs_iostat io={.stats=stats_present ? (void *)1 : NULL};
 struct erofs_sb_info sbi={.iostat=present ? &io : NULL};
 kfree_calls=0; free_percpu_calls=0;
 erofs_destroy_iostat(&sbi); assert(!sbi.iostat);
 return kfree_calls | (free_percpu_calls<<8);
}
'''


def run(args):
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
    from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X30, UC_ARM64_REG_PC, UC_ARM64_REG_SP
    contracts = load('verify-stock-recovered-contracts.py')
    diff = load('test-erofs-stock-differential.py')
    image = args.image.read_bytes()
    assert hashlib.sha256(image).hexdigest() == contracts.IMAGE_SHA
    assert hashlib.sha256(args.symbols.read_bytes()).hexdigest() == contracts.SYMBOL_SHA
    kernel = load('stock-binary-evidence.py').Kernel(args.image, args.symbols)
    root = Path(__file__).parents[1] / 'tools/stock-recovery'
    source = diff.FIXTURE + HELPERS + (root/'erofs_iostat_init.recovered.c').read_text()
    source += (root/'erofs_iostat_update.recovered.c').read_text() + WRAPPER
    with tempfile.TemporaryDirectory(prefix='erofs-init-') as folder:
        library = Path(folder)/'init.dylib'
        subprocess.run(['clang','-x','c','-std=c11','-Wall','-Wextra','-Werror',
                        '-dynamiclib','-o',str(library),'-'],input=source,text=True,check=True)
        host=ctypes.CDLL(str(library))
        host.host_init.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint,ctypes.c_uint,ctypes.c_uint64,ctypes.c_void_p]
        host.host_destroy.argtypes=[ctypes.c_int,ctypes.c_int]
        emu=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        emu.mem_map(kernel.base,(len(image)+4095)&~4095); emu.mem_write(kernel.base,image)
        ram=0x1000000; emu.mem_map(ram,0x50000)
        sbi,io,stats,stack,stop=[ram+x for x in (0,0x1000,0x2000,0x40000,0x41000)]
        for cpu in range(32):
            emu.mem_write(kernel.address('__per_cpu_offset')+8*cpu,struct.pack('<Q',cpu*4096))
        state={}
        def hook(uc,address,size,user):
            if address not in hooks: return
            name=hooks[address]
            x0=uc.reg_read(UC_ARM64_REG_X0)
            if name=='kmalloc_trace':
                assert uc.reg_read(UC_ARM64_REG_X1)==0xdc0
                assert uc.reg_read(UC_ARM64_REG_X2)==64
                result=0 if state['failure']==1 else io
                if result: uc.mem_write(io,bytes(64))
            elif name=='__alloc_percpu':
                assert x0==856 and uc.reg_read(UC_ARM64_REG_X1)==8
                result=0 if state['failure']==2 else stats
            elif name=='ktime_get':
                result=(state['now']+state['clocks'])&((1<<64)-1); state['clocks']+=1
            elif name=='kfree':
                assert x0==io; state['frees']+=1; result=0
            else:
                assert name=='free_percpu' and x0==stats
                state['percpu_frees']+=1; result=0
            uc.reg_write(UC_ARM64_REG_X0,result)
            uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_X30))
        hooks={kernel.address(n):n for n in ('kmalloc_trace','__alloc_percpu','ktime_get','kfree','free_percpu')}
        emu.hook_add(UC_HOOK_CODE,hook)
        def execute(name):
            emu.reg_write(UC_ARM64_REG_X0,sbi); emu.reg_write(UC_ARM64_REG_SP,stack)
            emu.reg_write(UC_ARM64_REG_X30,stop)
            emu.emu_start(kernel.address(name),stop,count=100000)
            assert emu.reg_read(UC_ARM64_REG_PC)==stop,'instruction bound exceeded'
            return ctypes.c_int32(emu.reg_read(UC_ARM64_REG_X0)&0xffffffff).value
        rng=random.Random(0x3041); count=0
        for mask in (0,1,0x89,0xff,0x80000000,0xffffffff):
            for failure in (0,1,2):
                for now in (0,123456789,(1<<64)-1):
                    initial_io=rng.randbytes(64); initial_stats=rng.randbytes(32*4096)
                    native_io=(ctypes.c_ubyte*64).from_buffer_copy(initial_io)
                    native_stats=(ctypes.c_ubyte*len(initial_stats)).from_buffer_copy(initial_stats)
                    meta=(ctypes.c_uint*3)()
                    expected=host.host_init(native_io,native_stats,mask,failure,now,meta)
                    emu.mem_write(io,initial_io); emu.mem_write(stats,initial_stats)
                    emu.mem_write(sbi+448,struct.pack('<Q',1))
                    emu.mem_write(kernel.address('__cpu_possible_mask'),struct.pack('<I',mask))
                    state.update(failure=failure,now=now,clocks=0,frees=0,percpu_frees=0)
                    result=execute('erofs_init_iostat')
                    assert result==expected,(mask,failure,now,result,expected)
                    pointer=struct.unpack('<Q',emu.mem_read(sbi+448,8))[0]
                    assert (0 if pointer==0 else 1 if pointer==io else 2)==meta[0]
                    assert state['frees']==meta[1] and state['clocks']==meta[2]
                    actual_io=bytearray(emu.mem_read(io,64))
                    if pointer:
                        ptr=struct.unpack_from('<Q',actual_io,56)[0]
                        struct.pack_into('<Q',actual_io,56,2 if ptr else 0)
                    assert bytes(actual_io)==bytes(native_io),('io',mask,failure,now)
                    assert bytes(emu.mem_read(stats,len(initial_stats)))==bytes(native_stats),('stats',mask,failure,now)
                    count+=1
        for present in (False,True):
            for stats_present in (False,True):
                emu.mem_write(sbi+448,struct.pack('<Q',io if present else 0))
                emu.mem_write(io+56,struct.pack('<Q',stats if stats_present else 0))
                state.update(frees=0,percpu_frees=0)
                execute('erofs_destroy_iostat')
                assert bytes(emu.mem_read(sbi+448,8))==bytes(8)
                assert state['frees']|(state['percpu_frees']<<8)==host.host_destroy(present,stats_present)
        print(f'PASS: {count} exact-stock init cases + 4 destroy cases; allocator arguments, failure effects, all 32 possible CPUs and padding preserved')
        print('Stock percpu-allocation failure leaves a freed iostat pointer: analysis finding, NOT approved production behavior.')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',type=Path,required=True)
    parser.add_argument('--symbols',type=Path,required=True)
    run(parser.parse_args())
