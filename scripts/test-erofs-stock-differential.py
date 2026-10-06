#!/usr/bin/env python3
"""Differentially execute actual stock ARM64 EROFS code vs recovered C.

Unicorn execution uses modeled clock/per-CPU task context only, not a device,
filesystem, concurrency or whole-kernel emulation. Host C uses matching layouts.
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


FIXTURE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
typedef uint64_t u64; typedef uint32_t u32;
struct latency_stats { u64 sum_lat, peak_lat; u32 bio_cnt; };
struct erofs_iostat_stats {
 u32 current_window_idx; u64 current_window_start;
 struct latency_stats window_stats[10],window_ab_stats[10];
 struct latency_stats daily_stats[5],daily_ab_stats[5],delay_stats[5];
};
struct erofs_iostat { bool iostat_enable; u64 window_period_ns;
 u64 latency_threshold_ns[5]; struct erofs_iostat_stats *stats; };
struct erofs_sb_info { unsigned char before[0x1c0]; struct erofs_iostat *iostat; };
struct bio { unsigned char before[0x28]; struct { u32 bi_size; } bi_iter;
 unsigned char gap[0x88-0x2c]; u64 android_oem_data1; };
_Static_assert(sizeof(struct latency_stats)==24,"latency layout");
_Static_assert(sizeof(struct erofs_iostat_stats)==856,"stats layout");
_Static_assert(sizeof(struct erofs_iostat)==64,"iostat layout");
_Static_assert(offsetof(struct erofs_iostat,stats)==0x38,"stats pointer");
_Static_assert(offsetof(struct bio,android_oem_data1)==0x88,"OEM timestamp");
static u64 fake_now;
static unsigned free_percpu_calls, kfree_calls;
static u64 ktime_get(void) { return fake_now; }
#define get_cpu_ptr(p) (p)
#define put_cpu_ptr(p) ((void)(p))
#define max(a,b) ((a)>(b)?(a):(b))
#define BUG_ON(x) assert(!(x))
static void free_percpu(void *p) { (void)p; free_percpu_calls++; }
static void kfree(void *p) { (void)p; kfree_calls++; }
'''


def run(args):
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
    from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
        UC_ARM64_REG_X30, UC_ARM64_REG_PC, UC_ARM64_REG_SP,
        UC_ARM64_REG_SP_EL0, UC_ARM64_REG_TPIDR_EL1)
    scripts = Path(__file__).parent
    spec = importlib.util.spec_from_file_location('contracts', scripts / 'verify-stock-recovered-contracts.py')
    contracts = importlib.util.module_from_spec(spec); spec.loader.exec_module(contracts)
    image = args.image.read_bytes()
    if hashlib.sha256(image).hexdigest() != contracts.IMAGE_SHA:
        raise ValueError('not the pinned stock Image')
    if hashlib.sha256(args.symbols.read_bytes()).hexdigest() != contracts.SYMBOL_SHA:
        raise ValueError('not the pinned stock kallsyms')
    spec = importlib.util.spec_from_file_location('compare', scripts / 'stock-binary-evidence.py')
    compare = importlib.util.module_from_spec(spec); spec.loader.exec_module(compare)
    kernel = compare.Kernel(args.image, args.symbols)
    records = kernel.btf.records()
    # Assert transitive layouts used by C, not merely top-level sizeof.
    expected = {
      'latency_stats': {'sum_lat':0,'peak_lat':8,'bio_cnt':16},
      'erofs_iostat_stats': {'current_window_idx':0,'current_window_start':8,
        'window_stats':16,'window_ab_stats':256,'daily_stats':496,
        'daily_ab_stats':616,'delay_stats':736},
      'erofs_iostat': {'iostat_enable':0,'window_period_ns':8,'latency_threshold_ns':16,'stats':56},
      'erofs_sb_info': {'iostat':448}, 'bio': {'android_oem_data1':136,'bi_iter':32},
      'bvec_iter': {'bi_size':8}}
    for name, fields in expected.items():
        variants = records['struct ' + name]
        assert len(variants) == 1
        actual = {m['name']: m['offset_bits']//8 for m in variants[0]['members']}
        for member, offset in fields.items():
            assert actual[member] == offset, (name,member,actual[member],offset)
    source = (scripts.parent / 'tools/stock-recovery/erofs_iostat_update.recovered.c').read_text()
    start_source = (scripts.parent / 'tools/stock-recovery/erofs_iostat_record_start.recovered.c').read_text()
    wrapper = r'''
void host_update(unsigned char *stats_bytes, bool enabled, u64 period,
 u64 *thresholds, u32 bytes, u64 *timestamp, u64 now) {
 struct erofs_iostat_stats stats; memcpy(&stats,stats_bytes,sizeof(stats));
 struct erofs_iostat io={.iostat_enable=enabled,.window_period_ns=period,.stats=&stats};
 memcpy(io.latency_threshold_ns,thresholds,sizeof(io.latency_threshold_ns));
 struct erofs_sb_info sbi={.iostat=&io};
 struct bio bio={.android_oem_data1=*timestamp}; bio.bi_iter.bi_size=bytes;
 fake_now=now; erofs_iostat_update(&sbi,&bio);
 memcpy(stats_bytes,&stats,sizeof(stats)); *timestamp=bio.android_oem_data1;
}
u64 host_start(bool enabled,u64 previous,u64 now) {
 struct erofs_iostat io={.iostat_enable=enabled}; struct erofs_sb_info sbi={.iostat=&io};
 struct bio bio={.android_oem_data1=previous}; fake_now=now;
 erofs_iostat_record_start(&sbi,&bio); return bio.android_oem_data1;
}
void host_destroy_test(void) {
 struct erofs_sb_info sbi={0}; erofs_destroy_iostat(&sbi);
 assert(!kfree_calls && !free_percpu_calls);
 struct erofs_iostat io={0}; sbi.iostat=&io; erofs_destroy_iostat(&sbi);
 assert(!sbi.iostat && kfree_calls==1 && free_percpu_calls==0);
 io.stats=(void *)1; sbi.iostat=&io; erofs_destroy_iostat(&sbi);
 assert(!sbi.iostat && kfree_calls==2 && free_percpu_calls==1);
 erofs_destroy_iostat(&sbi); assert(kfree_calls==2 && free_percpu_calls==1);
}
'''
    with tempfile.TemporaryDirectory(prefix='erofs-differential-') as folder:
        library = Path(folder) / 'recovered.dylib'
        subprocess.run(['clang','-x','c','-std=c11','-Wall','-Wextra','-Werror',
            '-dynamiclib','-o',str(library),'-'],
            input=FIXTURE + source + start_source + wrapper,text=True,check=True)
        host = ctypes.CDLL(str(library))
        host.host_update.argtypes = [ctypes.c_void_p,ctypes.c_bool,ctypes.c_uint64,
            ctypes.c_void_p,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint64]
        host.host_start.argtypes = [ctypes.c_bool,ctypes.c_uint64,ctypes.c_uint64]
        host.host_start.restype = ctypes.c_uint64
        host.host_destroy_test()
        # Map a private copy of immutable stock; no instruction patching.
        emulator = Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        base = kernel.base
        emulator.mem_map(base, (len(image)+4095)&~4095)
        emulator.mem_write(base,image)
        ram,stop = 0x1000000,0x1010000
        emulator.mem_map(ram,0x20000)
        sbi,bio,io,stats,task,stack = [ram + n for n in (0,0x1000,0x2000,0x3000,0x4000,0xf000)]
        clock = {'now':0}
        def ktime(uc,address,size,user):
            uc.reg_write(UC_ARM64_REG_X0, clock['now'])
            uc.reg_write(UC_ARM64_REG_PC,uc.reg_read(UC_ARM64_REG_X30))
        address = kernel.address('ktime_get')
        emulator.hook_add(UC_HOOK_CODE,ktime,begin=address,end=address)
        def execute(name):
            emulator.reg_write(UC_ARM64_REG_X0,sbi)
            emulator.reg_write(UC_ARM64_REG_X1,bio)
            emulator.reg_write(UC_ARM64_REG_X30,stop)
            emulator.reg_write(UC_ARM64_REG_SP,stack)
            emulator.reg_write(UC_ARM64_REG_SP_EL0,task)
            emulator.reg_write(UC_ARM64_REG_TPIDR_EL1,0)
            emulator.mem_write(task+0x10,struct.pack('<Q',1))
            emulator.emu_start(kernel.address(name),stop,count=3000)
            assert emulator.reg_read(UC_ARM64_REG_PC)==stop, 'did not return within instruction limit'
        emulator.mem_write(sbi+448,struct.pack('<Q',io))
        rng=random.Random(0x304)
        boundary_bytes=[0,16384,17407,17408,131072,132095,132096,263167,263168,525311,525312,0xffffffff]
        boundary_ns=[0,999999,1000000,4999999,5000000,9999999,10000000,
                     49999999,50000000,100000001,(1<<63)-1,(1<<64)-1]
        tests=[]
        for size in boundary_bytes:
            for delay in boundary_ns:
                for enabled in (False,True):
                    tests.append((size,delay,enabled))
        tests += [(rng.randrange(1<<32),rng.randrange(1<<40),bool(rng.randrange(2)))
                  for _ in range(args.random_cases)]
        for number,(size,delay,enabled) in enumerate(tests):
            initial=bytearray(rng.randbytes(856))
            index=number&1
            struct.pack_into('<I',initial,0,index)
            period=[0,1,60000000000,(1<<64)-1][number%4]
            timestamp=1 if number%13 else 0
            now=(timestamp+delay)&((1<<64)-1)
            window_start=(now - [period,period+1,0][number%3])&((1<<64)-1)
            struct.pack_into('<Q',initial,8,window_start)
            thresholds=[0,delay,delay+1,100000000,((1<<64)-1)][number%5]
            thresholds=tuple(thresholds & ((1<<64)-1) for _ in range(5))
            emulator.mem_write(stats,bytes(initial))
            emulator.mem_write(io,struct.pack('<B7xQ5QQ',enabled,period,*thresholds,stats))
            emulator.mem_write(bio,bytes(160))
            emulator.mem_write(bio+0x28,struct.pack('<I',size))
            emulator.mem_write(bio+0x88,struct.pack('<Q',timestamp))
            clock['now']=now
            execute('erofs_iostat_update')
            native=(ctypes.c_ubyte*856).from_buffer_copy(initial)
            limits=(ctypes.c_uint64*5)(*thresholds)
            native_timestamp=ctypes.c_uint64(timestamp)
            host.host_update(native,enabled,period,limits,size,ctypes.byref(native_timestamp),now)
            actual=bytes(emulator.mem_read(stats,856))
            assert actual==bytes(native), f'case {number}: stats mismatch'
            assert struct.unpack('<Q',emulator.mem_read(bio+0x88,8))[0]==native_timestamp.value
        for enabled in (False,True):
            for now in (0,123456789,(1<<63)-1):
                emulator.mem_write(io,struct.pack('<B7xQ5QQ',enabled,0,*([0]*5),stats))
                emulator.mem_write(bio+0x88,struct.pack('<Q',99))
                clock['now']=now;execute('erofs_iostat_record_start')
                assert struct.unpack('<Q',emulator.mem_read(bio+0x88,8))[0]==host.host_start(enabled,99,now)
        # Run the same recovered bodies in a separate sanitized executable too.
        sanitized = Path(folder) / 'sanitized'
        checks = r'''
int main(void) {
 struct erofs_iostat_stats stats={0}; u64 limits[5]={0},stamp=1;
 host_update((unsigned char *)&stats,true,60000000000ULL,limits,17408,&stamp,1000001);
 assert(!stamp && stats.daily_stats[1].bio_cnt==1);
 assert(stats.daily_stats[1].sum_lat==1000000 && stats.delay_stats[1].bio_cnt==1);
 assert(stats.daily_ab_stats[1].sum_lat==1000000);
 host_destroy_test(); return 0;
}
'''
        subprocess.run(['clang','-x','c','-std=c11','-Wall','-Wextra','-Werror',
            '-fsanitize=address,undefined','-o',str(sanitized),'-'],
            input=FIXTURE+source+start_source+wrapper+checks,text=True,check=True)
        subprocess.run([str(sanitized)],check=True)
        print(f'PASS: {len(tests)} stock ARM64 vs recovered C update cases; 6 record-start cases; destroy host cases')
        print('Not SMP, Kbuild, filesystem or hardware validation; contract integration still pending.')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',type=Path,required=True)
    parser.add_argument('--symbols',type=Path,required=True)
    parser.add_argument('--random-cases',type=int,default=1000)
    run(parser.parse_args())
