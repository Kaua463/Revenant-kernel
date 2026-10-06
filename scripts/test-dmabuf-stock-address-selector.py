#!/usr/bin/env python3
"""Exact stock ARM64 vs recovered C: outputs and allocator-helper arguments.

VMA lookup and vm_unmapped_area are mocked, not actual tree/allocator execution.
The stock BSS scalar is explicit private context, never extracted Image bytes.
"""
import argparse
import ctypes
import hashlib
import json
from importlib.machinery import SourceFileLoader
from itertools import product
from pathlib import Path
import random
import struct
import subprocess
import tempfile


def load(name):
    return SourceFileLoader(name, str(Path(__file__).with_name(name))).load_module()


FIXTURE = r'''
#include <stdint.h>
#include <string.h>
#define ENOMEM 12
#define MAP_FIXED 16
#define PAGE_SIZE 4096UL
#define VM_UNMAPPED_AREA_TOPDOWN 1
struct file { int unused; };
struct vm_area_struct { unsigned long vm_start,vm_end,vm_flags; };
struct vm_unmapped_area_info { unsigned long flags,length,low_limit,high_limit,align_mask,align_offset; };
typedef unsigned long (*area_fn)(struct file *,unsigned long,unsigned long,unsigned long,unsigned long);
struct mm_struct { area_fn get_unmapped_area; unsigned long mmap_base; };
static struct { struct mm_struct *mm; } task;
#define current (&task)
static unsigned long task_size,mmap_min_addr,guard;
#define TASK_SIZE task_size
static struct vm_area_struct next_vma,prev_vma;
static unsigned long rows[4][7],results[2];
static unsigned count,alloc_count,has_next,has_prev;
static unsigned long arch_get_unmapped_area_topdown(struct file *f,unsigned long a,unsigned long b,unsigned long c,unsigned long d)
{ (void)f;(void)a;(void)b;(void)c;(void)d;return 0; }
static struct vm_area_struct *find_vma_prev(struct mm_struct *mm,unsigned long addr,struct vm_area_struct **prev)
{ (void)mm; rows[count][0]=0;rows[count++][1]=addr;*prev=has_prev?&prev_vma:0;return has_next?&next_vma:0; }
static unsigned long vm_start_gap(struct vm_area_struct *v)
{ unsigned long start=v->vm_start;if(v->vm_flags&256){unsigned long adjusted=start-guard;start=adjusted>start?0:adjusted;}return start; }
static unsigned long vm_unmapped_area(struct vm_unmapped_area_info *info)
{ rows[count][0]=1;memcpy(&rows[count++][1],info,sizeof(*info));return results[alloc_count++]; }
'''
WRAPPER = r'''
unsigned host_selector(const uint64_t *in,uint64_t *out,uint64_t *trace)
{
 struct mm_struct mm={in[0]?arch_get_unmapped_area_topdown:0,in[1]};task.mm=&mm;
 task_size=in[2]?0xfffff000UL:0x8000000000UL;mmap_min_addr=in[3];guard=in[4];
 next_vma=(struct vm_area_struct){in[5],0,in[6]};prev_vma=(struct vm_area_struct){0,in[7],0};
 has_next=in[8];has_prev=in[9];results[0]=in[10];results[1]=in[11];
 count=alloc_count=0;memset(rows,0,sizeof(rows));
 *out=dma_buf_hugetlb_get_unmapped_area(0,in[12],in[13],in[14],in[15]);
 memcpy(trace,rows,count*sizeof(rows[0]));return count;
}
'''


def run(args):
    if args.output and (args.output.exists() or args.output.is_symlink()):
        raise ValueError('evidence exists')
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
    from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
        UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X30, UC_ARM64_REG_SP,
        UC_ARM64_REG_SP_EL0, UC_ARM64_REG_PC)
    proof = load('extract-dmabuf-address-selector.py')
    image = args.image.read_bytes()
    if hashlib.sha256(image).hexdigest() != proof.scanner.IMAGE_SHA or hashlib.sha256(args.symbols.read_bytes()).hexdigest() != proof.scanner.SYMBOL_SHA:
        raise ValueError('stock pin mismatch')
    k = proof.scanner.evidence.Kernel(args.image, args.symbols)
    fields = load('test-dmabuf-stock-wrappers.py').btf_fields
    required = {'task_struct': {'mm': 1440, 'stack_canary': 1568, 'thread_info': 0},
                'mm_struct': {'get_unmapped_area': 80, 'mmap_base': 88},
                'vm_area_struct': {'vm_start': 0, 'vm_end': 8, 'vm_flags': 32},
                'vm_unmapped_area_info': {'flags': 0, 'length': 8, 'low_limit': 16,
                                         'high_limit': 24, 'align_mask': 32, 'align_offset': 40}}
    for name, members in required.items():
        variants = [i for i,t in enumerate(k.btf.types) if t['kind'] == 4 and t['name'] == name]
        if not variants:
            raise ValueError('BTF absent: ' + name)
        for ident in variants:
            found = fields(k.btf, ident)
            if any(found.get(n) != offset for n,offset in members.items()):
                raise ValueError('BTF offset drift: ' + name)
    proof.field_offsets([k.btf.record(i) for i,t in enumerate(k.btf.types)
                         if t['kind'] == 4 and t['name'] == 'file_operations'])
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(k.base, (len(image)+4095)&~4095)
    uc.mem_write(k.base, image)
    minimum = k.address('mmap_min_addr')
    if k.symbols['mmap_min_addr'][0][1] != 'B' or k.span('mmap_min_addr') is not None:
        raise ValueError('expected explicitly modeled stock BSS scalar')
    uc.mem_map(minimum & ~4095, 4096)
    ram = 0x1000000
    uc.mem_map(ram, 0x20000)
    task, mm, vma, prev, stack, stop = (ram, ram+0x1000, ram+0x2000, ram+0x3000,
                                      ram+0xf000, ram+0x10000)
    state, trace, counts = {}, [], {'hint': 0, 'allocator': 0, 'fallback': 0}
    find, allocate = k.address('find_vma_prev'), k.address('vm_unmapped_area')
    def hook(emu, address, size, user):
        if address == find:
            if emu.reg_read(UC_ARM64_REG_X0) != mm:
                raise ValueError('lookup wrong mm')
            trace.append((0, emu.reg_read(UC_ARM64_REG_X1), 0, 0, 0, 0, 0))
            emu.mem_write(emu.reg_read(UC_ARM64_REG_X2), struct.pack('<Q', prev if state['has_prev'] else 0))
            emu.reg_write(UC_ARM64_REG_X0, vma if state['has_next'] else 0)
            emu.reg_write(UC_ARM64_REG_PC, emu.reg_read(UC_ARM64_REG_X30))
        elif address == allocate:
            info = struct.unpack('<6Q', emu.mem_read(emu.reg_read(UC_ARM64_REG_X0), 48))
            trace.append((1, *info))
            index = state['alloc_count']
            if index >= 2:
                raise ValueError('unexpected third allocator call')
            emu.reg_write(UC_ARM64_REG_X0, state['results'][index])
            state['alloc_count'] += 1
            emu.reg_write(UC_ARM64_REG_PC, emu.reg_read(UC_ARM64_REG_X30))
        elif address == k.address('__stack_chk_fail'):
            raise ValueError('stock canary failed')
    uc.hook_add(UC_HOOK_CODE, hook)
    source = Path(__file__).parents[1]/'tools/stock-recovery/dmabuf_huge_address.recovered.c'
    with tempfile.TemporaryDirectory(prefix='dma-selector-differential-') as temporary:
        lib = Path(temporary)/'selector.dylib'
        subprocess.run(['clang','-x','c','-std=c11','-Wall','-Wextra','-Werror',
                        '-dynamiclib','-o',str(lib),'-'], input=FIXTURE+source.read_text()+WRAPPER,
                       text=True, check=True)
        host = ctypes.CDLL(str(lib))
        host.host_selector.argtypes = [ctypes.c_void_p]*3
        host.host_selector.restype = ctypes.c_uint
        lengths = (0,1,4095,4096,65535,65536,65537,2097151,2097152,2097153,
                   0xffffefff,0xfffff000,0x7fffff0000,0x8000000000,(1<<64)-1)
        hints = (0,0x10001,0x100001,0xfffff001,(1<<64)-1)
        scenarios = (
            (0,0,0x8000000,0,0,0x400000,0x600000),
            (1,0,0x100000,0,0,0x400000,0x600000),
            (1,0,0x100000,256,0,0x400000,0x600000),
            (0,1,0,0,0x200000,0x400000,0x600000),
            (0,0,0,0,0,(1<<64)-12,0x600000),
            (1,1,0x10000,256,0x200000,(1<<64)-12,(1<<64)-12),
        )
        cases = []
        for top,compat,length,hint,minimum_value,scenario in product((0,1),(0,1),lengths,hints,(0,65536),scenarios):
            hn,hp,start,vflags,pend,r0,r1 = scenario
            cases.append([top,0x40000000,compat,minimum_value,0x100000,start,vflags,pend,hn,hp,r0,r1,hint,length,0xdead,0])
        # Explicit MAP_FIXED preserves raw hint; length rejection still precedes it.
        for compat,length,hint in product((0,1),lengths,hints):
            cases.append([1,0x40000000,compat,65536,0,0,0,0,0,0,0,0,hint,length,0,16])
        randomizer = random.Random(30477)
        for _ in range(300):
            cases.append([randomizer.randrange(2),randomizer.getrandbits(39),randomizer.randrange(2),
                          randomizer.choice((0,1,4096,65536)),randomizer.getrandbits(20),
                          randomizer.getrandbits(39),randomizer.choice((0,256)),randomizer.getrandbits(39),
                          randomizer.randrange(2),randomizer.randrange(2),
                          randomizer.choice((0x400000,(1<<64)-12,0x400001)),0x600000,
                          randomizer.getrandbits(64),randomizer.getrandbits(39),randomizer.getrandbits(64),0])
        observations = hashlib.sha256()
        for index, values in enumerate(cases):
            inputs = (ctypes.c_uint64*16)(*values)
            result, rows = ctypes.c_uint64(), (ctypes.c_uint64*28)()
            n = host.host_selector(inputs,ctypes.byref(result),rows)
            expected = [tuple(rows[i*7:(i+1)*7]) for i in range(n)]
            uc.mem_write(task, bytes(4096))
            uc.mem_write(task,struct.pack('<Q',values[2]<<22))
            uc.mem_write(task+1440,struct.pack('<Q',mm))
            uc.mem_write(task+1568,struct.pack('<Q',0x12345678))
            uc.mem_write(mm+80,struct.pack('<2Q',k.address('arch_get_unmapped_area_topdown') if values[0] else 0,values[1]))
            uc.mem_write(vma,struct.pack('<2Q',values[5],0))
            uc.mem_write(vma+32,struct.pack('<Q',values[6]))
            uc.mem_write(prev+8,struct.pack('<Q',values[7]))
            uc.mem_write(minimum,struct.pack('<Q',values[3]))
            uc.mem_write(k.address('stack_guard_gap'),struct.pack('<Q',values[4]))
            state.update(has_next=values[8],has_prev=values[9],results=values[10:12],alloc_count=0)
            trace.clear()
            for reg,value in zip((UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4),
                                 (0,values[12],values[13],values[14],values[15])):
                uc.reg_write(reg,value)
            uc.reg_write(UC_ARM64_REG_X30,stop)
            uc.reg_write(UC_ARM64_REG_SP,stack)
            uc.reg_write(UC_ARM64_REG_SP_EL0,task)
            uc.emu_start(k.address('dma_buf_hugetlb_get_unmapped_area'),stop,count=10000)
            actual = uc.reg_read(UC_ARM64_REG_X0)
            if uc.reg_read(UC_ARM64_REG_PC) != stop or actual != result.value or trace != expected:
                raise AssertionError({'case':index,'input':values,'actual':hex(actual),
                                      'expected':hex(result.value),'trace':trace,'expected_trace':expected})
            observations.update(json.dumps([values,actual,trace],separators=(',',':')).encode()+b'\n')
            counts['hint'] += any(row[0] == 0 for row in trace)
            counts['allocator'] += any(row[0] == 1 for row in trace)
            counts['fallback'] += state['alloc_count'] == 2
        if not all(counts.values()):
            raise ValueError('required routes not exercised')
        print(f'PASS: {len(cases)} exact-stock ARM64/C selector cases; routes={counts}')
        print('Lookup/allocator bodies modeled; no MMU, tree, SMP or complete integration proof.')
        if args.output:
            report = {'status':'STOCK_ARM64_C_HELPER_TRACE_EQUIVALENCE_NOT_FULL_DMA_PROOF',
                      'cases':len(cases),'routes':counts,'observations_sha256':observations.hexdigest(),
                      'image_sha256':proof.scanner.IMAGE_SHA,'symbols_sha256':proof.scanner.SYMBOL_SHA,
                      'recipe_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
                      'modeled':['find_vma_prev lookup result','vm_unmapped_area allocator result',
                                 'mmap_min_addr BSS scalar','private task/mm/VMA context'],
                      'pending':['actual allocator/tree behavior','VFS/producer activation',
                                 'complete failure/lifetime/MMU/SMP/hardware gates']}
            args.output.parent.mkdir(parents=True,exist_ok=True)
            with args.output.open('x') as stream:
                json.dump(report,stream,indent=2)
                stream.write('\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',type=Path,required=True)
    parser.add_argument('--symbols',type=Path,required=True)
    parser.add_argument('--output',type=Path)
    run(parser.parse_args())
