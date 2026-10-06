#!/usr/bin/env python3
"""Pinned ARM64 lock/zap differential; freeing, locks and MMU remain modeled."""
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


FIXTURE = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
typedef struct { uint64_t val; } pmd_t;
typedef void spinlock_t;
typedef unsigned char *pgtable_t;
struct vm_area_struct;
struct mm_struct { unsigned char raw[2048]; };
struct mmu_gather { struct mm_struct *mm; uint64_t batch,start,end; unsigned char rest[96]; };
static struct mm_struct mm;
static unsigned char page[128];
static uint64_t rows[16][4],counter;static unsigned nr;
#define HPAGE_PMD_SIZE (1UL<<21)
#define dmabuf_hugetlb_pmd_zap counter
static void trace(uint64_t op,uint64_t a,uint64_t b,uint64_t c) {
 assert(nr<16);uint64_t row[]={op,a,b,c};memcpy(rows[nr++],row,sizeof(row)); }
static void *pmd_ptdesc(pmd_t *p) { (void)p;return (void *)0xfffffffe00040000ULL; }
static spinlock_t *ptlock_ptr(void *p) {return (void *)((uintptr_t)p+0x68);}
static void spin_lock(spinlock_t *p) {trace(1,(uintptr_t)p,0,0);}
static void spin_unlock(spinlock_t *p) {trace(5,(uintptr_t)p,0,0);}
static int pmd_trans_huge(pmd_t p) {return (p.val&0xc00000000000001ULL) && !(p.val&2);}
static pmd_t pmdp_huge_get_and_clear(struct mm_struct *m,unsigned long a,pmd_t *p) {
 (void)m;(void)a;pmd_t old=*p;p->val=0;return old; }
static void tlb_remove_pmd_tlb_entry(struct mmu_gather *t,pmd_t *p,unsigned long a) {
 (void)p;if(a<t->start)t->start=a;if(a+HPAGE_PMD_SIZE>t->end)t->end=a+HPAGE_PMD_SIZE;
 t->rest[0]|=0x20; }
static pgtable_t pgtable_trans_huge_withdraw(struct mm_struct *m,pmd_t *p) {
 assert(m==&mm);(void)p;trace(2,0x1001000,0xffffff8001001000ULL,0);return page; }
static void pte_free(struct mm_struct *m,pgtable_t p) {
 assert(m==&mm && p==page);uint64_t flags;uint32_t type;int32_t pages=1;
 memcpy(&flags,p,8);memcpy(&type,p+0x30,4);type|=0x200;memcpy(p+0x30,&type,4);
 if(flags&64)memcpy(&pages,p+0x60,4);
 trace(3,0xfffffffe00040000ULL,39,(uint32_t)-pages);
 trace(4,0xfffffffe00040000ULL,(flags&64)?p[0x40]:0,0); }
static void mm_dec_nr_ptes(struct mm_struct *m) {
 uint64_t n;memcpy(&n,m->raw+0x80,8);n-=4096;memcpy(m->raw+0x80,&n,8); }
static void atomic64_inc(uint64_t *p) {++*p;}
'''

WRAPPER = r'''
uint64_t host_zap(const uint64_t *in,unsigned char *tlb_bytes,unsigned char *page_bytes,
 uint64_t *out,uint64_t *trace_out) {
 struct mmu_gather t;memcpy(&t,tlb_bytes,128);t.mm=&mm;
 memcpy(page,page_bytes,128);memcpy(mm.raw+0x80,&in[2],8);
 pmd_t p={in[0]};counter=in[3];nr=0;
 uint64_t ret=in[4]?(uintptr_t)__pmd_dmabuf_huge_lock(&p,NULL):
 (uint64_t)zap_dmabuf_huge_pmd(&t,NULL,&p,in[1]);
 t.mm=(void *)0x1001000;memcpy(tlb_bytes,&t,128);memcpy(page_bytes,page,128);
 out[0]=ret;out[1]=p.val;memcpy(out+2,mm.raw+0x80,8);out[3]=counter;
 memcpy(trace_out,rows,nr*4*sizeof(uint64_t));return nr;
}
'''


def run(args):
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
    from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                    UC_ARM64_REG_X3, UC_ARM64_REG_X30, UC_ARM64_REG_SP,
                                    UC_ARM64_REG_SP_EL0, UC_ARM64_REG_PC)
    contract = load('verify-stock-recovered-contracts.py')
    image = args.image.read_bytes()
    assert hashlib.sha256(image).hexdigest() == contract.IMAGE_SHA
    assert hashlib.sha256(args.symbols.read_bytes()).hexdigest() == contract.SYMBOL_SHA
    kernel = load('stock-binary-evidence.py').Kernel(args.image, args.symbols)
    btf = kernel.btf
    fields = load('test-dmabuf-stock-wrappers.py').btf_fields
    for name, required in {'mmu_gather': {'mm': 0, 'start': 16, 'end': 24},
                           'mm_struct': {'pgtables_bytes': 128}}.items():
        ident = next(i for i, t in enumerate(btf.types) if t['kind'] == 4 and t['name'] == name)
        actual = fields(btf, ident)
        for field, offset in required.items():
            assert actual[field] == offset, (name, field)
    gather = next(t for t in btf.types if t['kind'] == 4 and t['name'] == 'mmu_gather')
    assert gather['size'] == 128
    members = [gather['raw'][i:i+3] for i in range(0, len(gather['raw']), 3)]
    cleared = next(m for m in members if btf.string(m[0]) == 'cleared_pmds')
    assert cleared[2] & 0xffffff == 261 and cleared[2] >> 24 == 1
    signatures = {
        '__pmd_dmabuf_huge_lock': (['pmd_t', 'vm_area_struct'], 'spinlock_t'),
        'zap_dmabuf_huge_pmd': (['mmu_gather', 'vm_area_struct', 'pmd_t', 'unsigned long'], 'int'),
    }
    for name, (parameters, result) in signatures.items():
        funcs = [t for t in btf.types if t['kind'] == 12 and t['name'] == name]
        assert len(funcs) == 1
        proto = btf.types[funcs[0]['size']]
        assert len(proto['raw']) == len(parameters)*2
        for index, expected in enumerate(parameters):
            actual = btf.types[proto['raw'][index*2+1]]
            assert (actual['kind'] == 2) == (expected != 'unsigned long')
            target = btf.types[actual['size']] if actual['kind'] == 2 else actual
            assert target['name'] == expected, (name, target, expected)
        ret = btf.types[proto['size']]
        assert (ret['kind'] == 2) == (result == 'spinlock_t')
        assert (btf.types[ret['size']] if ret['kind'] == 2 else ret)['name'] == result
    callback = next(t for t in btf.types if t['kind'] == 12 and t['name'] == '__mod_lruvec_page_state')
    proto = btf.types[callback['size']]
    delta = btf.types[proto['raw'][5]]
    assert delta['kind'] == 1 and delta['name'] == 'int' and delta['size'] == 4
    code = FIXTURE + (Path(__file__).parents[1]/'tools/stock-recovery/dmabuf_huge_zap.recovered.c').read_text() + WRAPPER
    with tempfile.TemporaryDirectory(prefix='dmabuf-zap-') as tmp:
        library = Path(tmp)/'zap.dylib'
        subprocess.run(['clang', '-x', 'c', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-dynamiclib', '-o', str(library), '-'], input=code, text=True, check=True)
        host = ctypes.CDLL(str(library))
        host.host_zap.argtypes = [ctypes.c_void_p]*5
        host.host_zap.restype = ctypes.c_uint64
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        uc.mem_map(kernel.base, (len(image)+4095)&~4095)
        uc.mem_write(kernel.base, image)
        ram = 0x1000000
        uc.mem_map(ram, 0x20000)
        tlb, mm, task, stack, stop = [ram+x for x in (0, 0x1000, 0x4000, 0xf000, 0x10000)]
        direct = 0xffffff8001000000
        uc.mem_map(direct, 8192)
        pmd = direct+4096
        page = 0xfffffffe00040000
        uc.mem_map(page, 4096)
        counter = kernel.address('dmabuf_hugetlb_pmd_zap')
        assert kernel.symbols['dmabuf_hugetlb_pmd_zap'][0][1] == 'B'
        assert kernel.span('dmabuf_hugetlb_pmd_zap') is None
        uc.mem_map(counter&~4095, 4096)
        names = ('_raw_spin_lock', '_raw_spin_unlock', 'pgtable_trans_huge_withdraw',
                 '__mod_lruvec_page_state', '__free_pages')
        funcs = {kernel.address(n): n for n in names}
        trace = []
        def hook(emu, address, size, user):
            if address not in funcs:
                return
            name = funcs[address]
            x = [emu.reg_read(r) for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2)]
            op = {'_raw_spin_lock': 1, 'pgtable_trans_huge_withdraw': 2,
                  '__mod_lruvec_page_state': 3, '__free_pages': 4, '_raw_spin_unlock': 5}[name]
            trace.append((op, x[0], x[1] if op in (2, 3, 4) else 0, x[2] & 0xffffffff if op == 3 else 0))
            emu.reg_write(UC_ARM64_REG_X0, page if op == 2 else 0)
            emu.reg_write(UC_ARM64_REG_PC, emu.reg_read(UC_ARM64_REG_X30))
        uc.hook_add(UC_HOOK_CODE, hook)
        rng = random.Random(0x3042)
        for case in range(args.cases):
            old = 0x4000000 | (1, 3, 0, 1 << 58, 1 << 59, 0)[case % 6]
            if case % 6 == 5:
                old = 0
            address = (0, (1 << 64)-1, (1 << 64)-(1 << 21), 1 << 21)[case] if case < 4 else rng.getrandbits(64)
            initial = (old, address, (0, 4096, (1 << 64)-1)[case % 3],
                       (0, 1, (1 << 64)-1)[case % 3], case % 2)
            tlb_data = bytearray(rng.randbytes(128))
            struct.pack_into('<Q', tlb_data, 0, mm)
            page_data = bytearray(rng.randbytes(128))
            struct.pack_into('<Q', page_data, 0, rng.getrandbits(64) & ~64 | (64 if case % 3 else 0))
            page_data[0x40] = case % 4
            struct.pack_into('<i', page_data, 0x60, 1 << (case % 4))
            native_tlb = (ctypes.c_ubyte*128).from_buffer_copy(tlb_data)
            native_page = (ctypes.c_ubyte*128).from_buffer_copy(page_data)
            native_in = (ctypes.c_uint64*5)(*initial)
            out = (ctypes.c_uint64*4)()
            rows = (ctypes.c_uint64*64)()
            n = host.host_zap(native_in, native_tlb, native_page, out, rows)
            expected = [tuple(rows[i*4:(i+1)*4]) for i in range(n)]
            uc.mem_write(tlb, bytes(tlb_data))
            uc.mem_write(page, bytes(page_data))
            for addr, val in ((pmd, old), (mm+0x80, initial[2]), (counter, initial[3])):
                uc.mem_write(addr, struct.pack('<Q', val))
            trace.clear()
            regs = (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3)
            values = (pmd, 0, 0, 0) if initial[4] else (tlb, 0, pmd, address)
            for reg, val in zip(regs, values):
                uc.reg_write(reg, val)
            uc.reg_write(UC_ARM64_REG_X30, stop)
            uc.reg_write(UC_ARM64_REG_SP, stack)
            uc.reg_write(UC_ARM64_REG_SP_EL0, task)
            entry = '__pmd_dmabuf_huge_lock' if initial[4] else 'zap_dmabuf_huge_pmd'
            try:
                uc.emu_start(kernel.address(entry), stop, count=10000)
            except Exception as error:
                raise RuntimeError(f'case={case} PC={uc.reg_read(UC_ARM64_REG_PC):#x} trace={trace}') from error
            assert uc.reg_read(UC_ARM64_REG_PC) == stop, 'instruction bound'
            actual = [uc.reg_read(UC_ARM64_REG_X0)] + [struct.unpack('<Q', uc.mem_read(a, 8))[0] for a in (pmd, mm+0x80, counter)]
            assert actual == list(out), ('return/PMD/accounting', case, actual, list(out))
            assert bytes(uc.mem_read(tlb, 128)) == bytes(native_tlb), ('gather range/flags', case)
            assert bytes(uc.mem_read(page, 128)) == bytes(native_page), ('page metadata', case)
            assert trace == expected, ('helper order/args', case, trace, expected)
        print(f'PASS: {args.cases} exact-stock ARM64 lock/zap cases; PMD, gather, page metadata, counters and helper trace')
        print('Free/lock/MMU effects modeled; not SMP, lifecycle or hardware proof. No installation performed.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--symbols', type=Path, required=True)
    parser.add_argument('--cases', type=int, default=1000)
    run(parser.parse_args())
