#!/usr/bin/env python3
"""Exact ARM64 split writes/barrier ordering vs C, with MM/TLB/lock models only."""
import argparse
import ctypes
import hashlib
import importlib.util
from pathlib import Path
import random
import struct
import subprocess
import tempfile


FIXTURE=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
typedef struct { uint64_t val; } pmd_t,pte_t,pgprot_t;
typedef void *pgtable_t;typedef void spinlock_t;
struct mm_struct { unsigned char opaque[0x420]; void *notifier_subscriptions; };
struct folio;
struct vm_area_struct { uint64_t vm_start,vm_end; struct mm_struct *vm_mm; pgprot_t vm_page_prot; };
struct mmu_notifier_range { struct mm_struct *mm; unsigned long start,end; unsigned flags,event; void *owner; };
static struct mm_struct mm;static struct vm_area_struct vma;
static uint64_t ptes[512], counter, rows[1600][6];static unsigned nr;
static uint64_t expected_folio;
#define HPAGE_PMD_SIZE (1UL<<21)
#define HPAGE_PMD_MASK (~(HPAGE_PMD_SIZE-1))
#define PAGE_SIZE 4096
#define MMU_NOTIFY_CLEAR 1
#define pmd_val(p) ((p).val)
#define pgprot_val(p) ((p).val)
#define __pte(x) ((pte_t){x})
#define pte_none(p) (!(p).val)
#define BUG_ON(x) assert(!(x))
#define dmabuf_hugetlb_pmd_split counter
static void trace(uint64_t op,uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e) {
 assert(nr<1600);uint64_t row[]={op,a,b,c,d,e};memcpy(rows[nr++],row,sizeof(row));
}
static void barrier(uint64_t word) { trace(6,word,0,0,0,0); }
static void mmu_notifier_range_init_owner(struct mmu_notifier_range *r,unsigned event,unsigned flags,
 struct mm_struct *m,unsigned long start,unsigned long end,void *owner) { *r=(struct mmu_notifier_range){m,start,end,flags,event,owner}; }
static void notifier_trace(unsigned op,struct mmu_notifier_range *r) {
 assert(r->mm==&mm && !r->owner);trace(op,0x1001000,r->start,r->end,r->flags,r->event);
}
static void mmu_notifier_invalidate_range_start(struct mmu_notifier_range *r) {
 if(r->mm->notifier_subscriptions) {r->flags|=1;notifier_trace(1,r);} }
static void mmu_notifier_invalidate_range_end(struct mmu_notifier_range *r) {
 if(r->mm->notifier_subscriptions) notifier_trace(8,r); }
static spinlock_t *pmd_lock(struct mm_struct *m,pmd_t *p) {
 (void)m;(void)p;trace(2,0xfffffffe00040068ULL,0,0,0,0);return (void *)0xfffffffe00040068ULL; }
static void spin_unlock(spinlock_t *p) { trace(7,(uintptr_t)p,0,0,0,0); }
static int pmd_trans_huge(pmd_t p) { return (p.val&0xc00000000000001ULL) && !(p.val&2); }
static void *pmd_page(pmd_t p) { (void)p;return (void *)expected_folio; }
static struct folio *page_folio(void *p) { return p; }
static pgtable_t pgtable_trans_huge_withdraw(struct mm_struct *m,pmd_t *p) {
 (void)m;(void)p;trace(3,0x1001000,0xffffff8001001000ULL,0,0,0);return (void *)0xfffffffe00040000ULL; }
static pmd_t pmdp_invalidate(struct vm_area_struct *v,unsigned long addr,pmd_t *p) {
 (void)v;trace(4,0x1000000,addr,0xffffff8001001000ULL,0,0);return *p; }
static int pmd_dirty(pmd_t p) { return !!(p.val&(1ULL<<55)) || (p.val&0x8000000000080ULL)==0x8000000000000ULL; }
static int pmd_write(pmd_t p) { return !!(p.val&(1ULL<<51)); }
static int pmd_young(pmd_t p) { return !!(p.val&1024); }
static void pmd_populate(struct mm_struct *m,pmd_t *p,pgtable_t table) {
 (void)m;assert((uintptr_t)table==0xfffffffe00040000ULL);
 p->val=0x800000001000003ULL;barrier(0xd5033a9f);barrier(0xd5033fdf); }
static pte_t pte_mkwrite_novma(pte_t p) { p.val=(p.val|1ULL<<51)&~128ULL;return p; }
static pte_t pte_mkold(pte_t p) { p.val&=~1024ULL;return p; }
static pte_t pte_mkdirty(pte_t p) {p.val|=1ULL<<55;if(p.val&(1ULL<<51))p.val&=~128ULL;return p;}
static pte_t pte_mkspecial(pte_t p) {p.val|=1ULL<<56;return p;}
static pte_t *pte_offset_kernel(pmd_t *p,unsigned long addr) {(void)p;return (pte_t *)&ptes[(addr>>12)&511];}
static void set_pte_at(struct mm_struct *m,unsigned long addr,pte_t *out,pte_t p) {
 (void)m;(void)addr;p.val&=~(1ULL<<52);*out=p;
 if((p.val&0x40000000000041ULL)==0x40000000000001ULL) {barrier(0xd5033a9f);barrier(0xd5033fdf);} }
static void smp_wmb(void) {barrier(0xd5033abf);}
static void atomic64_inc(uint64_t *p) {++*p;}
'''


WRAPPER=r'''
unsigned host_split(const uint64_t *input,uint64_t *out,uint64_t *metadata,uint64_t *trace_out) {
 mm.notifier_subscriptions=input[3] ? (void *)1 : NULL;
 vma.vm_mm=&mm;vma.vm_page_prot.val=input[1];pmd_t pmd={input[0]};
 nr=0;memset(ptes,0,sizeof(ptes));counter=input[5];expected_folio=input[6];
 __split_dmabuf_huge_pmd(&vma,&pmd,input[2],input[7],(void *)input[4]);
 memcpy(out,ptes,sizeof(ptes));metadata[0]=pmd.val;metadata[1]=counter;
 memcpy(trace_out,rows,nr*6*sizeof(uint64_t));return nr;
}
'''


def load(name):
    s=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m


def run(args):
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
    from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X30,UC_ARM64_REG_SP,UC_ARM64_REG_SP_EL0,UC_ARM64_REG_PC
    contract=load('verify-stock-recovered-contracts.py');image=args.image.read_bytes()
    assert hashlib.sha256(image).hexdigest()==contract.IMAGE_SHA
    assert hashlib.sha256(args.symbols.read_bytes()).hexdigest()==contract.SYMBOL_SHA
    kernel=load('stock-binary-evidence.py').Kernel(args.image,args.symbols)
    btf=kernel.btf
    function=[t for t in btf.types if t['kind']==12 and t['name']=='__split_dmabuf_huge_pmd']
    assert len(function)==1
    prototype=btf.types[function[0]['size']]
    assert btf.ref(prototype['size'])=='0:void'
    types=[btf.types[prototype['raw'][i+1]] for i in range(0,len(prototype['raw']),2)]
    shapes=[('pointer:'+btf.types[t['size']]['name']) if t['kind']==2 else t['name'] for t in types]
    assert shapes==['pointer:vm_area_struct','pointer:pmd_t','unsigned long','bool','pointer:folio']
    event=next(t for t in btf.types if t['kind']==6 and t['name']=='mmu_notifier_event')
    values={btf.string(event['raw'][i]):event['raw'][i+1] for i in range(0,len(event['raw']),2)}
    assert values['MMU_NOTIFY_CLEAR']==1
    for name,expected in {'mm_struct':{'notifier_subscriptions':0x420},'vm_area_struct':{'vm_mm':16,'vm_page_prot':24},'mmu_notifier_range':{'mm':0,'start':8,'end':16,'flags':24,'event':28,'owner':32}}.items():
        ident=next(i for i,t in enumerate(btf.types) if t['kind']==4 and t['name']==name)
        actual=load('test-dmabuf-stock-wrappers.py').btf_fields(btf,ident)
        for field,offset in expected.items():assert actual[field]==offset
    code=FIXTURE+(Path(__file__).parents[1]/'tools/stock-recovery/dmabuf_huge_split.recovered.c').read_text()+WRAPPER
    with tempfile.TemporaryDirectory(prefix='dmabuf-split-') as directory:
        lib=Path(directory)/'split.dylib'
        subprocess.run(['clang','-x','c','-std=c11','-Wall','-Wextra','-Werror','-dynamiclib','-o',str(lib),'-'],input=code,text=True,check=True)
        host=ctypes.CDLL(str(lib));host.host_split.argtypes=[ctypes.c_void_p]*4
        uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);uc.mem_map(kernel.base,(len(image)+4095)&~4095);uc.mem_write(kernel.base,image)
        ram=0x1000000;uc.mem_map(ram,0x20000)
        vma,mm,task,stack,stop=[ram+x for x in (0,0x1000,0x4000,0xf000,0x10000)]
        direct=0xffffff8001000000;uc.mem_map(direct,8192);pmd=direct+4096
        folio_base=0xfffffffe00100000;uc.mem_map(folio_base,4096)
        counter=kernel.address('dmabuf_hugetlb_pmd_split');memstart=kernel.address('memstart_addr')
        # This global is uninitialized BSS, not backed by bytes in stock.Image.
        # Map an explicit private zeroed context page; do not invent file bytes.
        for symbol in ('dmabuf_hugetlb_pmd_split','system_cpucaps'):
            assert kernel.symbols[symbol][0][1]=='B'
            assert kernel.span(symbol) is None
            uc.mem_map(kernel.address(symbol)&~4095,4096)
        uc.mem_write(memstart,bytes(8));trace=[];state={}
        funcs={kernel.address(n):n for n in ('__mmu_notifier_invalidate_range_start','__mmu_notifier_invalidate_range_end','_raw_spin_lock','_raw_spin_unlock','pgtable_trans_huge_withdraw','pmdp_invalidate')}
        def hook(emu,address,size,user):
            if address in funcs:
                name=funcs[address];x=[emu.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2)]
                if name.startswith('__mmu_notifier'):
                    m,start,end,flags,event,owner=struct.unpack('<QQQIIQ',emu.mem_read(x[0],40));assert owner==0
                    trace.append((1 if name.endswith('start') else 8,m,start,end,flags,event));result=0
                elif name=='_raw_spin_lock':trace.append((2,x[0],0,0,0,0));result=0
                elif name=='_raw_spin_unlock':trace.append((7,x[0],0,0,0,0));result=0
                elif name=='pgtable_trans_huge_withdraw':trace.append((3,x[0],x[1],0,0,0));result=0xfffffffe00040000
                else:trace.append((4,*x,0,0));result=state['old']
                emu.reg_write(UC_ARM64_REG_X0,result);emu.reg_write(UC_ARM64_REG_PC,emu.reg_read(UC_ARM64_REG_X30))
            elif kernel.base<=address<kernel.base+len(image):
                word=struct.unpack_from('<I',image,address-kernel.base)[0]
                if word in (0xd5033a9f,0xd5033fdf,0xd5033abf):trace.append((6,word,0,0,0,0))
        uc.hook_add(UC_HOOK_CODE,hook)
        rng=random.Random(0x3045);completed=0
        for case in range(args.cases):
            present=(1,3,0,1<<58,1<<59,(1<<58)|(1<<59))[case%6]
            old=0x4000000 | present | ((case&1)<<51) | (((case>>1)&1)<<55) | (((case>>2)&1)<<10) | (((case>>3)&1)<<7)
            if case%17==0:old=0
            prot=3 | ((case&1)<<54) | (((case>>1)&1)<<6) | (((case>>2)&1)<<51) | (((case>>3)&1)<<7) | (((case>>4)&1)<<52) | (((case>>5)&1)<<55)
            address=((0,(1<<21)-1,1<<21,(1<<38)-1)[case] if case<4 else
                     (rng.randrange(0,64)<<21)+rng.randrange(1<<21))
            expected_folio=folio_base if case%5 else folio_base+64
            folio=(0,expected_folio,folio_base+128)[case%3]
            initial_counter=(0,1,(1<<64)-1)[case%3]
            values=(old,prot,address,case%2,folio,initial_counter,expected_folio,(case>>1)&1)
            input_native=(ctypes.c_uint64*8)(*values);out=(ctypes.c_uint64*512)();meta=(ctypes.c_uint64*2)();native_trace=(ctypes.c_uint64*(1600*6))()
            n=host.host_split(input_native,out,meta,native_trace)
            expected=[tuple(native_trace[i*6:(i+1)*6]) for i in range(n)]
            uc.mem_write(vma,struct.pack('<QQQQ',0,1<<38,mm,prot));uc.mem_write(mm+0x420,struct.pack('<Q',1 if case%2 else 0))
            uc.mem_write(direct,bytes(4096));uc.mem_write(pmd,struct.pack('<Q',old));uc.mem_write(counter,struct.pack('<Q',initial_counter))
            uc.mem_write(folio_base+8,struct.pack('<Q',0 if expected_folio==folio_base else expected_folio+1))
            trace.clear();state['old']=old
            for r,value in zip((UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4),(vma,pmd,address,values[7],folio)):uc.reg_write(r,value)
            uc.reg_write(UC_ARM64_REG_X30,stop);uc.reg_write(UC_ARM64_REG_SP,stack);uc.reg_write(UC_ARM64_REG_SP_EL0,task)
            try:
                uc.emu_start(kernel.address('__split_dmabuf_huge_pmd'),stop,count=200000)
            except Exception as error:
                raise RuntimeError(f'case={case} PC={uc.reg_read(UC_ARM64_REG_PC):#x} trace={trace[-8:]}') from error
            assert uc.reg_read(UC_ARM64_REG_PC)==stop,'instruction bound exceeded'
            assert bytes(uc.mem_read(direct,4096))==bytes(out),('PTE writes',case)
            assert struct.unpack('<Q',uc.mem_read(pmd,8))[0]==meta[0],('PMD write',case)
            assert struct.unpack('<Q',uc.mem_read(counter,8))[0]==meta[1],('counter',case)
            assert trace==expected,('helper/barrier order',case,trace[:12],expected[:12],len(trace),len(expected))
            completed+=1
        print(f'PASS: {completed} stock ARM64 split cases; 512-PTE outputs, PMD/counter writes, folio guards, notifier/lock/helper/barrier order')
        print('MM/TLB/allocator/lock effects and BSS modeled; raw Image alternatives unpatched. Not runtime CPU-alternative, concurrency, hardware MMU or full feature validation.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--symbols',type=Path,required=True);p.add_argument('--cases',type=int,default=200)
    run(p.parse_args())
