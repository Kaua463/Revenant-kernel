#!/usr/bin/env python3
"""PMD branch of exact-stock remap: writes, helper ordering, partial failures."""
import argparse
import ctypes
import hashlib
from pathlib import Path
import struct
import subprocess
import tempfile
from importlib.machinery import SourceFileLoader


def load(name):
    return SourceFileLoader(name,str(Path(__file__).with_name(name))).load_module()


def verify_btf(kernel):
    btf=kernel.btf;fields=load('test-dmabuf-stock-wrappers.py').btf_fields
    required={'mm_struct':{'pgd':112,'pgtables_bytes':128,'mm_lock_seq':224},
              'vm_area_struct':{'vm_start':0,'vm_end':8,'vm_mm':16,'vm_flags':32,'vm_lock_seq':44,'vm_lock':48,'vm_pgoff':120},
              'page':{'flags':0,'page_type':48},'ptdesc':{'ptl':40}}
    for name,wanted in required.items():
        ident=next(i for i,t in enumerate(btf.types) if t['kind']==4 and t['name']==name)
        actual=fields(btf,ident)
        for member,offset in wanted.items():assert actual[member]==offset,(name,member)
    func=next(t for t in btf.types if t['kind']==12 and t['name']=='dmabuf_huge_remap_pfn_range')
    proto=btf.types[func['size']];assert len(proto['raw'])==12
    params=[btf.types[proto['raw'][i+1]] for i in range(0,12,2)]
    assert params[0]['kind']==2 and btf.types[params[0]['size']]['name']=='vm_area_struct'
    assert [p['name'] for p in params[1:]]==['unsigned long','unsigned long','unsigned long','pgprot_t','unsigned int']
    assert btf.types[proto['size']]['name']=='int'
    for key,value in {'CONFIG_ARM64_4K_PAGES':'y','CONFIG_ARM64_VA_BITS':'39','CONFIG_PGTABLE_LEVELS':'3','CONFIG_NUMA':'n'}.items():assert kernel.cfg[key]==value


FIXTURE=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <setjmp.h>
typedef struct { uint64_t val; } pmd_t,pte_t,pgd_t,pud_t,pgprot_t;
typedef void spinlock_t;typedef unsigned char *pgtable_t;
struct mm_struct { uint64_t count;unsigned seq;pgd_t pgd; };
struct vm_area_struct { unsigned long vm_start,vm_end,vm_flags,vm_pgoff;unsigned seq;struct mm_struct *vm_mm; };
static struct mm_struct mm;static pmd_t pmds[512];static unsigned char pages[8][64];
static uint64_t rows[128][5],counter,other;static unsigned nr,allocs,fail,bug;static jmp_buf trap;
#define PAGE_SHIFT 12
#define PAGE_MASK (~4095UL)
#define PAGE_ALIGN(x) (((x)+4095UL)&PAGE_MASK)
#define VM_IO 0x4000UL
#define VM_PFNMAP 0x400UL
#define VM_DONTEXPAND 0x40000UL
#define VM_DONTDUMP 0x4000000UL
#define ENOMEM 12
#define EINVAL 22
#define pgd_val(x) ((x).val)
#define pgprot_val(x) ((x).val)
#define __pte(x) ((pte_t){x})
#define pte_none(x) (!(x).val)
#define BUG_ON(x) do {if(x){bug=1;longjmp(trap,1);}} while(0)
#define dmabuf_hugetlb_pmd_map counter
#define dmabuf_hugetlb_contpte_map other
static void trace(uint64_t op,uint64_t a,uint64_t b,uint64_t c,uint64_t d){assert(nr<128);uint64_t row[]={op,a,b,c,d};memcpy(rows[nr++],row,sizeof(row));}
static uint64_t pmd_address(pmd_t *p){return 0xffffff8001000000ULL+(p-pmds)*8;}
static int is_cow_mapping(unsigned long f){return (f&40)==32;}
static void vm_flags_set(struct vm_area_struct *v,unsigned long f){if(v->seq!=mm.seq){trace(1,0x1006000,0,0,0);v->seq=mm.seq;trace(2,0x1006000,0,0,0);}v->vm_flags|=f;}
static pgd_t *pgd_offset(struct mm_struct *m,unsigned long a){assert(a<1UL<<30);return &m->pgd;}
static uint64_t addr_end(uint64_t a,uint64_t e,uint64_t size){uint64_t n=(a&~(size-1))+size;return n-1<e-1?n:e;}
#define pgd_addr_end(a,e) addr_end(a,e,1UL<<30)
#define pmd_addr_end(a,e) addr_end(a,e,1UL<<21)
static int pgd_none(pgd_t p){return !p.val;}
static int __pmd_alloc(struct mm_struct *m,pud_t *p,unsigned long a){(void)p;trace(3,0x1001000,0x1002000,a,0);if(fail==1)return -12;m->pgd.val=0x1000003;return 0;}
static void *__va(uint64_t pa){assert(pa==0x1000000);return pmds;}
static pgtable_t pte_alloc_one(struct mm_struct *m){assert(m==&mm);trace(4,0x440dc0,0,0,0);if(++allocs==fail-1)return NULL;
 unsigned char *p=pages[allocs-1];uint32_t type;memcpy(&type,p+48,4);type&=~512U;memcpy(p+48,&type,4);memset(p+40,0,4);
 trace(5,0xfffffffe00050000ULL+(allocs-1)*64,39,1,0);return p;}
static spinlock_t *pmd_lock(struct mm_struct *m,pmd_t *p){(void)m;(void)p;trace(6,0xfffffffe00040028ULL,0,0,0);return (void *)0xfffffffe00040028ULL;}
static void pgtable_trans_huge_deposit(struct mm_struct *m,pmd_t *p,pgtable_t table){assert(m==&mm);trace(7,0x1001000,pmd_address(p),0xfffffffe00050000ULL+(table-pages[0]),0);}
static void mm_inc_nr_ptes(struct mm_struct *m){m->count+=4096;}
static int pmd_set_huge(pmd_t *p,uint64_t pa,pgprot_t prot){trace(8,pmd_address(p),pa,prot.val,0);p->val=(pa&~4095ULL)|(prot.val&~3ULL)|1;return 1;}
static void spin_unlock(spinlock_t *p){trace(9,(uintptr_t)p,0,0,0);}
static void atomic64_inc(uint64_t *p){++*p;}
/* Explicitly unsupported in this PMD-only fixture, not production stubs. */
static pte_t *pte_alloc_map_lock(struct mm_struct *m,pmd_t *p,unsigned long a,spinlock_t **l){(void)m;(void)p;(void)a;(void)l;assert(0);return NULL;}
static void set_ptes(struct mm_struct *m,unsigned long a,pte_t *p,pte_t v,unsigned n){(void)m;(void)a;(void)p;(void)v;(void)n;assert(0);}
static void pte_unmap_unlock(pte_t *p,spinlock_t *l){(void)p;(void)l;assert(0);}
'''
WRAPPER=r'''
unsigned host_remap(const uint64_t *in,uint64_t *out,uint64_t *trace_out,unsigned char *metadata) {
 struct vm_area_struct v={in[0],in[1],in[2],0xaabb,(unsigned)in[3],&mm};
 mm.seq=7;mm.count=in[4];mm.pgd.val=in[5];counter=in[6];other=0;fail=in[7];nr=allocs=bug=0;
 memset(pmds,0,sizeof(pmds));memset(pages,0xa5,sizeof(pages));
 for(unsigned i=0;i<8;i++){uint64_t flags=0;memcpy(pages[i],&flags,8);}
 int ret=0;if(!setjmp(trap))ret=dmabuf_huge_remap_pfn_range(&v,in[8],in[9],in[10],(pgprot_t){in[11]},0);
 out[0]=(uint32_t)ret;out[1]=v.vm_flags;out[2]=v.vm_pgoff;out[3]=v.seq;out[4]=mm.count;out[5]=counter;out[6]=mm.pgd.val;out[7]=bug;
 memcpy(out+8,pmds,sizeof(pmds));memcpy(metadata,pages,sizeof(pages));memcpy(trace_out,rows,nr*5*sizeof(uint64_t));return nr;
}
'''


def run(args):
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
    from unicorn.arm64_const import (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5,UC_ARM64_REG_X30,UC_ARM64_REG_SP,UC_ARM64_REG_SP_EL0,UC_ARM64_REG_PC)
    image=args.image.read_bytes();contract=load('verify-stock-recovered-contracts.py')
    assert hashlib.sha256(image).hexdigest()==contract.IMAGE_SHA
    assert hashlib.sha256(args.symbols.read_bytes()).hexdigest()==contract.SYMBOL_SHA
    kernel=load('stock-binary-evidence.py').Kernel(args.image,args.symbols)
    verify_btf(kernel)
    code=FIXTURE+(Path(__file__).parents[1]/'tools/stock-recovery/dmabuf_huge_remap.recovered.c').read_text()+WRAPPER
    with tempfile.TemporaryDirectory(prefix='dmabuf-remap-') as tmp:
        lib=Path(tmp)/'remap.dylib'
        subprocess.run(['clang','-x','c','-std=c11','-Wall','-Wextra','-Werror','-dynamiclib','-o',str(lib),'-'],input=code,text=True,check=True)
        host=ctypes.CDLL(str(lib));host.host_remap.argtypes=[ctypes.c_void_p]*4;host.host_remap.restype=ctypes.c_uint
        uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);uc.mem_map(kernel.base,(len(image)+4095)&~4095);uc.mem_write(kernel.base,image)
        ram=0x1000000;uc.mem_map(ram,0x20000)
        vma,mm,pgd,task,lock,stack,stop=[ram+x for x in (0,0x1000,0x2000,0x4000,0x6000,0xf000,0x10000)]
        direct=0xffffff8001000000;uc.mem_map(direct,4096)
        pages=0xfffffffe00050000;uc.mem_map(pages,4096)
        counter=kernel.address('dmabuf_hugetlb_pmd_map');assert kernel.span('dmabuf_hugetlb_pmd_map') is None
        uc.mem_map(counter&~4095,4096);uc.mem_write(kernel.address('memstart_addr'),bytes(8))
        names=('down_write','up_write','__pmd_alloc','__alloc_pages','__mod_lruvec_page_state','_raw_spin_lock','pgtable_trans_huge_deposit','pmd_set_huge','_raw_spin_unlock')
        funcs={kernel.address(n):i+1 for i,n in enumerate(names)};trace=[];state={}
        def hook(emu,address,size,user):
            if address in funcs:
                op=funcs[address];x=[emu.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3)]
                trace.append((op,*[x[i] if i<({1:1,2:1,3:3,4:4,5:3,6:1,7:3,8:3,9:1}[op]) else 0 for i in range(4)]))
                result=0
                if op==3:
                    result=(1<<64)-12 if state['fail']==1 else 0
                    if not result:emu.mem_write(pgd,struct.pack('<Q',0x1000003))
                elif op==4:
                    state['allocs']+=1;result=0 if state['allocs']==state['fail']-1 else pages+(state['allocs']-1)*64
                elif op==8:
                    emu.mem_write(x[0],struct.pack('<Q',(x[1]&~4095)|(x[2]&~3)|1));result=1
                emu.reg_write(UC_ARM64_REG_X0,result);emu.reg_write(UC_ARM64_REG_PC,emu.reg_read(UC_ARM64_REG_X30))
            elif kernel.base<=address<kernel.base+len(image):
                word=struct.unpack_from('<I',image,address-kernel.base)[0]
                if word&0xffe0001f==0xd4200000:state['bug']=1;emu.emu_stop()
        uc.hook_add(UC_HOOK_CODE,hook)
        cases=0;coverage={'multi_success':0,'partial_failure':0,'cow_reject':0,'bug':0}
        for case in range(216):
            address=(1<<21)+(4096 if case%9==0 else 0)
            size=(1,4096,1<<21,(1<<21)+4096,3<<21,0)[case%6]
            if case%19==0:address+=1
            end=address+((size+4095)&~4095)
            flags=(0,32,40,1<<39)[case%4]
            vma_end=end+(4096 if case%11==0 else 0)
            values=(address,vma_end,flags,case%8,(0,(1<<64)-1)[case%2],(0,0x1000003)[case%2],(0,(1<<64)-1)[case%2],(case//6)%6,address,0x4000,size,3|(case%2<<54))
            inputs=(ctypes.c_uint64*12)(*values);out=(ctypes.c_uint64*520)();rows=(ctypes.c_uint64*640)();meta=(ctypes.c_ubyte*512)()
            n=host.host_remap(inputs,out,rows,meta);expected=[tuple(rows[i*5:(i+1)*5]) for i in range(n)]
            uc.mem_write(vma,struct.pack('<5Q',values[0],values[1],mm,0,flags));uc.mem_write(vma+44,struct.pack('<I',values[3]));uc.mem_write(vma+48,struct.pack('<Q',lock));uc.mem_write(vma+120,struct.pack('<Q',0xaabb))
            for a,v in ((mm+112,pgd),(mm+128,values[4]),(pgd,values[5]),(counter,values[6])):uc.mem_write(a,struct.pack('<Q',v))
            uc.mem_write(mm+224,struct.pack('<I',7));uc.mem_write(direct,bytes(4096))
            page_data=bytearray(b'\xa5'*512)
            for i in range(8):struct.pack_into('<Q',page_data,i*64,0)
            uc.mem_write(pages,bytes(page_data));trace.clear();state.update(fail=values[7],allocs=0,bug=0)
            for r,v in zip((UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5),(vma,address,values[9],size,values[11],0)):uc.reg_write(r,v)
            uc.reg_write(UC_ARM64_REG_X30,stop);uc.reg_write(UC_ARM64_REG_SP,stack);uc.reg_write(UC_ARM64_REG_SP_EL0,task)
            uc.emu_start(kernel.address('dmabuf_huge_remap_pfn_range'),stop,count=100000)
            assert state['bug'] or uc.reg_read(UC_ARM64_REG_PC)==stop,'instruction bound'
            actual=[0 if state['bug'] else uc.reg_read(UC_ARM64_REG_X0)&0xffffffff]
            actual.extend(struct.unpack('<Q',uc.mem_read(a,8))[0] for a in (vma+32,vma+120))
            actual.append(struct.unpack('<I',uc.mem_read(vma+44,4))[0])
            actual.extend(struct.unpack('<Q',uc.mem_read(a,8))[0] for a in (mm+128,counter,pgd));actual.append(state['bug'])
            assert actual==list(out[:8]),('outputs',case,actual,list(out[:8]))
            assert bytes(uc.mem_read(direct,4096))==bytes(out)[64:],('PMDs',case)
            assert bytes(uc.mem_read(pages,512))==bytes(meta),('table metadata',case)
            assert trace==expected,('helper trace',case,trace,expected)
            mapped=(out[5]-values[6])&((1<<64)-1)
            coverage['multi_success']+=out[0]==0 and not out[7] and mapped>1
            coverage['partial_failure']+=out[0]==0xfffffff4 and mapped>0
            coverage['cow_reject']+=out[0]==0xffffffea
            coverage['bug']+=bool(out[7])
            cases+=1
        assert all(coverage.values()),coverage
        print(f'PASS: {cases} exact ARM64 remap PMD cases; flags, accounting, PGD/PMD writes, allocation failures, partial mappings and BUG guards')
        print(f'Coverage categories: {coverage}')
        print('PMD branch only; allocation/locks/pmd_set_huge modeled. No complete remap, MMU, lifetime or hardware claim.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--symbols',type=Path,required=True);run(p.parse_args())
