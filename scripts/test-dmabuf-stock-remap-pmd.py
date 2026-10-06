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
typedef void spinlock_t;
struct list_head {struct list_head *next,*prev;};
struct page {uint64_t flags;struct list_head lru;unsigned char rest[40];};
_Static_assert(sizeof(struct page)==64 && offsetof(struct page,lru)==8,"fixture page layout");
typedef struct page *pgtable_t;
struct mm_struct { uint64_t count;unsigned seq;pgd_t pgd; };
struct file {void *f_mapping;};
struct vm_area_struct { unsigned long vm_start,vm_end,vm_flags,vm_pgoff;unsigned seq;struct mm_struct *vm_mm;struct file *vm_file;void *anon_vma; };
static struct mm_struct mm;static pmd_t pmds[512],newpmds[512];static struct page page_objects[8];
static unsigned char (*pages)[64]=(void *)page_objects;static _Alignas(8) unsigned char pmd_metadata[64],new_metadata[64];
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
static unsigned char *metadata_for(pmd_t *p){uintptr_t a=(uintptr_t)p;if(a>=(uintptr_t)pmds && a<(uintptr_t)pmds+sizeof(pmds))return pmd_metadata;assert(a>=(uintptr_t)newpmds && a<(uintptr_t)newpmds+sizeof(newpmds));return new_metadata;}
static uint64_t pmd_address(pmd_t *p){return metadata_for(p)==pmd_metadata?0xffffff8001000000ULL+(uintptr_t)p-(uintptr_t)pmds:0xffffff8001001000ULL+(uintptr_t)p-(uintptr_t)newpmds;}
static pmd_t *indexed_pmd(unsigned i){assert(i<1024);return i<512?&pmds[i]:&newpmds[i-512];}
static void lock_state(spinlock_t *p,unsigned held){if((uintptr_t)p==0xfffffffe00040028ULL)memcpy(pmd_metadata+40,&held,4);else if((uintptr_t)p==0xfffffffe00040068ULL)memcpy(new_metadata+40,&held,4);}
static int is_cow_mapping(unsigned long f){return (f&40)==32;}
static void vm_flags_set(struct vm_area_struct *v,unsigned long f){if(v->seq!=mm.seq){trace(1,0x1006000,0,0,0);v->seq=mm.seq;trace(2,0x1006000,0,0,0);}v->vm_flags|=f;}
static pgd_t *pgd_offset(struct mm_struct *m,unsigned long a){assert(a<1UL<<30);return &m->pgd;}
static uint64_t addr_end(uint64_t a,uint64_t e,uint64_t size){uint64_t n=(a&~(size-1))+size;return n-1<e-1?n:e;}
#define pgd_addr_end(a,e) addr_end(a,e,1UL<<30)
#define pmd_addr_end(a,e) addr_end(a,e,1UL<<21)
static int pgd_none(pgd_t p){return !p.val;}
static int __pmd_alloc(struct mm_struct *m,pud_t *p,unsigned long a){(void)p;trace(3,0x1001000,0x1002000,a,0);if(fail==1)return -12;m->pgd.val=0x1000003;return 0;}
static void *__va(uint64_t pa){assert(pa==0x1000000);return indexed_pmd(0);}
static pgtable_t pte_alloc_one(struct mm_struct *m){assert(m==&mm);trace(4,0x440dc0,0,0,0);if(++allocs==fail-1)return NULL;
 unsigned char *p=pages[allocs-1];uint32_t type;memcpy(&type,p+48,4);type&=~512U;memcpy(p+48,&type,4);memset(p+40,0,4);
 trace(5,0xfffffffe00050000ULL+(allocs-1)*64,39,1,0);return (pgtable_t)p;}
static spinlock_t *pmd_lock(struct mm_struct *m,pmd_t *p){(void)m;spinlock_t *l=(void *)(0xfffffffe00040028ULL+(metadata_for(p)==new_metadata?64:0));trace(6,(uintptr_t)l,0,0,0);lock_state(l,1);return l;}
#define pmd_huge_pte(m,p) (*(pgtable_t *)(metadata_for(p)+16))
static spinlock_t *pmd_lockptr(struct mm_struct *m,pmd_t *p){assert(m==&mm);return metadata_for(p)+40;}
#define assert_spin_locked(p) assert(*(unsigned *)(p))
static void INIT_LIST_HEAD(struct list_head *l){l->next=l->prev=l;}
static void list_add(struct list_head *l,struct list_head *h){struct list_head *n=h->next;assert(n->prev==h && l!=h && l!=n);n->prev=l;l->next=n;l->prev=h;h->next=l;}
#define list_first_entry_or_null(head,type,member) ((head)->next==(head)?NULL:(type *)((char *)(head)->next - offsetof(type,member)))
static void list_del(struct list_head *l){assert(l->next->prev==l && l->prev->next==l);l->next->prev=l->prev;l->prev->next=l->next;l->next=(void *)0xdead000000000100ULL;l->prev=(void *)0xdead000000000122ULL;}
/* Exact pinned ACK bodies inserted here by the fixture builder. */
/* ACK_DEPOSIT_BODY */
static void pgtable_trans_huge_deposit(struct mm_struct *m,pmd_t *p,pgtable_t table){assert(m==&mm);trace(7,0x1001000,pmd_address(p),0xfffffffe00050000ULL+((unsigned char *)table-pages[0]),0);ack_deposit(m,p,table);}
static void mm_inc_nr_ptes(struct mm_struct *m){m->count+=4096;}
typedef uint64_t u64,pteval_t,phys_addr_t;
#define PTE_PXN (1ULL<<53)
#define PTE_RDONLY (1ULL<<7)
#define PTE_WRITE (1ULL<<51)
#define PTE_NG (1ULL<<11)
#define PTE_CONT (1ULL<<52)
#define PTE_ATTRINDX_MASK 28ULL
#define PTE_ATTRINDX(x) ((uint64_t)(x)<<2)
#define MT_NORMAL 0
#define MT_NORMAL_TAGGED 1
#define __pmd(x) ((pmd_t){x})
#define pte_valid(x) ((x).val&1)
#define pte_pfn(x) (((x).val&0xfffffffff000ULL)>>12)
#define pmd_val(x) ((x).val)
#define READ_ONCE(x) (x)
#define __phys_to_pfn(x) ((x)>>12)
#define pfn_pmd(p,prot) __pmd(((p)<<12)|(prot).val)
#define PMD_MASK (~((1ULL<<21)-1))
#define VM_BUG_ON(x) ((void)(x))
static pgprot_t mk_pmd_sect_prot(pgprot_t p){p.val=(p.val&~3ULL)|1;return p;}
static void set_pmd(pmd_t *p,pmd_t v){*p=v;if(v.val&1){trace(10,0xd5033a9f,0,0,0);trace(10,0xd5033fdf,0,0,0);}}
/* ACK_PMD_SET_BODY */
static int pmd_set_huge(pmd_t *p,uint64_t pa,pgprot_t prot){trace(8,pmd_address(p),pa,prot.val,0);return ack_pmd_set(p,pa,prot);}
static void spin_unlock(spinlock_t *p){trace(9,(uintptr_t)p,0,0,0);lock_state(p,0);}
static void atomic64_inc(uint64_t *p){++*p;}
/* Explicitly unsupported in this PMD-only fixture, not production stubs. */
static pte_t *pte_alloc_map_lock(struct mm_struct *m,pmd_t *p,unsigned long a,spinlock_t **l){(void)m;(void)p;(void)a;(void)l;assert(0);return NULL;}
static void set_ptes(struct mm_struct *m,unsigned long a,pte_t *p,pte_t v,unsigned n){(void)m;(void)a;(void)p;(void)v;(void)n;assert(0);}
static void pte_unmap_unlock(pte_t *p,spinlock_t *l){(void)p;(void)l;assert(0);}
'''
WRAPPER=r'''
static void host_metadata(unsigned char *metadata){
 memcpy(metadata,page_objects,sizeof(page_objects));memcpy(metadata+512,pmd_metadata,64);
 for(unsigned i=0;i<8;i++)for(unsigned j=0;j<2;j++){unsigned off=i*64+8+j*8;uint64_t ptr;memcpy(&ptr,metadata+off,8);uint64_t base=(uintptr_t)page_objects;if(ptr>=base && ptr<base+sizeof(page_objects))ptr=0xfffffffe00050000ULL+ptr-base;memcpy(metadata+off,&ptr,8);}
 uint64_t owner;memcpy(&owner,metadata+528,8);if(owner)owner=0xfffffffe00050000ULL+owner-(uintptr_t)page_objects;memcpy(metadata+528,&owner,8);
}
static void host_metadata_pair(unsigned char *metadata){host_metadata(metadata);memcpy(metadata+576,new_metadata,64);uint64_t owner;memcpy(&owner,metadata+592,8);if(owner)owner=0xfffffffe00050000ULL+owner-(uintptr_t)page_objects;memcpy(metadata+592,&owner,8);}
unsigned host_remap(const uint64_t *in,uint64_t *out,uint64_t *trace_out,unsigned char *metadata) {
 struct vm_area_struct v={in[0],in[1],in[2],0xaabb,(unsigned)in[3],&mm,NULL,NULL};
 mm.seq=7;mm.count=in[4];mm.pgd.val=in[5];counter=in[6];other=0;fail=in[7];nr=allocs=bug=0;
 memset(pmds,0,sizeof(pmds));memset(newpmds,0,sizeof(newpmds));memset(page_objects,0xa5,sizeof(page_objects));memset(pmd_metadata,0xa5,64);memset(pmd_metadata+16,0,8);memset(pmd_metadata+40,0,4);memset(new_metadata,0xa5,64);memset(new_metadata+16,0,8);memset(new_metadata+40,0,4);
 for(unsigned i=0;i<8;i++){uint64_t flags=0;memcpy(pages[i],&flags,8);}
 int ret=0;if(!setjmp(trap))ret=dmabuf_huge_remap_pfn_range(&v,in[8],in[9],in[10],(pgprot_t){in[11]},0);
 out[0]=(uint32_t)ret;out[1]=v.vm_flags;out[2]=v.vm_pgoff;out[3]=v.seq;out[4]=mm.count;out[5]=counter;out[6]=mm.pgd.val;out[7]=bug;
 memcpy(out+8,pmds,sizeof(pmds));host_metadata(metadata);
 memcpy(trace_out,rows,nr*5*sizeof(uint64_t));return nr;
}
uint64_t host_withdraw(unsigned index,unsigned char *metadata){
 assert(index<512);*(unsigned *)(pmd_metadata+40)=1;pgtable_t p=ack_withdraw(&mm,&pmds[index]);*(unsigned *)(pmd_metadata+40)=0;
 host_metadata(metadata);return p?0xfffffffe00050000ULL+((unsigned char *)p-pages[0]):0;
}
'''

ZAP_FIXTURE=r'''
struct mmu_gather {struct mm_struct *mm;uint64_t batch,start,end;unsigned char rest[96];};
static uint64_t zap_counter;
#define dmabuf_hugetlb_pmd_zap zap_counter
#define HPAGE_PMD_SIZE (1UL<<21)
static void *pmd_ptdesc(pmd_t *p){return metadata_for(p);}
static spinlock_t *ptlock_ptr(void *p){assert(p==pmd_metadata||p==new_metadata);return (void *)(0xfffffffe00040028ULL+(p==new_metadata?64:0));}
static void spin_lock(spinlock_t *p){trace(6,(uintptr_t)p,0,0,0);lock_state(p,1);}
static bool pmd_trans_huge(pmd_t p){return (p.val&0xc00000000000001ULL)&&!(p.val&2);}
static pmd_t pmdp_huge_get_and_clear(struct mm_struct *m,uint64_t a,pmd_t *p){(void)a;assert(m==&mm);pmd_t old=*p;p->val=0;return old;}
static void tlb_remove_pmd_tlb_entry(struct mmu_gather *t,pmd_t *p,uint64_t a){(void)p;if(a<t->start)t->start=a;if(a+HPAGE_PMD_SIZE>t->end)t->end=a+HPAGE_PMD_SIZE;t->rest[0]|=0x20;}
static pgtable_t pgtable_trans_huge_withdraw(struct mm_struct *m,pmd_t *p){trace(12,0x1001000,pmd_address(p),0,0);return ack_withdraw(m,p);}
static void pte_free(struct mm_struct *m,pgtable_t p){assert(m==&mm && p);unsigned char *b=(void *)p;uint32_t type;memcpy(&type,b+48,4);type|=512;memcpy(b+48,&type,4);uint64_t canon=0xfffffffe00050000ULL+(b-pages[0]);trace(5,canon,39,0xffffffff,0);trace(11,canon,0,0,0);}
static void mm_dec_nr_ptes(struct mm_struct *m){m->count-=4096;}
'''
ZAP_WRAPPER=r'''
void host_zap_reset(void){zap_counter=0;}
unsigned host_zap_step(unsigned index,uint64_t address,unsigned first,uint64_t *out,uint64_t *trace_out,unsigned char *metadata,unsigned char *tlb_bytes){
 static struct mmu_gather t;if(first){memset(&t,0,sizeof(t));t.mm=&mm;t.start=UINT64_MAX;}nr=0;
 struct vm_area_struct v={0,0,0,0,0,&mm,NULL,NULL};int ret=zap_dmabuf_huge_pmd(&t,&v,indexed_pmd(index),address);
 out[0]=ret;out[1]=mm.count;out[2]=zap_counter;memcpy(out+3,pmds,sizeof(pmds));memcpy(out+515,newpmds,sizeof(newpmds));host_metadata_pair(metadata);
 memcpy(tlb_bytes,&t,128);uint64_t m=0x1001000;memcpy(tlb_bytes,&m,8);
 memcpy(trace_out,rows,nr*5*sizeof(uint64_t));return nr;
}
'''

MOVE_FIXTURE=r'''
static bool pmd_none(pmd_t p){return !p.val;}
static bool pmd_present(pmd_t p){return !!(p.val&0xc00000000000001ULL);}
/* File/anon are NULL in this chain; separate move tests cover rmap routes. */
static void i_mmap_lock_write(void *p){(void)p;assert(0);}
static void i_mmap_unlock_write(void *p){(void)p;assert(0);}
static void anon_vma_lock_write(void *p){(void)p;assert(0);}
static void anon_vma_unlock_write(void *p){(void)p;assert(0);}
static void set_pmd_at(struct mm_struct *m,uint64_t a,pmd_t *p,pmd_t v){assert(m==&mm);(void)a;
 if((v.val&0x400000000000001ULL)&&!(v.val&0x140000000000000ULL))trace(13,v.val,0,0,0);
 p->val=v.val;if((v.val&0x40000000000041ULL)==0x40000000000001ULL){trace(10,0xd5033a9f,0,0,0);trace(10,0xd5033fdf,0,0,0);}}
static void flush_tlb_range(struct vm_area_struct *v,uint64_t start,uint64_t end){assert(v->vm_mm==&mm);start&=~4095ULL;end=(end+4095)&~4095ULL;assert(end-start==HPAGE_PMD_SIZE);
 /* Fixed explicit profile: ASID=0, no paired-ASID/range-TLBI/notifier. */
 trace(10,0xd5033a9f,0,0,0);trace(14,0xd5088340,0,0,0);trace(10,0xd5033b9f,0,0,0);trace(10,0xd5033b9f,0,0,0);}
'''
MOVE_WRAPPER=r'''
unsigned host_move_step(unsigned old_index,unsigned new_index,uint64_t old_address,uint64_t new_address,uint64_t *out,uint64_t *trace_out,unsigned char *metadata){
 assert(old_index<512&&new_index<1024);nr=0;bug=0;struct vm_area_struct v={0,0,0,0,0,&mm,NULL,NULL};bool ret=false;
 if(!setjmp(trap))ret=move_dmabuf_huge_pmd(&v,old_address,new_address,indexed_pmd(old_index),indexed_pmd(new_index),false);
 out[0]=ret;out[1]=mm.count;out[2]=bug;memcpy(out+3,pmds,sizeof(pmds));memcpy(out+515,newpmds,sizeof(newpmds));host_metadata_pair(metadata);
 memcpy(trace_out,rows,nr*5*sizeof(uint64_t));return nr;
}
'''


def real_helper_fixture(image_path,kernel):
    """Pinned ACK helper bodies shared with PTE fixture; names only renamed."""
    assert kernel.cfg['CONFIG_DEBUG_VM']=='n' and kernel.cfg['CONFIG_DEBUG_LIST']=='n' and kernel.cfg['CONFIG_LIST_HARDENED']=='y'
    assert kernel.cfg['CONFIG_ILLEGAL_POINTER_VALUE']=='0xdead000000000000'
    fields=load('test-dmabuf-stock-wrappers.py').btf_fields
    for name,required in {'page':{'lru':8},'ptdesc':{'pmd_huge_pte':16,'ptl':40}}.items():
        ident=next(i for i,t in enumerate(kernel.btf.types) if t['kind']==4 and t['name']==name)
        found=fields(kernel.btf,ident)
        for member,offset in required.items():assert found[member]==offset
    helper_dir=image_path.parent.parent/'stock-ack-dmabuf-helpers-reference-20261005'
    deposit_source=helper_dir/'mm/pgtable-generic.c';pmd_source=helper_dir/'arch/arm64/mm/mmu.c'
    assert hashlib.sha256(deposit_source.read_bytes()).hexdigest()=='990748e9f12d796834dbe92a194454cbe2620d2664e5982ac2da0d35d2610935'
    assert hashlib.sha256(pmd_source.read_bytes()).hexdigest()=='5faec6be3b00796e2a4693d0892fe6b2684c34712eeeb7ca0b5d1a8e1707d89b'
    extract=load('test-dmabuf-stock-deposit.py').body
    deposit=extract(deposit_source.read_text(),'void pgtable_trans_huge_deposit(').replace('void pgtable_trans_huge_deposit(','void ack_deposit(',1)+'\n'+extract(deposit_source.read_text(),'pgtable_t pgtable_trans_huge_withdraw(').replace('pgtable_t pgtable_trans_huge_withdraw(','pgtable_t ack_withdraw(',1)
    setter=extract(pmd_source.read_text(),'bool pgattr_change_is_safe(')+'\n'+extract(pmd_source.read_text(),'int pmd_set_huge(').replace('int pmd_set_huge(','int ack_pmd_set(',1)
    assert FIXTURE.count('/* ACK_DEPOSIT_BODY */')==1 and FIXTURE.count('/* ACK_PMD_SET_BODY */')==1
    return FIXTURE.replace('/* ACK_DEPOSIT_BODY */',deposit).replace('/* ACK_PMD_SET_BODY */',setter)


def run(args):
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
    from unicorn.arm64_const import (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5,UC_ARM64_REG_X30,UC_ARM64_REG_SP,UC_ARM64_REG_SP_EL0,UC_ARM64_REG_PC)
    image=args.image.read_bytes();contract=load('verify-stock-recovered-contracts.py')
    assert hashlib.sha256(image).hexdigest()==contract.IMAGE_SHA
    assert hashlib.sha256(args.symbols.read_bytes()).hexdigest()==contract.SYMBOL_SHA
    kernel=load('stock-binary-evidence.py').Kernel(args.image,args.symbols)
    verify_btf(kernel)
    btf=kernel.btf;fields=load('test-dmabuf-stock-wrappers.py').btf_fields
    ident=next(i for i,t in enumerate(btf.types) if t['kind']==4 and t['name']=='mmu_gather')
    assert btf.types[ident]['size']==128
    found=fields(btf,ident)
    for member,offset in {'mm':0,'start':16,'end':24}.items():assert found[member]==offset
    raw=btf.types[ident]['raw'];cleared=next(raw[i+2] for i in range(0,len(raw),3) if btf.string(raw[i])=='cleared_pmds')
    assert cleared&0xffffff==261 and cleared>>24==1
    func=next(t for t in btf.types if t['kind']==12 and t['name']=='__mod_lruvec_page_state');proto=btf.types[func['size']];delta=btf.types[proto['raw'][5]]
    assert delta['kind']==1 and delta['name']=='int' and delta['size']==4
    for name,required in {'vm_area_struct':{'vm_file':128,'anon_vma':104},'mm_struct':{'context':0x3c8,'notifier_subscriptions':0x420}}.items():
        ident=next(i for i,t in enumerate(btf.types) if t['kind']==4 and t['name']==name);found=fields(btf,ident)
        for member,offset in required.items():assert found[member]==offset
    fixture=real_helper_fixture(args.image,kernel)
    recovered=Path(__file__).parents[1]/'tools/stock-recovery'
    code=fixture+(recovered/'dmabuf_huge_remap.recovered.c').read_text()+ZAP_FIXTURE+(recovered/'dmabuf_huge_zap.recovered.c').read_text()+MOVE_FIXTURE+(recovered/'dmabuf_huge_move.recovered.c').read_text()+WRAPPER+ZAP_WRAPPER+MOVE_WRAPPER
    with tempfile.TemporaryDirectory(prefix='dmabuf-remap-') as tmp:
        lib=Path(tmp)/'remap.dylib'
        subprocess.run(['clang','-x','c','-std=c11','-Wall','-Wextra','-Werror','-dynamiclib','-o',str(lib),'-'],input=code,text=True,check=True)
        host=ctypes.CDLL(str(lib));host.host_remap.argtypes=[ctypes.c_void_p]*4;host.host_remap.restype=ctypes.c_uint
        host.host_withdraw.argtypes=[ctypes.c_uint,ctypes.c_void_p];host.host_withdraw.restype=ctypes.c_uint64
        host.host_zap_reset.argtypes=[];host.host_zap_step.argtypes=[ctypes.c_uint,ctypes.c_uint64,ctypes.c_uint]+[ctypes.c_void_p]*4;host.host_zap_step.restype=ctypes.c_uint
        host.host_move_step.argtypes=[ctypes.c_uint]*2+[ctypes.c_uint64]*2+[ctypes.c_void_p]*3;host.host_move_step.restype=ctypes.c_uint
        uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);uc.mem_map(kernel.base,(len(image)+4095)&~4095);uc.mem_write(kernel.base,image)
        ram=0x1000000;uc.mem_map(ram,0x20000)
        vma,mm,pgd,task,lock,stack,stop=[ram+x for x in (0,0x1000,0x2000,0x4000,0x6000,0xf000,0x10000)]
        direct=0xffffff8001000000;uc.mem_map(direct,8192)
        pages=0xfffffffe00050000;uc.mem_map(pages,4096)
        pmd_metadata=0xfffffffe00040000;uc.mem_map(pmd_metadata,4096)
        cap=kernel.address('system_cpucaps');assert kernel.span('system_cpucaps') is None and kernel.symbols['system_cpucaps'][0][1]=='B';uc.mem_map(cap&~4095,4096)
        counter=kernel.address('dmabuf_hugetlb_pmd_map');assert kernel.span('dmabuf_hugetlb_pmd_map') is None
        uc.mem_map(counter&~4095,4096);uc.mem_write(kernel.address('memstart_addr'),bytes(8))
        names=('down_write','up_write','__pmd_alloc','__alloc_pages','__mod_lruvec_page_state','_raw_spin_lock','pgtable_trans_huge_deposit','pmd_set_huge','_raw_spin_unlock')
        funcs={kernel.address(n):i+1 for i,n in enumerate(names)};trace=[];state={}
        funcs[kernel.address('__free_pages')]=11;funcs[kernel.address('pgtable_trans_huge_withdraw')]=12
        funcs[kernel.address('__sync_icache_dcache')]=13
        def hook(emu,address,size,user):
            if address in funcs:
                op=funcs[address];x=[emu.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3)]
                trace.append((op,*[x[i]&0xffffffff if op==5 and i==2 else x[i] if i<({1:1,2:1,3:3,4:4,5:3,6:1,7:3,8:3,9:1,11:2,12:2,13:1}[op]) else 0 for i in range(4)]))
                result=0
                if op in (7,8,12):return # Observe calls, execute original stock helpers.
                if op==3:
                    result=(1<<64)-12 if state['fail']==1 else 0
                    if not result:emu.mem_write(pgd,struct.pack('<Q',0x1000003))
                elif op==4:
                    state['allocs']+=1;result=0 if state['allocs']==state['fail']-1 else pages+(state['allocs']-1)*64
                elif op in (6,9):
                    assert x[0] in (pmd_metadata+40,pmd_metadata+104)
                    emu.mem_write(x[0],struct.pack('<I',op==6))
                elif op==11:
                    assert pages<=x[0]<pages+512 and (x[0]-pages)%64==0 and x[1]==0
                    assert x[0] not in state['freed'],'double free in chain';state['freed'].add(x[0])
                emu.reg_write(UC_ARM64_REG_X0,result);emu.reg_write(UC_ARM64_REG_PC,emu.reg_read(UC_ARM64_REG_X30))
            elif kernel.base<=address<kernel.base+len(image):
                word=struct.unpack_from('<I',image,address-kernel.base)[0]
                if word in (0xd5033a9f,0xd5033fdf,0xd5033b9f):trace.append((10,word,0,0,0))
                elif word&~31==0xd5088340:
                    reg=word&31;value=emu.reg_read(UC_ARM64_REG_X0+reg) if reg<31 else 0
                    trace.append((14,word&~31,value,0,0));emu.reg_write(UC_ARM64_REG_PC,address+4)
                if word&0xffe0001f==0xd4200000:state['bug']=1;emu.emu_stop()
        uc.hook_add(UC_HOOK_CODE,hook)
        def deposit_nodes(block):
            owner=struct.unpack('<Q',uc.mem_read(pmd_metadata+block*64+16,8))[0]
            if not owner:return set()
            start=node=owner+8;seen=set()
            while True:
                table=node-8;assert pages<=table<pages+512 and (table-pages)%64==0
                assert table not in seen,'duplicate/cyclic deposited table';seen.add(table)
                nxt,prev=struct.unpack('<2Q',uc.mem_read(node,16))
                assert struct.unpack('<Q',uc.mem_read(nxt+8,8))[0]==node and struct.unpack('<Q',uc.mem_read(prev,8))[0]==node,'broken list links'
                node=nxt
                if node==start:return seen
                assert len(seen)<8,'deposit list does not close'
        def check_pool(mapped,removed):
            old,new=deposit_nodes(0),deposit_nodes(1)
            assert not old&new,'same table owned by both PMD pages'
            allocated={pages+i*64 for i in range(mapped)}
            assert old|new==allocated-removed,('lost/extra deposited table',old,new,allocated,removed)
            return old,new
        cases=withdrawals=partial_chains=repeated_zaps=moves=0;coverage={'multi_success':0,'partial_failure':0,'cow_reject':0,'bug':0}
        for case in range(216):
            address=(1<<21)+(4096 if case%9==0 else 0)
            size=(1,4096,1<<21,(1<<21)+4096,3<<21,0)[case%6]
            if case%19==0:address+=1
            end=address+((size+4095)&~4095)
            flags=(0,32,40,1<<39)[case%4]
            vma_end=end+(4096 if case%11==0 else 0)
            values=(address,vma_end,flags,case%8,(0,(1<<64)-1)[case%2],(0,0x1000003)[case%2],(0,(1<<64)-1)[case%2],(case//6)%6,address,0x4000,size,3|(case%2<<54))
            inputs=(ctypes.c_uint64*12)(*values);out=(ctypes.c_uint64*520)();rows=(ctypes.c_uint64*640)();meta=(ctypes.c_ubyte*576)()
            n=host.host_remap(inputs,out,rows,meta);expected=[tuple(rows[i*5:(i+1)*5]) for i in range(n)]
            uc.mem_write(vma,struct.pack('<5Q',values[0],values[1],mm,0,flags));uc.mem_write(vma+44,struct.pack('<I',values[3]));uc.mem_write(vma+48,struct.pack('<Q',lock));uc.mem_write(vma+120,struct.pack('<Q',0xaabb))
            for a,v in ((mm+112,pgd),(mm+128,values[4]),(pgd,values[5]),(counter,values[6])):uc.mem_write(a,struct.pack('<Q',v))
            uc.mem_write(mm+224,struct.pack('<I',7));uc.mem_write(direct,bytes(8192))
            page_data=bytearray(b'\xa5'*512)
            for i in range(8):struct.pack_into('<Q',page_data,i*64,0)
            uc.mem_write(pages,bytes(page_data));trace.clear();state.update(fail=values[7],allocs=0,bug=0,freed=set())
            desc=bytearray(b'\xa5'*128)
            for block in (0,64):desc[block+16:block+24]=bytes(8);desc[block+40:block+44]=bytes(4)
            uc.mem_write(pmd_metadata,bytes(desc))
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
            assert bytes(uc.mem_read(pages,512))+bytes(uc.mem_read(pmd_metadata,64))==bytes(meta),('table list/owner metadata',case)
            assert trace==expected,('helper trace',case,trace,expected)
            mapped=(out[5]-values[6])&((1<<64)-1)
            coverage['multi_success']+=out[0]==0 and not out[7] and mapped>1
            coverage['partial_failure']+=out[0]==0xfffffff4 and mapped>0
            coverage['cow_reject']+=out[0]==0xffffffea
            coverage['bug']+=bool(out[7])
            # Continue from precisely the metadata produced by remap, including
            # successful deposits left behind by a partial allocation failure.
            if not out[7]:
                seen=set();index=(address>>21)&511
                check_pool(mapped,set())
                if args.teardown in ('zap','move-zap','cross-move-zap'):
                    moved_index=index
                    if args.teardown in ('move-zap','cross-move-zap'):
                        moved_index=640 if args.teardown=='cross-move-zap' else 128;uc.mem_write(mm+0x3c8,bytes(8));uc.mem_write(mm+0x420,bytes(8));uc.mem_write(cap,bytes(16))
                        for step in range(mapped):
                            old_addr=address+step*(1<<21);new_addr=(moved_index+step)*(1<<21)
                            move_out=(ctypes.c_uint64*1027)();move_rows=(ctypes.c_uint64*640)();move_meta=(ctypes.c_ubyte*640)()
                            owner_before=bytes(uc.mem_read(pmd_metadata,128));tables_before=bytes(uc.mem_read(pages,512))
                            nmove=host.host_move_step(index+step,moved_index+step,old_addr,new_addr,move_out,move_rows,move_meta);want=[tuple(move_rows[j*5:(j+1)*5]) for j in range(nmove)]
                            trace.clear()
                            for r,v in zip((UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5),(vma,old_addr,new_addr,direct+(index+step)*8,direct+(moved_index+step)*8,0)):uc.reg_write(r,v)
                            uc.reg_write(UC_ARM64_REG_X30,stop);uc.reg_write(UC_ARM64_REG_SP,stack)
                            uc.emu_start(kernel.address('move_dmabuf_huge_pmd'),stop,count=20000)
                            assert not state['bug'] and uc.reg_read(UC_ARM64_REG_PC)==stop
                            actual=[uc.reg_read(UC_ARM64_REG_X0),struct.unpack('<Q',uc.mem_read(mm+128,8))[0],state['bug']]
                            assert actual==list(move_out[:3]) and actual[0]==1,('chain move return/account',case,step)
                            assert bytes(uc.mem_read(direct,8192))==bytes(move_out)[24:],('chain move PMDs',case,step)
                            assert bytes(uc.mem_read(pages,512))+bytes(uc.mem_read(pmd_metadata,128))==bytes(move_meta),('chain move metadata',case,step)
                            assert trace==want,('chain move trace',case,step,trace,want)
                            if args.teardown=='move-zap':assert bytes(uc.mem_read(pmd_metadata,128))==owner_before and bytes(uc.mem_read(pages,512))==tables_before,('same-table move preserves deposit list',case,step)
                            else:
                                assert struct.unpack('<Q',uc.mem_read(pmd_metadata+80,8))[0]!=0,('destination deposit owner',case,step)
                                if step==mapped-1:assert struct.unpack('<Q',uc.mem_read(pmd_metadata+16,8))[0]==0,('source deposit drained by move',case)
                            old_pool,new_pool=check_pool(mapped,set())
                            if args.teardown=='cross-move-zap':assert len(old_pool)==mapped-step-1 and len(new_pool)==step+1,('per-owner transfer count',case,step)
                            moves+=1
                    tlb=ram+0x7000;zap_count=kernel.address('dmabuf_hugetlb_pmd_zap');assert kernel.span('dmabuf_hugetlb_pmd_zap') is None
                    uc.mem_write(zap_count,bytes(8));host.host_zap_reset();gather=bytearray(128);struct.pack_into('<Q',gather,0,mm);struct.pack_into('<Q',gather,16,(1<<64)-1);uc.mem_write(tlb,bytes(gather))
                    for step in range(mapped+bool(mapped)):
                        offset=min(step,mapped-1);at=moved_index+offset;addr=at*(1<<21)
                        zap_out=(ctypes.c_uint64*1027)();zap_meta=(ctypes.c_ubyte*640)();zap_rows=(ctypes.c_uint64*640)();zap_tlb=(ctypes.c_ubyte*128)()
                        z=host.host_zap_step(at,addr,step==0,zap_out,zap_rows,zap_meta,zap_tlb);want=[tuple(zap_rows[j*5:(j+1)*5]) for j in range(z)]
                        trace.clear()
                        for r,v in zip((UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3),(tlb,vma,direct+at*8,addr)):uc.reg_write(r,v)
                        uc.reg_write(UC_ARM64_REG_X30,stop);uc.reg_write(UC_ARM64_REG_SP,stack)
                        uc.emu_start(kernel.address('zap_dmabuf_huge_pmd'),stop,count=10000)
                        assert not state['bug'] and uc.reg_read(UC_ARM64_REG_PC)==stop
                        actual=[uc.reg_read(UC_ARM64_REG_X0)]+[struct.unpack('<Q',uc.mem_read(a,8))[0] for a in (mm+128,zap_count)]
                        assert actual==list(zap_out[:3]) and actual[0]==int(step<mapped),('zap outputs',case,step,actual,list(zap_out[:3]))
                        assert bytes(uc.mem_read(direct,8192))==bytes(zap_out)[24:],('chain PMDs',case,step)
                        assert bytes(uc.mem_read(pages,512))+bytes(uc.mem_read(pmd_metadata,128))==bytes(zap_meta),('chain zap metadata',case,step)
                        assert bytes(uc.mem_read(tlb,128))==bytes(zap_tlb),('chain gather',case,step)
                        assert trace==want,('chain zap trace',case,step,trace,want)
                        check_pool(mapped,state['freed'])
                        withdrawals+=step<mapped;repeated_zaps+=step==mapped
                    assert len(state['freed'])==mapped and struct.unpack('<Q',uc.mem_read(mm+128,8))[0]==values[4],('table ownership/accounting',case)
                    assert bytes(uc.mem_read(direct,8192))==bytes(8192),('stale mapped PMD',case)
                    assert struct.unpack('<Q',uc.mem_read(pmd_metadata+16,8))[0]==0,('deposit leak',case)
                    assert struct.unpack('<Q',uc.mem_read(pmd_metadata+80,8))[0]==0,('destination deposit leak',case)
                    partial_chains+=bool(mapped and out[0]==0xfffffff4);cases+=1;continue
                for step in range(mapped):
                    want=host.host_withdraw(index,meta);assert want and want not in seen;seen.add(want)
                    uc.mem_write(pmd_metadata+40,struct.pack('<I',1));trace.clear()
                    uc.reg_write(UC_ARM64_REG_X0,mm);uc.reg_write(UC_ARM64_REG_X1,direct+index*8);uc.reg_write(UC_ARM64_REG_X30,stop);uc.reg_write(UC_ARM64_REG_SP,stack)
                    uc.emu_start(kernel.address('pgtable_trans_huge_withdraw'),stop,count=10000)
                    assert not state['bug'] and uc.reg_read(UC_ARM64_REG_PC)==stop
                    assert uc.reg_read(UC_ARM64_REG_X0)==want,('chain withdraw return',case,step)
                    uc.mem_write(pmd_metadata+40,bytes(4))
                    assert bytes(uc.mem_read(pages,512))+bytes(uc.mem_read(pmd_metadata,64))==bytes(meta),('chain list/owner bytes',case,step)
                    assert bytes(uc.mem_read(direct,4096))==bytes(out)[64:],('withdraw does not clear PMDs',case)
                    assert struct.unpack('<Q',uc.mem_read(mm+128,8))[0]==out[4],('withdraw alone does not free/account',case)
                    check_pool(mapped,seen)
                    withdrawals+=1
                assert struct.unpack('<Q',uc.mem_read(pmd_metadata+16,8))[0]==0,('deposited table leak',case)
                partial_chains+=bool(mapped and out[0]==0xfffffff4)
            cases+=1
        assert all(coverage.values()),coverage
        print(f'PASS: {cases} exact ARM64 remap PMD cases; flags, accounting, PGD/PMD writes, allocation failures, partial mappings and BUG guards')
        print(f'Coverage categories: {coverage}')
        assert withdrawals and partial_chains
        print(f'PASS: remap→{args.teardown} sequence: {withdrawals} tables, including {partial_chains} partial-failure chains; owner drains to NULL')
        if args.teardown in ('zap','move-zap','cross-move-zap'):
            assert repeated_zaps
            print(f'Deposited tables freed exactly once in allocator model; {repeated_zaps} repeated zap calls return zero without freeing/accounting again. PMDs clear and pgtables_bytes restores initial value; gather/counters/metadata/helper traces compared at each step.')
        if args.teardown in ('move-zap','cross-move-zap'):
            assert moves==withdrawals;print(f'PASS: {moves} remap→{args.teardown} steps; source clears, destination mapping then tears down; owner/list checked on both PMD pages')
        print('Real stock deposit/pmd_set_huge/withdraw bodies executed; native exact ACK bodies, list/owner bytes and barriers compared. Allocation/free/locks modeled; not full remap/move/split lifecycle, MMU, SMP or hardware proof.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--symbols',type=Path,required=True);p.add_argument('--teardown',choices=('withdraw','zap','move-zap','cross-move-zap'),default='withdraw');run(p.parse_args())
