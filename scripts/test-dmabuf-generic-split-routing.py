#!/usr/bin/env python3
"""Actual ACK generic split body + generated dispatch; routing, not MMU proof."""
from importlib.machinery import SourceFileLoader
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile

HERE=Path(__file__).resolve().parent
prepare=SourceFileLoader('dma_generic_split_prepare',str(HERE/'prepare-dmabuf-reimplementation.py')).load_module()
extract=SourceFileLoader('dma_generic_split_extract',str(HERE/'test-dmabuf-stock-deposit.py')).load_module().body
REFERENCE=Path(os.environ.get('DMA_ACK_REFERENCE',str(HERE.parent.parent.parent/'outputs/stock-ack-dmabuf-overlay-reference-20261005')))


def run():
    source,recipes={},{}
    for name,sha in prepare.SOURCES.items():
        data=(REFERENCE/name).read_bytes()
        if hashlib.sha256(data).hexdigest()!=sha:raise ValueError('ACK input drift')
        source[name]=data.decode()
    for name,sha in prepare.RECIPES.items():
        data=(HERE.parent/'tools/stock-recovery'/('dmabuf_huge_'+name+'.recovered.c')).read_bytes()
        if hashlib.sha256(data).hexdigest()!=sha:raise ValueError('recipe drift')
        recipes[name]=data.decode()
    body=extract(prepare.candidate(source,recipes)['mm/huge_memory.c'],'void __split_huge_pmd(')
    fixture=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
typedef unsigned spinlock_t;
typedef struct {unsigned long val;} pmd_t;
struct mm_struct {int unused;}; struct folio {int unused;};
struct vm_area_struct {unsigned long vm_flags;struct mm_struct *vm_mm;};
struct mmu_notifier_range {unsigned long start;};
#define VM_XIAOMI_DMABUF_HUGE (1UL<<39)
#define HPAGE_PMD_SIZE (1UL<<21)
#define HPAGE_PMD_MASK (~(HPAGE_PMD_SIZE-1))
#define MMU_NOTIFY_CLEAR 1
#define VM_BUG_ON(x) assert(!(x))
#define VM_WARN_ON_ONCE(x) ((void)(x))
static unsigned native, dma, notify_start, notify_end, locks, unlocks;
static unsigned long last_address;static bool last_freeze;static struct folio *last_folio;
static spinlock_t lock;
static void mmu_notifier_range_init(struct mmu_notifier_range *r,unsigned e,unsigned f,struct mm_struct *mm,unsigned long a,unsigned long b){
 assert(e==1 && !f && mm && b-a==HPAGE_PMD_SIZE);r->start=a;}
static void mmu_notifier_invalidate_range_start(struct mmu_notifier_range *r){(void)r;notify_start++;}
static void mmu_notifier_invalidate_range_end(struct mmu_notifier_range *r){(void)r;notify_end++;}
static spinlock_t *pmd_lock(struct mm_struct *mm,pmd_t *p){assert(mm && p);locks++;return &lock;}
static void spin_unlock(spinlock_t *l){assert(l==&lock);unlocks++;}
static bool folio_test_locked(struct folio *f){return f!=0;}
static bool pmd_trans_huge(pmd_t p){return (p.val&3)==1;}
static bool pmd_devmap(pmd_t p){(void)p;return false;}
static bool is_pmd_migration_entry(pmd_t p){(void)p;return false;}
static void *pmd_page(pmd_t p){return (void *)(uintptr_t)(p.val&~4095UL);}
static struct folio *page_folio(void *p){return p;}
static void __split_huge_pmd_locked(struct vm_area_struct *v,pmd_t *p,unsigned long a,bool f){
 (void)v;(void)a;(void)f;native++;p->val=0; /* model native file-backed teardown */}
#ifdef CONFIG_XIAOMI_DMABUF_HUGETLB
static void __split_dmabuf_huge_pmd(struct vm_area_struct *v,pmd_t *p,unsigned long a,bool f,struct folio *folio){
 assert(v && p);dma++;last_address=a;last_freeze=f;last_folio=folio;}
#endif
'''
    main=r'''
int main(void){
 struct mm_struct mm={0};
 for(unsigned flagged=0;flagged<2;flagged++)
  for(unsigned huge=0;huge<2;huge++)
   for(unsigned with_folio=0;with_folio<2;with_folio++) {
    struct vm_area_struct v={flagged?VM_XIAOMI_DMABUF_HUGE:0,&mm};
    pmd_t p={huge?0x200001:0};
    struct folio *f=with_folio?(void *)0x200000:0;
    native=dma=notify_start=notify_end=locks=unlocks=0;
    __split_huge_pmd(&v,&p,0x401000,with_folio,f);
#ifdef CONFIG_XIAOMI_DMABUF_HUGETLB
    if(flagged){
     assert(dma==1 && !native && !locks && !unlocks && !notify_start && !notify_end);
     assert(last_address==0x401000 && last_freeze==with_folio && last_folio==f);
     assert(p.val==(huge?0x200001UL:0));continue;
    }
#endif
    assert(!dma && native==huge && locks==1 && unlocks==1 && notify_start==1 && notify_end==1);
    assert(!p.val);
   }
 (void)last_address;(void)last_freeze;(void)last_folio;
 return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='dma-generic-split-') as temporary:
        for enabled in (False,True):
            binary=Path(temporary)/str(enabled)
            command=['clang','-x','c','-std=c11','-Wall','-Wextra','-Werror',
                     '-fsanitize=address,undefined','-o',str(binary),'-']
            if enabled:command.append('-DCONFIG_XIAOMI_DMABUF_HUGETLB=1')
            subprocess.run(command,input=fixture+body+main,text=True,check=True)
            subprocess.run([str(binary)],check=True)
    print('PASS: generated generic split dispatch enabled/disabled, ordinary VMA routing and argument forwarding; helpers modeled, NOT MMU proof')


if __name__=='__main__':run()
