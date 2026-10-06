#!/usr/bin/env python3
"""Integration-only mapper guards/rollback with exact pinned ACK table helpers.

Native ASan/UBSan; allocations and locks modeled. Not MMU/SMP/runtime proof.
"""
import argparse
import hashlib
from importlib.machinery import SourceFileLoader
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent


def load(name):
    return SourceFileLoader(name,str(HERE/name)).load_module()


def run(args):
    prepare = load('prepare-dmabuf-reimplementation.py')
    pmd = load('test-dmabuf-stock-remap-pmd.py')
    if bool(args.image) != bool(args.symbols):
        raise ValueError('stock Image and symbols must be paired')
    if args.image:
        contract = load('verify-stock-recovered-contracts.py')
        if (hashlib.sha256(args.image.read_bytes()).hexdigest()!=contract.IMAGE_SHA or
            hashlib.sha256(args.symbols.read_bytes()).hexdigest()!=contract.SYMBOL_SHA):
            raise ValueError('stock evidence identity mismatch')
        kernel = load('stock-binary-evidence.py').Kernel(args.image,args.symbols)
        pmd.verify_btf(kernel)
        fixture = pmd.real_helper_fixture(args.image,kernel)
    elif args.ack_helpers:
        fixture = pmd.pinned_helper_fixture(args.ack_helpers)
    else:
        raise ValueError('stock evidence or exact ACK helper directory required')
    fixture = fixture.replace('static int pmd_set_huge(pmd_t *p,uint64_t pa,pgprot_t prot){',
                              'static unsigned fail_publish, publish_calls;\n'
                              'static int pmd_set_huge(pmd_t *p,uint64_t pa,pgprot_t prot){'
                              'if (++publish_calls==fail_publish) return 0;')
    # Add real-table PTE destinations for overwrite guard; no fake MMU claim.
    fixture = fixture.replace('/* Explicitly unsupported in this PMD-only fixture, not production stubs. */',
                              'static pte_t test_ptes[512]; static unsigned bulk_calls, unlock_calls;')
    fixture = fixture.replace('(void)m;(void)p;(void)a;(void)l;assert(0);return NULL;',
                              '(void)m;(void)p;(void)a;*l=(void *)0x1234;return test_ptes;')
    fixture = fixture.replace('(void)m;(void)a;(void)p;(void)v;(void)n;assert(0);',
                              '(void)m;(void)a;bulk_calls++;for(unsigned i=0;i<n;i++)p[i]=v;')
    fixture = fixture.replace('(void)p;(void)l;assert(0);',
                              '(void)p;assert(l==(void *)0x1234);unlock_calls++;')
    extra = '''
#include <limits.h>
#define PAGE_SIZE 4096UL
#define PHYS_MASK ((1UL<<48)-1)
#define EBUSY 16
static bool pmd_none(pmd_t p){return !p.val;}
'''
    recipe = (HERE.parent/'tools/stock-recovery/dmabuf_huge_remap.recovered.c').read_text()
    adapted = prepare.integration_remap(recipe)
    main = r'''
static struct vm_area_struct reset(void) {
 memset(&mm,0,sizeof(mm)); memset(pmds,0,sizeof(pmds));
 memset(newpmds,0,sizeof(newpmds));memset(page_objects,0,sizeof(page_objects));
 memset(pmd_metadata,0,sizeof(pmd_metadata));memset(new_metadata,0,sizeof(new_metadata));
 memset(test_ptes,0,sizeof(test_ptes));
 mm.seq=7;mm.pgd.val=0x1000003;nr=allocs=bug=fail=publish_calls=fail_publish=0;
 counter=other=bulk_calls=unlock_calls=0;
 return (struct vm_area_struct){0x400000,0xc00000,0,0xaabb,7,&mm,NULL,NULL,{0}};
}
static int map(struct vm_area_struct *v,unsigned long a,unsigned long p,unsigned long s,unsigned mode) {
 return dmabuf_huge_remap_pfn_range(v,a,p,s,(pgprot_t){1025},mode);
}
static void assert_untouched(struct vm_area_struct *v) {
 assert(!v->vm_flags && v->vm_pgoff==0xaabb && !allocs && !nr && !mm.count);
 assert(!counter && !other && !bulk_calls && !unlock_calls);
}
int main(void) {
 struct vm_area_struct v;
 const unsigned long bad[][3]={
  {0x400001,0x2000,0x200000}, {0x401000,0x2000,0x200000},
  {0x400000,0x2001,0x200000}, {0x400000,0x2000,4096},
  {0x400000,0x2000,0}, {0x400000,0x2000,ULONG_MAX},
  {0x3ff000,0x2000,0x200000}, {0xbff000,0x2000,0x200000},
  {ULONG_MAX-4095,0x2000,8192}, {0x400000,1UL<<36,0x200000},
  {0x400000,(1UL<<36)-512,0x400000}
 };
 for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++) {
  v=reset(); assert(map(&v,bad[i][0],bad[i][1],bad[i][2],0)==-EINVAL);assert_untouched(&v);
 }
 v=reset();assert(map(NULL,0x400000,0x2000,0x200000,0)==-EINVAL);assert_untouched(&v);
 v=reset();v.vm_mm=NULL;assert(map(&v,0x400000,0x2000,0x200000,0)==-EINVAL);assert_untouched(&v);
 /* Original COW rejection remains before VMA flags and table allocations. */
 v=reset();v.vm_flags=32;assert(map(&v,0x400000,0x2000,0x200000,0)==-EINVAL);
 assert(v.vm_flags==32 && !allocs && !nr && !mm.count);
 /* Publication failure first/second block: free only newly deposited table. */
 for(unsigned ordinal=1;ordinal<=2;ordinal++) {
  v=reset();fail_publish=ordinal;
  assert(map(&v,0x400000,0x2000,0x400000,0)==-EINVAL);
  assert(counter==ordinal-1 && mm.count==(ordinal-1)*4096UL);
  assert(!*(unsigned *)(pmd_metadata+40));
  pgtable_t owner=*(pgtable_t *)(pmd_metadata+16);
  assert((owner!=NULL)==(ordinal==2));
  assert(!pmds[ordinal+1].val);
  unsigned frees=0; for(unsigned i=0;i<nr;i++)frees+=rows[i][0]==11;
  assert(frees==1);
  /* The normal recovered zap releases earlier successful PMD publication. */
  if(ordinal==2) {
   struct mmu_gather t={.mm=&mm};
   assert(zap_dmabuf_huge_pmd(&t,&v,&pmds[2],0x400000)==1);
   assert(!mm.count && !*(pgtable_t *)(pmd_metadata+16));
  }
 }
 /* Occupied PMD is never deposited into or overwritten; fresh table freed. */
 v=reset();pmds[2].val=0x600001;
 assert(map(&v,0x400000,0x2000,0x200000,0)==-EBUSY);
 assert(pmds[2].val==0x600001 && !counter && !mm.count && !publish_calls);
 assert(!*(pgtable_t *)(pmd_metadata+16) && !*(unsigned *)(pmd_metadata+40));
 /* Every occupied PTE position is checked, including the final entry. */
 for(unsigned i=0;i<512;i++) {
  v=reset();test_ptes[i].val=0xabc001;
  assert(map(&v,0x400000,0x2000,0x200000,1)==-EBUSY);
  assert(!bulk_calls && unlock_calls==1 && !other);
  for(unsigned j=0;j<512;j++)assert(test_ptes[j].val==(i==j?0xabc001:0));
 }
 v=reset();assert(map(&v,0x400000,0x2000,0x200000,1)==0);
 assert(bulk_calls==1 && unlock_calls==1 && other==1);
 v=reset();assert(map(&v,0x400000,0x2000,0x400000,0)==0);
 assert(counter==2 && mm.count==8192 && publish_calls==2);
 /* Allocation failure semantics unchanged; caller must unwind earlier maps. */
 v=reset();fail=3;assert(map(&v,0x400000,0x2000,0x400000,0)==-ENOMEM);
 assert(counter==1 && mm.count==4096 && !*(unsigned *)(pmd_metadata+40));
 return 0;
}
'''
    source = fixture+pmd.ZAP_FIXTURE+extra+(HERE.parent/'tools/stock-recovery/dmabuf_huge_zap.recovered.c').read_text()+adapted+main
    with tempfile.TemporaryDirectory(prefix='dma-remap-safety-') as temporary:
        binary = Path(temporary)/'test'
        subprocess.run(['clang','-x','c','-std=c11','-Wall','-Wextra','-Werror',
                        '-fsanitize=address,undefined','-fno-sanitize-recover=all',
                        '-fno-strict-aliasing','-o',str(binary),'-'],
                       input=source,text=True,check=True)
        subprocess.run([str(binary)],check=True)
    print('PASS: native integration guards, 512 occupied PTE positions, publication rollback, exact ACK deposit/withdraw; NOT MMU/SMP proof'+
          ('; stock BTF layouts checked' if args.image else '; native fixture layouts only, NOT stock BTF validation'))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('image','symbols'):
        parser.add_argument('--'+name,type=Path)
    parser.add_argument('--ack-helpers',type=Path)
    run(parser.parse_args())
