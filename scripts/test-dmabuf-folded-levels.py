#!/usr/bin/env python3
"""Native ACK folded predicates + actual recovered allocation condition.

Exercises the zero-entry branch with pinned real helper definitions, not a
mock pgd_none(raw)==0 assumption. No allocator/MMU/lifetime execution proof.
"""
from pathlib import Path
import hashlib
import os
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = Path(os.environ.get('DMA_FOLDED_ACK_SOURCE', str(
    ROOT.parent.parent/'outputs/stock-ack-dma-folded-reference-20261006')))
WALK_REFERENCE = Path(os.environ.get('DMA_ACK_REFERENCE', str(
    ROOT.parent.parent/'outputs/stock-ack-dmabuf-overlay-reference-20261005')))
PINS = {
    'include/asm-generic/pgtable-nop4d.h':'cd44b14101a24b43beabda8be0f2a1f54c3d5d5492bbb89fcc9eb93fd575dadb',
    'include/asm-generic/pgtable-nopud.h':'2f14e307a55d9a6bd6d00c1967893f4f01d8dcec53efd8785cdcc1a68b288dbf',
    'arch/arm64/include/asm/pgtable.h':'e1f09d4c505f326c18dc93ca18a132978232245b0bb0ea3669404f6cf52f5d61',
}


def exact(text, pattern):
    rows = re.findall(pattern,text,re.M)
    if len(rows) != 1:
        raise ValueError('unique native helper/condition required')
    return rows[0]


def native_context():
    headers = {}
    for name,sha in PINS.items():
        data = (REFERENCE/name).read_bytes()
        if hashlib.sha256(data).hexdigest() != sha:
            raise ValueError('native folded header drift: '+name)
        headers[name] = data.decode()
    p4d = headers['include/asm-generic/pgtable-nop4d.h']
    pud = headers['include/asm-generic/pgtable-nopud.h']
    arm = headers['arch/arm64/include/asm/pgtable.h']
    return '''#include <stdio.h>
typedef struct { unsigned long pgd; } pgd_t;
#define pgd_val(x) ((x).pgd)
''' + '\n'.join((
        exact(p4d,r'^(typedef struct \{ pgd_t pgd; \} p4d_t;)$'),
        exact(pud,r'^(typedef struct \{ p4d_t p4d; \} pud_t;)$'),
        exact(p4d,r'^(static inline int pgd_none\(pgd_t pgd\).*?\{ return 0; \})$'),
        exact(p4d,r'^(#define p4d_val\(x\).*?)$'),
        exact(pud,r'^(#define pud_val\(x\).*?)$'),
        exact(arm,r'^(#define pud_none\(pud\).*?)$'),
    )) + '\n_Static_assert(sizeof(pgd_t)==8 && sizeof(pud_t)==8,"folded alias size");\n'


def compile_branch(context, recipe):
    condition = exact(recipe,r'\t\tif \((.*?) && __pmd_alloc\(mm, \(pud_t \*\)pgd, address\)\)')
    code = context + '''
struct mm_struct { int calls, fail; };
static int __pmd_alloc(struct mm_struct *mm,pud_t *pud,unsigned long address) {
 (void)address; mm->calls++; if(mm->fail)return -12;
 ((pgd_t *)pud)->pgd=0x1000003; return 0;
}
static int branch(struct mm_struct *mm,pgd_t *pgd) {
 unsigned long address=0x40200000;
 if (''' + condition + ''' && __pmd_alloc(mm,(pud_t *)pgd,address))return -12;
 return 0;
}
int main(void) {
 for(int present=0;present<2;present++)for(int fail=0;fail<2;fail++) {
  pgd_t entry={present?0x1000003UL:0}; struct mm_struct mm={0,fail};
  int actual=branch(&mm,&entry),expected=!present&&fail?-12:0;
  if(actual!=expected || mm.calls!=!present ||
     (!present&&!fail&&entry.pgd!=0x1000003UL)) {
   fprintf(stderr,"folded branch mismatch present=%d fail=%d calls=%d result=%d\\n",present,fail,mm.calls,actual);
   return 1;
  }
 }
 if(pgd_none((pgd_t){0})!=0 || !pud_none((pud_t){{{0}}}))return 2;
 return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='dma-native-folded-') as temporary:
        executable = Path(temporary)/'branch'
        subprocess.run(['clang','-x','c','-std=c11','-Wall','-Wextra','-Werror',
                        '-Wno-unused-parameter','-fno-strict-aliasing','-o',str(executable),'-'],
                       input=code,text=True,check=True,capture_output=True)
        return subprocess.run([str(executable)],capture_output=True,text=True)


def compile_walk(recipe, wrong_folded_level=False):
    data = (WALK_REFERENCE/'include/linux/pgtable.h').read_bytes()
    if hashlib.sha256(data).hexdigest() != 'bdfc3c9f86b18719f0bec51cfb5174918a81285da4eefefe9afd3880fac164fc':
        raise ValueError('native pgtable walk header drift')
    text = data.decode()
    macro = exact(text,r'^(#define pgd_addr_end\(addr, end\)[\s\S]*?\n\}\))$')
    expression = exact(recipe,r'\t\tunsigned long next = (.*?);')
    if wrong_folded_level:
        expression = expression.replace('pgd_addr_end','p4d_addr_end')
    p4d = (REFERENCE/'include/asm-generic/pgtable-nop4d.h').read_bytes()
    if hashlib.sha256(p4d).hexdigest() != PINS['include/asm-generic/pgtable-nop4d.h']:
        raise ValueError('native folded walk header drift')
    folded = exact(p4d.decode(),r'^(#define p4d_addr_end\(addr, end\).*?)$')
    code = '''#include <stdio.h>
#include <limits.h>
#define PGDIR_SIZE (1UL<<30) /* explicit pinned ARM64/4K/VA39 profile */
#define PGDIR_MASK (~(PGDIR_SIZE-1))
''' + macro + '\n' + folded + '''
int main(void) {
 const unsigned long starts[]={0, (1UL<<30)-(2UL<<20),
   (2UL<<30)-(4UL<<20), (511UL<<30)-(2UL<<20)};
 const unsigned long lengths[]={4UL<<20,4UL<<20,8UL<<20,4UL<<20};
 for(unsigned i=0;i<4;i++) {
  unsigned long address=starts[i],end=address+lengths[i],slots=0;
  while(address!=end) {
   unsigned long next=''' + expression + ''';
   unsigned long expected=end;
   if ((address>>30)!=(end-1)>>30) expected=((address>>30)+1)<<30;
   if(next!=expected || next<=address) {
    fprintf(stderr,"native root boundary mismatch case=%u\\n",i); return 1;
   }
   slots++;address=next;
  }
  if(slots!=(i?2UL:1UL))return 2;
 }
 unsigned long address=ULONG_MAX-(2UL<<20),end=ULONG_MAX-4095;
 if(pgd_addr_end(address,end)!=end)return 3; /* rounded boundary wraps */
 return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='dma-native-root-walk-') as temporary:
        executable = Path(temporary)/'walk'
        subprocess.run(['clang','-x','c','-std=gnu11','-Wall','-Wextra','-Werror',
                        '-fsanitize=address,undefined','-o',str(executable),'-'],
                       input=code,text=True,check=True,capture_output=True)
        return subprocess.run([str(executable)],capture_output=True,text=True)


class Folded(unittest.TestCase):
    def test_native_pgd_boundary_crossing_and_wrap(self):
        recipe = (ROOT/'tools/stock-recovery/dmabuf_huge_remap.recovered.c').read_text()
        result = compile_walk(recipe)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_wrong_folded_walk_macro_is_rejected(self):
        recipe = (ROOT/'tools/stock-recovery/dmabuf_huge_remap.recovered.c').read_text()
        result = compile_walk(recipe,wrong_folded_level=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('native root boundary mismatch',result.stderr)

    def test_real_native_predicates_allocate_missing_pmd(self):
        recipe = (ROOT/'tools/stock-recovery/dmabuf_huge_remap.recovered.c').read_text()
        result = compile_branch(native_context(),recipe)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_old_pgd_none_regression_is_rejected(self):
        recipe = (ROOT/'tools/stock-recovery/dmabuf_huge_remap.recovered.c').read_text()
        self.assertEqual(recipe.count('pud_none(*(pud_t *)pgd)'),1)
        result = compile_branch(native_context(),recipe.replace('pud_none(*(pud_t *)pgd)','pgd_none(*pgd)'))
        self.assertNotEqual(result.returncode,0)
        self.assertIn('folded branch mismatch',result.stderr)


if __name__ == '__main__':
    unittest.main()
