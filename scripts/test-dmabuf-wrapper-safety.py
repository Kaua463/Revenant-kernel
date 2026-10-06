#!/usr/bin/env python3
"""V35/V39: preserve stock recipe; test declared integration-only NULL guard."""
from importlib.machinery import SourceFileLoader
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
prepare = SourceFileLoader('dma_prepare_safety', str(HERE / 'prepare-dmabuf-reimplementation.py')).load_module()
wrappers = SourceFileLoader('dma_stock_wrappers', str(HERE / 'test-dmabuf-stock-wrappers.py')).load_module()
RECIPE = HERE.parent / 'tools/stock-recovery/dmabuf_huge_wrappers.recovered.c'


class Safety(unittest.TestCase):
    def test_null_lookup_guard_and_defined_stock_traces(self):
        stock = RECIPE.read_text()
        candidate = prepare.integration_wrappers(stock)
        fixture = wrappers.FIXTURE.replace('return &next;', 'return missing_next ? NULL : &next;')
        fixture = fixture.replace('static struct vm_area_struct vma, next;',
                                  'static struct vm_area_struct vma, next;\nstatic bool missing_next;')
        # Separate translation-unit names, identical helper recording.
        stock = stock.replace('vma_adjust_dmabuf_huge(', 'stock_adjust(').replace(
            'split_dmabuf_huge_pmd_address(', 'stock_address(').replace(
            'zap_split_dmabuf_huge_pmd(', 'stock_zap(').replace(
            'dmabuf_recovered_split_boundary(', 'stock_boundary(')
        main = r'''
int main(int argc, char **argv) {
 uint64_t saved[32][6]; unsigned count;
 (void)argv;
 vma=(struct vm_area_struct){0,8UL<<21,(void *)0x1234};
 next=(struct vm_area_struct){8UL<<21,16UL<<21,(void *)0x1234};
 if (argc>1) { missing_next=true; stock_adjust(&vma,0,8UL<<21,1); return 0; }
 for (unsigned mask=0; mask<8; mask++)
  for (long adj=-1; adj<=(4L<<21); adj+=(1L<<21)) {
   nr=0; find_calls=0; missing_mask=mask; missing_next=false;
   stock_adjust(&vma,1, (8UL<<21)-1,adj);
   count=nr; memcpy(saved,rows,sizeof(saved));
   nr=0; find_calls=0;
   vma_adjust_dmabuf_huge(&vma,1,(8UL<<21)-1,adj);
   assert(nr==count && !memcmp(saved,rows,nr*sizeof(rows[0])));
  }
 nr=0; find_calls=0; missing_mask=0; missing_next=true;
 vma_adjust_dmabuf_huge(&vma,0,8UL<<21,1);
 assert(nr==1 && rows[0][0]==3); /* lookup only, no NULL access/split */
 nr=0; vma_adjust_dmabuf_huge(NULL,1,2,0); assert(nr==0);
 return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='dma-wrapper-safety-') as temp:
            binary = Path(temp) / 'test'
            subprocess.run(['clang', '-x', 'c', '-std=c11', '-Wall', '-Wextra',
                            '-Werror', '-fsanitize=address,undefined',
                            '-fno-sanitize-recover=all', '-o', str(binary), '-'],
                           input=fixture+stock+candidate+main, text=True, check=True)
            # Reproduce original stock hazard in a disposable host process only.
            original = subprocess.run([str(binary), 'stock-null'], capture_output=True, text=True)
            self.assertNotEqual(original.returncode, 0)
            self.assertIn('null pointer', original.stderr)
            subprocess.run([str(binary)], check=True, capture_output=True, text=True)

    def test_adaptation_rejects_anchor_drift(self):
        with self.assertRaisesRegex(ValueError, 'anchor'):
            prepare.integration_wrappers(RECIPE.read_text().replace(
                'next_start = next->vm_start + adj_next;', 'next_start = 0;'))


if __name__ == '__main__':
    unittest.main()
