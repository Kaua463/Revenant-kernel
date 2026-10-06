#!/usr/bin/env python3
"""Guarded core-only patch scope, anchor and clean round-trip tests."""
import hashlib
from importlib.machinery import SourceFileLoader
from pathlib import Path
import tempfile
import difflib
import subprocess
import unittest

module = SourceFileLoader('dma_address_overlay', str(Path(__file__).with_name('prepare-dmabuf-address-overlay.py'))).load_module()


class Overlay(unittest.TestCase):
    def test_map_fixed_header_is_explicit_and_guarded(self):
        result = module.candidate(module.FOPS+'};\n','static void recipe(void) {}\n')
        self.assertIn('#ifdef '+module.GUARD+'\n#include <linux/mman.h>\n',result)
        self.assertEqual(result.count('#include <linux/mman.h>'),1)

    def test_recipe_pin_and_disabled_scope(self):
        recipe = (Path(__file__).parents[1]/'tools/stock-recovery/dmabuf_huge_address.recovered.c').read_text()
        self.assertEqual(hashlib.sha256(recipe.encode()).hexdigest(), module.RECIPE_SHA)
        core = '#include <linux/mm.h>\n'+module.FOPS+'\t.mmap = dma_buf_mmap_internal,\n};\n'
        result = module.candidate(core,recipe)
        disabled, depth = [], 0
        for line in result.splitlines(keepends=True):
            if line == '#ifdef '+module.GUARD+'\n':
                depth += 1
            elif line == '#endif\n':
                depth -= 1
            elif not depth:
                disabled.append(line)
        self.assertEqual(''.join(disabled).replace('\n\n'+module.FOPS,'\n'+module.FOPS), core)
        self.assertEqual(result.count('.get_unmapped_area ='),1)
        self.assertNotIn('EXPORT_SYMBOL',result)

    def test_anchor_and_double_apply_rejected(self):
        for core in ('',module.FOPS*2,module.FOPS+'dma_buf_hugetlb_get_unmapped_area'):
            with self.assertRaises(ValueError):
                module.candidate(core,'recipe')
        with self.assertRaises(ValueError):
            module.candidate(module.candidate(module.FOPS+'};\n','recipe'),'recipe')

    def test_patch_applies_and_reverses_only_core(self):
        core = module.FOPS+'\t.mmap = dma_buf_mmap_internal,\n};\n'
        recipe = 'static void recovered(void) {}\n'
        result = module.candidate(core,recipe)
        patch = ''.join(difflib.unified_diff(core.splitlines(keepends=True),result.splitlines(keepends=True),
                                          fromfile='a/'+module.PATH,tofile='b/'+module.PATH))
        with tempfile.TemporaryDirectory(prefix='dma-address-overlay-test-') as temporary:
            root = Path(temporary)
            subprocess.run(['git','init','-q'],cwd=root,check=True)
            target = root/module.PATH
            target.parent.mkdir(parents=True)
            target.write_text(core)
            stats = subprocess.run(['git','apply','--numstat','-'],cwd=root,input=patch,text=True,
                                   check=True,capture_output=True).stdout
            self.assertEqual({row.split('\t')[2] for row in stats.splitlines()},{module.PATH})
            subprocess.run(['git','apply','-'],cwd=root,input=patch,text=True,check=True)
            self.assertEqual(target.read_text(),result)
            subprocess.run(['git','apply','--reverse','-'],cwd=root,input=patch,text=True,check=True)
            self.assertEqual(target.read_text(),core)


if __name__ == '__main__':
    unittest.main()
