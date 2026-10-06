#!/usr/bin/env python3
"""Synthetic ARM64 ELF pattern checks; no firmware or module execution."""
from importlib.machinery import SourceFileLoader
from pathlib import Path
import subprocess
import tempfile
import unittest

module = SourceFileLoader('dma_module_activation', str(Path(__file__).with_name('scan-dmabuf-module-activation.py'))).load_module()


class ModulePattern(unittest.TestCase):
    def test_real_cross_assembled_elf_bounds_and_undefined_target(self):
        with tempfile.TemporaryDirectory(prefix='dma-module-pattern-') as temporary:
            source = Path(temporary) / 'input.s'
            output = Path(temporary) / 'input.o'
            source.write_text('.text\n.global candidate\n.type candidate,%function\ncandidate:\n'
                              'orr x0,x1,#0x8000000000\n'
                              'bl dmabuf_huge_remap_pfn_range\nret\n.size candidate,.-candidate\n'
                              '.section .bss\n.space 4096\n')
            subprocess.run(['clang', '--target=aarch64-linux-gnu', '-c', str(source), '-o', str(output)], check=True)
            original = output.read_bytes()
            result = module.scan(original)
            self.assertEqual(result['code_bytes'], 12)
            self.assertEqual(result['target_symbols'][0]['section'], 'SHN_UNDEF')
            self.assertEqual(result['orr_masks_containing_bit39'],
                             [{'section': '.text', 'offset': '0x0', 'elf_function_bounds': ['candidate'],
                               'mask': '0x8000000000', 'only_bit39': True}])
            self.assertEqual(result['literal_sections'], ['.strtab'])
            self.assertEqual(output.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
