#!/usr/bin/env python3
"""Synthetic ARM64 ELF: exact function bounds, branch addends, callback objects."""
from importlib.machinery import SourceFileLoader
from pathlib import Path
import subprocess
import tempfile
import unittest

module = SourceFileLoader('dma_exporter_routes', str(Path(__file__).with_name(
    'extract-dmabuf-exporter-routing.py'))).load_module()
ASSEMBLY = '''.text
.global heap_mmap
.type heap_mmap,%function
heap_mmap:
 bl remap_pfn_range
 ret
.size heap_mmap,.-heap_mmap
.global caller
.type caller,%function
caller:
 b dma_buf_mmap
.size caller,.-caller
.data
.global ops
.type ops,%object
ops:
 .quad 0
 .quad heap_mmap
.size ops,.-ops
.bss
.space 4096
'''


class Routing(unittest.TestCase):
    def test_branch_and_callback_registration(self):
        with tempfile.TemporaryDirectory(prefix='dma-exporter-elf-') as temporary:
            source, output = Path(temporary)/'test.s', Path(temporary)/'test.o'
            source.write_text(ASSEMBLY)
            subprocess.run(['clang', '--target=aarch64-linux-gnu', '-c', str(source),
                            '-o', str(output)], check=True)
            data = output.read_bytes()
            result = module.inspect(data)
            self.assertEqual([(r['caller'],r['target'],r['kind']) for r in result['branch_routes']],
                             [('heap_mmap','remap_pfn_range','CALL26'),('caller','dma_buf_mmap','JUMP26')])
            registrations = result['data_callback_registrations']
            self.assertEqual(registrations[0]['callbacks'], ['heap_mmap'])
            self.assertEqual(registrations[0]['containers'], [{'name':'ops','field_offset':8,'size':16}])
            self.assertEqual(result['special_mapper_symbols'], [])
            self.assertEqual(output.read_bytes(), data)


if __name__=='__main__':
    unittest.main()
