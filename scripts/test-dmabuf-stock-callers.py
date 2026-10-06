#!/usr/bin/env python3
"""Signed ARM64 branch decoding, text bounds and context; no stock execution."""
from importlib.machinery import SourceFileLoader
from pathlib import Path
import struct
import unittest

module=SourceFileLoader('dma_stock_callers',str(Path(__file__).with_name('extract-dmabuf-stock-callers.py'))).load_module()


class Callers(unittest.TestCase):
    def test_signed_forward_backward_and_nonbranches(self):
        for opcode,kind in ((0x94000000,'BL'),(0x14000000,'B')):
            for delta in (-0x8000000,-4,0,4,0x7fffffc):
                self.assertEqual(module.branch(opcode|((delta//4)&0x3ffffff),0x8000000),
                                 (kind,0x8000000+delta))
        for word in (0,0xd503201f,0xd63f0000,0x54000000):
            self.assertIsNone(module.branch(word,0x1000))

    def test_scan_exact_target_context_and_text_only(self):
        data=struct.pack('<4I',0x94000002,0x17ffffff,0xd503201f,0x94000000)
        rows=module.scan(data,0x1000,[(0x1000,0x100c)],
                         {0x1008:'helper',0x1000:'self'}, {0x1000:['caller','alias']})
        self.assertEqual([(r['target'],r['instruction'],r['nearest_symbol_offset']) for r in rows],
                         [('helper','BL',0),('self','B',4)])
        self.assertEqual(rows[0]['nearest_text_symbols'],['caller','alias'])
        self.assertEqual(len(rows),2) # Last word outside text excluded.

    def test_invalid_bounds_and_overlap_rejected(self):
        for intervals in ([(0x1001,0x1008)],[(0xffc,0x1008)],[(0x1000,0x1014)],
                          [(0x1008,0x1008)],[(0x1000,0x100c),(0x1008,0x1010)]):
            with self.subTest(intervals=intervals),self.assertRaises(ValueError):
                module.scan(bytes(16),0x1000,intervals,{}, {})


if __name__=='__main__':unittest.main()
