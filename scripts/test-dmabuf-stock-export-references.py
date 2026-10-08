#!/usr/bin/env python3
from importlib.machinery import SourceFileLoader
from pathlib import Path
import struct
import unittest

m = SourceFileLoader('export_relative_test', str(Path(__file__).with_name('audit-dmabuf-stock-export-references.py'))).load_module()


class Relative(unittest.TestCase):
    def test_signed_sites_and_unaligned_false_positive(self):
        self.assertEqual(m.relative_sites(struct.pack('<ii', 0x100, 0xfc), 0x1000, 0x1100), [0x1000, 0x1004])
        self.assertEqual(m.relative_sites(struct.pack('<ii', -0x100, -0x104), 0x1100, 0x1000), [0x1100, 0x1104])
        self.assertEqual(m.relative_sites(b'x' + struct.pack('<i', 0xff), 0x1000, 0x1100), [])
        self.assertEqual(m.relative_sites(bytes(3), 0x1000, 0x1100), [])

    def test_fde_reference_is_not_a_callback(self):
        cie_body = bytes(4) + b'\x01zR\0\x01\x7c\x1e\x01\x1b\x0c\x1f\0'
        cie = struct.pack('<I', len(cie_body)) + cie_body
        site = 0x2000 + len(cie) + 8
        fde_body = struct.pack('<IiI', len(cie) + 4, 0x1000-site, 0x100) + bytes(4)
        payload = cie + struct.pack('<I', len(fde_body)) + fde_body
        class Kernel:
            base = 0x2000
            data = payload
            def address(self, name):
                return self.base if name == '__eh_frame_start' else self.base + len(payload)
        result = m.frame_context(Kernel(), site, 0x1000)
        self.assertEqual(result['kind'], 'EH_FRAME_FDE_INITIAL_LOCATION_NOT_CALLER')
        self.assertEqual(result['address_range'], 0x100)
        for where, target in ((site+4, 0x1000), (site, 0x1004)):
            with self.assertRaises(ValueError):
                m.frame_context(Kernel(), where, target)


if __name__ == '__main__':
    unittest.main()
