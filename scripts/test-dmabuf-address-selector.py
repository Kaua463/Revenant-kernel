#!/usr/bin/env python3
"""BTF/registration drift tests; synthetic data, not stock execution."""
import copy
from importlib.machinery import SourceFileLoader
from pathlib import Path
import struct
import unittest

module = SourceFileLoader('dma_selector', str(Path(__file__).with_name('extract-dmabuf-address-selector.py'))).load_module()


class Registration(unittest.TestCase):
    def layout(self):
        return {'size_bytes': 264, 'members': [
            {'name': name, 'offset_bits': offset, 'type': signature, 'bitfield_bits': 0}
            for name, (offset, signature, _) in module.FIELDS.items()]}

    def test_consistent_multiple_btf_records(self):
        layout = self.layout()
        self.assertEqual(module.field_offsets([layout, copy.deepcopy(layout)]),
                         {'mmap': 88, 'release': 120, 'get_unmapped_area': 152})

    def test_layout_drift_fails_closed(self):
        with self.assertRaises(ValueError):
            module.field_offsets([])
        for key, value in (('offset_bits', 1224), ('type', '*fn()->1:unsigned long'),
                           ('bitfield_bits', 1), ('name', 'unknown')):
            layout = self.layout()
            layout['members'][-1][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                module.field_offsets([self.layout(), layout])
        layout = self.layout()
        layout['members'].append(copy.deepcopy(layout['members'][-1]))
        with self.assertRaises(ValueError):
            module.field_offsets([layout])
        layout = self.layout()
        layout['size_bytes'] = 272
        with self.assertRaises(ValueError):
            module.field_offsets([layout])

    def test_exact_pointer_and_file_backed_bounds(self):
        data = bytearray(264)
        struct.pack_into('<Q', data, 152, 0x12345678)
        self.assertEqual(module.pointer_at(data, 0x1000, 0x1000, 152, 0x12345678),
                         {'field_address': '0x1098', 'pointer': '0x12345678', 'offset_bytes': 152})
        for table, offset, expected in ((0x1000, 152, 0), (0x0fff, 0, 0),
                                         (0x1000, 257, 0), (0x2000, 152, 0)):
            with self.subTest(table=table, offset=offset), self.assertRaises(ValueError):
                module.pointer_at(data, 0x1000, table, offset, expected)


if __name__ == '__main__':
    unittest.main()
