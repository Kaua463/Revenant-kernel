#!/usr/bin/env python3
from importlib.machinery import SourceFileLoader
from pathlib import Path
import gzip
import struct
import unittest

m = SourceFileLoader('offline_boot', str(Path(__file__).with_name('audit-dmabuf-boot-offline.py'))).load_module()


class Geometry(unittest.TestCase):
    def test_config_only_dma_and_no_unrequested_kfence_changes(self):
        installed = b'CONFIG_KFENCE=y\nCONFIG_KFENCE_SAMPLE_INTERVAL=500\n'
        candidate = installed + b'CONFIG_XIAOMI_DMABUF_HUGETLB=y\n'
        self.assertEqual(m.config_difference(installed, candidate),
                         {'CONFIG_XIAOMI_DMABUF_HUGETLB': [None, 'y']})
        for changed in (installed, candidate.replace(b'INTERVAL=500', b'INTERVAL=100'),
                        candidate.replace(b'KFENCE=y', b'KFENCE=n')):
            with self.assertRaises(ValueError):
                m.config_difference(installed, changed)

    def test_embedded_config_unique_intact_and_ordered(self):
        config = b'CONFIG_FIXTURE=y\n'
        blob = b'prefixIKCFG_ST' + gzip.compress(config) + b'IKCFG_EDsuffix'
        self.assertEqual(m.embedded_config(blob), config)
        for changed in (blob + b'IKCFG_ST', blob + b'IKCFG_ED',
                        b'IKCFG_EDIKCFG_ST', b'no configuration'):
            with self.assertRaises(ValueError):
                m.embedded_config(changed)

    def boot(self):
        data = bytearray(m.PARTITION)
        data[:8] = b'ANDROID!'
        struct.pack_into('<4I', data, 8, 4096, 0, 0, 1584)
        struct.pack_into('<I', data, 40, 4)
        data[8192:8196] = b'AVB0'
        struct.pack_into('>4sIIQQQ', data, len(data) - 64, b'AVBf', 1, 0, 8192, 8192, 2432)
        return data

    def test_valid_bounded_header(self):
        self.assertEqual(m.boot_layout(self.boot())['payload_end'], 8192)

    def test_corrupt_header_and_avb_bounds_fail(self):
        for offset, value in [(8, m.PARTITION), (20, 1580), (24, 1), (40, 3)]:
            data = self.boot()
            struct.pack_into('<I', data, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                m.boot_layout(data)
        for original, start, size in [(4096, 8192, 2432), (8192, 4096, 2432),
                                       (8192, 8192, m.PARTITION), (8192, 8192, 255)]:
            data = self.boot()
            struct.pack_into('>QQQ', data, len(data) - 52, original, start, size)
            with self.subTest(start=start, size=size), self.assertRaises(ValueError):
                m.boot_layout(data)

    def test_truncation_rejected(self):
        with self.assertRaises(ValueError):
            m.boot_layout(self.boot()[:-1])

    def test_image_size_endian_geometry_and_magic(self):
        data = bytearray(4096)
        struct.pack_into('<3Q', data, 8, 0, 4096, 2)
        struct.pack_into('<I', data, 56, 0x644d5241)
        self.assertTrue(m.arm64_layout(data)['raw_payload_fits'])
        # Required RAM may exceed file bytes; it is not a truncation signal.
        struct.pack_into('<Q', data, 16, 8192)
        self.assertEqual(m.arm64_layout(data)['required_ram_bytes'], 8192)
        for offset, value in [(16, 0), (16, 63), (24, 3), (24, 4), (24, 16), (56, 0)]:
            changed = bytearray(data)
            struct.pack_into('<Q' if offset != 56 else '<I', changed, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(ValueError):
                m.arm64_layout(changed)


if __name__ == '__main__':
    unittest.main()
