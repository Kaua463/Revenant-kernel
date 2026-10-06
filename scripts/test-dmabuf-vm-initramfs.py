#!/usr/bin/env python3
"""Independent newc decoding and negative input tests; not guest boot."""
import argparse
from importlib.machinery import SourceFileLoader
from pathlib import Path
import stat
import struct
import tempfile
import unittest

module = SourceFileLoader('dma_initramfs', str(Path(__file__).with_name('build-dmabuf-vm-initramfs.py'))).load_module()


def fixture(program_type=1):
    data = bytearray(120)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<HH', data, 16, 2, 183)
    struct.pack_into('<Q', data, 32, 64)
    struct.pack_into('<HH', data, 54, 56, 1)
    struct.pack_into('<I', data, 64, program_type)
    return bytes(data)


def decode(data):
    offset, entries = 0, {}
    while True:
        if data[offset:offset + 6] != b'070701':
            raise ValueError('bad newc')
        values = [int(data[offset + 6 + n * 8:offset + 14 + n * 8], 16) for n in range(13)]
        offset += 110
        name = data[offset:offset + values[11]]
        if not name.endswith(b'\0'):
            raise ValueError('missing terminator')
        offset = (offset + values[11] + 3) // 4 * 4
        payload = data[offset:offset + values[6]]
        offset = (offset + values[6] + 3) // 4 * 4
        if name == b'TRAILER!!!\0':
            if any(data[offset:]):
                raise ValueError('nonzero trailing data')
            break
        entries[name[:-1].decode('ascii')] = (values, payload)
    return entries


class Initramfs(unittest.TestCase):
    def test_archive_contents_and_determinism(self):
        init, guest = fixture(), fixture() + b'guest payload'
        archive = module.build(init, guest)
        self.assertEqual(archive, module.build(init, guest))
        self.assertEqual(len(archive) % 512, 0)
        entries = decode(archive)
        self.assertEqual(set(entries), {'dev', 'proc', 'sys', 'tmp', 'dev/console', 'init', 'guest'})
        self.assertEqual(entries['init'][1], init)
        self.assertEqual(entries['guest'][1], guest)
        self.assertEqual(stat.S_IFMT(entries['dev/console'][0][1]), stat.S_IFCHR)
        self.assertEqual(entries['dev/console'][0][9:11], [5, 1])
        for values, _ in entries.values():
            self.assertEqual(values[2:4], [0, 0])
            self.assertEqual(values[5], 0)

    def test_wrong_elfs(self):
        for data in (b'bad', fixture()[:64], fixture(3), fixture()[:119]):
            with self.subTest(length=len(data)), self.assertRaises(ValueError):
                module.static_arm64(data)
        for offset, value in ((4, 1), (5, 2), (18, 62)):
            data = bytearray(fixture())
            data[offset] = value
            with self.assertRaises(ValueError):
                module.static_arm64(bytes(data))

    def test_existing_output_preserved(self):
        with tempfile.TemporaryDirectory(prefix='dma-initramfs-test-') as directory:
            folder = Path(directory)
            output = folder / 'owned'
            output.write_bytes(b'owned')
            args = argparse.Namespace(output=output, init=folder/'missing', guest=folder/'missing')
            with self.assertRaises(ValueError):
                module.run(args)
            self.assertEqual(output.read_bytes(), b'owned')

    def test_symlink_output_preserved(self):
        with tempfile.TemporaryDirectory(prefix='dma-initramfs-test-') as directory:
            output = Path(directory) / 'link'
            output.symlink_to(Path(directory) / 'missing')
            with self.assertRaises(ValueError):
                module.run(argparse.Namespace(output=output, init=output, guest=output))
            self.assertTrue(output.is_symlink())


if __name__ == '__main__':
    unittest.main()
