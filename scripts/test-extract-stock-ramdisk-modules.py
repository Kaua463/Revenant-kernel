#!/usr/bin/env python3
import hashlib
import importlib.util
import io
from pathlib import Path
import stat
import tempfile
import unittest

s=importlib.util.spec_from_file_location('extract',Path(__file__).with_name('extract-stock-ramdisk-modules.py'))
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)


def entry(name,data=b'',mode=stat.S_IFREG|0o644,nlink=1,crc=False):
    raw=name.encode()+b'\0'
    fields=[1,mode,0,0,nlink,0,len(data),0,0,0,0,len(raw),sum(data) if crc else 0]
    header=(b'070702' if crc else b'070701')+''.join(f'{x:08x}' for x in fields).encode()
    return header+raw+bytes((-110-len(raw))%4)+data+bytes((-len(data))%4)


class Extraction(unittest.TestCase):
    def run_archive(self,data):
        with tempfile.TemporaryDirectory() as temporary:
            output=Path(temporary)/'new'
            report=m.extract(io.BytesIO(data+entry('TRAILER!!!')+bytes(512)),output)
            self.assertEqual(list(output.rglob('*.ko')),[output/'lib/modules/a.ko'])
            self.assertEqual((output/'lib/modules/a.ko').read_bytes(),b'ELFfixture')
            return report

    def test_regular_only_and_crc(self):
        report=self.run_archive(entry('lib/modules/a.ko',b'ELFfixture',crc=True)+entry('not-in-scope',b'skipped'))
        self.assertEqual(report['selected_count'],1)
        self.assertEqual(report['modules'][0]['sha256'],hashlib.sha256(b'ELFfixture').hexdigest())

    def rejects(self,data):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):m.extract(io.BytesIO(data+entry('TRAILER!!!')),Path(temporary)/'new')

    def test_traversal(self):self.rejects(entry('../a.ko'))
    def test_absolute(self):self.rejects(entry('/lib/modules/a.ko'))
    def test_symlink(self):self.rejects(entry('lib/modules/a.ko',b'elsewhere',mode=stat.S_IFLNK|0o777))
    def test_hardlink(self):self.rejects(entry('lib/modules/a.ko',nlink=2))
    def test_duplicate(self):self.rejects(entry('lib/modules/a.ko')*2)
    def test_truncation(self):self.rejects(entry('lib/modules/a.ko',b'data')[:-10])
    def test_existing_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):m.extract(io.BytesIO(b''),Path(temporary))


if __name__=='__main__':unittest.main()
