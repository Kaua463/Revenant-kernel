#!/usr/bin/env python3
import gzip
import importlib.util
from pathlib import Path
import struct
import unittest

s=importlib.util.spec_from_file_location('evidence',Path(__file__).with_name('stock-binary-evidence.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m)


def btf(types=b'',strings=b'\0'):
    return struct.pack('<HBBIIIII',0xeb9f,1,0,24,0,len(types),len(types),len(strings))+types+strings


class Evidence(unittest.TestCase):
    def test_config_values_and_disabled(self):
        text=b'CONFIG_FOO=y\nCONFIG_BAR=123\n# CONFIG_BAZ is not set\n'
        image=b'prefixIKCFG_ST'+gzip.compress(text)+b'IKCFG_EDsuffix'
        self.assertEqual(m.config(image),{'CONFIG_FOO':'y','CONFIG_BAR':'123','CONFIG_BAZ':'n'})
    def test_empty_btf(self):self.assertEqual(m.BTF(btf()).ref(0),'0:void')
    def test_int_btf(self):
        integer=struct.pack('<IIII',1,1<<24,4,32)
        data=m.BTF(btf(integer,b'\0unsigned int\0'))
        self.assertEqual(data.ref(1),'1:unsigned int')
    def test_unsupported_kind(self):
        with self.assertRaises(ValueError):m.BTF(btf(struct.pack('<III',0,31<<24,0)))
    def test_truncated_extent(self):
        raw=btf(struct.pack('<IIII',1,1<<24,4,32),b'\0uint\0')
        with self.assertRaises(ValueError):m.BTF(raw[:-1])
    def test_invalid_string_offset(self):
        with self.assertRaises(ValueError):m.BTF(btf(struct.pack('<IIII',999,1<<24,4,32)))


if __name__=='__main__':unittest.main()
