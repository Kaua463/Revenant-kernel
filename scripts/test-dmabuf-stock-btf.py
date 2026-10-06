#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import unittest

s=importlib.util.spec_from_file_location('wrappers',Path(__file__).with_name('test-dmabuf-stock-wrappers.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m)


class BTF:
    def __init__(self):
        self.types=[{'kind':0},
            {'kind':4,'flag':0,'raw':[0,2,0,3,4,128]},
            {'kind':5,'flag':0,'raw':[0,3,0]},
            {'kind':4,'flag':0,'raw':[1,4,0,2,4,64]},
            {'kind':1}]
    def string(self,offset):return ('','vm_start','vm_end','vm_mm')[offset]


class Layout(unittest.TestCase):
    def test_anonymous_nested_vma(self):
        self.assertEqual(m.btf_fields(BTF(),1),{'vm_start':0,'vm_end':8,'vm_mm':16})
    def test_anonymous_parent_offset(self):
        b=BTF();b.types[1]['raw'][2]=64
        self.assertEqual(m.btf_fields(b,1)['vm_start'],8)
    def test_conflicting_member_rejected(self):
        b=BTF();b.types[1]['raw'] += [1,4,192]
        with self.assertRaises(ValueError):m.btf_fields(b,1)


if __name__=='__main__':unittest.main()
