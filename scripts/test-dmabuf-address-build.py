#!/usr/bin/env python3
from importlib.machinery import SourceFileLoader
from pathlib import Path
import struct
import unittest

m = SourceFileLoader('address_build',str(Path(__file__).with_name('check-dmabuf-address-build.py'))).load_module()


class Build(unittest.TestCase):
    def test_pointer_and_provider(self):
        data = bytearray(264)
        struct.pack_into('<Q',data,152,0x1000)
        obj = {'size':264,'address':0x2000,'type':'STT_OBJECT'}
        fun = {'size':640,'address':0x1000,'type':'STT_FUNC'}
        self.assertEqual(m.registration(data,obj,fun)['offset_bytes'],152)
        for changes in ({'type':'STT_NOTYPE'},{'size':0},{'address':0},{'address':0x1004}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                m.registration(data,obj,dict(fun,**changes))
        for payload, size in ((data[:152],152),(data[:263],264)):
            with self.assertRaises(ValueError):
                m.registration(payload,dict(obj,size=size),fun)


if __name__ == '__main__':
    unittest.main()
