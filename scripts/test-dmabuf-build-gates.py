#!/usr/bin/env python3
"""Negative provider/config and duplicate-artifact gates for the DMA build audit."""
from importlib.machinery import SourceFileLoader
from pathlib import Path
import tempfile
import unittest

m=SourceFileLoader('check_dma',str(Path(__file__).with_name('check-dmabuf-build.py'))).load_module()


class Gates(unittest.TestCase):
    def setUp(self):
        self.cfg={'CONFIG_ARM64_4K_PAGES':'y','CONFIG_ARM64_VA_BITS_39':'y','CONFIG_PGTABLE_LEVELS':'3',
                  'CONFIG_TRANSPARENT_HUGEPAGE':'y','CONFIG_HAVE_ARCH_HUGE_VMAP':'y','CONFIG_SMP':'y',
                  'CONFIG_XIAOMI_DMABUF_HUGETLB':'y','CONFIG_NR_CPUS':'32','CONFIG_SPLIT_PTLOCK_CPUS':'4'}
        self.table={n:[{'type':'STT_FUNC' if n in m.FUNCTIONS else 'STT_OBJECT','address':0x1000,'size':8}] for n in m.FUNCTIONS+m.COUNTERS}

    def test_enabled_and_disabled(self):
        self.assertEqual(len(m.validate(self.cfg,self.table,'y')),14)
        self.cfg['CONFIG_XIAOMI_DMABUF_HUGETLB']='n'
        self.assertEqual(m.validate(self.cfg,{},'n'),{})
        with self.assertRaisesRegex(ValueError,'disabled'):m.validate(self.cfg,self.table,'n')

    def test_missing_duplicate_and_zero_size(self):
        for value in ([],self.table[m.FUNCTIONS[0]]*2,[{'type':'STT_FUNC','address':0,'size':8}],[{'type':'STT_FUNC','address':0x1000,'size':0}]):
            table=dict(self.table);table[m.FUNCTIONS[0]]=value
            with self.assertRaises(ValueError):m.validate(self.cfg,table,'y')

    def test_geometry_and_locks(self):
        for name,value in (('CONFIG_ARM64_4K_PAGES','n'),('CONFIG_ARM64_VA_BITS_39','n'),('CONFIG_PGTABLE_LEVELS','4'),('CONFIG_NR_CPUS','2')):
            cfg=dict(self.cfg);cfg[name]=value
            with self.assertRaises(ValueError):m.validate(cfg,self.table,'y')

    def test_counter_and_function_types(self):
        for name,value in ((m.COUNTERS[0],{'type':'STT_OBJECT','address':0x1000,'size':4}),(m.FUNCTIONS[0],{'type':'STT_NOTYPE','address':0x1000,'size':8})):
            table=dict(self.table);table[name]=[value]
            with self.assertRaises(ValueError):m.validate(self.cfg,table,'y')

    def test_artifact_aliases_require_equal_bytes(self):
        with tempfile.TemporaryDirectory(prefix='dma-inputs-') as temp:
            a=Path(temp)/'a';b=Path(temp)/'b';a.write_bytes(b'elf');b.write_bytes(b'elf')
            self.assertEqual(m.select_equal([a,b]),a)
            b.write_bytes(b'different')
            with self.assertRaises(ValueError):m.select_equal([a,b])
            with self.assertRaises(ValueError):m.select_equal([])


if __name__=='__main__':unittest.main()
