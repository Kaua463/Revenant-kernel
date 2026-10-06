#!/usr/bin/env python3
"""Recovery scope must not silently analyze other requested feature families."""
import importlib.util
from pathlib import Path
import re
import unittest

spec=importlib.util.spec_from_file_location('prepare',Path(__file__).with_name('prepare-stock-decompiler.py'))
prepare=importlib.util.module_from_spec(spec);spec.loader.exec_module(prepare)


class ScopeTests(unittest.TestCase):
    def test_dma_scope_excludes_other_families(self):
        pattern=prepare.pattern_for_scope('dmabuf')
        for name in ('dmabuf_huge_remap_pfn_range','move_dmabuf_huge_pmd','__split_dmabuf_huge_range'):
            self.assertIsNotNone(re.search(pattern,name))
        for name in ('xring_lb_ioctl','erofs_iostat_update','f2fs_fastdiscard_store'):
            self.assertIsNone(re.search(pattern,name))

    def test_all_scope_preserves_previous_pattern(self):
        self.assertEqual(prepare.pattern_for_scope('all'),r'xring_lb|dmabuf_huge|iostat|fastdiscard')

    def test_unknown_scope_fails_closed(self):
        with self.assertRaises(ValueError):prepare.pattern_for_scope('unknown')


if __name__=='__main__':unittest.main()
