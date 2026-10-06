#!/usr/bin/env python3
"""Pinned ACK fetch allowlist: explicit MM build files, no path expansion."""
from importlib.machinery import SourceFileLoader
from pathlib import Path
import unittest

fetch=SourceFileLoader('fetch_ack',str(Path(__file__).with_name('fetch-stock-ack-source.py'))).load_module()


class Paths(unittest.TestCase):
    def test_named_mm_build_and_lifetime_inputs(self):
        for value in ('mm/Kconfig','mm/Makefile','kernel/fork.c','mm/memory.c','arch/arm64/include/asm/tlb.h'):
            self.assertEqual(fetch.validate_path(value),value)

    def test_no_broadening_to_other_build_files(self):
        for value in ('Makefile','Kconfig','mm/Kconfig.debug','arch/arm64/Makefile','mm/Makefile.bak','kernel/Makefile','kernel/sched/core.c'):
            with self.assertRaises(ValueError):fetch.validate_path(value)

    def test_no_normalization_or_escape(self):
        for value in ('/mm/Kconfig','mm/../mm/Kconfig','mm//Makefile','mm/./Makefile','mm/Makefile/','mm/../../secret.h'):
            with self.assertRaises(ValueError):fetch.validate_path(value)


if __name__=='__main__':unittest.main()
