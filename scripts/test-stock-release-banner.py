#!/usr/bin/env python3
from importlib.machinery import SourceFileLoader
from pathlib import Path
import unittest

module = SourceFileLoader('stock_banner', str(Path(__file__).with_name('check-stock-release-banner.py'))).load_module()


class Banner(unittest.TestCase):
    def test_release_with_zero_and_n_not_truncated(self):
        expected = ('Linux version ' + module.STOCK_RELEASE + ' compiler version 0 clang\n').encode()
        self.assertEqual(module.banner(b'prefix\0' + expected + b'tail', module.STOCK_RELEASE), expected.rstrip(b'\n'))

    def test_nul_boundary(self):
        expected = ('Linux version ' + module.STOCK_RELEASE + ' compiler').encode()
        self.assertEqual(module.banner(expected + b'\0arbitrary tail', module.STOCK_RELEASE), expected)

    def test_wrong_suffix_missing_and_duplicate_fail(self):
        valid = ('Linux version ' + module.STOCK_RELEASE + ' compiler').encode()
        for data in (b'none', valid.replace(b'-4k ', b'-4k-maybe-dirty '), valid + b'\0' + valid + b'different',
                     valid + b'\0' + valid.replace(b'6.6.77', b'6.6.78')):
            with self.subTest(data=data[:90]), self.assertRaises(ValueError):
                module.banner(data, module.STOCK_RELEASE)

    def test_identical_stock_banner_aliases(self):
        valid = ('Linux version ' + module.STOCK_RELEASE + ' compiler').encode()
        self.assertEqual(module.banner(valid + b'\0' + valid, module.STOCK_RELEASE), valid)


if __name__ == '__main__':
    unittest.main()
