#!/usr/bin/env python3
"""Audit site generation/preservation tests; no kernel or VM execution."""
from importlib.machinery import SourceFileLoader
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
module = SourceFileLoader('dma_fault_sites', str(ROOT / 'scripts/prepare-dmabuf-fault-sites.py')).load_module()
SOURCE = ROOT.parent.parent / 'outputs/stock-dmabuf-overlay-20261005-v4/candidate/mm/huge_memory.c'


class Sites(unittest.TestCase):
    def setUp(self):
        self.data = SOURCE.read_bytes()

    def test_two_sites_and_outside_function_preserved(self):
        before = self.data.decode()
        after = module.transform(self.data).decode()
        start = before.index(module.FUNCTION_START)
        end = before.index(module.FUNCTION_END, start)
        self.assertTrue(after.startswith(before[:start] + module.DECLARATION))
        self.assertTrue(after.endswith(before[end:]))
        body = after[start + len(module.DECLARATION):after.index(module.FUNCTION_END, start)]
        # Removing the exact audit substitutions must restore the source byte-for-byte.
        for original, replacement in module.SITES:
            self.assertEqual(body.count(replacement), 1)
            body = body.replace(replacement, original)
        self.assertEqual(body, before[start:end])
        self.assertEqual(after.count('if (recovered_dma_audit_fail_alloc(mm, map_type))'), 2)
        self.assertNotIn('EXPORT_SYMBOL', module.DECLARATION)

    def test_drift_and_repeat_fail_closed(self):
        for data in (self.data + b'\n', self.data.replace(b'pte_alloc_one(mm)', b'pte_alloc_one(NULL)', 1),
                     module.transform(self.data)):
            with self.assertRaises(ValueError):
                module.transform(data)

    def test_generation_input_unchanged_and_evidence_preserved(self):
        with tempfile.TemporaryDirectory(prefix='dma-fault-sites-test-') as temporary:
            folder = Path(temporary)
            source = folder / 'huge_memory.c'
            source.write_bytes(self.data)
            args = SimpleNamespace(source=source, output=folder / 'evidence')
            module.run(args)
            result = (args.output / 'huge_memory.c').read_bytes()
            self.assertEqual(source.read_bytes(), self.data)
            self.assertEqual(result, module.transform(self.data))
            with self.assertRaises(ValueError):
                module.run(args)
            self.assertEqual((args.output / 'huge_memory.c').read_bytes(), result)

    def test_symlink_input_and_output_rejected(self):
        with tempfile.TemporaryDirectory(prefix='dma-fault-sites-test-') as temporary:
            folder = Path(temporary)
            link = folder / 'source'
            link.symlink_to(SOURCE)
            with self.assertRaises(ValueError):
                module.run(SimpleNamespace(source=link, output=folder / 'evidence'))
            output = folder / 'evidence'
            output.symlink_to(folder / 'missing')
            with self.assertRaises(ValueError):
                module.run(SimpleNamespace(source=SOURCE, output=output))


if __name__ == '__main__':
    unittest.main()
