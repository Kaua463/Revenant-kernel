import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('validator', Path(__file__).with_name('validate-stock-decompiler.py'))
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


class DecompilerValidation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='stock-validator-')
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.selected = self.folder / 'selected.json'
        self.selected.write_text(json.dumps(['sample']))
        self.log = self.folder / 'headless.log'
        self.log.write_text('Import succeeded\n')
        self.status = self.folder / 'status.tsv'
        self.status.write_text('symbol\tentry\tstatus\tbody_bytes\terror\n'
                               'sample\t1000\tdecompiled_unverified\t16\t\n')
        self.pseudo = self.folder / 'sample.pseudo.c'
        self.pseudo.write_text('void sample(void) {}\n')

    def verify(self):
        return validator.validate(self.selected, self.folder, self.log)

    def test_V36_inventory_pass_not_semantic_claim(self):
        self.assertEqual(self.verify(), 1)

    def test_V36_zero_exit_script_error_rejected(self):
        self.log.write_text('ERROR REPORT SCRIPT ERROR: unsupported prototype\n')
        with self.assertRaisesRegex(ValueError, 'script/pcode'):
            self.verify()

    def test_V36_pcode_warning_rejected(self):
        self.log.write_text('WARN pcode error at 1004\n')
        with self.assertRaisesRegex(ValueError, 'script/pcode'):
            self.verify()

    def test_V36_missing_selected_symbol_rejected(self):
        self.selected.write_text(json.dumps(['sample', 'missing']))
        with self.assertRaisesRegex(ValueError, 'inventory mismatch'):
            self.verify()

    def test_V36_duplicate_symbol_rejected(self):
        with self.status.open('a') as stream:
            stream.write('sample\t1000\tdecompiled_unverified\t16\t\n')
        with self.assertRaisesRegex(ValueError, 'inventory mismatch'):
            self.verify()

    def test_V36_bad_flow_rejected(self):
        self.pseudo.write_text('void sample(void) { halt_baddata(); }\n')
        with self.assertRaisesRegex(ValueError, 'bad-flow'):
            self.verify()

    def test_V36_gapped_status_rejected(self):
        self.status.write_text(self.status.read_text().replace('decompiled_unverified', 'decompiled_with_gaps'))
        with self.assertRaisesRegex(ValueError, 'gapped'):
            self.verify()


if __name__ == '__main__':
    unittest.main()
