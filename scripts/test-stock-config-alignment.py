import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('gate', ROOT / 'scripts/check-stock-config-alignment.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
GOOD = 'CONFIG_PM_USERSPACE_AUTOSLEEP=y\n# CONFIG_USB_XHCI_SIDEBAND is not set\nCONFIG_LTO_NONE=y\n# CONFIG_LTO_CLANG_THIN is not set\n'


class AlignmentTests(unittest.TestCase):
    def test_fragment(self):
        gate.validate((ROOT / 'configs/rodin-6.6.77-ksun-susfs.fragment').read_text())

    def test_missing(self):
        for line in GOOD.splitlines():
            with self.subTest(line=line), self.assertRaises(ValueError):
                gate.validate(GOOD.replace(line + '\n', ''))

    def test_wrong_values(self):
        for key, value in gate.EXPECTED.items():
            old = f'{key}=y' if value == 'y' else f'# {key} is not set'
            new = f'# {key} is not set' if value == 'y' else f'{key}=y'
            with self.subTest(key=key), self.assertRaises(ValueError):
                gate.validate(GOOD.replace(old, new))

    def test_lto_and_duplicates(self):
        for extra in ('CONFIG_LTO=y\n', 'CONFIG_LTO_CLANG=y\n', 'CONFIG_LTO_CLANG_FULL=y\n', 'CONFIG_LTO_NONE=y\n'):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                gate.validate(GOOD + extra)

    def test_workflow(self):
        text = (ROOT / '.github/workflows/audit-rodin-6.6.77-ksun-susfs.yml').read_text()
        self.assertIn('tools/bazel build --lto=none --page_size=4k', text)
        self.assertIn('python3 scripts/check-stock-config-alignment.py dist/config', text)
        self.assertNotIn('LTO_MODE=thin', text)


if __name__ == '__main__':
    unittest.main()
