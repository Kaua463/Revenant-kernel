import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("gate", ROOT / "scripts/check-stock-kfence.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
GOOD = "CONFIG_KFENCE=y\nCONFIG_KFENCE_SAMPLE_INTERVAL=500\nCONFIG_KFENCE_NUM_OBJECTS=63\n# CONFIG_KFENCE_STATIC_KEYS is not set\n"


class StockKfenceTests(unittest.TestCase):
    def test_fragment(self):
        gate.validate((ROOT / "configs/rodin-6.6.77-ksun-susfs.fragment").read_text())

    def test_stock(self):
        gate.validate(GOOD)

    def test_bad_or_missing_values(self):
        for line in GOOD.splitlines():
            with self.subTest(line=line):
                with self.assertRaises(ValueError):
                    gate.validate(GOOD.replace(line + "\n", ""))
        with self.assertRaises(ValueError):
            gate.validate(GOOD.replace("# CONFIG_KFENCE_STATIC_KEYS is not set", "CONFIG_KFENCE_STATIC_KEYS=y"))

    def test_duplicate(self):
        with self.assertRaises(ValueError):
            gate.validate(GOOD + "CONFIG_KFENCE_STATIC_KEYS=y\n")

    def test_workflow_checks_output(self):
        workflow = (ROOT / ".github/workflows/audit-rodin-6.6.77-ksun-susfs.yml").read_text()
        self.assertIn("python3 scripts/check-stock-kfence.py dist/config", workflow)


if __name__ == "__main__":
    unittest.main()
