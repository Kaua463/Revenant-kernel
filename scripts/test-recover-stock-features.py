import importlib.util
from pathlib import Path
import unittest
import re

spec = importlib.util.spec_from_file_location('recover', Path(__file__).with_name('recover-stock-features.py'))
recover = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recover)


class RecoveryTests(unittest.TestCase):
    def test_forward_bl(self):
        self.assertEqual(recover.bl_target(0x94000003, 0x1000), 0x100c)

    def test_backward_bl(self):
        self.assertEqual(recover.bl_target(0x97ffffff, 0x1000), 0xffc)

    def test_non_bl(self):
        for word in (0x14000003, 0xd65f03c0, 0xd63f0000, 0):
            self.assertIsNone(recover.bl_target(word, 0x1000))

    def test_wrong_boot_rejected(self):
        with self.assertRaisesRegex(ValueError, 'pinned'):
            recover.stock_payload(b'ANDROID!' + bytes(4096))

    def test_family_count(self):
        self.assertEqual(len(recover.FAMILIES), 7)

    def test_shared_named_helpers_not_dropped(self):
        for family, name in [('f2fs_fastdiscard', 'fastdiscard_enable_show'),
                             ('enhanced_iostat', 'iostat_daily_stats_reset'),
                             ('erofs_iostat', 'erofs_init_iostat')]:
            self.assertRegex(name, recover.FAMILIES[family][1])
        self.assertIsNone(re.search(recover.FAMILIES['enhanced_iostat'][1], 'erofs_init_iostat'))


if __name__ == '__main__':
    unittest.main()
