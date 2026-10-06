#!/usr/bin/env python3
"""DMA overlay validation must reject drift/tampering before touching a tree."""
import argparse
import hashlib
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path
import shutil
import tempfile
import unittest

m=SourceFileLoader('validate_dma',str(Path(__file__).with_name('validate-dmabuf-overlay.py'))).load_module()
ARGS=None


class Validator(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='dma-validator-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.source=self.root/'source';self.overlay=self.root/'overlay'
        shutil.copytree(ARGS.source,self.source);shutil.copytree(ARGS.overlay,self.overlay)
        self.args=argparse.Namespace(source=self.source,overlay=self.overlay,apply_review=False)

    def report(self,edit):
        path=self.overlay/'manifest.json';r=json.loads(path.read_text());edit(r);path.write_text(json.dumps(r))

    def test_apply_and_repeat_rejected(self):
        m.run(self.args);self.args.apply_review=True;m.run(self.args)
        report=json.loads((self.overlay/'manifest.json').read_text())
        for name,record in report['changes'].items():self.assertEqual(hashlib.sha256((self.source/name).read_bytes()).hexdigest(),record['after'])
        with self.assertRaisesRegex(ValueError,'input drift'):m.run(self.args)

    def test_changed_patch_even_with_updated_checksum_rejected(self):
        patch=self.overlay/'dmabuf-review.patch'
        patch.write_text(patch.read_text().replace('VM_XIAOMI_DMABUF_HUGE (1UL << 39)','VM_XIAOMI_DMABUF_HUGE (1UL << 38)'))
        self.report(lambda r:r.update(patch_sha256=hashlib.sha256(patch.read_bytes()).hexdigest()))
        with self.assertRaisesRegex(ValueError,'pinned recipes'):m.run(self.args)
        self.assertFalse((self.source/'include/linux/xiaomi_dmabuf_huge.h').exists())

    def test_claimed_ready_or_extra_scope_rejected(self):
        self.report(lambda r:r.update(status='READY'))
        with self.assertRaisesRegex(ValueError,'contract'):m.run(self.args)

    def test_posthash_cannot_be_invented(self):
        self.report(lambda r:r['changes']['mm/mmap.c'].update(after='0'*64))
        with self.assertRaisesRegex(ValueError,'candidate hash'):m.run(self.args)

    def test_existing_header_rejected(self):
        path=self.source/'include/linux/xiaomi_dmabuf_huge.h';path.write_text('user-owned header\n')
        with self.assertRaisesRegex(ValueError,'already exists'):m.run(self.args)
        self.assertEqual(path.read_text(),'user-owned header\n')

    def test_hidden_safety_deviation_rejected(self):
        self.report(lambda r:r.update(safety_deviations=[]))
        with self.assertRaisesRegex(ValueError,'safety deviations'):m.run(self.args)
        self.assertFalse((self.source/'include/linux/xiaomi_dmabuf_huge.h').exists())


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','overlay'):p.add_argument('--'+name,type=Path,required=True)
    ARGS=p.parse_args();unittest.main(argv=[__file__])
