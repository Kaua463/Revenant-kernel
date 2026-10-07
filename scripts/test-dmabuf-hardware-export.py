#!/usr/bin/env python3
"""V8/V15/V27/V39: export evidence, not a flash approval or VM kernel."""
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path
import struct
import tempfile
import unittest

m = SourceFileLoader('hardware_export', str(Path(__file__).with_name('export-dmabuf-hardware-test.py'))).load_module()


class ExportGates(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.evidence = self.root / 'evidence'
        self.evidence.mkdir()
        self.image = self.root / 'Image'
        header = bytearray(65)
        struct.pack_into('<I', header, 56, 0x644D5241)
        self.image.write_bytes(header)
        (self.evidence / 'composition.json').write_text(json.dumps({
            'composed_tracked_manifest_sha256': m.COMPOSITION}))
        (self.evidence / 'config').write_text(''.join(k + '=y\n' for k in [
            'CONFIG_XIAOMI_DMABUF_HUGETLB', 'CONFIG_KSU', 'CONFIG_KSU_SUSFS', 'CONFIG_ARM64_4K_PAGES']))
        self.refresh_provider()
        for name in ['Module.symvers', 'address-registration.json', 'kernel-banner.txt', 'build-manifest.commit']:
            (self.evidence / name).write_text('fixture\n')
        self.proofs = {name: {'id': pin[0], 'head_sha': pin[1], 'status': 'completed',
                             'conclusion': 'success', 'path': '.github/workflows/' + pin[2]}
                       for name, pin in m.PROOFS.items()}

    def refresh_provider(self):
        (self.evidence / 'providers.json').write_text(json.dumps({
            'enabled': 'y', 'providers': {str(i): {} for i in range(14)},
            'config_sha256': m.digest(self.evidence / 'config')}))

    def test_export_relative_checksums_and_no_flash_approval(self):
        out = self.root / 'artifact'
        m.export(self.evidence, self.image, out, self.proofs, 'fixture')
        report = json.loads((out / 'hardware-test.json').read_text())
        self.assertEqual(report['status'], 'EXPERIMENTAL_CANDIDATE_NOT_CLEARED_FOR_FLASH')
        self.assertTrue(report['no_installer'])
        self.assertTrue(report['no_hardware_approval'])
        manifest = (out / 'SHA256SUMS').read_text()
        self.assertNotIn(str(self.root), manifest)
        self.assertNotIn('SHA256SUMS', manifest)
        self.assertEqual(m.digest(out / 'Image'), m.digest(self.image))
        with self.assertRaises(FileExistsError):
            m.export(self.evidence, self.image, out, self.proofs, 'fixture')

    def test_failed_wrong_or_unfinished_proofs_rejected(self):
        for pin in m.PROOFS.values():
            good = {'id': pin[0], 'head_sha': pin[1], 'status': 'completed',
                    'conclusion': 'success', 'path': '.github/workflows/' + pin[2]}
            for key, value in [('id', 0), ('head_sha', 'wrong'), ('status', 'in_progress'),
                               ('conclusion', 'failure'), ('path', 'wrong')]:
                with self.subTest(key=key, pin=pin[0]), self.assertRaises(ValueError):
                    m.validate_proof(dict(good, **{key: value}), pin)

    def test_vm_producer_rejected_even_when_evidence_matches(self):
        config = self.evidence / 'config'
        for value in ['y', 'm']:
            config.write_text(config.read_text() + 'CONFIG_XIAOMI_DMABUF_RUNTIME_AUDIT=' + value + '\n')
            self.refresh_provider()
            with self.assertRaisesRegex(ValueError, 'VM producer'):
                m.validate_evidence(self.evidence, self.image)

    def test_modified_config_rejected(self):
        config = self.evidence / 'config'
        config.write_text(config.read_text() + 'CONFIG_EXTRA=y\n')
        with self.assertRaisesRegex(ValueError, 'config/evidence'):
            m.validate_evidence(self.evidence, self.image)

    def test_composition_drift_rejected(self):
        (self.evidence / 'composition.json').write_text(json.dumps({'composed_tracked_manifest_sha256': 'wrong'}))
        with self.assertRaisesRegex(ValueError, 'composition'):
            m.validate_evidence(self.evidence, self.image)

    def test_disabled_dma_rejected(self):
        config = self.evidence / 'config'
        config.write_text(config.read_text().replace('CONFIG_XIAOMI_DMABUF_HUGETLB=y', 'CONFIG_XIAOMI_DMABUF_HUGETLB=n'))
        self.refresh_provider()
        with self.assertRaisesRegex(ValueError, 'required hardware config'):
            m.validate_evidence(self.evidence, self.image)

    def test_not_arm64_and_oversize_rejected(self):
        self.image.write_bytes(b'not a kernel')
        with self.assertRaisesRegex(ValueError, 'ARM64'):
            m.validate_evidence(self.evidence, self.image)
        header = bytearray(64)
        struct.pack_into('<I', header, 56, 0x644D5241)
        with self.image.open('wb') as stream:
            stream.write(header)
            stream.truncate(64 * 1024 * 1024)
        with self.assertRaisesRegex(ValueError, 'limit'):
            m.validate_evidence(self.evidence, self.image)


if __name__ == '__main__':
    unittest.main()
