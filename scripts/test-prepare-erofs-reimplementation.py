#!/usr/bin/env python3
"""Reference integrity and exact patch round-trip, NOT kernel compilation."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest


def load(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name))
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result


class Anchors(unittest.TestCase):
    def test_unique_anchor(self):
        self.assertEqual(load('prepare-erofs-reimplementation.py').once('one two','one','new'),'new two')

    def test_missing_anchor(self):
        with self.assertRaises(ValueError):load('prepare-erofs-reimplementation.py').once('one','two','new')

    def test_duplicate_anchor(self):
        with self.assertRaises(ValueError):load('prepare-erofs-reimplementation.py').once('one one','one','new')


def run(reference):
    prep=load('prepare-erofs-reimplementation.py')
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(Anchors)
    if not unittest.TextTestRunner().run(suite).wasSuccessful():raise SystemExit(1)
    with tempfile.TemporaryDirectory(prefix='erofs-overlay-') as directory:
        folder=Path(directory);base=folder/'reference';shutil.copytree(reference,base)
        output=folder/'generated';prep.run(SimpleNamespace(reference=base,output=output))
        report=json.loads((output/'review.json').read_text())
        assert report['status']=='BLOCKED_NOT_INSTALLABLE' and len(report['source_sha256'])==8
        tree=folder/'roundtrip';shutil.copytree(base,tree)
        patch=output/'REVIEW_ONLY.patch'
        subprocess.run(['git','apply','--check','--whitespace=error',str(patch)],cwd=tree,check=True)
        subprocess.run(['git','apply','--whitespace=error',str(patch)],cwd=tree,check=True)
        for relative,digest in report['source_sha256'].items():
            assert hashlib.sha256((tree/relative).read_bytes()).hexdigest()==digest
            assert (tree/relative).read_bytes()==(output/'overlay'/relative).read_bytes()
        original=json.loads((base/'manifest.json').read_text())
        for relative,record in original['files'].items():
            if relative not in report['source_sha256']:
                assert hashlib.sha256((tree/relative).read_bytes()).hexdigest()==record['sha256']
        with unittest.TestCase().assertRaises(ValueError):prep.run(SimpleNamespace(reference=base,output=output))
        # Source must reject input tampering BEFORE creating output.
        source=base/'fs/erofs/sysfs.c';source.write_bytes(source.read_bytes()+b'\n')
        bad=folder/'bad'
        with unittest.TestCase().assertRaises(AssertionError):prep.run(SimpleNamespace(reference=base,output=bad))
        assert not bad.exists()
        init=(tree/'fs/erofs/xiaomi_iostat.c').read_text()
        assert 'sbi->iostat = NULL; /* Intentional safety deviation from stock. */' in init
        super_source=(tree/'fs/erofs/super.c').read_text()
        assert super_source.index('err = erofs_init_iostat(sbi)') < super_source.index('err = erofs_register_sysfs(sb)')
        print('PASS: exact 8-file patch round-trip; untouched-file preservation, source-tamper/output-reuse rejection and safety-deviation markers')
        print('No Kbuild, KMI, SMP or hardware validation claimed.')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--reference',type=Path,required=True)
    run(parser.parse_args().reference)
