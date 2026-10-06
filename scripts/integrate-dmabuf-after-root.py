#!/usr/bin/env python3
"""Compose root and recovered DMA only in a clean, exact ACK build checkout.

Invokes the original root integrator unchanged, checks its ordered manifest,
then applies the independently validated DMA composition. No build, packaging,
release, signing relaxation, device access or rollback of failed trees.
"""
import argparse
import hashlib
from importlib.machinery import SourceFileLoader
import json
import os
from pathlib import Path
import subprocess
import tempfile

composition = SourceFileLoader('dma_root_composition', str(Path(__file__).with_name('validate-dmabuf-susfs-overlay.py'))).load_module()
ROOT_MANIFEST = 'ceb50cf610affc7a7a671fb07568e5ec033e9d63ad12b7de1a51994f6c935fd2'
COMPOSED_MANIFEST = '3b48c383849fa925e3b1a41dd013d668f8f1a4c0e3c179d9f8638a3b94e9c9c9'
KSU_PIN = '234f6e040fcbca18b16d2398e1aa225712ec99ad'
KSU_V330 = '3b18216f71df189ab3d1b1ce0bdb21be1268e771'
KSU_UAPI = 'fc98ae0140c80815260ecaf86ddb6ef06ad29863'
NATIVES_PATH = 'manager/app/src/main/java/com/rifsxd/ksunext/Natives.kt'
KSU_NATIVES = '0fafa35dc7d31ef4c8add60c3f8d98a090027544'
COPIED = {'fs/susfs.c': 'c556c644dcb345bbe7814812c6ff084e22762d4d0381c8ee331ada1b25cd6770',
          'include/linux/susfs.h': '05d4ec96ba75d459612d6269614bc7e1948c4e7b1ecd4dfaf47fbd4ec4a3fcfb',
          'include/linux/susfs_def.h': '4eef49b81b6d8320194284adf02987b7e89df81495f7cdf9de9b29072dd9d87a'}


def git(source, *arguments):
    return subprocess.run(['git', '-C', str(source), *arguments], check=True, capture_output=True).stdout


def changed(source):
    # Match the original gate, which operates before any commit/staging.
    return git(source, 'diff', '--name-only', '--diff-filter=ACMRTUXB').decode().splitlines()


def ordered_manifest(source, names):
    names = sorted(names)
    if len(names) != len(set(names)):
        raise ValueError('duplicate manifest path')
    digest = hashlib.sha256()
    for name in names:
        if name.startswith('/') or '..' in Path(name).parts:
            raise ValueError('unsafe manifest path')
        digest.update(name.encode() + b'\0')
        digest.update(hashlib.sha256(composition.payload(source, name)).digest())
    return digest.hexdigest()


def root_gate(source):
    names = changed(source)
    if len(names) != 26 or ordered_manifest(source, names) != ROOT_MANIFEST:
        raise ValueError('root ordered manifest mismatch; DMA not applied')
    for name, sha in COPIED.items():
        if composition.digest(composition.payload(source, name)) != sha:
            raise ValueError('copied SUSFS source drift: ' + name)
    return names


def ksu_compatibility_gate(source):
    # Preserve the manager/API checks made before the original root workflow.
    for object_name, expected in (('HEAD', KSU_PIN), (KSU_PIN + ':uapi', KSU_UAPI),
                                  (KSU_PIN + ':' + NATIVES_PATH, KSU_NATIVES)):
        if git(source, 'rev-parse', object_name).decode().strip() != expected:
            raise ValueError('KernelSU manager/API pin mismatch')
    git(source, 'merge-base', '--is-ancestor', KSU_V330, KSU_PIN)
    if b'const val MINIMAL_SUPPORTED_KERNEL = 33188' not in git(source, 'show', KSU_PIN + ':' + NATIVES_PATH):
        raise ValueError('KernelSU manager minimum mismatch')


def run(args):
    if args.output.exists() or args.output.is_symlink() or not args.output.parent.is_dir():
        raise ValueError('evidence output unavailable')
    if git(args.source, 'rev-parse', 'HEAD').decode().strip() != composition.validator.prepare.COMMIT:
        raise ValueError('ACK HEAD mismatch')
    if git(args.source, 'status', '--porcelain', '--untracked-files=all'):
        raise ValueError('build checkout must be pristine before root integration')
    ksu_compatibility_gate(args.ksu_source)
    # Both original validators remain independently fail-closed. Snapshot only
    # the eleven pinned inputs, not arbitrary worktree or user files.
    with tempfile.TemporaryDirectory(prefix='dma-root-reference-') as temporary:
        reference = Path(temporary)
        for name, sha in composition.validator.prepare.SOURCES.items():
            data = git(args.source, 'show', composition.validator.prepare.COMMIT + ':' + name)
            if composition.digest(data) != sha or composition.payload(args.source, name) != data:
                raise ValueError('pristine DMA source drift: ' + name)
            path = reference / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        composition.validator.run(argparse.Namespace(source=reference, overlay=args.overlay, apply_review=False))
        environment = dict(os.environ)
        environment.update(KERNEL_DIR=str(args.source.resolve()), KSU_DIR=str(args.ksu_source.resolve()),
                           SUSFS_DIR=str(args.susfs_source.resolve()), FIX_DIR=str(args.fix_source.resolve()))
        integrator = Path(__file__).with_name('integrate-ksun-susfs-6.6.77.sh')
        subprocess.run(['bash', str(integrator.resolve())], env=environment, check=True)
        root_names = root_gate(args.source)
        print('PASS: original root integration and independent ordered manifest; composing DMA', flush=True)
        report = composition.run(argparse.Namespace(source=args.source, ack_reference=reference, overlay=args.overlay,
                                                   susfs_source=args.susfs_source, apply_review=True, output=None))
        # Unchanged DMA inputs do not belong in the tracked delta.
        expected = set(root_names) | {name for name in report['before'] if report['before'][name] != report['after'][name]}
        actual = changed(args.source)
        if set(actual) != expected:
            raise ValueError('unexpected tracked change after DMA integration')
        for name, sha in COPIED.items():
            if composition.digest(composition.payload(args.source, name)) != sha:
                raise ValueError('DMA altered copied SUSFS source')
        composed_sha = ordered_manifest(args.source, actual)
        if composed_sha != COMPOSED_MANIFEST:
            raise ValueError('composed ordered manifest drift')
        report.update(root_manifest_sha256=ROOT_MANIFEST,
                      composed_tracked_manifest_sha256=composed_sha,
                      composed_tracked_paths=sorted(actual), copied_susfs_sources=COPIED,
                      scope='ROOT_INTEGRATION_AND_DMA_SOURCES_ONLY')
        report['pending'].remove('full KSUN/SUSFS integration manifest')
        with args.output.open('x') as output:
            output.write(json.dumps(report, indent=2) + '\n')
    print('PASS: root + DMA source integration only; still REVIEW_ONLY_NOT_INSTALLABLE')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'ksu-source', 'susfs-source', 'fix-source', 'overlay', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    run(parser.parse_args())
