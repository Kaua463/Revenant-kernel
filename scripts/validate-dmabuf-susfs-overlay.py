#!/usr/bin/env python3
"""Apply DMA after the exact SUSFS MM delta, without relaxing pristine gates.

Only the eleven DMA input files are covered here. The full KSUN/SUSFS ordered
manifest must already have passed independently; this is not its replacement.
"""
import argparse
import hashlib
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path
import subprocess
import tempfile

validator = SourceFileLoader('dma_pristine_validator', str(Path(__file__).with_name('validate-dmabuf-overlay.py'))).load_module()
PIN = 'be7b7ef49a1e1b189c3abf00eacaa7ebdb4168c1'
PATCH_PATH = 'kernel_patches/50_add_susfs_in_gki-android15-6.6.patch'
PATCH_SHA = 'fb8ed4e7fcd95b01a1bb275c1dd1985f32c72d2997475b94dd39ab4f90775792'
HEADER = 'include/linux/xiaomi_dmabuf_huge.h'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def payload(root, name):
    root = root.resolve()
    path = root / name
    for part in (path, *path.parents):
        if part == root:
            break
        if part.is_symlink():
            raise ValueError('symlink in DMA input: ' + name)
    return path.read_bytes()


def apply(tree, patch, include=None, check=False):
    command = ['git', 'apply']
    if check:
        command.append('--check')
    if include:
        command.append('--include=' + include)
    subprocess.run(command + [str(patch.resolve())], cwd=tree, check=True, capture_output=True)


def run(args):
    if args.output and (args.output.exists() or args.output.is_symlink()):
        raise ValueError('evidence output already exists')
    if args.output and not args.output.parent.is_dir():
        raise ValueError('evidence output parent missing')
    susfs = subprocess.run(['git', '-C', str(args.susfs_source), 'show', PIN + ':' + PATCH_PATH], check=True, capture_output=True).stdout
    if digest(susfs) != PATCH_SHA:
        raise ValueError('SUSFS patch drift')
    paths = {line.split()[2][2:] for line in susfs.decode().splitlines() if line.startswith('diff --git ')}
    if paths & set(validator.prepare.SOURCES) != {'mm/memory.c'}:
        raise ValueError('unexpected SUSFS/DMA input overlap')
    with tempfile.TemporaryDirectory(prefix='dma-composed-validation-') as temporary:
        temporary = Path(temporary)
        before = temporary / 'before'
        after = temporary / 'after'
        for tree in (before, after):
            for name, sha in validator.prepare.SOURCES.items():
                data = payload(args.ack_reference, name)
                if digest(data) != sha:
                    raise ValueError('ACK reference drift: ' + name)
                path = tree / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
        # Validate the existing canonical overlay first; no new canonical recipe.
        validator.run(argparse.Namespace(source=after, overlay=args.overlay, apply_review=True))
        susfs_path = temporary / 'susfs.patch'
        susfs_path.write_bytes(susfs)
        for tree in (before, after):
            apply(tree, susfs_path, include='mm/memory.c', check=True)
            apply(tree, susfs_path, include='mm/memory.c')
        expected_before = {name: digest(payload(before, name)) for name in validator.prepare.SOURCES}
        expected_after = {name: digest(payload(after, name)) for name in (*validator.prepare.SOURCES, HEADER)}
        for name, sha in expected_before.items():
            if digest(payload(args.source, name)) != sha:
                raise ValueError('composed preimage drift: ' + name)
        header = args.source / HEADER
        if header.exists() or header.is_symlink():
            raise ValueError('new header already exists')
        patch = args.overlay / 'dmabuf-review.patch'
        apply(args.source, patch, check=True)
        if args.apply_review:
            apply(args.source, patch)
            for name, sha in expected_after.items():
                if digest(payload(args.source, name)) != sha:
                    raise ValueError('composed postimage drift: ' + name)
        report = {'status': 'REVIEW_ONLY_NOT_INSTALLABLE', 'scope': 'DMA_INPUT_FILES_ONLY',
                  'ack_commit': validator.prepare.COMMIT, 'susfs_commit': PIN,
                  'susfs_patch_sha256': PATCH_SHA, 'dma_patch_sha256': digest(patch.read_bytes()),
                  'before': expected_before, 'after': expected_after,
                  'applied': args.apply_review,
                  'pending': ['full KSUN/SUSFS integration manifest', 'composed Kbuild/KMI',
                              'producer ownership/unwind', 'VMA callbacks/refcounts', 'MMU/SMP/hardware']}
        if args.output:
            # Evidence never overwrites an existing file.
            with args.output.open('x') as output:
                output.write(json.dumps(report, indent=2) + '\n')
    print('PASS: exact composed DMA pre/postimages; full root integration and runtime still unproven')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'ack-reference', 'overlay', 'susfs-source'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--apply-review', action='store_true')
    parser.add_argument('--output', type=Path)
    run(parser.parse_args())
