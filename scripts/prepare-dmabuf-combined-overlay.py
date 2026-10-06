#!/usr/bin/env python3
"""Compose exact MM and DMA-BUF core patches, review-only; no live-tree edits."""
import argparse
import hashlib
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path
import tempfile

HERE = Path(__file__).resolve().parent
base = SourceFileLoader('dma_combined_base', str(HERE/'prepare-dmabuf-reimplementation.py')).load_module()
address = SourceFileLoader('dma_combined_address', str(HERE/'prepare-dmabuf-address-overlay.py')).load_module()


def run(args):
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('output must not exist')
    # Generate and hash-validate both components BEFORE creating any final output.
    with tempfile.TemporaryDirectory(prefix='dma-combined-') as temporary:
        root = Path(temporary)
        base.run(argparse.Namespace(source=args.source, image=args.image,
                                    symbols=args.symbols, output=root/'base'))
        address.run(argparse.Namespace(core=args.core, output=root/'address'))
        first = json.loads((root/'base/manifest.json').read_text())
        second = json.loads((root/'address/manifest.json').read_text())
        if first['ack_commit'] != second['ack_commit']:
            raise ValueError('mixed ACK identities')
        if set(first['changes']) & set(second['changes']):
            raise ValueError('overlapping component writes')
        patches = [(root/'base/dmabuf-review.patch').read_bytes(),
                   (root/'address/dmabuf-address-review.patch').read_bytes()]
        for patch, report in zip(patches, (first, second)):
            if hashlib.sha256(patch).hexdigest() != report['patch_sha256']:
                raise ValueError('component patch hash mismatch')
        changes = dict(first['changes'], **second['changes'])
        expected = {'mm/Kconfig', 'mm/huge_memory.c', 'mm/memory.c', 'mm/mmap.c',
                    'mm/mremap.c', 'include/linux/xiaomi_dmabuf_huge.h', address.PATH}
        if set(changes) != expected:
            raise ValueError('combined scope mismatch')
        candidates = {}
        for component, report in (('base', first), ('address', second)):
            for name, record in report['changes'].items():
                payload = (root/component/'candidate'/name).read_bytes()
                if hashlib.sha256(payload).hexdigest() != record['after']:
                    raise ValueError('component candidate hash mismatch')
                candidates[name] = payload
        combined = b''.join(patches)
        report = {'status': 'REVIEW_ONLY_NOT_INSTALLABLE',
                  'ack_commit': first['ack_commit'], 'image_sha256': first['image_sha256'],
                  'patch_sha256': hashlib.sha256(combined).hexdigest(),
                  'changes': changes, 'components': {'mm': first, 'core': second},
                  'safety_deviations': first['safety_deviations'],
                  'pending': sorted(set(first['pending']+second['pending']+
                                       ['exact stock exporter activation route']))}
        args.output.mkdir(parents=True)
        for name, payload in candidates.items():
            target = args.output/'candidate'/name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        (args.output/'dmabuf-combined-review.patch').write_bytes(combined)
        (args.output/'manifest.json').write_text(json.dumps(report, indent=2)+'\n')
    print('Prepared 7-file MM + DMA-BUF core composition; REVIEW_ONLY_NOT_INSTALLABLE')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'core', 'image', 'symbols', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    run(parser.parse_args())
