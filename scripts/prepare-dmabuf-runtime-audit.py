#!/usr/bin/env python3
"""Wire pinned test producer into a disposable DMA-only ACK tree. Never shipping."""
import argparse
import hashlib
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
validator = SourceFileLoader('runtime_dma_validator', str(ROOT / 'scripts/validate-dmabuf-overlay.py')).load_module()
fault_sites = SourceFileLoader('runtime_dma_fault_sites', str(ROOT / 'scripts/prepare-dmabuf-fault-sites.py')).load_module()
PINS = {
    'recovered-dma-audit.c': 'bccacfc00ce6b439cbbc965c3b96cefe0078ba725e23601c860b5e43cecfb32a',
    'recovered-dma-export-audit.c': 'ec4cf6663865992215d3d130a86cea978c02ee09514e8f081ca7bb0672de9b13',
    'audit-export-contract.h': '442bce26daf008e6f00564ce89dd9a8c1410e6326aa5cb23b45946a1cce8a13a',
    'audit-fault-plan.h': '4474736edbe74f299fe0907ee209cc628abf8b382e558c1c2cf1f134de240201',
    'audit-map-contract.h': '3bcb3044740336508a49ea37b4af205a52c0510cf9bc0ff3cd6f751709d0388c',
    'Kconfig': '4771cb7d047b3723f804d36d1ab234c5c67a0f0e85b76cc161319ddf97367c17',
    'Makefile': '1b33ba4f90b487b9d79d6582497dafe3b5058e1a39e97f7f3c085b2fe1922ff8',
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def regular_path(root, relative):
    path = root
    if root.is_symlink():
        raise ValueError('symlink root')
    for part in Path(relative).parts:
        path = path / part
        if path.is_symlink():
            raise ValueError('symlink: ' + relative)
    return path


def run(args):
    # Full canonical/recipe validation on pristine inputs, not trusting JSON alone.
    # A reference nested inside the workflow checkout is NOT its Git root.
    # git apply would filter paths using that unrelated prefix. Validate the
    # same exact bytes in a fresh, disposable root; don't weaken path/hash gates.
    with tempfile.TemporaryDirectory(prefix='dma-pristine-runtime-reference-') as temporary:
        reference = Path(temporary)
        subprocess.run(['git', 'init', '-q', str(reference)], check=True)
        for name in validator.prepare.SOURCES:
            data = regular_path(args.ack_reference, name).read_bytes()
            target = reference / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        validator.run(SimpleNamespace(source=reference, overlay=args.overlay, apply_review=False))
    manifest = json.loads((args.overlay / 'manifest.json').read_text())
    expected = dict(manifest['sources'])
    expected.update({name: record['after'] for name, record in manifest['changes'].items()})
    for name, sha in expected.items():
        if digest(regular_path(args.source, name).read_bytes()) != sha:
            raise ValueError('post-DMA input drift: ' + name)
    destination = regular_path(args.source, 'mm/recovered-dma-audit')
    if destination.exists():
        raise ValueError('audit destination already exists')
    changes = {}
    for name, sha in PINS.items():
        data = regular_path(ROOT / 'tools/stock-recovery/runtime-audit', name).read_bytes()
        if digest(data) != sha:
            raise ValueError('producer input drift: ' + name)
        changes['mm/recovered-dma-audit/' + name] = (None, data)
    before = regular_path(args.source, 'mm/huge_memory.c').read_bytes()
    changes['mm/huge_memory.c'] = (before, fault_sites.transform(before))
    for name, suffix in {
        'mm/Kconfig': '\n# Disposable VM audit only; never a phone build.\nsource "mm/recovered-dma-audit/Kconfig"\n',
        'mm/Makefile': '\n# Disposable VM audit only.\nobj-$(CONFIG_XIAOMI_DMABUF_RUNTIME_AUDIT) += recovered-dma-audit/\n',
    }.items():
        before = regular_path(args.source, name).read_bytes()
        changes[name] = (before, before + suffix.encode())
    output = args.output
    if output and (output.exists() or output.is_symlink()):
        raise ValueError('evidence already exists')
    report = {
        'status': 'DISPOSABLE_VM_SOURCE_ONLY_NOT_INSTALLABLE',
        'ack_commit': manifest['ack_commit'],
        'producer_pins': PINS,
        'changes': {name: {'before': digest(before) if before is not None else None,
                           'after': digest(after)} for name, (before, after) in changes.items()},
        'pending': ['Kbuild', 'MMU/SMP', 'partial mmap unwind', 'backing lifetime', 'stock producer route'],
    }
    if args.apply_review:
        destination.mkdir()
        for name, (_, after) in changes.items():
            regular_path(args.source, name).write_bytes(after)
        for name, record in report['changes'].items():
            if digest(regular_path(args.source, name).read_bytes()) != record['after']:
                raise ValueError('post-write drift: ' + name)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open('x') as stream:
            json.dump(report, stream, indent=2)
            stream.write('\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--ack-reference', type=Path, required=True)
    parser.add_argument('--overlay', type=Path, default=ROOT / 'tools/stock-recovery/overlays/dma-6.6.77')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--apply-review', action='store_true')
    run(parser.parse_args())
    print('PASS: disposable producer source gate; NOT compilation/runtime/shipping proof')
