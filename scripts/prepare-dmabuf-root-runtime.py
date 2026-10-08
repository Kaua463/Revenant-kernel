#!/usr/bin/env python3
"""Instrument exact root+DMA composition for a disposable VM, never shipping."""
import argparse
import hashlib
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
root = SourceFileLoader('root_runtime_composition', str(HERE / 'integrate-dmabuf-after-root.py')).load_module()
runtime = SourceFileLoader('root_runtime_producer', str(HERE / 'prepare-dmabuf-runtime-audit.py')).load_module()


def validate_composition(source, report):
    if report['ack_commit'] != root.composition.validator.prepare.COMMIT:
        raise ValueError('root runtime ACK identity drift')
    names = report['composed_tracked_paths']
    if len(names) != 31 or report['composed_tracked_manifest_sha256'] != root.COMPOSED_MANIFEST:
        raise ValueError('root runtime manifest identity drift')
    if root.ordered_manifest(source, names) != root.COMPOSED_MANIFEST:
        raise ValueError('actual root runtime sources differ from audited composition')
    for name, expected in dict(root.COPIED, **report['after']).items():
        if hashlib.sha256(runtime.regular_path(source, name).read_bytes()).hexdigest() != expected:
            raise ValueError('root runtime copied/DMA source drift: ' + name)


def run(args):
    report = json.loads(args.composition.read_text())
    validate_composition(args.source, report)
    destination = runtime.regular_path(args.source, 'mm/recovered-dma-audit')
    if destination.exists() or args.output.exists() or args.output.is_symlink():
        raise ValueError('root runtime destination/evidence already exists')
    changes = {}
    for name, expected in runtime.PINS.items():
        data = runtime.regular_path(runtime.ROOT / 'tools/stock-recovery/runtime-audit', name).read_bytes()
        if runtime.digest(data) != expected:
            raise ValueError('root runtime producer pin drift: ' + name)
        changes['mm/recovered-dma-audit/' + name] = (None, data)
    path = runtime.regular_path(args.source, 'mm/huge_memory.c')
    before = path.read_bytes()
    changes['mm/huge_memory.c'] = (before, runtime.runtime_trace.transform(runtime.fault_sites.transform(before)))
    for name, suffix in {
        'mm/Kconfig': '\n# Disposable root VM only.\nsource "mm/recovered-dma-audit/Kconfig"\n',
        'mm/Makefile': '\n# Disposable root VM only.\nobj-$(CONFIG_XIAOMI_DMABUF_RUNTIME_AUDIT) += recovered-dma-audit/\n',
    }.items():
        before = runtime.regular_path(args.source, name).read_bytes()
        changes[name] = (before, before + suffix.encode())
    # All preimages and pins are checked before the first write.
    destination.mkdir()
    for name, (_, after) in changes.items():
        runtime.regular_path(args.source, name).write_bytes(after)
    for name, (_, after) in changes.items():
        if runtime.regular_path(args.source, name).read_bytes() != after:
            raise ValueError('root runtime postimage drift')
    evidence = {'status': 'ROOT_VM_INSTRUMENTATION_NOT_PHONE_IMAGE',
                'composition_sha256': root.COMPOSED_MANIFEST,
                'producer_pins': runtime.PINS,
                'changes': {name: {'before': runtime.digest(before) if before is not None else None,
                                   'after': runtime.digest(after)} for name, (before, after) in changes.items()}}
    with args.output.open('x') as stream:
        stream.write(json.dumps(evidence, indent=2) + '\n')
    print('PASS: exact root+DMA composition instrumented for VM only')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'composition', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    run(parser.parse_args())
