#!/usr/bin/env python3
"""Repeat cached DMA host/stock tests sequentially. No phone or kernel build."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
UNITS = '''activation-decoder address-build address-overlay address-selector
audit-fault-plan audit-log-formats audit-map-contract build-gates exporter-routing
exporter-source fault-sites folded-levels generic-split-routing guest-data
guest-prefork guest-split-move hardware-export module-activation move-safety
root-fragment root-integration-gates runtime-integration runtime-producer-source
runtime-trace stock-btf stock-callers vm-initramfs vm-runner wrapper-safety
root-runtime boot-offline'''.split()
STOCK = '''remap-safety stock-remap-pmd stock-remap-pte stock-split stock-move
stock-zap stock-range stock-wrappers stock-fork-hook stock-unmap-hook
stock-move-hook stock-vma-hooks stock-deposit stock-pmd-set stock-table-rcu
stock-file-put stock-split-vma-hook'''.split()


def commands(outputs, python):
    image = outputs / 'stock-recovery-features-20261005-v2/stock.Image'
    symbols = outputs / 'kernel-stock-custom-comparison/stock.kallsyms'
    for name in UNITS:
        yield name, [str(python), str(ROOT / f'scripts/test-dmabuf-{name}.py')]
    extras = {
        'stock-remap-pmd': ['--teardown', 'cross-move-split-unmap', '--free-split-tables'],
        'stock-deposit': ['--source', outputs / 'stock-ack-dmabuf-helpers-reference-20261005/mm/pgtable-generic.c'],
        'stock-pmd-set': ['--source', outputs / 'stock-ack-dmabuf-helpers-reference-20261005/arch/arm64/mm/mmu.c'],
        'stock-table-rcu': ['--source', outputs / 'stock-ack-dmabuf-free-reference-20261005/mm/mmu_gather.c'],
        'stock-file-put': ['--source', outputs / 'stock-ack-dma-file-lifetime-reference-20261006'],
        'stock-split-vma-hook': ['--close-source', outputs / 'stock-ack-dma-vma-close-reference-20261006',
                               '--free-source', outputs / 'stock-ack-dma-vma-free-reference-20261006'],
    }
    for name in STOCK:
        yield name, [str(python), str(ROOT / f'scripts/test-dmabuf-{name}.py'),
                     '--image', str(image), '--symbols', str(symbols),
                     *map(str, extras.get(name, []))]
    reference = outputs / 'stock-ack-dmabuf-overlay-reference-20261005'
    core = outputs / 'stock-ack-dma-core-reference-20261006/drivers/dma-buf/dma-buf.c'
    overlay = ROOT / 'tools/stock-recovery/overlays/dma-6.6.77'
    susfs = ROOT.parent / 'susfs-audit/repo'
    generated = {
        'test-prepare-dmabuf-reimplementation': ['--source', reference, '--image', image, '--symbols', symbols],
        'test-dmabuf-overlay-validator': ['--source', reference, '--overlay', overlay],
        'test-dmabuf-combined-overlay': ['--source', reference, '--core', core, '--image', image, '--symbols', symbols],
        'test-dmabuf-susfs-overlay': ['--ack-reference', reference, '--overlay', overlay, '--susfs-source', susfs],
        'test-dmabuf-susfs-composition': ['--source', reference, '--overlay', overlay, '--susfs-source', susfs],
        'test-dmabuf-root-snapshot': ['--source', outputs / 'stock-ack-dma-root-snapshot-reference-20261006',
                                     '--susfs-source', susfs, '--overlay', overlay, '--core', core],
        'test-dmabuf-stock-address-selector': ['--image', image, '--symbols', symbols],
    }
    for name, arguments in generated.items():
        yield name, [str(python), str(ROOT / f'scripts/{name}.py'), *map(str, arguments)]
    candidate = outputs / 'dma-hardware-candidate-37703159922'
    yield '610-module-abi', [str(python), str(ROOT / 'scripts/rom-module-reference.py'), 'check',
                             '--symvers', str(candidate / 'Module.symvers'), '--image', str(candidate / 'Image'),
                             '--config', str(candidate / 'config')]
    yield 'installed-kfence-parity', [str(python), str(ROOT / 'scripts/check-stock-kfence.py'), str(candidate / 'config')]
    for validator in ('root-build', 'root-vm', 'hardware-test'):
        yield validator + '-workflow', ['ruby', str(ROOT / f'scripts/validate-dmabuf-{validator}.rb')]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--outputs', type=Path, default=ROOT.parents[1] / 'outputs')
    parser.add_argument('--python', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    outputs = args.outputs.resolve()
    python = (args.python or outputs / 'stock-recovery-runtime/bin/python').absolute()
    if args.report.exists() or args.report.is_symlink():
        raise ValueError('refuse stale/existing report')
    environment = dict(os.environ, PYTHONPATH=str(ROOT.parent / 'fenrir-python'))
    jobs = list(commands(outputs, python))
    results = []
    for number, (label, command) in enumerate(jobs, 1):
        started = time.monotonic()
        try:
            run = subprocess.run(command, cwd=ROOT, env=environment, text=True,
                                 capture_output=True, timeout=180)
            result = dict(test=label, command=command, exit_code=run.returncode,
                          output=run.stdout + run.stderr)
        except (OSError, subprocess.TimeoutExpired) as error:
            result = dict(test=label, command=command, exit_code=None, error=str(error))
        result['elapsed_seconds'] = round(time.monotonic() - started, 2)
        results.append(result)
        print(f'{number}/{len(jobs)} {label}: ' + ('PASS' if result['exit_code'] == 0 else 'FAIL'), flush=True)
    failures = [r['test'] for r in results if r['exit_code'] != 0]
    report = dict(status='FAIL' if failures else 'SCOPED_OFFLINE_TESTS_PASS_NOT_HARDWARE_APPROVAL',
                  results=results, failed=failures,
                  limits=['bounded models, source checks and ARM64 emulation',
                          'no real GPU producer, device MMU/TLB or phone boot test',
                          'VM/root runtime results are separate remote evidence'])
    with args.report.open('x') as stream:
        stream.write(json.dumps(report, indent=2) + '\n')
    print(report['status'], args.report)
    raise SystemExit(bool(failures))


if __name__ == '__main__':
    main()
