#!/usr/bin/env python3
"""Run disposable, network/disk-free ARM64 QEMU. Never uses a phone connection."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

REQUIRED = ('ARM64', 'ARM64_4K_PAGES', 'ARM64_VA_BITS_39', 'SMP', 'BLK_DEV_INITRD',
            'BINFMT_ELF', 'PROC_FS', 'SYSFS', 'SERIAL_AMBA_PL011',
            'SERIAL_AMBA_PL011_CONSOLE', 'XIAOMI_DMABUF_HUGETLB', 'XIAOMI_DMABUF_RUNTIME_AUDIT')


def check_config(text):
    for name in REQUIRED:
        if text.splitlines().count('CONFIG_' + name + '=y') != 1:
            raise ValueError('guest requirement not built-in: ' + name)


def check_log(text):
    for marker in ('DMA_GUEST_CASE_PASS: /dev/recovered-dma-audit-pmd',
                   'DMA_GUEST_CASE_PASS: /dev/recovered-dma-audit-pte',
                   'DMA_GUEST_PASS:', 'DMA_VM_RESULT_PASS:'):
        if text.count(marker) != 1:
            raise ValueError('missing/duplicate guest completion: ' + marker)
    if re.search(r'DMA_(?:GUEST_FAIL|VM_RESULT_FAIL)|BUG:|WARNING:|Oops:|Kernel panic|Call trace:', text):
        raise ValueError('guest/kernel failure reported')


def command(args):
    return ['qemu-system-aarch64', '-machine', 'virt', '-cpu', 'max', '-smp', '4',
            '-m', '1024', '-nographic', '-monitor', 'none', '-nic', 'none', '-no-reboot',
            '-kernel', str(args.kernel.resolve()), '-initrd', str(args.initramfs.resolve()),
            '-append', 'console=ttyAMA0 rdinit=/init panic=1 nokaslr']


def run(args):
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('evidence destination already exists')
    if not 30 <= args.timeout <= 600:
        raise ValueError('bounded VM timeout required')
    check_config(args.config.read_text())
    image = args.kernel.read_bytes()
    if len(image) < 64 or image[56:60] != b'ARMd':
        raise ValueError('ARM64 Image header required')
    initramfs = args.initramfs.read_bytes()
    if not initramfs.startswith(b'070701'):
        raise ValueError('uncompressed newc audit initramfs required')
    args.output.mkdir(parents=True)
    cmd = command(args)
    reason = None
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=args.timeout, check=False)
        log = result.stdout
        if result.returncode:
            reason = 'QEMU nonzero exit: ' + str(result.returncode)
    except subprocess.TimeoutExpired as error:
        log = error.stdout or b''
        reason = 'VM watchdog timeout; runtime unproven'
    (args.output / 'serial.log').write_bytes(log)
    try:
        check_log(log.decode('utf-8', errors='replace'))
    except ValueError as error:
        reason = str(error) if reason is None else reason + '; ' + str(error)
    report = {
        'status': 'BASIC_GUEST_WORKLOAD_PASS_NOT_FULL_DMA_PROOF' if reason is None else 'GUEST_FAILED',
        'failure': reason, 'command': cmd,
        'kernel_sha256': hashlib.sha256(image).hexdigest(),
        'initramfs_sha256': hashlib.sha256(initramfs).hexdigest(),
        'pending': ['fault-injected partial ENOMEM unwind', 'final backing-free verification',
                    'stock GPU producer activation', 'hardware/complete lifetime'],
    }
    (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    if reason:
        raise RuntimeError(reason)
    print(report['status'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('kernel', 'config', 'initramfs', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=240)
    run(parser.parse_args())
