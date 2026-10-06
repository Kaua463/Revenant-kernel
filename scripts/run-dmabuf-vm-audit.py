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
                   'DMA_GUEST_CASE_PASS: /dev/recovered-dma-audit-fault-pmd',
                   'DMA_GUEST_CASE_PASS: /dev/recovered-dma-audit-fault-pte',
                   'DMA_GUEST_PASS:', 'DMA_VM_RESULT_PASS:'):
        if text.count(marker) != 1:
            raise ValueError('missing/duplicate guest completion: ' + marker)
    if re.search(r'DMA_(?:GUEST_FAIL|VM_RESULT_FAIL|AUDIT_FAULT_FAIL)|BUG:|WARNING:|Oops:|Kernel panic|Call trace:', text):
        raise ValueError('guest/kernel failure reported')
    allocations = list(re.finditer(r'DMA_AUDIT_ALLOC id=([1-9][0-9]*) mode=([01]) bytes=4194304 fault=([01])\r?\n', text))
    releases = list(re.finditer(r'DMA_AUDIT_RELEASE id=([1-9][0-9]*) mode=([01])\r?\n', text))
    if (len(allocations) != 4 or len(releases) != 4 or
            text.count('DMA_AUDIT_ALLOC') != 4 or text.count('DMA_AUDIT_RELEASE') != 4):
        raise ValueError('missing/duplicate/malformed allocation or final release')
    if len({match.group(1) for match in allocations}) != 4:
        raise ValueError('allocation IDs must be unique')
    faults = list(re.finditer(r'DMA_AUDIT_FAULT id=([1-9][0-9]*) mode=([01]) ordinal=2 published=1 table=1\r?\n', text))
    returns = list(re.finditer(r'DMA_AUDIT_FAULT_RETURN id=([1-9][0-9]*) mode=([01]) result=-12 fired=1\r?\n', text))
    if (len(faults) != 2 or len(returns) != 2 or text.count('DMA_AUDIT_FAULT id=') != 2 or
            text.count('DMA_AUDIT_FAULT_RETURN') != 2 or text.count('DMA_GUEST_ENOMEM_PASS:') != 2):
        raise ValueError('missing/duplicate/malformed partial ENOMEM evidence')
    for mode, device, inject in ((0, 'pmd', 0), (1, 'pte', 0),
                                 (0, 'fault-pmd', 1), (1, 'fault-pte', 1)):
        allocated = [match for match in allocations if match.group(2) == str(mode) and match.group(3) == str(inject)]
        if len(allocated) != 1:
            raise ValueError('missing/duplicate mode allocation: ' + device)
        allocation = allocated[0]
        released = [match for match in releases if match.group(1) == allocation.group(1)]
        boundary = 'DMA_GUEST_LAST_UNMAP: /dev/recovered-dma-audit-' + device
        completed = 'DMA_GUEST_CASE_PASS: /dev/recovered-dma-audit-' + device
        if len(allocated) != 1 or len(released) != 1 or text.count(boundary) != 1:
            raise ValueError('missing/duplicate mode lifetime: ' + device)
        release = released[0]
        if release.group(2) != str(mode):
            raise ValueError('release does not match allocated buffer: ' + device)
        if not allocation.start() < text.index(boundary) < release.start() < text.index(completed):
            raise ValueError('release outside last-unmap interval: ' + device)
        if not text.index(completed) < text.index('DMA_GUEST_PASS:') < text.index('DMA_VM_RESULT_PASS:'):
            raise ValueError('completion emitted before all case results: ' + device)
        if inject:
            fired = [match for match in faults if match.group(1) == allocation.group(1) and match.group(2) == str(mode)]
            returned = [match for match in returns if match.group(1) == allocation.group(1) and match.group(2) == str(mode)]
            retry = 'DMA_GUEST_ENOMEM_PASS: /dev/recovered-dma-audit-' + device + ' same_address_retry=1'
            if len(fired) != 1 or len(returned) != 1 or text.count(retry) != 1:
                raise ValueError('partial ENOMEM ID/mode/retry mismatch: ' + device)
            if not allocation.start() < fired[0].start() < returned[0].start() < text.index(retry) < text.index(boundary):
                raise ValueError('partial ENOMEM lifetime order wrong: ' + device)


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
        'verified': ['basic guest workload', 'four file-owned buffers freed exactly once after final unmap',
                     'PMD/PTE ordinal-two ENOMEM after one published block; same-address retry'] if reason is None else [],
        'pending': ['all allocator failure sites and accounting', 'stock GPU producer activation', 'hardware/complete lifetime'],
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
