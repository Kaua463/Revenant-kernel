#!/usr/bin/env python3
"""Run disposable, network/disk-free ARM64 QEMU. Never uses a phone connection."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

REQUIRED = ('ARM64', 'ARM64_4K_PAGES', 'ARM64_VA_BITS_39', 'MMU', 'SMP', 'BLK_DEV_INITRD',
            'BINFMT_ELF', 'PROC_FS', 'SYSFS', 'DMA_SHARED_BUFFER', 'SERIAL_AMBA_PL011',
            'SERIAL_AMBA_PL011_CONSOLE', 'XIAOMI_DMABUF_HUGETLB', 'XIAOMI_DMABUF_RUNTIME_AUDIT')


def check_config(text):
    for name in REQUIRED:
        if text.splitlines().count('CONFIG_' + name + '=y') != 1:
            raise ValueError('guest requirement not built-in: ' + name)


def check_log(text):
    # Preserve causal kernel failure rather than replacing it with the later
    # missing-pass-marker symptom when a guest dies before completing.
    error = re.search(r'DMA_(?:GUEST_FAIL|VM_RESULT_FAIL|AUDIT_FAULT_FAIL|AUDIT_ACCOUNTING_FAIL)|BUG:|WARNING:|Oops:|Kernel panic|Call trace:',text)
    if error:
        raise ValueError('guest/kernel failure reported: '+error.group(0))
    for marker in ('DMA_GUEST_CASE_PASS: /dev/recovered-dma-audit-pmd',
                   'DMA_GUEST_CASE_PASS: /dev/recovered-dma-audit-pte',
                   'DMA_GUEST_CASE_PASS: /dev/recovered-dma-audit-fault-pmd',
                   'DMA_GUEST_CASE_PASS: /dev/recovered-dma-audit-fault-pte',
                   'DMA_GUEST_CASE_PASS: /dev/recovered-dma-audit-first-pmd',
                   'DMA_GUEST_CASE_PASS: /dev/recovered-dma-audit-first-pte',
                   'DMA_GUEST_CASE_PASS: /dev/recovered-dma-audit-table-pmd',
                   'DMA_GUEST_CASE_PASS: /dev/recovered-dma-audit-table-pte',
                   'DMA_GUEST_CASE_PASS: /dev/recovered-dma-audit-table-cross-pmd',
                   'DMA_GUEST_CASE_PASS: /dev/recovered-dma-audit-table-cross-pte',
                   'DMA_GUEST_PASS:', 'DMA_VM_RESULT_PASS:'):
        if text.count(marker) != 1:
            raise ValueError('missing/duplicate guest completion: ' + marker)
    allocations = list(re.finditer(r'DMA_AUDIT_ALLOC id=([1-9][0-9]*) mode=([01]) bytes=4194304 fault=([01])\r?\n', text))
    releases = list(re.finditer(r'DMA_AUDIT_RELEASE id=([1-9][0-9]*) mode=([01])\r?\n', text))
    if (len(allocations) != 10 or len(releases) != 10 or
            text.count('DMA_AUDIT_ALLOC') != 10 or text.count('DMA_AUDIT_RELEASE') != 10):
        raise ValueError('missing/duplicate/malformed allocation or final release')
    if len({match.group(1) for match in allocations}) != 10:
        raise ValueError('allocation IDs must be unique')
    if text.count('DMA_GUEST_CROSS_PGD:') != 10:
        raise ValueError('missing/duplicate cross-PGD mapping evidence')
    faults = list(re.finditer(r'DMA_AUDIT_FAULT id=([1-9][0-9]*) mode=([01]) ordinal=([12]) published=([01]) table=([01])\r?\n', text))
    table_faults = list(re.finditer(r'DMA_AUDIT_TABLE_FAULT id=([1-9][0-9]*) mode=([01]) ordinal=([12]) published=([01]) table=([01]) cold=1\r?\n',text))
    if len(table_faults) != 4 or text.count('DMA_AUDIT_TABLE_FAULT') != 4 or text.count('DMA_GUEST_COLD_RANGE') != 4:
        raise ValueError('missing/duplicate/malformed cold-PUD evidence')
    returns = list(re.finditer(r'DMA_AUDIT_FAULT_RETURN id=([1-9][0-9]*) mode=([01]) result=-12 fired=1\r?\n', text))
    unwinds = list(re.finditer(r'DMA_AUDIT_UNWIND id=([1-9][0-9]*) mode=([01]) before=([0-9]+) partial=([0-9]+) retry=([0-9]+)\r?\n', text))
    if len(unwinds) != 8 or text.count('DMA_AUDIT_UNWIND') != 8:
        raise ValueError('missing/duplicate/malformed page-table accounting evidence')
    if (len(faults) != 4 or len(returns) != 8 or text.count('DMA_AUDIT_FAULT id=') != 4 or
            text.count('DMA_AUDIT_FAULT_RETURN') != 8 or text.count('DMA_GUEST_ENOMEM_PASS:') != 8):
        raise ValueError('missing/duplicate/malformed partial ENOMEM evidence')
    for mode, device, inject in ((0, 'pmd', 0), (1, 'pte', 0),
                                 (0, 'fault-pmd', 2), (1, 'fault-pte', 2),
                                 (0, 'first-pmd', 1), (1, 'first-pte', 1),
                                 (0, 'table-pmd', 3), (1, 'table-pte', 3),
                                 (0, 'table-cross-pmd', 4), (1, 'table-cross-pte', 4)):
        selected_faults = table_faults if inject >= 3 else faults
        ordinal = inject-2 if inject >= 3 else inject
        allocated = [match for match in allocations if match.group(2) == str(mode) and match.group(3) == str(inject)]
        if inject:
            scenario_ids = {m.group(1) for m in selected_faults if m.group(2,3) == (str(mode),str(ordinal))}
            allocated = [m for m in allocations if m.group(2,3) == (str(mode),'1') and m.group(1) in scenario_ids]
        if len(allocated) != 1:
            raise ValueError('missing/duplicate mode allocation: ' + device)
        allocation = allocated[0]
        released = [match for match in releases if match.group(1) == allocation.group(1)]
        boundary = 'DMA_GUEST_LAST_UNMAP: /dev/recovered-dma-audit-' + device
        completed = 'DMA_GUEST_CASE_PASS: /dev/recovered-dma-audit-' + device
        if len(allocated) != 1 or len(released) != 1 or text.count(boundary) != 1:
            raise ValueError('missing/duplicate mode lifetime: ' + device)
        release = released[0]
        crossing = 'DMA_GUEST_CROSS_PGD: /dev/recovered-dma-audit-' + device + ' bytes=4194304 root_slots=2 data_verified=1'
        if text.count(crossing) != 1 or not allocation.start() < text.index(crossing) < text.index(boundary):
            raise ValueError('cross-PGD data proof missing/outside owned lifetime: '+device)
        if release.group(2) != str(mode):
            raise ValueError('release does not match allocated buffer: ' + device)
        if not allocation.start() < text.index(boundary) < release.start() < text.index(completed):
            raise ValueError('release outside last-unmap interval: ' + device)
        if not text.index(completed) < text.index('DMA_GUEST_PASS:') < text.index('DMA_VM_RESULT_PASS:'):
            raise ValueError('completion emitted before all case results: ' + device)
        if inject:
            fired = [match for match in selected_faults if match.group(1) == allocation.group(1) and match.group(2) == str(mode)]
            returned = [match for match in returns if match.group(1) == allocation.group(1) and match.group(2) == str(mode)]
            unwound = [match for match in unwinds if match.group(1) == allocation.group(1) and match.group(2) == str(mode)]
            retry = 'DMA_GUEST_ENOMEM_PASS: /dev/recovered-dma-audit-' + device + ' same_address_retry=1'
            if len(fired) != 1 or len(returned) != 1 or len(unwound) != 1 or text.count(retry) != 1:
                raise ValueError('partial ENOMEM ID/mode/retry mismatch: ' + device)
            before, partial, after = map(int, unwound[0].group(3, 4, 5))
            if fired[0].group(3,4,5) != (str(ordinal),str(ordinal-1),str(ordinal-1)):
                raise ValueError('fault ordinal/publication mismatch: ' + device)
            deltas = (8192,) if inject == 4 else (0,) if inject == 3 else (0,4096) if inject == 1 else (4096,8192)
            if before % 4096 or after != before or partial - before not in deltas:
                raise ValueError('page-table accounting did not return to baseline: ' + device)
            if not allocation.start() < fired[0].start() < returned[0].start() < unwound[0].start() < text.index(retry) < text.index(crossing) < text.index(boundary):
                raise ValueError('partial ENOMEM lifetime order wrong: ' + device)
            if inject >= 3:
                cold = f'DMA_GUEST_COLD_RANGE mode={mode} bytes={ordinal << 30} aligned=1'
                if text.count(cold) != 1 or not allocation.start() < text.index(cold) < fired[0].start():
                    raise ValueError('cold-PUD reservation order/mode mismatch: '+device)
    check_export_log(text)


def check_export_log(text):
    allocated = list(re.finditer(r'DMA_EXPORT_ALLOC id=([1-9][0-9]*) mode=([01]) bytes=4194304\r?\n',text))
    released = list(re.finditer(r'DMA_EXPORT_RELEASE id=([1-9][0-9]*) mode=([01])\r?\n',text))
    mappings = list(re.finditer(r'DMA_EXPORT_MMAP id=([1-9][0-9]*) mode=([01]) bytes=([0-9]+) offset=0 huge=([01]) result=0\r?\n',text))
    if (len(allocated) != 2 or len(released) != 2 or len(mappings) != 8 or
        text.count('DMA_EXPORT_ALLOC') != 2 or text.count('DMA_EXPORT_RELEASE') != 2 or
        text.count('DMA_EXPORT_MMAP') != 8 or text.count('DMA_EXPORT_ALIGN') != 8 or
        text.count('DMA_EXPORT_LAST_UNMAP') != 2 or text.count('DMA_EXPORT_CASE_PASS') != 2 or
        len({m.group(1) for m in allocated}) != 2):
        raise ValueError('missing/duplicate/malformed DMA-BUF core/export evidence')
    for mode in (0,1):
        allocations = [m for m in allocated if m.group(2) == str(mode)]
        if len(allocations) != 1:
            raise ValueError('DMA-BUF mode allocation missing/duplicate')
        allocation = allocations[0]
        releases = [m for m in released if m.group(1,2) == allocation.group(1,2)]
        boundary = 'DMA_EXPORT_LAST_UNMAP mode='+str(mode)
        complete = 'DMA_EXPORT_CASE_PASS mode='+str(mode)+' live=0'
        if len(releases) != 1 or text.count(complete) != 1 or text.count(boundary) != 1:
            raise ValueError('DMA-BUF final release/lifetime mismatch')
        if not allocation.start() < text.index(boundary) < releases[0].start() < text.index(complete) < text.index('DMA_GUEST_PASS:'):
            raise ValueError('DMA-BUF release outside final-unmap interval')
        for length,mask,huge,hint in ((4096,4095,0,0),(65536,65535,0,1),
                                      (2097152,2097151,1,1),(4194304,2097151,1,0)):
            matching = [m for m in mappings if m.group(1,2) == allocation.group(1,2) and
                        m.group(3,4) == (str(length),str(huge))]
            alignment = f'DMA_EXPORT_ALIGN mode={mode} bytes={length} mask={mask} aligned=1 hint_checked={hint}'
            if len(matching) != 1 or text.count(alignment) != 1:
                raise ValueError('DMA-BUF callback/size/alignment proof missing')
            if not allocation.start() < matching[0].start() < text.index(alignment) < text.index(boundary):
                raise ValueError('DMA-BUF callback/alignment order mismatch')


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
        'verified': ['basic guest workload', 'ten file-owned buffers freed exactly once after final unmap',
                     'PMD/PTE first and second leaf ENOMEM; publication checks and same-address retry',
                     'cold-PUD PMD-table ENOMEM in both modes; zero publication/accounting delta and retry',
                     'second cold-PUD allocation ENOMEM after one published block; exact 8KiB partial accounting and retry',
                     'ten owned 4MiB aliases cross two PGD slots with every data word verified',
                     'page-table accounting returns to baseline after selected partial ENOMEM',
                     'real DMA-BUF core to exporter mmap, 4K/64K/2M/4M alignment including nonaligned hints',
                     'two DMA-BUF-owned buffers survive fd close/fork/move until final unmap'] if reason is None else [],
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
