#!/usr/bin/env python3
"""Explicit read-only technical collection; never invoked by packaging."""
import argparse
import json
import shlex
from pathlib import Path
import subprocess

PATTERN = r'dmabuf_huge|dma_buf|dma-buf|mali|Mali|GPU|gpufreq|BUG:|WARNING:|Oops:|Kernel panic|Call trace:|watchdog|rcu.*stall'


def jobs(recovery):
    # No application inventories, personal storage, logcat or process memory.
    commands = [
        ('kernel', 'uname -a'),
        ('codename', 'getprop ro.product.device'),
        ('slot', 'getprop ro.boot.slot_suffix'),
        ('boot_complete', 'getprop sys.boot_completed'),
        ('snapshot_state', 'getprop ro.boot.snapshot_merge.status'),
        ('page_size', 'getconf PAGE_SIZE'),
        ('selinux_read_only', 'getenforce'),
        ('memory_totals', "grep -E '^(MemTotal|MemAvailable|Slab|PageTables):' /proc/meminfo"),
    ]
    root = [('kernel_filtered', "dmesg | grep -E '" + PATTERN + "'"),
            ('crash_console_filtered', "if [ -f /sys/fs/pstore/console-ramoops-0 ]; then grep -E '" +
             PATTERN + "' /sys/fs/pstore/console-ramoops-0; fi")]
    return [(name, ['adb', 'shell', command]) for name, command in commands] + [
        (name, ['adb', 'shell', command] if recovery else ['adb', 'shell', 'su -c ' + shlex.quote(command)])
        for name, command in root]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--recovery', action='store_true')
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('refuse existing report')
    if subprocess.check_output(['adb', 'get-state'], timeout=10).strip() != b'device':
        raise ValueError('one authorized ADB device required')
    results = []
    for name, command in jobs(args.recovery):
        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
        results.append(dict(name=name, exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr))
    with args.output.open('x') as stream:
        json.dump(dict(status='READ_ONLY_TECHNICAL_SNAPSHOT_NOT_ACTIVATION_PROOF', results=results), stream, indent=2)
        stream.write('\n')
    print(args.output)


if __name__ == '__main__':
    main()
