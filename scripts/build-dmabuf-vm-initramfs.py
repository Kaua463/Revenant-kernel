#!/usr/bin/env python3
"""Build RAM-only deterministic newc initramfs from two static ARM64 audit ELFs."""
import argparse
import hashlib
import json
from pathlib import Path
import stat
import struct


def static_arm64(data):
    if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('64-bit little-endian ELF required')
    if struct.unpack_from('<HH', data, 16) != (2, 183):
        raise ValueError('static executable AArch64 ELF required')
    offset = struct.unpack_from('<Q', data, 32)[0]
    size, count = struct.unpack_from('<HH', data, 54)
    if size != 56 or not count or offset > len(data) or count > (len(data) - offset) // size:
        raise ValueError('invalid ELF program headers')
    for index in range(count):
        if struct.unpack_from('<I', data, offset + index * size)[0] == 3:
            raise ValueError('dynamic interpreter forbidden')


def newc(entries):
    archive = bytearray()
    for inode, (name, mode, data, major, minor) in enumerate(entries + [('TRAILER!!!', 0, b'', 0, 0)], 1):
        encoded = name.encode('ascii') + b'\0'
        fields = (inode, mode, 0, 0, 1, 0, len(data), 0, 0, major, minor, len(encoded), 0)
        archive.extend(b'070701' + ''.join(f'{field:08x}' for field in fields).encode('ascii'))
        archive.extend(encoded)
        archive.extend(b'\0' * (-len(archive) % 4))
        archive.extend(data)
        archive.extend(b'\0' * (-len(archive) % 4))
    archive.extend(b'\0' * (-len(archive) % 512))
    return bytes(archive)


def build(init, guest):
    static_arm64(init)
    static_arm64(guest)
    entries = [(name, stat.S_IFDIR | 0o755, b'', 0, 0) for name in ('dev', 'proc', 'sys', 'tmp')]
    entries += [('dev/console', stat.S_IFCHR | 0o600, b'', 5, 1),
                ('init', stat.S_IFREG | 0o755, init, 0, 0),
                ('guest', stat.S_IFREG | 0o755, guest, 0, 0)]
    return newc(entries)


def run(args):
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('output already exists')
    data = build(args.init.read_bytes(), args.guest.read_bytes())
    with args.output.open('xb') as stream:
        stream.write(data)
    print(json.dumps({'status': 'RAM_ONLY_ARCHIVE_NOT_RUNTIME_PROOF',
                      'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('init', 'guest', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    run(parser.parse_args())
