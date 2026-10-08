#!/usr/bin/env python3
"""Read-only boot geometry and backup audit. Never packs or approves a flash."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

PAGE = 4096
PARTITION = 64 * 1024 * 1024
BOOT_SHA = 'e99184cfed1bdd747a9b2d63fcf30398e71c3e2529ca418432df7992a9bb7f24'
RECOVERY_SHA = 'ba23ef2949f9f9671c68be6b129d97e670b23ab1c7e416ceb3c6333d236f5770'
IMAGE_SHA = '85edf0c274cf26db611e46b014a2070284587bbc0b5ac3f2d7b5fc09b437517f'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def align(value):
    return (value + PAGE - 1) // PAGE * PAGE


def embedded_config(image):
    if image.count(b'IKCFG_ST') != 1 or image.count(b'IKCFG_ED') != 1:
        raise ValueError('unique embedded kernel config required')
    start = image.index(b'IKCFG_ST') + 8
    end = image.index(b'IKCFG_ED')
    if end <= start:
        raise ValueError('embedded config extent invalid')
    return gzip.decompress(image[start:end])


def config_difference(installed, candidate):
    def parse(data):
        return dict(line.split('=', 1) for line in data.decode().splitlines()
                    if line.startswith('CONFIG_') and '=' in line)
    a, b = parse(installed), parse(candidate)
    differences = {key: [a.get(key), b.get(key)] for key in sorted(a.keys() | b.keys())
                   if a.get(key) != b.get(key)}
    if differences != {'CONFIG_XIAOMI_DMABUF_HUGETLB': [None, 'y']}:
        raise ValueError('candidate config changes more than requested DMA flag')
    return differences


def boot_layout(data):
    if len(data) != PARTITION or data[:8] != b'ANDROID!':
        raise ValueError('64 MiB Android boot partition required')
    kernel, ramdisk, os_version, header_size = struct.unpack_from('<4I', data, 8)
    version = struct.unpack_from('<I', data, 40)[0]
    signature = struct.unpack_from('<I', data, 1580)[0]
    if version != 4 or header_size != 1584 or data[24:40] != bytes(16):
        raise ValueError('exact v4 header/reserved fields required')
    end = PAGE + align(kernel) + align(ramdisk) + align(signature)
    if not kernel or end > len(data) - 64:
        raise ValueError('invalid boot payload extent')
    magic, major, minor, original, vbmeta, size = struct.unpack_from('>4sIIQQQ', data, len(data) - 64)
    if magic != b'AVBf' or major != 1 or minor != 0:
        raise ValueError('AVB footer required')
    if not end <= original <= vbmeta or not 256 <= size <= len(data) - 64 - vbmeta:
        raise ValueError('AVB bounds overlap/truncation')
    if data[vbmeta:vbmeta + 4] != b'AVB0':
        raise ValueError('vbmeta magic required')
    return dict(header_version=version, kernel_bytes=kernel, ramdisk_bytes=ramdisk,
                os_version=hex(os_version), command_line_hex=data[44:1580].hex(),
                gki_signature_bytes=signature, payload_end=end,
                avb_original_bytes=original, vbmeta_offset=vbmeta, vbmeta_bytes=size,
                kernel_prefix_hex=data[PAGE:PAGE + 4].hex())


def arm64_layout(data):
    if len(data) < 64 or struct.unpack_from('<I', data, 56)[0] != 0x644d5241:
        raise ValueError('raw ARM64 Image required')
    offset, size, flags = struct.unpack_from('<3Q', data, 8)
    # image_size is the required RAM span, not the file length (e.g. BSS).
    # https://www.kernel.org/doc/html/latest/arch/arm64/booting.html
    if size < 64 or flags & 1 or (flags >> 1) & 3 != 1 or flags >> 4:
        raise ValueError('little-endian 4K Image header required')
    # Conservative raw/uncompressed geometry; compression is not needed to fit.
    if PAGE + align(len(data)) > PARTITION - PAGE:
        raise ValueError('candidate does not leave room for boot metadata')
    return dict(file_bytes=len(data), required_ram_bytes=size, text_offset=offset,
                flags=hex(flags), raw_payload_fits=True)


def run(args):
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('refuse existing output')
    inputs = {}
    for label, path, expected in [('boot_backup', args.boot, BOOT_SHA),
                                  ('recovery_backup', args.recovery, RECOVERY_SHA),
                                  ('candidate', args.image, IMAGE_SHA)]:
        if path.is_symlink() or not path.is_file():
            raise ValueError('regular technical input required')
        data = path.read_bytes()
        if digest(data) != expected:
            raise ValueError('pinned input identity mismatch: ' + label)
        inputs[label] = data
    layout = boot_layout(inputs['boot_backup'])
    candidate = arm64_layout(inputs['candidate'])
    compressed = inputs['boot_backup'][PAGE:PAGE + layout['kernel_bytes']]
    decoded = subprocess.run(['lz4', '--decompress', '--stdout'], input=compressed,
                             capture_output=True, timeout=30, check=True).stdout
    installed_config = embedded_config(decoded)
    candidate_config = embedded_config(inputs['candidate'])
    if candidate_config != args.config.read_bytes():
        raise ValueError('candidate embedded config differs from exported evidence')
    differences = config_difference(installed_config, candidate_config)
    if len(inputs['recovery_backup']) != PARTITION or inputs['recovery_backup'][:8] != b'VNDRBOOT':
        raise ValueError('vendor recovery geometry mismatch')
    with tempfile.TemporaryDirectory() as folder:
        # avbtool resolves a boot descriptor to boot.img, not an arbitrary name.
        boot = Path(folder) / 'boot.img'
        boot.write_bytes(inputs['boot_backup'])
        info = subprocess.run(['python3', str(args.avbtool), 'info_image', '--image', str(boot)],
                              capture_output=True, text=True, check=True)
        verify = subprocess.run(['python3', str(args.avbtool), 'verify_image', '--image', str(boot)],
                                capture_output=True, text=True)
        if boot.read_bytes() != inputs['boot_backup']:
            raise ValueError('read-only AVB verification mutated input')
    result = dict(status='OFFLINE_LAYOUT_AND_BACKUP_IDENTITY_ONLY_NOT_FLASH_APPROVAL',
                  inputs={k: dict(sha256=digest(v), bytes=len(v)) for k, v in inputs.items()},
                  boot_layout=layout, candidate_layout=candidate,
                  installed_image_sha256=digest(decoded),
                  installed_config_sha256=digest(installed_config),
                  candidate_config_sha256=digest(candidate_config),
                  config_differences=differences,
                  avbtool_sha256=digest(args.avbtool.read_bytes()),
                  avb_info=info.stdout, avb_verify_exit=verify.returncode,
                  avb_verify_output=verify.stdout + verify.stderr,
                  avb_verification_passed=verify.returncode == 0,
                  limits=['embedded public key is not device trust verification',
                          'pinned prior device backups; device not reread in this audit',
                          'no new boot container, installer, signature removal or flash',
                          'raw size fit does not prove bootloader acceptance or hardware boot'])
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(result['status'])
    print('Backup AVB content verification:', 'PASS' if verify.returncode == 0 else 'FAIL (not flash approval)')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('boot', 'recovery', 'image', 'config', 'avbtool', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    run(parser.parse_args())
