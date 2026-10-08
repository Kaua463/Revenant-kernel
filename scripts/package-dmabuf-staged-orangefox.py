#!/usr/bin/env python3
"""Package a pinned, experimental boot-only test plus exact working rollback."""
import argparse
import hashlib
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path
import struct
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
boot = SourceFileLoader('staged_boot_audit', str(ROOT / 'scripts/audit-dmabuf-boot-offline.py')).load_module()
export = SourceFileLoader('staged_export_gate', str(ROOT / 'scripts/export-dmabuf-hardware-test.py')).load_module()
reference = SourceFileLoader('staged_module_gate', str(ROOT / 'scripts/rom-module-reference.py')).load_module()
STOCK_TEMPLATE = ROOT / 'packaging/rodin'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def archive(path, files):
    files = dict(files)
    files['SHA256SUMS'] = ''.join(f'{sha(value)}  {name}\n' for name, value in sorted(files.items())).encode()
    with zipfile.ZipFile(path, 'x', zipfile.ZIP_DEFLATED, compresslevel=6) as stream:
        for name, value in sorted(files.items()):
            entry = zipfile.ZipInfo(name)
            entry.external_attr = (0o100755 if name.endswith('update-binary') or name.startswith('tools/') else 0o100644) << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            stream.writestr(entry, value)
    with zipfile.ZipFile(path) as stream:
        if stream.testzip() is not None or len(stream.namelist()) != len(files):
            raise ValueError('archive corruption/duplicate members')
        for line in stream.read('SHA256SUMS').decode().splitlines():
            expected, name = line.split('  ', 1)
            if sha(stream.read(name)) != expected:
                raise ValueError('archive checksum mismatch: ' + name)


def script(mode, payload, payload_hash, binaries):
    text = (ROOT / 'packaging/dma-staged/update-binary.sh').read_text()
    substitutions = {'MODE': mode, 'BOOT_SHA': boot.BOOT_SHA, 'PAYLOAD_NAME': payload,
                     'PAYLOAD_SHA': payload_hash, 'BUSYBOX_SHA': sha(binaries['tools/busybox']),
                     'MAGISKBOOT_SHA': sha(binaries['tools/magiskboot'])}
    for name, value in substitutions.items():
        text = text.replace('@' + name + '@', value)
    if '@' in text:
        raise ValueError('unexpanded installer token')
    subprocess.run(['bash', '-n'], input=text.encode(), check=True)
    return text.encode()


def run(args):
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('refuse existing output')
    for path, expected in ((args.backup, boot.BOOT_SHA), (args.recovery, boot.RECOVERY_SHA),
                           (args.dist / 'Image', boot.IMAGE_SHA)):
        if path.is_symlink() or sha(path.read_bytes()) != expected:
            raise ValueError('pinned input mismatch: ' + str(path))
    export.validate_evidence(args.dist, args.dist / 'Image')
    reference.check(ROOT / 'configs/rodin-304-module-reference.json', args.dist / 'Module.symvers',
                    args.dist / 'Image', args.dist / 'config')
    image = (args.dist / 'Image').read_bytes()
    backup = args.backup.read_bytes()
    layout = boot.boot_layout(backup)
    if layout['ramdisk_bytes'] or layout['gki_signature_bytes'] or layout['header_version'] != 4:
        raise ValueError('unsupported boot layout')
    installed = subprocess.run(['lz4', '-d', '-c'], input=backup[4096:4096+layout['kernel_bytes']],
                               capture_output=True, check=True, timeout=30).stdout
    delta = boot.config_difference(boot.embedded_config(installed), boot.embedded_config(image))
    if boot.embedded_config(image) != (args.dist / 'config').read_bytes():
        raise ValueError('embedded/exported config drift')
    if b'recovered-dma-audit' in image or b'DMA_VMA_FAULT' in image:
        raise ValueError('audit producer/trace in shipping candidate')
    tools = {}
    pins = dict((name, digest) for digest, name in
                (line.split('  ', 1) for line in (ROOT / 'packaging/rodin-template.sha256').read_text().splitlines()))
    for name in ('tools/busybox', 'tools/magiskboot'):
        data = (STOCK_TEMPLATE / name).read_bytes()
        if sha(data) != pins[name] or data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', data, 18)[0] != 183:
            raise ValueError('pinned AArch64 executable mismatch')
        tools[name] = data
    args.output.mkdir()
    # Create and verify restoration first, before exposing the flash ZIP.
    packages = []
    for mode, name, payload, data in (
            ('restore', 'Revenant-rodin-no-DMA-RESTORE-OrangeFox.zip', 'boot-restore.img', backup),
            ('preflight', 'Revenant-rodin-DMA-PRECHECK-NO-FLASH-OrangeFox.zip', 'Image', image),
            ('flash', 'Revenant-rodin-DMA-EXPERIMENTAL-OrangeFox.zip', 'Image', image)):
        files = {payload: data, 'tools/busybox': tools['tools/busybox'],
                 'META-INF/com/google/android/updater-script': b'# Recovery update-binary package\n',
                 'META-INF/com/google/android/update-binary': script(mode, payload, sha(data), tools),
                 'PACKAGE_INFO.txt': (f'Operation: {mode}\nDevice: rodin; verified slot: A only\n'
                                      f'Rollback boot SHA256: {boot.BOOT_SHA}\nPayload SHA256: {sha(data)}\n'
                                      'EXPERIMENTAL: no hardware acceptance guarantee; no data wipe; boot only.\n').encode()}
        if mode in ('flash', 'preflight'):
            files['tools/magiskboot'] = tools['tools/magiskboot']
        path = args.output / name
        archive(path, files)
        packages.append(dict(file=name, sha256=sha(path.read_bytes()), bytes=path.stat().st_size))
    evidence = dict(status='EXPERIMENTAL_PACKAGES_OFFLINE_VERIFIED_NOT_FLASHED', packages=packages,
                    candidate_image_sha256=sha(image), rollback_boot_sha256=sha(backup),
                    recovery_sha256=sha(args.recovery.read_bytes()), config_delta=delta,
                    gates=['610 module rows / 3506 CRC imports / 78 signatures', 'pinned AArch64 tools',
                           'exact working boot rollback packaged first', 'only DMA config delta',
                           'actual repack/kernel/header/footer check occurs in recovery before writes'],
                    pending=['live slot/snapshot/current boot identity', 'recovery repack execution',
                             'hardware boot/peripherals', 'stock mapper activation'],
                    avb_note='Working backup has a stale boot hash descriptor. No valid Xiaomi signature claim; '
                             'no vbmeta partition write or verification-disabling flags requested.')
    (args.output / 'package-evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print(evidence['status'], args.output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('dist', 'backup', 'recovery', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    run(parser.parse_args())
