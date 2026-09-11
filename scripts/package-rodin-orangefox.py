#!/usr/bin/env python3
"""Produce a directly flashable OrangeFox ZIP only after stock module gates pass."""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dist', type=Path, required=True)
    parser.add_argument('--run-id', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9]+', args.run_id):
        raise ValueError('Invalid run identifier')
    dist = args.dist.resolve()
    spec = importlib.util.spec_from_file_location('reference', ROOT / 'scripts/rom-module-reference.py')
    ref = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ref)
    ref.check(ROOT / 'configs/rodin-304-module-reference.json', dist / 'Module.symvers', dist / 'Image', dist / 'config')
    image = (dist / 'Image').read_bytes()
    if image[56:60] != b'ARM\x64' or not 0 < len(image) < 64 * 1024 * 1024:
        raise ValueError('Invalid ARM64 kernel payload')
    banner = b'Linux version 6.6.77-android15-8-gca30f3b4bef6-abogki440974771-4k '
    if banner not in image:
        raise ValueError('Unexpected kernel release')
    sha = lambda data: hashlib.sha256(data).hexdigest()
    template = ROOT / 'packaging/rodin'
    for line in (ROOT / 'packaging/rodin-template.sha256').read_text().splitlines():
        expected, name = line.split('  ', 1)
        if sha((template / name).read_bytes()) != expected:
            raise ValueError(f'Unreviewed installer template change: {name}')
    target = dist / f'Revenant-rodin-DyperOS304-{args.run_id}-EXPERIMENTAL-OrangeFox.zip'
    if target.exists():
        raise ValueError('Refusing to overwrite an existing package')
    with tempfile.TemporaryDirectory(prefix='rodin-package-') as tmp:
        stage = Path(tmp) / 'install'
        shutil.copytree(template, stage)
        ak = stage / 'anykernel.sh'
        ak.write_text(ak.read_text().replace('@IMAGE_SHA256@', sha(image)).replace('@RUN_ID@', args.run_id))
        (stage / 'Image').write_bytes(image)
        (stage / 'PACKAGE_INFO.txt').write_text(
            f'Actions run: {args.run_id}\nImage SHA256: {sha(image)}\n'
            'EXPERIMENTAL: no hardware boot or peripheral guarantee.\n'
            'Only current-slot boot is written; no data wipe or module replacement.\n'
            'Requires exact stock boot hash 3c555f2f5dda7b6085dd38a2869d23ffe680c05d5bcc59625885b726690a00ce.\n'
            'Keep the matching full stock boot backup on your computer for fastboot rollback.\n')
        for path in stage.rglob('*'):
            if not path.is_file():
                continue
            data = path.read_bytes()
            if data.startswith(b'\x7fELF') and (data[4:6] != b'\x02\x01' or struct.unpack_from('<H', data, 18)[0] != 183):
                raise ValueError(f'Non-AArch64 installer executable: {path}')
        for name in ['anykernel.sh', 'tools/ak3-core.sh', 'META-INF/com/google/android/update-binary']:
            subprocess.run(['bash', '-n', str(stage / name)], check=True)
        files = sorted(p for p in stage.rglob('*') if p.is_file())
        manifest = ''.join(f'{sha(p.read_bytes())}  {p.relative_to(stage).as_posix()}\n' for p in files)
        (stage / 'SHA256SUMS').write_text(manifest)
        with zipfile.ZipFile(target, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as z:
            for path in sorted(p for p in stage.rglob('*') if p.is_file()):
                z.write(path, path.relative_to(stage).as_posix())
        with zipfile.ZipFile(target) as z:
            if z.testzip() is not None or z.read('Image') != image:
                raise ValueError('ZIP payload/integrity failure')
            for line in z.read('SHA256SUMS').decode().splitlines():
                expected, name = line.split('  ', 1)
                if sha(z.read(name)) != expected:
                    raise ValueError(f'ZIP checksum failed: {name}')
    print(f'Flashable ZIP verified: {target}')


if __name__ == '__main__':
    main()
