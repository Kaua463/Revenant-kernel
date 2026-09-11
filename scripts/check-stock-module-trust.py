#!/usr/bin/env python3
"""Pin the ROM public certificate and verify stock module signatures, not just CRCs."""
import argparse
import hashlib
from pathlib import Path
import ssl
import struct
import subprocess
import tempfile

FINGERPRINT = '5ebc9677a7726f47d4ec021753617a197d3777eabce29fb338eddd6a1f3f7424'
MARKER = b'~Module signature appended~\n'


def certificate_der(path):
    der = ssl.PEM_cert_to_DER_cert(path.read_text())
    if hashlib.sha256(der).hexdigest() != FINGERPRINT:
        raise ValueError('Unexpected ROM certificate fingerprint')
    return der


def require_embedded(image, der):
    if der not in image:
        raise ValueError('Stock module signing certificate absent from candidate Image')


def signed_parts(data):
    if not data.endswith(MARKER):
        raise ValueError('Expected signed stock module; signature missing')
    end = len(data) - len(MARKER)
    if end < 12:
        raise ValueError('Truncated module signature metadata')
    meta = data[end - 12:end]
    size = struct.unpack('>I', meta[8:12])[0]
    if meta[2] != 2 or meta[3:8] != bytes(5) or not 0 < size < end - 12:
        raise ValueError('Invalid PKCS7 module signature metadata')
    return data[:end - 12 - size], data[end - 12 - size:end - 12]


def verify_module(module, certificate):
    original = module.read_bytes()
    content, signature = signed_parts(original)
    with tempfile.TemporaryDirectory(prefix='rodin-signature-') as tmp:
        tmp = Path(tmp)
        (tmp / 'content').write_bytes(content)
        (tmp / 'signature').write_bytes(signature)
        # -noverify skips X.509 CA/time policy only, never the CMS signature.
        # Trust is pinned above; -nointern forbids a signature-supplied signer.
        result = subprocess.run([
            'openssl', 'cms', '-verify', '-binary', '-inform', 'DER',
            '-in', str(tmp / 'signature'), '-content', str(tmp / 'content'),
            '-certfile', str(certificate), '-nointern', '-noverify',
            '-out', '/dev/null'], capture_output=True, text=True)
    if result.returncode:
        raise ValueError(f'{module}: {result.stderr.strip()}')
    if module.read_bytes() != original:
        raise ValueError(f'Audit modified input: {module}')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--certificate', type=Path, default=Path('configs/rodin-stock-304-modules.pem'))
    parser.add_argument('--image', type=Path)
    parser.add_argument('--modules', type=Path)
    args = parser.parse_args()
    der = certificate_der(args.certificate)
    if args.image:
        require_embedded(args.image.read_bytes(), der)
    if args.modules:
        modules = sorted(args.modules.rglob('*.ko'))
        if not modules:
            raise ValueError('No modules found')
        for module in modules:
            verify_module(module, args.certificate)
        print(f'{len(modules)} stock module signatures verified; inputs unchanged')
    print('Pinned ROM public certificate verified' + (' inside Image' if args.image else ''))


if __name__ == '__main__':
    main()
