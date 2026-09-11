#!/usr/bin/env python3
"""Generate checked metadata from pristine ROM modules, or audit a build against it."""
import argparse
import collections
import hashlib
import importlib.util
import json
from pathlib import Path


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def generate(roots, output):
    abi = load('abi', 'audit-rom-module-abi.py')
    trust = load('trust', 'check-stock-module-trust.py')
    cert = Path(__file__).resolve().parents[1] / 'configs/rodin-stock-304-modules.pem'
    trust.certificate_der(cert)
    modules, exports, imports = [], {}, []
    for root in roots:
        paths = sorted(root.rglob('*.ko'))
        if not paths:
            raise ValueError(f'Empty module root: {root}')
        for path in paths:
            data = path.read_bytes()
            signed = data.endswith(trust.MARKER)
            if signed:
                trust.verify_module(path, cert)
            elif 'system' in root.name or 'stock-signature' in root.name:
                raise ValueError(f'Stock system module lost its signature: {path}')
            module_exports = abi.read_module_exports(path)
            for symbol, crc in module_exports.items():
                if symbol in exports and exports[symbol] != crc:
                    raise ValueError(f'Conflicting export: {symbol}')
                exports[symbol] = crc
            optional = abi.weak_imports(path)
            required = abi.read_versions(path, 'unused')
            imports.extend((name, crc, name in optional) for name, crc in required)
            modules.append({'path': root.name + '/' + path.relative_to(root).as_posix(),
                            'sha256': hashlib.sha256(data).hexdigest(),
                            'signed_by_stock': signed,
                            'vermagic': abi.modinfo_value(path, 'vermagic'),
                            'depends': abi.modinfo_value(path, 'depends') or '',
                            'imports': len(required)})
            if path.read_bytes() != data:
                raise ValueError(f'Audit modified {path}')
    kernel, optional_missing = {}, set()
    for name, crc, weak in imports:
        if name in exports:
            if exports[name] != crc:
                raise ValueError(f'Stock module-to-module CRC mismatch: {name}')
        elif weak:
            optional_missing.add(name)
        else:
            if name in kernel and kernel[name] != crc:
                raise ValueError(f'Conflicting kernel import: {name}')
            kernel[name] = crc
    report = {'schema': 1, 'certificate_sha256': trust.FINGERPRINT,
              'modules': modules, 'signed_count': sum(m['signed_by_stock'] for m in modules),
              'kernel_import_crcs': dict(sorted(kernel.items())),
              'stock_export_count': len(exports), 'import_records': len(imports),
              'optional_missing': sorted(optional_missing),
              'limitations': 'Static signature/CRC coverage, not runtime load order or hardware proof.'}
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(f'Reference: {len(modules)} modules, {report["signed_count"]} verified signatures, {len(kernel)} kernel imports')


def check(reference, symvers, image, config):
    trust = load('trust', 'check-stock-module-trust.py')
    abi = load('abi', 'audit-rom-module-abi.py')
    report = json.loads(reference.read_text())
    if report['schema'] != 1 or report['signed_count'] < 78 or len(report['modules']) != 610:
        raise ValueError('Incomplete ROM module inventory')
    cert = Path(__file__).resolve().parents[1] / 'configs/rodin-stock-304-modules.pem'
    der = trust.certificate_der(cert)
    if report['certificate_sha256'] != trust.FINGERPRINT:
        raise ValueError('Reference signer mismatch')
    trust.require_embedded(image.read_bytes(), der)
    actual = abi.read_symvers(symvers)
    errors = {name: [crc, actual.get(name)] for name, crc in report['kernel_import_crcs'].items()
              if actual.get(name) != crc}
    if errors:
        raise ValueError(f'ROM kernel imports missing/mismatched: {errors}')
    cfg = config.read_text().splitlines()
    for value in ['CONFIG_MODULE_SIG=y', 'CONFIG_MODULE_SIG_PROTECT=y', 'CONFIG_MODVERSIONS=y',
                  'CONFIG_ARM64_4K_PAGES=y']:
        if value not in cfg:
            raise ValueError(f'Missing safety configuration: {value}')
    print(f'PASS: {len(report["modules"])} module reference entries; {report["signed_count"]} signatures covered; '
          f'{len(report["kernel_import_crcs"])} kernel import CRCs match; stock certificate embedded')
    print('Hardware boot, loading order and runtime behavior remain unverified.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command', required=True)
    gen = sub.add_parser('generate')
    gen.add_argument('--root', type=Path, action='append', required=True)
    gen.add_argument('--output', type=Path, required=True)
    audit = sub.add_parser('check')
    audit.add_argument('--reference', type=Path, default=Path('configs/rodin-304-module-reference.json'))
    for name in ('symvers', 'image', 'config'):
        audit.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'generate':
        generate(args.root, args.output)
    else:
        check(args.reference, args.symvers, args.image, args.config)
