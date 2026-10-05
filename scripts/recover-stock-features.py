#!/usr/bin/env python3
"""Read-only stock feature recovery: raw bytes, disassembly and direct BL xrefs.

Inferred kallsyms spans are not ELF sizes; direct calls are not a complete graph.
No decompiler output, ABI compatibility or hardware success is claimed.
"""
import argparse
from bisect import bisect_right
from collections import defaultdict
import csv
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess

BOOT_SHA = '3c555f2f5dda7b6085dd38a2869d23ffe680c05d5bcc59625885b726690a00ce'
IMAGE_SHA = '99485b0132e3aa28f4e965119591c8149fe3c20e7e0fd10d753ef014a582472e'
FAMILIES = {
    'dmabuf_hugetlb': ('CONFIG_XIAOMI_DMABUF_HUGETLB', r'dmabuf_huge'),
    'xring_lb': ('CONFIG_XRING_LB', r'xring_lb'),
    'f2fs_fastdiscard': ('CONFIG_F2FS_FASTDISCARD', r'fastdiscard'),
    'scsi_fastdiscard': ('CONFIG_SCSI_FASTDISCARD', r'scsi.*fastdiscard|fastdiscard.*scsi'),
    'scsi_discard': ('CONFIG_SCSI_DISCARD', r'scsi.*discard|discard.*scsi'),
    'enhanced_iostat': ('CONFIG_XIAOMI_ENHANCED_IOSTAT', r'^(?!.*erofs).*iostat'),
    'erofs_iostat': ('CONFIG_XIAOMI_EROFS_IOSTAT', r'erofs.*iostat'),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def bl_target(word, address):
    if word & 0xfc000000 != 0x94000000:
        return None
    immediate = word & 0x03ffffff
    if immediate & 0x02000000:
        immediate -= 0x04000000
    return address + immediate * 4


def stock_payload(boot):
    if sha(boot) != BOOT_SHA:
        raise ValueError('boot does not match the pinned DyperOS 3.0.304 reference')
    if boot[:8] != b'ANDROID!' or struct.unpack_from('<I', boot, 40)[0] != 4:
        raise ValueError('expected Android boot header v4')
    size = struct.unpack_from('<I', boot, 8)[0]
    packed = boot[4096:4096 + size]
    if len(packed) != size:
        raise ValueError('truncated kernel payload')
    image = subprocess.run(['lz4', '-d', '-c'], input=packed,
                           capture_output=True, check=True).stdout
    if sha(image) != IMAGE_SHA:
        raise ValueError('decompressed Image differs from the recorded stock reference')
    return image


def run(args):
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    spec = importlib.util.spec_from_file_location('stock_compare',
                                                 Path(__file__).with_name('compare-kernel-images.py'))
    compare = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(compare)
    if args.output.exists():
        raise ValueError('output must not exist; preserve previous evidence')
    boot = args.boot.read_bytes()
    image = stock_payload(boot)
    symbols_bytes = args.symbols.read_bytes()
    expected = json.loads((args.comparison / 'summary.json').read_text())['inputs']
    expected_symbol_sha = next(v for k, v in expected.items() if k.endswith('/stock.kallsyms'))
    if sha(symbols_bytes) != expected_symbol_sha:
        raise ValueError('stock kallsyms differs from recorded reference')
    # Validate previous CSV provenance before using its candidate classifications.
    manifest = json.loads((args.comparison / 'manifest.json').read_text())
    for filename in ('config-all.csv', 'symbols-stock-only.csv'):
        if sha((args.comparison / filename).read_bytes()) != manifest[filename]:
            raise ValueError('comparison evidence hash mismatch: ' + filename)
    args.output.mkdir(parents=True)
    image_path = args.output / 'stock.Image'
    image_path.write_bytes(image)
    kernel = compare.Kernel(image_path, args.symbols)
    exports = kernel.exports()
    matches = {family: [n for n in sorted(kernel.symbols) if re.search(pattern, n, re.I)]
               for family, (_, pattern) in FAMILIES.items()}
    selected = set().union(*map(set, matches.values()))
    addresses = sorted(kernel.names_at)
    direct = []
    # Scan every backed code symbol, not just selected functions, for incoming BLs.
    for address, kind, caller in kernel.entries:
        if kind not in 'tT':
            continue
        data = kernel.span(caller)
        if data is None:
            continue
        for offset in range(0, len(data) - 3, 4):
            target = bl_target(struct.unpack_from('<I', data, offset)[0], address + offset)
            if target is None:
                continue
            index = bisect_right(addresses, target) - 1
            if index < 0:
                continue
            target_base = addresses[index]
            # Reject targets outside a known, file-backed symbol span.
            end = kernel.next_address.get(target_base)
            if end is None or target >= end or not 0 <= target - kernel.base < len(image):
                continue
            names = kernel.names_at[target_base]
            if caller in selected or any(n in selected for n in names):
                direct.append({'caller': caller, 'site': hex(address + offset),
                               'target': hex(target), 'target_names': names,
                               'target_offset': target - target_base,
                               'evidence': 'decoded_BL_in_inferred_code_span;not_runtime_proof'})
    configs = {r['name']: r for r in csv.DictReader((args.comparison / 'config-all.csv').open())}
    missing = {r['name'] for r in csv.DictReader((args.comparison / 'symbols-stock-only.csv').open())}
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    decoder.skipdata = True
    records = []
    for family, (config_key, _) in FAMILIES.items():
        folder = args.output / family
        folder.mkdir()
        evidence = []
        for name in matches[family]:
            rows = kernel.symbols[name]
            data = kernel.span(name)
            entry = {'name': name, 'locations': [(hex(a), k) for a, k, _ in rows],
                     'stock_export_crc': exports.get(name),
                     'absent_in_previous_candidate_symbols': name in missing,
                     'span_kind': 'next-distinct-symbol;not_ELF_size',
                     'span_sha256': sha(data) if data is not None else None}
            if len(rows) == 1 and data is not None:
                # Sanitize generated filenames without dropping original symbol names in JSON.
                stem = re.sub(r'[^A-Za-z0-9_.-]', '_', name)
                (folder / (stem + '.bin')).write_bytes(data)
            if len(rows) == 1 and rows[0][1] in 'tT' and data is not None:
                disassembly = [f'{i.address:#x}\t{i.bytes.hex()}\t{i.mnemonic}\t{i.op_str}'
                               for i in decoder.disasm(data, rows[0][0])]
                (folder / (stem + '.asm')).write_text('\n'.join(disassembly) + '\n')
                entry['decoded_span_bytes'] = sum(len(i.bytes) for i in decoder.disasm(data, rows[0][0]))
            evidence.append(entry)
        calls = [c for c in direct if c['caller'] in matches[family]
                 or set(c['target_names']).intersection(matches[family])]
        record = {'family': family, 'stock_config': kernel.cfg.get(config_key, 'not_recorded'),
                  'old_comparison_config': configs.get(config_key),
                  'identification': 'name_based_candidates;unmatched_shared_functions_not_excluded',
                  'symbols': evidence, 'direct_calls': calls,
                  'implementation_status': 'not_reimplemented;contracts_and_runtime_unverified'}
        (folder / 'evidence.json').write_text(json.dumps(record, indent=2) + '\n')
        records.append(record)
        print(f'{family}: {len(evidence)} símbolos candidatos; {len(calls)} referências BL', flush=True)
    summary = {'boot_sha256': sha(boot), 'stock_image_sha256': sha(image),
               'kallsyms_sha256': sha(symbols_bytes),
               'candidate_scope': 'historical comparison, not current installed Revenant',
               'families': [{k: v for k, v in r.items() if k not in ('symbols', 'direct_calls')}
                            | {'symbol_count': len(r['symbols']), 'direct_call_count': len(r['direct_calls'])}
                            for r in records],
               'limits': ['symbol names do not prove feature ownership',
                          'shared/renamed/inlined functions may be missed',
                          'indirect/tail calls and dynamic lookup not captured',
                          'data and BSS semantics not recovered',
                          'no source implementation or hardware validation']}
    (args.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    lines = ['# Recuperação inicial de recursos Xiaomi', '',
             'Bytes e disassembly extraídos do stock exato; não é implementação nem RE completo.', '',
             '|Família|Símbolos candidatos|Referências BL|', '|---|---|---|']
    lines += [f'|{r["family"]}|{len(r["symbols"])}|{len(r["direct_calls"])}|' for r in records]
    lines += ['', 'Cada diretório contém evidence.json e os trechos .bin/.asm disponíveis.',
              'CONFIGs e ausências referem-se ao comparativo histórico; não ao build atual.',
              'Nenhum consumidor indireto ou contrato funcional considerado comprovado apenas por estes dados.']
    (args.output / 'LEIA-ME.md').write_text('\n'.join(lines) + '\n')
    hashes = {str(p.relative_to(args.output)): sha(p.read_bytes())
              for p in sorted(args.output.rglob('*')) if p.is_file()}
    (args.output / 'manifest.json').write_text(json.dumps(hashes, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('boot', 'symbols', 'comparison', 'output'):
        parser.add_argument('--' + key, type=Path, required=True)
    run(parser.parse_args())
