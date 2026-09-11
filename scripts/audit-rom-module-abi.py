#!/usr/bin/env python3
"""Compare ROM module ABI requirements with a candidate Module.symvers/module set."""

import argparse
import collections
import json
import pathlib
import struct
import subprocess


def read_versions(module: pathlib.Path, objcopy: str):
    proc = subprocess.run(
        [objcopy, "--dump-section=__versions=/dev/stdout", str(module)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    data = proc.stdout
    if proc.returncode or not data:
        raise ValueError(f"cannot read module versions: {module}")
    if len(data) % 64:
        raise ValueError(f"invalid __versions size: {module}: {len(data)}")
    result = []
    for offset in range(0, len(data), 64):
        record = data[offset : offset + 64]
        crc = struct.unpack_from("<Q", record)[0] & 0xFFFFFFFF
        name = record[8:].split(b"\0", 1)[0].decode("ascii", "strict")
        result.append((name, crc))
    return result


def modinfo_value(module: pathlib.Path, key: str):
    proc = subprocess.run(
        ["strings", str(module)], stdout=subprocess.PIPE, check=True, text=True
    )
    prefix = key + "="
    for line in proc.stdout.splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :]
    return None


def read_symvers(path: pathlib.Path):
    symbols = {}
    for line in path.read_text().splitlines():
        fields = line.split()
        if len(fields) >= 2:
            symbols[fields[1]] = int(fields[0], 16)
    return symbols


def read_module_exports(module: pathlib.Path):
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError as exc:
        raise SystemExit("--stock-providers requires pyelftools") from exc
    result = {}
    with module.open("rb") as stream:
        elf = ELFFile(stream)
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            return result
        for symbol in symtab.iter_symbols():
            if not symbol.name.startswith("__crc_"):
                continue
            section_index = symbol.entry["st_shndx"]
            if not isinstance(section_index, int):
                continue
            section = elf.get_section(section_index)
            offset = symbol.entry["st_value"]
            data = section.data()[offset : offset + 4]
            if len(data) == 4:
                result[symbol.name[6:]] = struct.unpack("<I", data)[0]
    return result


def weak_imports(module):
    from elftools.elf.elffile import ELFFile
    with module.open('rb') as stream:
        elf = ELFFile(stream)
        symtab = elf.get_section_by_name('.symtab')
        if symtab is None:
            raise ValueError(f'missing ELF symbol table: {module}')
        return {s.name for s in symtab.iter_symbols()
                if s.entry['st_shndx'] == 'SHN_UNDEF'
                and s.entry['st_info']['bind'] == 'STB_WEAK'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stock-modules", type=pathlib.Path, required=True)
    parser.add_argument("--extra-stock-modules", type=pathlib.Path, action="append", default=[])
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--candidate-modules", type=pathlib.Path, required=True)
    parser.add_argument("--candidate-symvers", type=pathlib.Path, required=True)
    parser.add_argument("--stock-providers", action="store_true")
    parser.add_argument("--objcopy", required=True)
    parser.add_argument("--json", type=pathlib.Path, required=True)
    args = parser.parse_args()

    stock = sorted(args.stock_modules.rglob("*.ko"))
    for root in args.extra_stock_modules:
        extra = sorted(root.rglob("*.ko"))
        if not extra:
            raise ValueError(f"empty module source: {root}")
        stock.extend(extra)
    if not stock:
        raise ValueError("no stock modules found")
    candidate = sorted(args.candidate_modules.rglob("*.ko"))
    candidate_by_name = collections.defaultdict(list)
    for module in candidate:
        candidate_by_name[module.name].append(str(module))
    symvers = read_symvers(args.candidate_symvers)
    stock_exports = {}
    if args.stock_providers:
        for module in stock:
            for name, crc in read_module_exports(module).items():
                old = stock_exports.setdefault(name, crc)
                if old != crc:
                    raise ValueError(f"conflicting stock provider CRC for {name}")

    symbol_state = collections.Counter()
    module_rows = []
    vermagic = collections.Counter()
    unique_imports = {}
    for module in stock:
        states = collections.Counter()
        optional = weak_imports(module)
        for name, stock_crc in read_versions(module, args.objcopy):
            provider = "stock_module" if name in stock_exports else "candidate_kernel"
            candidate_crc = stock_exports.get(name, symvers.get(name))
            if candidate_crc is None:
                state = "optional_weak_missing" if name in optional else "missing"
            elif candidate_crc != stock_crc:
                state = "crc_mismatch"
            else:
                state = "match"
            states[state] += 1
            old = unique_imports.get(name)
            row = {"stock_crc": f"0x{stock_crc:08x}", "candidate_crc": None if candidate_crc is None else f"0x{candidate_crc:08x}", "provider": provider, "state": state}
            if old is not None and old != row:
                raise ValueError(f"inconsistent stock CRC for {name}")
            unique_imports[name] = row
        vm = modinfo_value(module, "vermagic")
        vermagic[vm or "<missing>"] += 1
        module_rows.append({
            "path": str(module),
            "basename_in_candidate": module.name in candidate_by_name,
            "imports": sum(states.values()),
            **states,
        })
        symbol_state.update(states)

    unique_states = collections.Counter(row["state"] for row in unique_imports.values())
    report = {
        "stock_module_count": len(stock),
        "candidate_module_count": len(candidate),
        "stock_basenames_present_in_candidate": sum(row["basename_in_candidate"] for row in module_rows),
        "stock_basenames_absent_from_candidate": sum(not row["basename_in_candidate"] for row in module_rows),
        "stock_vermagic": dict(vermagic),
        "import_records": dict(symbol_state),
        "unique_import_symbols": dict(unique_states),
        "stock_export_symbols": len(stock_exports),
        "critical_modules": sorted(
            (row for row in module_rows if row.get("missing", 0) or row.get("crc_mismatch", 0)),
            key=lambda row: (-(row.get("missing", 0) + row.get("crc_mismatch", 0)), row["path"]),
        ),
        "symbols": unique_imports,
    }
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: report[key] for key in (
        "stock_module_count", "candidate_module_count",
        "stock_basenames_present_in_candidate", "stock_basenames_absent_from_candidate",
        "stock_vermagic", "import_records", "unique_import_symbols")
    }, indent=2))
    if args.strict and (unique_states["missing"] or unique_states["crc_mismatch"]):
        raise SystemExit("ABI gate failed: unresolved or mismatched imports")


if __name__ == "__main__":
    main()
