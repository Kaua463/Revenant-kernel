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
    if not data:
        return []
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stock-modules", type=pathlib.Path, required=True)
    parser.add_argument("--candidate-modules", type=pathlib.Path, required=True)
    parser.add_argument("--candidate-symvers", type=pathlib.Path, required=True)
    parser.add_argument("--objcopy", required=True)
    parser.add_argument("--json", type=pathlib.Path, required=True)
    args = parser.parse_args()

    stock = sorted(args.stock_modules.rglob("*.ko"))
    candidate = sorted(args.candidate_modules.rglob("*.ko"))
    candidate_by_name = collections.defaultdict(list)
    for module in candidate:
        candidate_by_name[module.name].append(str(module))
    symvers = read_symvers(args.candidate_symvers)

    symbol_state = collections.Counter()
    module_rows = []
    vermagic = collections.Counter()
    unique_imports = {}
    for module in stock:
        states = collections.Counter()
        for name, stock_crc in read_versions(module, args.objcopy):
            candidate_crc = symvers.get(name)
            if candidate_crc is None:
                state = "missing"
            elif candidate_crc != stock_crc:
                state = "crc_mismatch"
            else:
                state = "match"
            states[state] += 1
            old = unique_imports.get(name)
            row = {"stock_crc": f"0x{stock_crc:08x}", "candidate_crc": None if candidate_crc is None else f"0x{candidate_crc:08x}", "state": state}
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


if __name__ == "__main__":
    main()
