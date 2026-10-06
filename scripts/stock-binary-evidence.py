#!/usr/bin/env python3
"""Read-only raw ARM64 Image/BTF evidence primitives for stock recovery.

Requires independently extracted kallsyms for each Image. Inferred symbol spans
are NOT ELF function sizes. Identical code bytes may reference different data.
Absence from kallsyms may mean inlining/renaming, not absence of functionality.
Adapted from the local comparison analyzer; kept separate so recovery scripts
do not depend on an unrelated, untracked workspace file.
"""
import argparse
from collections import Counter, defaultdict
import gzip
import hashlib
import json
from pathlib import Path
import re
import struct


def digest(data):
    return hashlib.sha256(data).hexdigest()


def config(data):
    start = data.index(b'IKCFG_ST') + 8
    end = data.index(b'IKCFG_ED', start)
    text = gzip.decompress(data[start:end]).decode()
    result = {}
    for line in text.splitlines():
        match = re.fullmatch(r'# (CONFIG_\w+) is not set', line)
        if match:
            result[match[1]] = 'n'
        elif line.startswith('CONFIG_') and '=' in line:
            key, value = line.split('=', 1)
            result[key] = value
    return result


class Kernel:
    def __init__(self, image, kallsyms):
        self.data = image.read_bytes()
        if self.data[56:60] != b'ARM\x64':
            raise ValueError('expected uncompressed ARM64 Image')
        self.symbols = defaultdict(list)
        self.entries = []
        for line in kallsyms.read_text().splitlines():
            address, kind, name = line.split(maxsplit=2)
            entry = (int(address, 16), kind, name)
            self.symbols[name].append(entry)
            self.entries.append(entry)
        self.base = self.address('_text')
        # Validate mapping against both ASCII and binary embedded anchors.
        if not self.data[self.offset('linux_banner'):].startswith(b'Linux version '):
            raise ValueError('kallsyms does not map linux_banner to Image')
        if self.data[self.offset('__start_BTF'):self.offset('__start_BTF') + 4] != b'\x9f\xeb\x01\x00':
            raise ValueError('kallsyms does not map BTF to Image')
        addresses = sorted({e[0] for e in self.entries})
        self.next_address = dict(zip(addresses, addresses[1:]))
        self.names_at = defaultdict(list)
        for address,kind,name in self.entries:
            self.names_at[address].append(name)
        self.cfg = config(self.data)
        btf = self.data[self.offset('__start_BTF'):self.offset('__stop_BTF')]
        self.btf = BTF(btf)

    def address(self, name):
        rows = self.symbols[name]
        if len(rows) != 1:
            raise ValueError(f'expected unique symbol: {name}')
        return rows[0][0]

    def offset(self, name):
        return self.address(name) - self.base

    def span(self, name):
        rows = self.symbols[name]
        if len(rows) != 1:
            return None
        address, kind, _ = rows[0]
        end = self.next_address.get(address)
        if end is None or not (0 <= address - self.base < end - self.base <= len(self.data)):
            return None  # includes uninitialized BSS, never invent its bytes
        return self.data[address - self.base:end - self.base]

    def exports(self):
        result = {}
        for suffix in ('', '_gpl'):
            start = self.offset('__start___ksymtab'+suffix)
            end = self.offset('__stop___ksymtab'+suffix)
            crc_start = self.offset('__start___kcrctab'+suffix)
            if (end-start) % 12:
                raise ValueError('invalid PREL32 export table size')
            for i, pos in enumerate(range(start,end,12)):
                name_offset = pos+4+struct.unpack_from('<i',self.data,pos+4)[0]
                if not 0 <= name_offset < len(self.data):
                    raise ValueError('export name outside Image')
                name = self.data[name_offset:self.data.index(b'\0',name_offset)].decode()
                crc = struct.unpack_from('<I',self.data,crc_start+4*i)[0]
                if self.offset('__ksymtab_'+name) != pos or name in result:
                    raise ValueError('export table / kallsyms disagreement')
                result[name] = crc
        return result


class BTF:
    """Parse BTF v1 layouts, preserving offsets and bitfield widths.

References to named records stay symbolic; records themselves get separate
    rows. Equal rows do not imply equal transitive layouts.
    """
    def __init__(self, data):
        magic, version, flags, hdr, toff, tlen, soff, slen = struct.unpack_from('<HBBIIIII', data)
        if (magic, version, flags) != (0xeb9f, 1, 0) or hdr < 24:
            raise ValueError('invalid BTF header')
        if max(hdr + toff + tlen, hdr + soff + slen) > len(data):
            raise ValueError('BTF outside input')
        self.strings = data[hdr + soff:hdr + soff + slen]
        self.types = [dict(kind=0, name='void', size=0, raw=[])]
        pos, end = hdr + toff, hdr + toff + tlen
        while pos < end:
            name, info, size = struct.unpack_from('<III', data, pos)
            kind, count, flag = (info >> 24) & 31, info & 65535, info >> 31
            words = {1: 1, 2: 0, 3: 3, 4: 3*count, 5: 3*count,
                     6: 2*count, 7: 0, 8: 0, 9: 0, 10: 0, 11: 0,
                     12: 0, 13: 2*count, 14: 1, 15: 3*count, 16: 0,
                     17: 1, 18: 0, 19: 3*count}.get(kind)
            if words is None or pos + 12 + 4*words > end:
                raise ValueError(f'invalid BTF kind/extent: {kind}')
            raw = list(struct.unpack_from('<' + 'I'*words, data, pos + 12))
            self.types.append(dict(kind=kind, name=self.string(name), size=size,
                                   flag=flag, raw=raw))
            pos += 12 + 4*words
        if pos != end:
            raise ValueError('BTF type extent mismatch')

    def string(self, offset):
        if offset >= len(self.strings):
            raise ValueError('invalid BTF string offset')
        end = self.strings.index(b'\0', offset)
        return self.strings[offset:end].decode()

    def ref(self, ident, seen=()):
        if ident in seen:
            return 'recursive'
        t = self.types[ident]
        kind, name, size, raw = t['kind'], t['name'], t['size'], t['raw']
        if kind in (0, 1, 4, 5, 6, 7, 16, 19) and name:
            return f'{kind}:{name}'
        recurse = lambda i: self.ref(i, seen + (ident,))
        if kind == 2:
            return '*' + recurse(size)
        if kind in (8, 9, 10, 11, 18):
            return f'{kind}:{name}({recurse(size)})'
        if kind == 3:
            return f'array[{raw[2]}]({recurse(raw[0])})'
        if kind in (6, 19):
            width = 2 if kind == 6 else 3
            values = [(self.string(raw[i]), raw[i+1:i+width]) for i in range(0,len(raw),width)]
            return f'enum:{size}:{t["flag"]}:' + json.dumps(values)
        if kind == 13:
            return f'fn({",".join(recurse(raw[i+1]) for i in range(0,len(raw),2))})->{recurse(size)}'
        if kind in (4, 5):
            return json.dumps(self.record(ident, seen + (ident,)), sort_keys=True)
        return f'{kind}:{name}:{size}:{raw}'

    def record(self, ident, seen=()):
        t = self.types[ident]
        members = []
        for i in range(0, len(t['raw']), 3):
            name, typ, off = t['raw'][i:i+3]
            members.append(dict(name=self.string(name), type=self.ref(typ, seen),
                                offset_bits=off & 0xffffff if t['flag'] else off,
                                bitfield_bits=off >> 24 if t['flag'] else 0))
        return dict(size_bytes=t['size'], members=members)

    def records(self):
        result = defaultdict(list)
        for ident, t in enumerate(self.types):
            if t['kind'] in (4, 5) and t['name']:
                key = ('struct ' if t['kind'] == 4 else 'union ') + t['name']
                rec = self.record(ident, (ident,))
                if rec not in result[key]:
                    result[key].append(rec)
        for variants in result.values():
            variants.sort(key=lambda record: json.dumps(record, sort_keys=True))
        return result

    def named_types(self):
        result = defaultdict(list)
        for ident,t in enumerate(self.types):
            kind,name,size,raw=t['kind'],t['name'],t['size'],t['raw']
            if not name:
                continue
            if kind in (4,5):
                value=self.record(ident,(ident,))
            elif kind in (6,19):
                width=2 if kind==6 else 3
                value=dict(size=size,signed=t['flag'],values=[(self.string(raw[i]),raw[i+1:i+width])
                                                            for i in range(0,len(raw),width)])
            elif kind in (8,9,10,11,12,14,17,18):
                value=dict(type=self.ref(size),extra=raw)
            elif kind==15:
                value=dict(size=size,entries=[(self.ref(raw[i]),raw[i+1:i+3]) for i in range(0,len(raw),3)])
            else:
                value=dict(size_or_type=size,extra=raw)
            key=f'{kind}:{name}'
            if value not in result[key]:
                result[key].append(value)
        for variants in result.values():
            variants.sort(key=lambda value:json.dumps(value,sort_keys=True))
        return result
