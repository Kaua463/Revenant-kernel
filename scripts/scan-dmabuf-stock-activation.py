#!/usr/bin/env python3
"""Pinned stock activation candidates; instruction patterns are NOT reachable CFG proof."""
import argparse
from bisect import bisect_right
import hashlib
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path
import struct

evidence = SourceFileLoader('dma_activation_binary', str(Path(__file__).with_name('stock-binary-evidence.py'))).load_module()
IMAGE_SHA = '99485b0132e3aa28f4e965119591c8149fe3c20e7e0fd10d753ef014a582472e'
SYMBOL_SHA = '2b7929e77d87d54a9a2385dcc1f0a262a2fe17d7226dd304d40b5fa59dd30805'


def signed(value, width):
    return value - (1 << width) if value & (1 << (width - 1)) else value


def branch(word, pc):
    if word & 0x7c000000 != 0x14000000:
        return None
    return pc + (signed(word & 0x3ffffff, 26) << 2)


def adr(word, pc):
    if word & 0x1f000000 != 0x10000000:
        return None
    immediate = signed(((word >> 29) & 3) | (((word >> 5) & 0x7ffff) << 2), 21)
    address = (pc & ~4095) + (immediate << 12) if word & 0x80000000 else pc + immediate
    return word & 31, address, bool(word & 0x80000000)


def orr_mask(word):
    if word & 0x7f800000 != 0x32000000:
        return None
    width = 64 if word >> 31 else 32
    n, immr, imms = (word >> 22) & 1, (word >> 16) & 63, (word >> 10) & 63
    if width == 32 and n:
        return None
    length = ((n << 6) | (~imms & 63)).bit_length() - 1
    if length < 1:
        return None
    levels = (1 << length) - 1
    s, r, element = imms & levels, immr & levels, 1 << length
    if s == levels or element > width:
        return None
    ones = (1 << (s + 1)) - 1
    value = ((ones >> r) | (ones << (element - r))) & ((1 << element) - 1)
    return sum(value << position for position in range(0, width, element))


def add_immediate(word):
    # 64-bit ADD (not ADDS/SUB/32-bit or shifted-register ADD).
    if word & 0xff800000 != 0x91000000:
        return None
    return word & 31, (word >> 5) & 31, ((word >> 10) & 4095) << (12 if word & (1 << 22) else 0)


def page_add_candidates(data, offset, pc, target, boundaries=(), decoder=None):
    """Bounded linear pattern only. Stop on clobbers/control/boundaries/unknown."""
    # Lazy dependency: module inventory using only orr_mask needs no Capstone.
    from capstone import (Cs, CsError, CS_ARCH_ARM64, CS_MODE_ARM,
                          CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET, CS_GRP_INT, CS_GRP_IRET)
    decoded = adr(struct.unpack_from('<I', data, offset)[0], pc)
    if decoded is None or not decoded[2] or decoded[0] == 31:
        return []
    register, address, _ = decoded
    delta = target - address
    if not (0 <= delta <= 4095 or 0 <= delta <= 4095 << 12 and delta % 4096 == 0):
        return []
    if decoder is None:
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        decoder.detail = True
    found = []
    for distance in range(1, 9):
        position = offset + 4 * distance
        site = pc + 4 * distance
        if position + 4 > len(data) or site in boundaries:
            break
        payload = bytes(data[position:position + 4])
        instructions = list(decoder.disasm(payload, site, count=1))
        if len(instructions) != 1 or instructions[0].size != 4:
            break
        instruction = instructions[0]
        if any(instruction.group(group) for group in (CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET, CS_GRP_INT, CS_GRP_IRET)):
            break
        if instruction.mnemonic in ('eret', 'drps', 'brk', 'hlt', 'svc', 'hvc', 'smc', 'udf'):
            break
        addition = add_immediate(struct.unpack('<I', payload)[0])
        if addition and addition[1] == register and addition[0] != 31 and address + addition[2] == target:
            found.append({'add_site': hex(site), 'distance_instructions': distance,
                          'page_register': register, 'destination': addition[0]})
        try:
            _, writes = instruction.regs_access()
        except CsError:
            break
        names = {decoder.reg_name(item) for item in writes}
        # A W-register write also destroys the corresponding X value.
        aliases = {f'x{register}', f'w{register}'}
        if register == 29:
            aliases.add('fp')
        if register == 30:
            aliases.add('lr')
        if names & aliases:
            break
    return found


def run(args):
    for path, sha in ((args.image, IMAGE_SHA), (args.symbols, SYMBOL_SHA)):
        if hashlib.sha256(path.read_bytes()).hexdigest() != sha:
            raise ValueError('stock input pin mismatch')
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('evidence already exists')
    kernel = evidence.Kernel(args.image, args.symbols)
    target = kernel.address('dmabuf_huge_remap_pfn_range')
    addresses = sorted(kernel.names_at)
    boundaries = set(addresses)
    def record(pc, **fields):
        index = bisect_right(addresses, pc) - 1
        return dict(site=hex(pc), inferred_owner=kernel.names_at[addresses[index]] if index >= 0 else [], **fields)
    regions = []
    for start, end in (('_stext', '_etext'), ('_sinittext', '_einittext')):
        if start in kernel.symbols and end in kernel.symbols:
            low, high = kernel.address(start), kernel.address(end)
            if not kernel.base <= low < high <= kernel.base + len(kernel.data):
                raise ValueError('text bounds not file-backed')
            regions.append((low, high))
    if not regions:
        raise ValueError('no verified text regions')
    direct, materialized, masks = [], [], []
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    decoder.detail = True
    for low, high in regions:
        data = memoryview(kernel.data)[low - kernel.base:high - kernel.base]
        for offset in range(0, len(data) - 3, 4):
            pc = low + offset
            word = struct.unpack_from('<I', data, offset)[0]
            if branch(word, pc) == target:
                direct.append(record(pc, kind='BL' if word >> 31 else 'B'))
            decoded = adr(word, pc)
            if decoded:
                register, address, page = decoded
                if not page and address == target:
                    materialized.append(record(pc, kind='ADR', register=register))
                if page:
                    for candidate in page_add_candidates(data, offset, pc, target, boundaries, decoder):
                        materialized.append(record(pc, kind='bounded_linear_ADRP_ADD', **candidate))
            mask = orr_mask(word)
            if mask is not None and mask & (1 << 39):
                masks.append(record(pc, mask=hex(mask), only_bit39=mask == 1 << 39,
                                    destination=word & 31, source=(word >> 5) & 31))
    pointer = struct.pack('<Q', target)
    absolute = []
    offset = kernel.data.find(pointer)
    while offset >= 0:
        absolute.append(record(kernel.base + offset, aligned8=offset % 8 == 0))
        offset = kernel.data.find(pointer, offset + 1)
    report = dict(status='STATIC_ACTIVATION_CANDIDATES_NOT_RUNTIME_PROOF',
                  target=hex(target), image_sha256=IMAGE_SHA, symbols_sha256=SYMBOL_SHA,
                  regions=[(hex(low), hex(high)) for low, high in regions],
                  direct_entry_branches=direct, entry_address_patterns=materialized,
                  absolute_entry_values=absolute, orr_masks_containing_bit39=masks,
                  limits=['text includes possible padding/CFI data; no CFG reachability proof',
                          'ORR bit39 does not prove VMA ownership or a vm_flags store',
                          'ADRP/ADD window at most 8 instructions; no register-copy/loaded/relocated/dynamic lookup resolution',
                          'linear patterns stop on control/clobbers/symbols; no incoming-edge or CFG reachability proof',
                          'external modules and runtime configuration not inspected here',
                          'no matches does not prove feature unused'])
    with args.output.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(f'Candidates: direct={len(direct)}, address={len(materialized)}, absolute={len(absolute)}, ORR-bit39={len(masks)}; NOT activation proof')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('image', 'symbols', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    run(parser.parse_args())
