#!/usr/bin/env python3
"""Encoding unit tests and exhaustive logical-immediate comparison to Capstone."""
from importlib.machinery import SourceFileLoader
from pathlib import Path
import struct
import unittest
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_IMM

module = SourceFileLoader('dma_activation', str(Path(__file__).with_name('scan-dmabuf-stock-activation.py'))).load_module()


class Decoder(unittest.TestCase):
    def test_page_add_nonadjacent_and_destination(self):
        page, nop = 0x90000005, 0xd503201f
        addition = 0x91000000 | (0x120 << 10) | (5 << 5) | 7
        data = struct.pack('<IIII', page, nop, 0xf9000005, addition)  # STR reads x5, not a clobber.
        result = module.page_add_candidates(data, 0, 0x1000, 0x1120)
        self.assertEqual(result, [{'add_site': '0x100c', 'distance_instructions': 3,
                                  'page_register': 5, 'destination': 7}])
        self.assertEqual(module.page_add_candidates(data, 0, 0x1000, 0x1121), [])

    def test_page_add_clobbers_controls_and_boundaries_stop(self):
        page = 0x90000005
        addition = 0x91000000 | (0x120 << 10) | (5 << 5) | 7
        # X5 and W5 overwrite; load into x5; B, BL, B.cond, CBZ, TBZ,
        # BR, BLR, RET, SVC and unallocated encoding.
        for middle in (0xaa0003e5, 0x2a0003e5, 0xf9400005, 0xf8008ca0, 0xa9bf04a0, 0x90000005, 0x14000001,
                       0x94000001, 0x54000020, 0xb4000020, 0x36000020,
                       0xd61f0000, 0xd63f0000, 0xd65f03c0, 0xd4000001, 0):
            data = struct.pack('<III', page, middle, addition)
            with self.subTest(middle=hex(middle)):
                self.assertEqual(module.page_add_candidates(data, 0, 0x1000, 0x1120), [])
        data = struct.pack('<III', page, 0xd503201f, addition)
        self.assertEqual(module.page_add_candidates(data, 0, 0x1000, 0x1120, {0x1008}), [])

    def test_page_add_fp_lr_aliases_and_discarded_register(self):
        for register in (29, 30):
            page = 0x90000000 | register
            overwrite = 0xaa0003e0 | register  # MOV Xd, X0; Capstone may name FP/LR.
            addition = 0x91000000 | (0x120 << 10) | (register << 5) | 7
            data = struct.pack('<III', page, overwrite, addition)
            self.assertEqual(module.page_add_candidates(data, 0, 0x1000, 0x1120), [])
        self.assertEqual(module.page_add_candidates(struct.pack('<II', 0x9000001f, 0x910483e7),
                                                   0, 0x1000, 0x1120), [])

    def test_page_add_window_and_inplace_write(self):
        page, nop = 0x90000005, 0xd503201f
        addition = 0x91000000 | (0x120 << 10) | (5 << 5) | 5
        for distance in (1, 8, 9):
            data = struct.pack('<' + 'I' * (distance + 2), page, *([nop] * (distance - 1)), addition, addition)
            result = module.page_add_candidates(data, 0, 0x1000, 0x1120)
            self.assertEqual(len(result), int(distance <= 8))
            if result:
                self.assertEqual(result[0]['distance_instructions'], distance)

    def test_add_imm_encoding_against_capstone(self):
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        decoder.detail = True
        for shift in (0, 1):
            for immediate in (0, 1, 0x120, 4095):
                for destination in (0, 7, 30, 31):
                    word = 0x91000000 | (shift << 22) | (immediate << 10) | (5 << 5) | destination
                    instruction = list(decoder.disasm(struct.pack('<I', word), 0x1000))[0]
                    if instruction.mnemonic == 'mov':  # ADD SP, Xn, #0 aliases MOV SP, Xn.
                        self.assertEqual(immediate, 0)
                        self.assertEqual(len(instruction.operands), 2)
                        value = 0
                    else:
                        self.assertEqual(len(instruction.operands), 3)
                        value = instruction.operands[2].imm << instruction.operands[2].shift.value
                    self.assertEqual(module.add_immediate(word), (destination, 5, value))
        for word in (0x110480a7, 0xb10480a7, 0xd10480a7, 0x8b050007):
            self.assertIsNone(module.add_immediate(word))

    def test_branch_and_adr_boundaries(self):
        self.assertEqual(module.branch(0x94000002, 0x1000), 0x1008)
        self.assertEqual(module.branch(0x17ffffff, 0x1000), 0xffc)
        self.assertIsNone(module.branch(0xd503201f, 0x1000))
        self.assertEqual(module.adr(0x10000000, 0x1234), (0, 0x1234, False))
        self.assertEqual(module.adr(0x90000001, 0x1234), (1, 0x1000, True))
        self.assertIsNone(module.adr(0xd503201f, 0x1000))

    def test_all_logical_immediates_against_independent_decoder(self):
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        decoder.detail = True
        cases = 0
        for sf in (0, 1):
            width = 64 if sf else 32
            for n in (0, 1):
                for imms in range(64):
                    for immr in range(64):
                        word = 0x32000020 | (sf << 31) | (n << 22) | (imms << 10) | (immr << 16)
                        instructions = list(decoder.disasm(struct.pack('<I', word), 0))
                        expected = None
                        if instructions:
                            operand = instructions[0].operands[-1]
                            self.assertEqual(operand.type, ARM64_OP_IMM)
                            expected = operand.imm & ((1 << width) - 1)
                        self.assertEqual(module.orr_mask(word), expected, hex(word))
                        cases += 1
        self.assertEqual(cases, 16384)

    def test_adr_signed_page_boundaries_against_independent_decoder(self):
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        decoder.detail = True
        for page in (False, True):
            for pc in (0x10000000, 0x10000ffc, 0x10001000, 0xffffffc080000004):
                for immediate in (-1048576, -1048575, -4096, -1, 0, 1, 4095, 4096, 1048574, 1048575):
                    raw = immediate & 0x1fffff
                    word = (0x90000000 if page else 0x10000000) | ((raw & 3) << 29) | ((raw >> 2) << 5) | 7
                    instructions = list(decoder.disasm(struct.pack('<I', word), pc))
                    self.assertEqual(len(instructions), 1)
                    expected = instructions[0].operands[-1].imm & ((1 << 64) - 1)
                    register, actual, is_page = module.adr(word, pc)
                    self.assertEqual((register, actual & ((1 << 64) - 1), is_page), (7, expected, page))


if __name__ == '__main__':
    unittest.main()
