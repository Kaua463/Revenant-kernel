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
