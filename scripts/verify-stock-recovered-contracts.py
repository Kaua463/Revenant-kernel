#!/usr/bin/env python3
"""Exact-stock checks for two recovered contracts; not full subsystem validation."""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import struct
import subprocess
import tempfile

IMAGE_SHA = '99485b0132e3aa28f4e965119591c8149fe3c20e7e0fd10d753ef014a582472e'
SYMBOL_SHA = '2b7929e77d87d54a9a2385dcc1f0a262a2fe17d7226dd304d40b5fa59dd30805'


def run(image, symbols):
    assert hashlib.sha256(image.read_bytes()).hexdigest() == IMAGE_SHA
    assert hashlib.sha256(symbols.read_bytes()).hexdigest() == SYMBOL_SHA
    spec = importlib.util.spec_from_file_location('compare', Path(__file__).with_name('stock-binary-evidence.py'))
    compare = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(compare)
    kernel = compare.Kernel(image, symbols)
    records = kernel.btf.records()
    def member(record, name, offset):
        variants = records['struct ' + record]
        assert len(variants) == 1
        found = [m for m in variants[0]['members'] if m['name'] == name]
        assert len(found) == 1 and found[0]['offset_bits'] == offset * 8
        return found[0]
    assert member('erofs_sb_info', 'iostat', 0x1c0)['type'] == '*4:erofs_iostat'
    member('erofs_iostat', 'iostat_enable', 0)
    member('bio', 'android_oem_data1', 0x88)
    prototype = [t for t in kernel.btf.types if t['kind'] == 12 and t['name'] == 'erofs_iostat_record_start']
    assert len(prototype) == 1
    assert kernel.btf.ref(prototype[0]['size']) == 'fn(*4:erofs_sb_info,*4:bio)->0:void'
    body = kernel.span('erofs_iostat_record_start')
    assert hashlib.sha256(body).hexdigest() == '0b538fa684ce51df4b48c3c65171ab6ded22ab197c1c6e2cf906d0c8e6aef490'
    assert kernel.names_at[0xffffffc08018967c] == ['ktime_get']
    # This body is intentionally tiny; host tests cover semantics, not arm64 execution.
    recovered = Path(__file__).parents[1] / 'tools/stock-recovery/erofs_iostat_record_start.recovered.c'
    fixture = '''#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
struct erofs_iostat { bool iostat_enable; };
struct erofs_sb_info { struct erofs_iostat *iostat; };
struct bio { uint64_t android_oem_data1; };
static unsigned calls;
static uint64_t ktime_get(void) { calls++; return 123456789; }
'''
    fixture += recovered.read_text()
    fixture += '''
int main(void) {
 struct erofs_iostat stats={false}; struct erofs_sb_info sbi={&stats};
 struct bio bio={99};
 erofs_iostat_record_start(&sbi,&bio); assert(bio.android_oem_data1==99 && calls==0);
 stats.iostat_enable=true;
 erofs_iostat_record_start(&sbi,&bio); assert(bio.android_oem_data1==123456789 && calls==1);
 return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='stock-contract-') as folder:
        binary = Path(folder) / 'test'
        subprocess.run(['clang', '-x', 'c', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-o', str(binary), '-'],
                       input=fixture, text=True, check=True)
        subprocess.run([str(binary)], check=True)
    print('PASS: EROFS record_start stock bytes, BTF prototype/layout and recovered C host behavior')
    # Recover XRING's six-way indirect dispatch from its actual byte table.
    base = 0xffffffc0812d2fc0
    table = kernel.data[base - kernel.base:base - kernel.base + 6]
    assert table == bytes.fromhex('001523313f4d')
    expected = ['collect', 'preread', 'clear', 'flush', 'stop', 'recovery']
    def word(address):
        return struct.unpack_from('<I', kernel.data, address - kernel.base)[0]
    for index, operation in enumerate(expected):
        branch = 0xffffffc080cdd99c + table[index] * 4
        assert word(branch) == 0xaa0203e0  # mov x0,x2: forward ioctl user argument
        instruction = word(branch + 4)
        assert instruction & 0xfc000000 == 0x94000000
        displacement = instruction & 0x03ffffff
        if displacement & 0x02000000:
            displacement -= 0x04000000
        target = branch + 4 + displacement * 4
        assert kernel.names_at[target] == ['xring_lb_dealwith_' + operation + '_cmd']
    # Validate normalization and upper bound instructions too, not table alone.
    assert word(0xffffffc080cdd96c) == 0x52967fe8  # mov w8,#0xb3ff
    assert word(0xffffffc080cdd974) == 0x72a7dee8  # movk w8,#0x3ef7,lsl16
    assert word(0xffffffc080cdd978) == 0x0b080028  # add w8,w1,w8
    assert word(0xffffffc080cdd97c) == 0x7100151f  # cmp w8,#5
    assert word(0xffffffc080cdd980) == 0x540002e8  # b.hi invalid-command path
    minimum = (-0x3ef7b3ff) & 0xffffffff
    assert minimum == 0xc1084c01
    print('PASS: XRING ioctl commands 0xc1084c01..06 and six verified target handlers')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--symbols', type=Path, required=True)
    args = parser.parse_args()
    run(args.image, args.symbols)
