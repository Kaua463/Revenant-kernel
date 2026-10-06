#!/usr/bin/env python3
"""Exact unique stock release-banner check; not ABI or hardware compatibility proof."""
import argparse
from pathlib import Path
import re

STOCK_RELEASE = '6.6.77-android15-8-gca30f3b4bef6-abogki440974771-4k'


def banner(data, release):
    banners = re.findall(rb'Linux version [^\0\n]+', data)
    # Exact stock contains two byte-identical copies. Deduplicate content, not
    # versions: any distinct concrete banner (including a wrong release) fails.
    concrete = set(row for row in banners if re.match(rb'Linux version [0-9]', row))
    matching = [row for row in concrete if row.startswith(('Linux version ' + release + ' ').encode())]
    if len(concrete) != 1 or len(matching) != 1:
        raise ValueError('exact stock release banner missing or ambiguous: ' + repr(banners))
    return matching[0]


def run(args):
    if args.expected_release != STOCK_RELEASE:
        raise ValueError('stock release pin mismatch')
    result = banner(args.image.read_bytes(), args.expected_release)
    with args.output.open('xb') as output:
        output.write(result + b'\n')
    print('PASS: unique exact stock release banner; not runtime compatibility proof')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--expected-release', required=True)
    parser.add_argument('--output', type=Path, required=True)
    run(parser.parse_args())
