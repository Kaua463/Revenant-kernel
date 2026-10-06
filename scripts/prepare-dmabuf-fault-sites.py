#!/usr/bin/env python3
"""Generate two audit-only failure sites from exact recovered source; no writes to input."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'tools/stock-recovery/overlays/dma-6.6.77/manifest.json'
FUNCTION_START = 'int dmabuf_huge_remap_pfn_range('
FUNCTION_END = '\n\n#endif'
DECLARATION = '''#ifdef CONFIG_XIAOMI_DMABUF_RUNTIME_AUDIT
/* NEW disposable audit only. Defined by the built-in audit producer. */
extern bool recovered_dma_audit_fail_alloc(struct mm_struct *mm,
		unsigned int map_type);
#endif

'''
SITES = (
    ('pgtable_t pgtable = pte_alloc_one(mm);',
     '''pgtable_t pgtable;

#ifdef CONFIG_XIAOMI_DMABUF_RUNTIME_AUDIT
				if (recovered_dma_audit_fail_alloc(mm, map_type))
					return -ENOMEM;
#endif
				pgtable = pte_alloc_one(mm);'''),
    ('''pte_t *pte = pte_alloc_map_lock(mm, pmd, address, &ptl);
				unsigned int count = (pmd_next - address) >> PAGE_SHIFT;
				unsigned long value;''',
     '''pte_t *pte;
				unsigned int count = (pmd_next - address) >> PAGE_SHIFT;
				unsigned long value;

#ifdef CONFIG_XIAOMI_DMABUF_RUNTIME_AUDIT
				if (recovered_dma_audit_fail_alloc(mm, map_type))
					return -ENOMEM;
#endif
				pte = pte_alloc_map_lock(mm, pmd, address, &ptl);'''),
)


def transform(data):
    expected = json.loads(MANIFEST.read_text())['changes']['mm/huge_memory.c']['after']
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('exact recovered huge_memory source required')
    text = data.decode()
    if text.count(FUNCTION_START) != 1:
        raise ValueError('unique recovered mapper definition required')
    start = text.index(FUNCTION_START)
    end = text.index(FUNCTION_END, start)
    body = text[start:end]
    for before, after in SITES:
        if body.count(before) != 1:
            raise ValueError('unique allocator site required: ' + before)
        body = body.replace(before, after)
    # Preserve everything outside this single recovered function exactly.
    return (text[:start] + DECLARATION + body + text[end:]).encode()


def run(args):
    if args.source.is_symlink() or not args.source.is_file():
        raise ValueError('regular input file required')
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('output evidence already exists')
    before = args.source.read_bytes()
    after = transform(before)
    args.output.mkdir(parents=True)
    (args.output / 'huge_memory.c').write_bytes(after)
    report = {
        'status': 'AUDIT_FAILURE_SITES_ONLY_NOT_WIRED_OR_RUNTIME_PROOF',
        'input_sha256': hashlib.sha256(before).hexdigest(),
        'output_sha256': hashlib.sha256(after).hexdigest(),
        'sites': ['PMD deposited-table pte_alloc_one', 'PTE pte_alloc_map_lock'],
        'scope': 'only recovered remap function; built-in VM audit config',
        'pending': ['producer callback/task-mm serialization',
                    'guest ENOMEM and retry assertions', 'real partial unwind runtime'],
    }
    (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(report['status'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    run(parser.parse_args())
