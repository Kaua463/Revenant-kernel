#!/usr/bin/env python3
"""Audit site generation/preservation tests; no kernel or VM execution."""
from importlib.machinery import SourceFileLoader
from pathlib import Path
import tempfile
import hashlib
import json
import os
import subprocess
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
module = SourceFileLoader('dma_fault_sites', str(ROOT / 'scripts/prepare-dmabuf-fault-sites.py')).load_module()
prepare = SourceFileLoader('fault_site_candidate',str(ROOT/'scripts/prepare-dmabuf-reimplementation.py')).load_module()
REFERENCE = Path(os.environ.get('DMA_ACK_REFERENCE',str(ROOT.parent.parent/'outputs/stock-ack-dmabuf-overlay-reference-20261005')))


def current_candidate():
    source, recipes = {}, {}
    for name,sha in prepare.SOURCES.items():
        data = (REFERENCE/name).read_bytes()
        if hashlib.sha256(data).hexdigest() != sha:
            raise ValueError('ACK source drift')
        source[name] = data.decode()
    for name,sha in prepare.RECIPES.items():
        data = (ROOT/'tools/stock-recovery'/('dmabuf_huge_'+name+'.recovered.c')).read_bytes()
        if hashlib.sha256(data).hexdigest() != sha:
            raise ValueError('recipe drift')
        recipes[name] = data.decode()
    return prepare.candidate(source,recipes)['mm/huge_memory.c'].encode()


class Sites(unittest.TestCase):
    def setUp(self):
        self.data = current_candidate()
        self.fixture = tempfile.TemporaryDirectory(prefix='dma-current-fault-source-')
        self.addCleanup(self.fixture.cleanup)
        self.source = Path(self.fixture.name)/'huge_memory.c'
        self.source.write_bytes(self.data)

    def test_three_sites_and_outside_function_preserved(self):
        before = self.data.decode()
        after = module.transform(self.data).decode()
        start = before.index(module.FUNCTION_START)
        end = before.index(module.FUNCTION_END, start)
        self.assertTrue(after.startswith(before[:start] + module.DECLARATION))
        self.assertTrue(after.endswith(before[end:]))
        body = after[start + len(module.DECLARATION):after.index(module.FUNCTION_END, start)]
        # Removing the exact audit substitutions must restore the source byte-for-byte.
        for original, replacement in module.SITES:
            self.assertEqual(body.count(replacement), 1)
            body = body.replace(replacement, original)
        self.assertEqual(body, before[start:end])
        self.assertEqual(after.count('if (recovered_dma_audit_fail_alloc(mm, map_type))'), 2)
        self.assertEqual(after.count('if (recovered_dma_audit_fail_pmd_table(mm, map_type))'), 1)
        self.assertIn('if (pud_none(*(pud_t *)pgd)) {\n#ifdef CONFIG_XIAOMI_DMABUF_RUNTIME_AUDIT', after)
        self.assertNotIn('EXPORT_SYMBOL', module.DECLARATION)

    def test_cold_pud_site_and_disabled_allocator_equivalence(self):
        # Compile the exact generated branch, not a rewritten allocation model.
        # Helpers only count routing: this does not prove native MMU behavior.
        branch = module.SITES[0][1]
        source = '''#include <assert.h>
#include <errno.h>
typedef unsigned long pud_t;
static int cold, fail_site, fail_alloc, calls_site, calls_alloc;
static int pud_none(pud_t p) { (void)p; return cold; }
static int __pmd_alloc(void *mm, pud_t *p, unsigned long a) {
 (void)mm; (void)p; (void)a; calls_alloc++; return fail_alloc;
}
#ifdef CONFIG_XIAOMI_DMABUF_RUNTIME_AUDIT
static int recovered_dma_audit_fail_pmd_table(void *mm, unsigned int type) {
 (void)mm; (void)type; calls_site++; return fail_site;
}
#endif
static int run(void) {
 pud_t entry = 0, *pgd = &entry;
 void *mm = 0; unsigned long address = 0;
#ifdef CONFIG_XIAOMI_DMABUF_RUNTIME_AUDIT
 unsigned int map_type = 0;
#endif
''' + branch + '''
 return 0;
}
int main(void) {
 for (cold = 0; cold <= 1; cold++)
  for (fail_site = 0; fail_site <= 1; fail_site++)
   for (fail_alloc = 0; fail_alloc <= 1; fail_alloc++) {
    calls_site = calls_alloc = 0;
    int result = run();
#ifdef CONFIG_XIAOMI_DMABUF_RUNTIME_AUDIT
    assert(calls_site == cold);
    assert(calls_alloc == (cold && !fail_site));
    assert(result == (cold && (fail_site || fail_alloc) ? -ENOMEM : 0));
#else
    assert(calls_site == 0); assert(calls_alloc == cold);
    assert(result == (cold && fail_alloc ? -ENOMEM : 0));
#endif
   }
 return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='dma-cold-pud-routing-') as temporary:
            folder = Path(temporary)
            fixture = folder/'site.c'
            fixture.write_text(source)
            for enabled in (False, True):
                executable = folder/str(enabled)
                command = ['clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                           '-fsanitize=address,undefined', str(fixture), '-o', str(executable)]
                if enabled:
                    command.append('-DCONFIG_XIAOMI_DMABUF_RUNTIME_AUDIT=1')
                subprocess.run(command, check=True, timeout=30)
                subprocess.run([str(executable)], check=True, timeout=30)

    def test_drift_and_repeat_fail_closed(self):
        for data in (self.data + b'\n', self.data.replace(b'pte_alloc_one(mm)', b'pte_alloc_one(NULL)', 1),
                     module.transform(self.data)):
            with self.assertRaises(ValueError):
                module.transform(data)

    def test_generation_input_unchanged_and_evidence_preserved(self):
        with tempfile.TemporaryDirectory(prefix='dma-fault-sites-test-') as temporary:
            folder = Path(temporary)
            source = folder / 'huge_memory.c'
            source.write_bytes(self.data)
            args = SimpleNamespace(source=source, output=folder / 'evidence')
            module.run(args)
            result = (args.output / 'huge_memory.c').read_bytes()
            self.assertEqual(source.read_bytes(), self.data)
            self.assertEqual(result, module.transform(self.data))
            report = json.loads((args.output/'report.json').read_text())
            self.assertEqual(len(report['sites']), 3)
            self.assertIn('dormant', report['coverage']['pmd_table'])
            self.assertIn('not implemented', report['coverage']['leaf_ordinal_1'])
            with self.assertRaises(ValueError):
                module.run(args)
            self.assertEqual((args.output / 'huge_memory.c').read_bytes(), result)

    def test_symlink_input_and_output_rejected(self):
        with tempfile.TemporaryDirectory(prefix='dma-fault-sites-test-') as temporary:
            folder = Path(temporary)
            link = folder / 'source'
            link.symlink_to(self.source)
            with self.assertRaises(ValueError):
                module.run(SimpleNamespace(source=link, output=folder / 'evidence'))
            output = folder / 'evidence'
            output.symlink_to(folder / 'missing')
            with self.assertRaises(ValueError):
                module.run(SimpleNamespace(source=self.source, output=output))


if __name__ == '__main__':
    unittest.main()
