#!/usr/bin/env python3
"""Source-policy regression only: NOT Kbuild or MMU/lifetime proof."""
from pathlib import Path
import subprocess
import tempfile
import re
import unittest

ROOT = Path(__file__).resolve().parents[1] / 'tools/stock-recovery/runtime-audit'


def validate(source, config, makefile):
    required = (
        'defined(MODULE)', '!defined(CONFIG_XIAOMI_DMABUF_RUNTIME_AUDIT)',
        'CONFIG_PGTABLE_LEVELS != 3', 'capable(CAP_SYS_ADMIN)',
        '__GFP_ZERO | __GFP_COMP', '__free_pages(buffer->pages, AUDIT_ORDER)',
        'mmap_assert_write_locked(vma->vm_mm)',
        'vma->vm_pgoff > (ULONG_MAX >> PAGE_SHIFT)',
        'if (!audit_empty_destination(vma))', 'if (!pmd_none(*pmd))',
        'vm_flags_clear(vma, VM_MAYEXEC)', 'vma->vm_flags & VM_EXEC',
        '!!(vma->vm_flags & VM_SHARED)',
        'page_to_pfn(buffer->pages) + (offset >> PAGE_SHIFT)',
        'result = dmabuf_huge_remap_pfn_range(',
        'misc_deregister(&audit_pmd_device)',
        'atomic64_inc_return(&audit_next_id)',
        'unsigned long long id = buffer->id;',
        'unsigned int map_type = buffer->map_type;',
        'DMA_AUDIT_ALLOC id=%llu mode=%u bytes=%lu fault=%u',
        'DMA_AUDIT_RELEASE id=%llu mode=%u',
        'lockdep_assert_held(&audit_fault_mutex)',
        'mutex_lock(&audit_fault_mutex)',
        'mutex_unlock(&audit_fault_mutex)',
        'dma_audit_fault_check(&audit_fault_plan, (unsigned long)current,',
        '(unsigned long)mm)',
        'if (published != audit_fault_plan.ordinal - 1 ||',
        'table_present != (audit_fault_plan.ordinal == 2)',
        'buffer->fault_ordinal',
        'misc_deregister(&audit_first_pmd_device)',
        'misc_deregister(&audit_fault_pte_device)',
        'misc_deregister(&audit_table_pmd_device)',
        'misc_deregister(&audit_first_pte_device)',
        'if (buffer->fault_pending && buffer->table_fault &&',
        '!pud_none(*(pud_t *)pgd_offset(vma->vm_mm, vma->vm_start))',
        'buffer->table_fault ? DMA_AUDIT_FAULT_PMD_TABLE : DMA_AUDIT_FAULT_LEAF',
        'table_present != (audit_fault_plan.ordinal == 2) || !cold)',
        '(audit_fault_plan.ordinal - 1) * DMA_AUDIT_BLOCK_BYTES));',
        'misc_deregister(&audit_table_cross_pmd_device)',
        'misc_deregister(&audit_table_pte_device)',
        '(vma->vm_start & ((1UL << 30) - 1)) != (1UL << 30) - DMA_AUDIT_BLOCK_BYTES',
        '!pud_none(*(pud_t *)pgd_offset(vma->vm_mm, vma->vm_start + DMA_AUDIT_BLOCK_BYTES))',
        '(buffer->fault_ordinal == 1 ? 0 : 2 * PAGE_SIZE)',
        'table_present = audit_first_block_present(map_type);',
        'pmd_pfn(*pmd) == audit_fault_first_pfn',
        'pte_pfn(pte[index]) != audit_fault_first_pfn + index',
        'audit_fault_plan = (struct dma_audit_fault_plan){0};',
        'buffer->fault_pending = false;',
        'goto undo_fault_pmd;',
        'misc_deregister(&audit_fault_pmd_device)',
        'goto undo_pte;',
        'misc_deregister(&audit_pte_device)',
        'audit_fault_buffer->table_bytes_partial = mm_pgtables_bytes(mm);',
        'buffer->table_bytes_before = mm_pgtables_bytes(vma->vm_mm);',
        'buffer->unwind_mm_token != (unsigned long)vma->vm_mm',
        'buffer->unwind_task_token != (unsigned long)current',
        'table_bytes_retry != buffer->table_bytes_before',
        'buffer->table_bytes_partial < buffer->table_bytes_before',
        'DMA_AUDIT_UNWIND id=%llu mode=%u before=%lu partial=%lu retry=%lu',
        'audit_fault_buffer = NULL;',
    )
    for token in required:
        if token not in source:
            raise ValueError('missing producer guard: ' + token)
    for token in ('EXPORT_SYMBOL', '.unlocked_ioctl', '.compat_ioctl', '.read =',
                  '.write =', 'ioremap(', 'memremap(', 'vm_operations_struct',
                  'vm_file =', 'module_init(', 'module_exit('):
        if token in source:
            raise ValueError('forbidden audit interface: ' + token)
    if source.count('.mode = 0600') != 10:
        raise ValueError('all ten devices must be root-only')
    release = source.split('static int audit_release(', 1)[1].split('static bool audit_empty_destination', 1)[0]
    if not release.index('__free_pages(') < release.index('kfree(buffer);') < release.index('pr_info('):
        raise ValueError('release event must follow both real frees')
    if 'buffer->' in release.split('kfree(buffer);', 1)[1]:
        raise ValueError('use of buffer after free')
    if 'default n' not in config or '\tbool ' not in config or 'tristate' in config:
        raise ValueError('audit must default off and be built-in')
    expected_objects = ['obj-$(CONFIG_XIAOMI_DMABUF_RUNTIME_AUDIT) += recovered-dma-audit.o',
                        'obj-$(CONFIG_XIAOMI_DMABUF_RUNTIME_AUDIT) += recovered-dma-export-audit.o']
    if [line for line in makefile.splitlines() if line and not line.startswith('#')] != expected_objects:
        raise ValueError('unexpected build scope')


class SourcePolicy(unittest.TestCase):
    def test_guest_mapper_cases_and_init_nodes_match_producer_inventory(self):
        names = re.findall(r'\.name = "(recovered-dma-audit-[^"]+)"',self.source)
        self.assertEqual(len(names),10)
        self.assertEqual(len(set(names)),10)
        guest = (ROOT/'guest-workload.c').read_text()
        cases = re.findall(r'\bexercise\("/dev/([^"]+)", [01]\);',guest)
        self.assertCountEqual(cases,names)
        init = (ROOT/'guest-init.c').read_text()
        nodes = re.findall(r'\bmake_audit_node\("([^"]+)"\);',init)
        self.assertCountEqual(nodes,names+['recovered-dma-export-audit'])

    def test_each_misc_registration_failure_unwinds_exactly_once(self):
        body = self.source.split('static int __init audit_init(void)',1)[1].split('device_initcall',1)[0]
        names = ('audit_pmd_device','audit_pte_device','audit_fault_pmd_device',
                 'audit_fault_pte_device','audit_first_pmd_device','audit_first_pte_device',
                 'audit_table_pmd_device','audit_table_pte_device',
                 'audit_table_cross_pmd_device','audit_table_cross_pte_device')
        fixture = '''#include <assert.h>
struct miscdevice { int index; };
static int fail_at, registered, removed, seen[10], gone[10];
static int misc_register(struct miscdevice *d) {
 assert(registered < 10); seen[registered++] = d->index;
 return d->index == fail_at ? -19 : 0;
}
static void misc_deregister(struct miscdevice *d) {
 assert(removed < 10); gone[removed++] = d->index;
}
''' + '\n'.join(f'static struct miscdevice {name} = {{{index}}};' for index,name in enumerate(names)) + '''
static int audit_init(void)''' + body + '''
int main(void) {
 for (fail_at = -1; fail_at < 10; fail_at++) {
  registered = removed = 0;
  int result = audit_init();
  assert(result == (fail_at < 0 ? 0 : -19));
  assert(registered == (fail_at < 0 ? 10 : fail_at+1));
  assert(removed == (fail_at < 0 ? 0 : fail_at));
  for (int i=0; i<registered; i++) assert(seen[i] == i);
  for (int i=0; i<removed; i++) assert(gone[i] == fail_at-i-1);
 }
 return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='dma-misc-unwind-') as temporary:
            path = Path(temporary)/'unwind.c'
            path.write_text(fixture)
            executable = path.with_suffix('')
            subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror',
                            '-fsanitize=address,undefined',str(path),'-o',str(executable)],
                           check=True,timeout=30)
            subprocess.run([str(executable)],check=True,timeout=30)

    def setUp(self):
        self.source = (ROOT / 'recovered-dma-audit.c').read_text()
        self.config = (ROOT / 'Kconfig').read_text()
        self.makefile = (ROOT / 'Makefile').read_text()

    def test_current(self):
        validate(self.source, self.config, self.makefile)

    def test_each_guard_required(self):
        for token in ('capable(CAP_SYS_ADMIN)', '__GFP_ZERO | __GFP_COMP',
                      'if (!audit_empty_destination(vma))', 'if (!pmd_none(*pmd))',
                      'vm_flags_clear(vma, VM_MAYEXEC)',
                      'page_to_pfn(buffer->pages) + (offset >> PAGE_SHIFT)',
                      'vma->vm_pgoff > (ULONG_MAX >> PAGE_SHIFT)'):
            with self.subTest(token=token), self.assertRaises(ValueError):
                validate(self.source.replace(token, 'REMOVED'), self.config, self.makefile)

    def test_extra_interfaces_rejected(self):
        for token in ('EXPORT_SYMBOL(x)', '.read = dump', 'vm_file = 0',
                      'vm_operations_struct', 'ioremap(x)', '.unlocked_ioctl = x'):
            with self.subTest(token=token), self.assertRaises(ValueError):
                validate(self.source + '\n' + token, self.config, self.makefile)

    def test_permissions(self):
        with self.assertRaises(ValueError):
            validate(self.source.replace('.mode = 0600', '.mode = 0666', 1), self.config, self.makefile)

    def test_default_off_builtin(self):
        for config in (self.config.replace('default n', 'default y'),
                       self.config.replace('\tbool ', '\ttristate ')):
            with self.assertRaises(ValueError):
                validate(self.source, config, self.makefile)

    def test_makefile_scope(self):
        with self.assertRaises(ValueError):
            validate(self.source, self.config, self.makefile + '\nobj-m += dump.o\n')

    def test_release_instrumentation_order_and_no_freed_dereference(self):
        event = 'pr_info("DMA_AUDIT_RELEASE id=%llu mode=%u\\n", id, map_type);'
        for source in (self.source.replace('kfree(buffer);\n\t/* Log after', event + '\n\tkfree(buffer);\n\t/* Log after'),
                       self.source.replace(event, event + '\n\tbuffer->map_type = 0;')):
            with self.assertRaises(ValueError):
                validate(source, self.config, self.makefile)

    def test_fault_scope_serialization_and_cleanup_required(self):
        for token in ('lockdep_assert_held(&audit_fault_mutex)',
                      'mutex_lock(&audit_fault_mutex)', 'mutex_unlock(&audit_fault_mutex)',
                      'dma_audit_fault_check(&audit_fault_plan, (unsigned long)current,',
                      '(unsigned long)mm)', 'if (published != audit_fault_plan.ordinal - 1 ||',
                      'table_present = audit_first_block_present(map_type);',
                      'audit_fault_plan = (struct dma_audit_fault_plan){0};',
                      'buffer->fault_pending = false;', 'goto undo_fault_pmd;',
                      'misc_deregister(&audit_fault_pmd_device)', 'goto undo_pte;'):
            with self.subTest(token=token), self.assertRaises(ValueError):
                validate(self.source.replace(token, 'REMOVED'), self.config, self.makefile)

    def test_cold_pud_cannot_silently_degrade_to_leaf_or_populated_table(self):
        for token in ('if (buffer->fault_pending && buffer->table_fault &&',
                      '!pud_none(*(pud_t *)pgd_offset(vma->vm_mm, vma->vm_start))',
                      'buffer->table_fault ? DMA_AUDIT_FAULT_PMD_TABLE : DMA_AUDIT_FAULT_LEAF',
                      'table_present != (audit_fault_plan.ordinal == 2) || !cold)',
                      '(audit_fault_plan.ordinal - 1) * DMA_AUDIT_BLOCK_BYTES));',
                      'misc_deregister(&audit_table_pmd_device)',
                      'misc_deregister(&audit_first_pte_device)'):
            with self.subTest(token=token), self.assertRaises(ValueError):
                validate(self.source.replace(token,'REMOVED'),self.config,self.makefile)

    def test_second_pgd_failure_requires_two_cold_slots_and_fixed_crossing_extent(self):
        for token in ('(vma->vm_start & ((1UL << 30) - 1)) != (1UL << 30) - DMA_AUDIT_BLOCK_BYTES',
                      '!pud_none(*(pud_t *)pgd_offset(vma->vm_mm, vma->vm_start + DMA_AUDIT_BLOCK_BYTES))',
                      '(buffer->fault_ordinal == 1 ? 0 : 2 * PAGE_SIZE)',
                      'misc_deregister(&audit_table_cross_pmd_device)',
                      'misc_deregister(&audit_table_pte_device)'):
            with self.subTest(token=token), self.assertRaises(ValueError):
                validate(self.source.replace(token,'REMOVED'),self.config,self.makefile)

    def test_unwind_accounting_baseline_owner_and_context_required(self):
        for token in ('audit_fault_buffer->table_bytes_partial = mm_pgtables_bytes(mm);',
                      'buffer->table_bytes_before = mm_pgtables_bytes(vma->vm_mm);',
                      'buffer->unwind_mm_token != (unsigned long)vma->vm_mm',
                      'buffer->unwind_task_token != (unsigned long)current',
                      'table_bytes_retry != buffer->table_bytes_before',
                      'buffer->table_bytes_partial < buffer->table_bytes_before',
                      'audit_fault_buffer = NULL;'):
            with self.subTest(token=token), self.assertRaises(ValueError):
                validate(self.source.replace(token, 'REMOVED'), self.config, self.makefile)


if __name__ == '__main__':
    unittest.main()
