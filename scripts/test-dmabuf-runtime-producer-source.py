#!/usr/bin/env python3
"""Source-policy regression only: NOT Kbuild or MMU/lifetime proof."""
from pathlib import Path
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
        'if (published != 1 || !table_present)',
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
    if source.count('.mode = 0600') != 4:
        raise ValueError('all four devices must be root-only')
    release = source.split('static int audit_release(', 1)[1].split('static bool audit_empty_destination', 1)[0]
    if not release.index('__free_pages(') < release.index('kfree(buffer);') < release.index('pr_info('):
        raise ValueError('release event must follow both real frees')
    if 'buffer->' in release.split('kfree(buffer);', 1)[1]:
        raise ValueError('use of buffer after free')
    if 'default n' not in config or '\tbool ' not in config or 'tristate' in config:
        raise ValueError('audit must default off and be built-in')
    if makefile.splitlines()[-1] != 'obj-$(CONFIG_XIAOMI_DMABUF_RUNTIME_AUDIT) += recovered-dma-audit.o':
        raise ValueError('unexpected build scope')


class SourcePolicy(unittest.TestCase):
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
                      '(unsigned long)mm)', 'if (published != 1 || !table_present)',
                      'table_present = audit_first_block_present(map_type);',
                      'audit_fault_plan = (struct dma_audit_fault_plan){0};',
                      'buffer->fault_pending = false;', 'goto undo_fault_pmd;',
                      'misc_deregister(&audit_fault_pmd_device)', 'goto undo_pte;'):
            with self.subTest(token=token), self.assertRaises(ValueError):
                validate(self.source.replace(token, 'REMOVED'), self.config, self.makefile)

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
