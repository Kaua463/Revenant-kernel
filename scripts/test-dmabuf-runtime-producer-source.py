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
        'return dmabuf_huge_remap_pfn_range(',
        'misc_deregister(&audit_pmd_device)',
    )
    for token in required:
        if token not in source:
            raise ValueError('missing producer guard: ' + token)
    for token in ('EXPORT_SYMBOL', '.unlocked_ioctl', '.compat_ioctl', '.read =',
                  '.write =', 'ioremap(', 'memremap(', 'vm_operations_struct',
                  'vm_file =', 'module_init(', 'module_exit('):
        if token in source:
            raise ValueError('forbidden audit interface: ' + token)
    if source.count('.mode = 0600') != 2:
        raise ValueError('both devices must be root-only')
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


if __name__ == '__main__':
    unittest.main()
