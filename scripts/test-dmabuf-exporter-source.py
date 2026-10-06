#!/usr/bin/env python3
"""RAM-only exporter source/format policy. NOT kernel compilation or runtime."""
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]/'tools/stock-recovery/runtime-audit'


def validate(source):
    required = (
        'defined(MODULE)', '!defined(CONFIG_XIAOMI_DMABUF_RUNTIME_AUDIT)',
        '!defined(CONFIG_DMA_SHARED_BUFFER)', 'CONFIG_PGTABLE_LEVELS != 3',
        'EXPORT_MAX_LIVE 8', 'if (atomic_inc_return(&export_live) > EXPORT_MAX_LIVE)',
        'if (argument || (command != DMA_AUDIT_EXPORT_PMD',
        'command != DMA_AUDIT_EXPORT_PTE && command != DMA_AUDIT_EXPORT_LIVE)',
        'return atomic_read(&export_live);', '__GFP_ZERO | __GFP_COMP',
        'length > EXPORT_BYTES - offset', 'vma->vm_pgoff > (ULONG_MAX >> PAGE_SHIFT)',
        'vm_flags_clear(vma, VM_MAYEXEC)', '!export_empty_destination(vma)',
        'if (!pmd_none(*pmd))', 'vma->vm_flags & VM_EXEC',
        '!(vma->vm_flags & VM_SHARED)', 'info.size = EXPORT_BYTES;',
        'info.priv = buffer;', 'dma_buf_export(&info)', 'dma_buf_fd(dmabuf, O_CLOEXEC)',
        'if (fd < 0)\n\t\tdma_buf_put(dmabuf);',
        'recovered_dma_audit_plain_remap(vma, pfn, buffer->mode)',
        'mmap_assert_write_locked(vma->vm_mm)', 'sg_set_page(table->sgl, buffer->pages, EXPORT_BYTES, 0)',
        'dma_map_sgtable(attachment->dev, table, direction, 0)',
        'dma_unmap_sgtable(attachment->dev, table, direction, 0)',
        '.mmap = dma_export_audit_mmap', '.release = dma_export_audit_release', '.mode = 0600',
    )
    for token in required:
        if token not in source:
            raise ValueError('missing RAM-only exporter boundary: '+token)
    if source.count('if (!capable(CAP_SYS_ADMIN))') != 2:
        raise ValueError('factory open+ioctl capability required')
    for token in ('EXPORT_SYMBOL', 'ioremap(', 'memremap(', 'copy_from_user(',
                  'copy_to_user(', '.read =', '.write =', 'vm_file =', 'vm_operations_struct'):
        if token in source:
            raise ValueError('forbidden exporter interface: '+token)
    release = source.split('static void dma_export_audit_release(',1)[1].split('static bool export_empty_destination',1)[0]
    if not release.index('__free_pages(') < release.index('kfree(buffer);') < release.index('pr_info(') < release.index('atomic_dec('):
        raise ValueError('release/query must follow actual backing frees')
    if 'buffer->' in release.split('kfree(buffer);',1)[1]:
        raise ValueError('export buffer used after free')


def compile_formats(source):
    structure = re.search(r'struct export_buffer \{.*?\n\};',source,re.S)
    logs = re.findall(r'\bpr_info\((.*?)\);',source,re.S)
    if not structure or len(logs) != 3:
        raise ValueError('export log inventory drift')
    code = '''#include "audit-map-contract.h"
#define EXPORT_BYTES (2UL * DMA_AUDIT_BLOCK_BYTES)
void checked_log(const char *, ...) __attribute__((format(printf,1,2)));
''' + structure.group(0) + '''
void check_logs(void) {
 struct export_buffer storage = {0}, *buffer = &storage;
 unsigned long long id = 0;
 unsigned int mode = 0;
 unsigned long length = 0, offset = 0;
 int result = 0;
''' + '\n'.join('checked_log('+log+');' for log in logs) + '\n}\n'
    return subprocess.run(['clang','-x','c','-std=c11','-Wall','-Wextra','-Werror',
                           '-Wformat','-fsyntax-only','-I',str(ROOT),'-'],
                          input=code,text=True,capture_output=True)


class Exporter(unittest.TestCase):
    def setUp(self):
        self.source = (ROOT/'recovered-dma-export-audit.c').read_text()

    def test_source_boundaries(self):
        validate(self.source)

    def test_missing_guard_and_extra_interface(self):
        for token in ('length > EXPORT_BYTES - offset', 'info.size = EXPORT_BYTES;',
                      'vm_flags_clear(vma, VM_MAYEXEC)', '!export_empty_destination(vma)',
                      'if (!capable(CAP_SYS_ADMIN))', 'dma_buf_fd(dmabuf, O_CLOEXEC)',
                      'if (argument || (command != DMA_AUDIT_EXPORT_PMD'):
            with self.subTest(token=token), self.assertRaises(ValueError):
                validate(self.source.replace(token,'REMOVED'))
        for token in ('copy_from_user(x)', 'ioremap(x)', '.read = dump', 'EXPORT_SYMBOL(x)'):
            with self.subTest(token=token), self.assertRaises(ValueError):
                validate(self.source+'\n'+token)

    def test_free_order_and_no_use_after_free(self):
        changed = self.source.replace('kfree(buffer);\n\tpr_info(', 'pr_info(')
        with self.assertRaises((ValueError,IndexError)):
            validate(changed)
        changed = self.source.replace('id, mode);','buffer->id, mode);',1)
        with self.assertRaises(ValueError):
            validate(changed)

    def test_actual_printf_expressions(self):
        result = compile_formats(self.source)
        self.assertEqual(result.returncode,0,result.stderr)
        result = compile_formats(self.source.replace('(unsigned long)EXPORT_BYTES','EXPORT_BYTES'))
        self.assertNotEqual(result.returncode,0)
        self.assertIn('format specifies type',result.stderr)

    def test_shared_fault_site_mutex_on_plain_remap(self):
        source = (ROOT/'recovered-dma-audit.c').read_text()
        body = source.split('int recovered_dma_audit_plain_remap(struct vm_area_struct *vma,',2)[2].split('static bool audit_first_block_present',1)[0]
        self.assertLess(body.index('mutex_lock(&audit_fault_mutex)'),body.index('dmabuf_huge_remap_pfn_range('))
        self.assertLess(body.index('dmabuf_huge_remap_pfn_range('),body.index('mutex_unlock(&audit_fault_mutex)'))
        self.assertNotIn('EXPORT_SYMBOL',source)

    def test_guest_fcntl_negative_is_not_cloexec_success(self):
        guest = (ROOT/'guest-workload.c').read_text()
        self.assertIn('fd_flags = fcntl(fd, F_GETFD);',guest)
        self.assertIn('if (fd_flags < 0 || !(fd_flags & FD_CLOEXEC) ||',guest)
        program = '''#include <fcntl.h>
int reject_flags(int flags) { return flags < 0 || !(flags & FD_CLOEXEC); }
int main(void) { return !reject_flags(-1) || !reject_flags(0) || reject_flags(FD_CLOEXEC); }
'''
        import tempfile
        with tempfile.TemporaryDirectory(prefix='dma-cloexec-regression-') as temporary:
            executable = Path(temporary)/'flags'
            subprocess.run(['clang','-x','c','-std=c11','-Wall','-Wextra','-Werror',
                            '-o',str(executable),'-'],input=program,text=True,check=True)
            subprocess.run([str(executable)],check=True)


if __name__ == '__main__':
    unittest.main()
