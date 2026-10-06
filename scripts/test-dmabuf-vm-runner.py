#!/usr/bin/env python3
"""Runner failure/command policy tests; no QEMU invocation."""
from importlib.machinery import SourceFileLoader
from pathlib import Path
import json
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

module = SourceFileLoader('dma_vm_runner', str(Path(__file__).with_name('run-dmabuf-vm-audit.py'))).load_module()
def mock_pass():
    lines = []
    for identity, mode, device, inject in ((1, 0, 'pmd', 0), (2, 1, 'pte', 0),
                                           (3, 0, 'fault-pmd', 2), (4, 1, 'fault-pte', 2),
                                           (5, 0, 'first-pmd', 1), (6, 1, 'first-pte', 1),
                                           (7, 0, 'table-pmd', 3), (8, 1, 'table-pte', 3),
                                           (9, 0, 'table-cross-pmd', 4), (10, 1, 'table-cross-pte', 4)):
        lines.append(f'DMA_AUDIT_ALLOC id={identity} mode={mode} bytes=4194304 fault={int(bool(inject))}')
        if inject:
            partial = 20480 if inject == 4 else 16384 if inject == 2 else 12288
            if inject >= 3:
                ordinal = inject-2
                lines.append(f'DMA_GUEST_COLD_RANGE mode={mode} bytes={ordinal << 30} aligned=1')
                fired = f'DMA_AUDIT_TABLE_FAULT id={identity} mode={mode} ordinal={ordinal} published={ordinal-1} table={ordinal-1} cold=1'
            else:
                fired = f'DMA_AUDIT_FAULT id={identity} mode={mode} ordinal={inject} published={inject-1} table={inject-1}'
            lines.extend((fired,
                          f'DMA_AUDIT_FAULT_RETURN id={identity} mode={mode} result=-12 fired=1',
                          f'DMA_AUDIT_UNWIND id={identity} mode={mode} before=12288 partial={partial} retry=12288',
                          f'DMA_GUEST_ENOMEM_PASS: /dev/recovered-dma-audit-{device} same_address_retry=1'))
        lines.extend((f'DMA_GUEST_CROSS_PGD: /dev/recovered-dma-audit-{device} bytes=4194304 root_slots=2 data_verified=1',
                      *((['DMA_AUDIT_HUGE_MOVE','DMA_AUDIT_HUGE_MOVE','DMA_AUDIT_HUGE_SPLIT']) if mode==0 else []),
                      f'DMA_GUEST_PRE_FORK: /dev/recovered-dma-audit-{device} move=1 protect=1 read_concurrent=1 cpu_migrate=1 data_verified=1',
                      f'DMA_GUEST_FORK_PASS: /dev/recovered-dma-audit-{device} shared_write=1 data_verified=1',
                      f'DMA_GUEST_SPLIT_MOVE: /dev/recovered-dma-audit-{device} segments=3 whole_move_errno=14 data_verified=1',
                      f'DMA_GUEST_LAST_UNMAP: /dev/recovered-dma-audit-{device}',
                      f'DMA_AUDIT_RELEASE id={identity} mode={mode}',
                      f'DMA_GUEST_CASE_PASS: /dev/recovered-dma-audit-{device} reader_passes=1'))
    for mode in (0,1):
        identity = mode + 1
        lines.append(f'DMA_EXPORT_ALLOC id={identity} mode={mode} bytes=4194304')
        for length,mask,huge,hint in ((4096,4095,0,0),(65536,65535,0,1),
                                      (2097152,2097151,1,1),(4194304,2097151,1,0)):
            lines.append(f'DMA_EXPORT_MMAP id={identity} mode={mode} bytes={length} offset=0 huge={huge} result=0')
            lines.append(f'DMA_EXPORT_ALIGN mode={mode} bytes={length} mask={mask} aligned=1 hint_checked={hint}')
        lines.extend((*((['DMA_AUDIT_HUGE_MOVE','DMA_AUDIT_HUGE_MOVE','DMA_AUDIT_HUGE_SPLIT']) if mode==0 else []),
                      f'DMA_GUEST_PRE_FORK: export-mode-{mode} move=1 protect=1 read_concurrent=1 cpu_migrate=1 data_verified=1',
                      f'DMA_EXPORT_FORK_PASS mode={mode} shared_write=1 data_verified=1',
                      f'DMA_GUEST_SPLIT_MOVE: export-mode-{mode} segments=3 whole_move_errno=14 data_verified=1',
                      f'DMA_EXPORT_LAST_UNMAP mode={mode}',
                      f'DMA_EXPORT_RELEASE id={identity} mode={mode}',
                      f'DMA_EXPORT_CASE_PASS mode={mode} live=0'))
    return '\n'.join(lines + ['DMA_GUEST_PASS: basic tests', 'DMA_VM_RESULT_PASS: finished'])


PASS = mock_pass()


class Runner(unittest.TestCase):
    def test_fragmented_vma_move_coverage_is_required_and_ordered(self):
        for label, fork in (('/dev/recovered-dma-audit-pmd',
                             'DMA_GUEST_FORK_PASS: /dev/recovered-dma-audit-pmd shared_write=1 data_verified=1'),
                            ('export-mode-0', 'DMA_EXPORT_FORK_PASS mode=0 shared_write=1 data_verified=1')):
            marker=f'DMA_GUEST_SPLIT_MOVE: {label} segments=3 whole_move_errno=14 data_verified=1'
            for replacement in ('',marker+'\n'+marker,marker.replace('segments=3','segments=2'),
                                marker.replace('whole_move_errno=14','whole_move_errno=0')):
                with self.subTest(label=label,replacement=replacement), self.assertRaises(ValueError):
                    module.check_log(PASS.replace(marker,replacement))
            with self.assertRaises(ValueError):
                module.check_log(PASS.replace(marker,'').replace(fork,marker+'\n'+fork))

    def test_all_huge_events_require_unique_owned_pmd_lifetime(self):
        event = 'DMA_AUDIT_HUGE_SPLIT\n'
        for changed in (event+PASS, PASS+'\n'+event,
                        PASS+'\nDMA_AUDIT_HUGE_UNKNOWN\n',
                        PASS.replace('DMA_AUDIT_RELEASE id=2 mode=1',
                                     event+'DMA_AUDIT_RELEASE id=2 mode=1'),
                        PASS.replace('DMA_EXPORT_RELEASE id=2 mode=1',
                                     event+'DMA_EXPORT_RELEASE id=2 mode=1')):
            with self.subTest(changed=changed[-90:]),self.assertRaises(ValueError):
                module.check_log(changed)
        # Fork legitimately splits another PMD after the pre-fork marker.
        module.check_log(PASS.replace('DMA_GUEST_FORK_PASS: /dev/recovered-dma-audit-pmd',
                                     event+'DMA_GUEST_FORK_PASS: /dev/recovered-dma-audit-pmd'))

    def test_actual_huge_move_and_split_trace_required_before_prefork_marker(self):
        for event in ('DMA_AUDIT_HUGE_MOVE','DMA_AUDIT_HUGE_SPLIT'):
            for replace in ('',event+' invalid',event+'\n'+event):
                with self.subTest(event=event,replace=replace),self.assertRaises(ValueError):
                    module.check_log(PASS.replace(event,replace,1))
        pte='DMA_GUEST_PRE_FORK: /dev/recovered-dma-audit-pte'
        with self.assertRaises(ValueError):
            module.check_log(PASS.replace(pte,'DMA_AUDIT_HUGE_MOVE\n'+pte))
        # A guest marker alone must not pass a PMD workload run as ordinary PTE.
        with self.assertRaises(ValueError):
            module.check_log(PASS.replace('DMA_AUDIT_HUGE_MOVE\n','').replace('DMA_AUDIT_HUGE_SPLIT\n',''))

    def test_prefork_checks_cannot_be_missing_duplicated_or_run_after_fork(self):
        for label, fork in (('/dev/recovered-dma-audit-pmd',
                             'DMA_GUEST_FORK_PASS: /dev/recovered-dma-audit-pmd shared_write=1 data_verified=1'),
                            ('export-mode-0','DMA_EXPORT_FORK_PASS mode=0 shared_write=1 data_verified=1')):
            before = f'DMA_GUEST_PRE_FORK: {label} move=1 protect=1 read_concurrent=1 cpu_migrate=1 data_verified=1'
            for changed in ('',before+'\n'+before,before.replace('data_verified=1','data_verified=0'),
                            before.replace('read_concurrent=1','read_concurrent=0'),
                            before.replace('cpu_migrate=1','cpu_migrate=0')):
                with self.subTest(label=label,changed=changed), self.assertRaises(ValueError):
                    module.check_log(PASS.replace(before,changed))
            with self.assertRaises(ValueError):
                module.check_log(PASS.replace(before+'\n'+fork,fork+'\n'+before))

    def test_second_pgd_failure_requires_one_owned_block_and_exact_two_table_pages(self):
        event = 'DMA_AUDIT_TABLE_FAULT id=9 mode=0 ordinal=2 published=1 table=1 cold=1'
        for before,after in (('ordinal=2','ordinal=1'),('published=1','published=0'),
                             ('table=1','table=0'),('cold=1','cold=0'),
                             ('id=9','id=7'),('mode=0','mode=1')):
            with self.subTest(before=before), self.assertRaises(ValueError):
                module.check_log(PASS.replace(event,event.replace(before,after)))
        accounting = 'DMA_AUDIT_UNWIND id=9 mode=0 before=12288 partial=20480 retry=12288'
        for replacement in ('',accounting.replace('partial=20480','partial=16384'),
                            accounting.replace('partial=20480','partial=12288'),
                            accounting.replace('partial=20480','partial=24576'),
                            accounting.replace('retry=12288','retry=20480'),
                            accounting.replace('id=9','id=10')):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                module.check_log(PASS.replace(accounting,replacement))
        cold = 'DMA_GUEST_COLD_RANGE mode=0 bytes=2147483648 aligned=1'
        for replacement in ('',cold.replace('2147483648','1073741824'),
                            cold.replace('mode=0','mode=1')):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                module.check_log(PASS.replace(cold,replacement))

    def test_cross_pgd_data_proof_is_required_for_every_owned_buffer(self):
        crossing = 'DMA_GUEST_CROSS_PGD: /dev/recovered-dma-audit-pmd bytes=4194304 root_slots=2 data_verified=1'
        for replacement in ('',crossing.replace('root_slots=2','root_slots=1'),
                            crossing.replace('data_verified=1','data_verified=0'),
                            crossing.replace('bytes=4194304','bytes=2097152'),
                            crossing.replace('audit-pmd','audit-pte')):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                module.check_log(PASS.replace(crossing,replacement))
        with self.assertRaises(ValueError):
            module.check_log(crossing+'\n'+PASS.replace(crossing,''))
        with self.assertRaises(ValueError):
            module.check_log(PASS+'\n'+crossing)
        for identity,device in ((5,'first-pmd'),(7,'table-pmd')):
            crossing = f'DMA_GUEST_CROSS_PGD: /dev/recovered-dma-audit-{device} bytes=4194304 root_slots=2 data_verified=1'
            allocation = f'DMA_AUDIT_ALLOC id={identity} mode=0 bytes=4194304 fault=1'
            early = PASS.replace(crossing,'',1).replace(allocation,allocation+'\n'+crossing,1)
            with self.subTest(device=device), self.assertRaises(ValueError):
                module.check_log(early)

    def test_cold_pud_fault_requires_empty_table_zero_accounting_and_reservation(self):
        original = 'DMA_AUDIT_TABLE_FAULT id=7 mode=0 ordinal=1 published=0 table=0 cold=1'
        for before,after in (('ordinal=1','ordinal=2'),('published=0','published=1'),
                             ('table=0','table=1'),('cold=1','cold=0'),('id=7','id=5'),
                             ('mode=0','mode=1')):
            with self.subTest(before=before), self.assertRaises(ValueError):
                module.check_log(PASS.replace(original,original.replace(before,after)))
        accounting = 'DMA_AUDIT_UNWIND id=7 mode=0 before=12288 partial=12288 retry=12288'
        for before,after in (('partial=12288','partial=16384'),('partial=12288','partial=8192'),
                             ('retry=12288','retry=16384'),('id=7','id=8')):
            with self.subTest(before=before), self.assertRaises(ValueError):
                module.check_log(PASS.replace(accounting,accounting.replace(before,after)))
        cold = 'DMA_GUEST_COLD_RANGE mode=0 bytes=1073741824 aligned=1'
        for replacement in ('',cold.replace('mode=0','mode=1'),
                            cold.replace('aligned=1','aligned=0'),cold.replace('1073741824','4194304')):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                module.check_log(PASS.replace(cold,replacement))
        with self.assertRaises(ValueError):
            module.check_log(PASS.replace(cold+'\n'+original,original+'\n'+cold))
        with self.assertRaises(ValueError):
            module.check_log(PASS+'\n'+original+'\n')

    def test_first_leaf_requires_zero_publication_and_restored_accounting(self):
        original = 'DMA_AUDIT_FAULT id=5 mode=0 ordinal=1 published=0 table=0'
        for replacement in (
                original.replace('ordinal=1', 'ordinal=2'),
                original.replace('published=0', 'published=1'),
                original.replace('table=0', 'table=1'),
                original.replace('id=5', 'id=3'),
                original.replace('mode=0', 'mode=1'), ''):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                module.check_log(PASS.replace(original,replacement))
        accounting = 'DMA_AUDIT_UNWIND id=5 mode=0 before=12288 partial=12288 retry=12288'
        module.check_log(PASS.replace(accounting,accounting.replace('partial=12288','partial=16384')))
        for replacement in (
                accounting.replace('partial=12288','partial=20480'),
                accounting.replace('partial=12288','partial=8192'),
                accounting.replace('retry=12288','retry=16384'),
                accounting.replace('id=5','id=6'), ''):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                module.check_log(PASS.replace(accounting,replacement))
        for marker in ('DMA_GUEST_ENOMEM_PASS: /dev/recovered-dma-audit-first-pmd same_address_retry=1',
                       'DMA_GUEST_LAST_UNMAP: /dev/recovered-dma-audit-first-pmd',
                       'DMA_GUEST_CASE_PASS: /dev/recovered-dma-audit-first-pmd reader_passes=1'):
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                module.check_log(PASS.replace(marker,''))

    def test_kernel_error_precedes_missing_completion_diagnostic(self):
        with self.assertRaisesRegex(ValueError,'guest/kernel failure reported: Oops:'):
            module.check_log('Internal error: Oops: bad pointer\nKernel panic\n')

    def test_export_core_events_fail_closed(self):
        mutations = (
            PASS.replace('DMA_EXPORT_RELEASE id=1 mode=0\n',''),
            PASS.replace('DMA_EXPORT_ALLOC id=2','DMA_EXPORT_ALLOC id=1'),
            PASS.replace('offset=0 huge=1 result=0','offset=0 huge=1 result=-12',1),
            PASS.replace('mask=65535','mask=4095',1),
            PASS.replace('hint_checked=1','hint_checked=0',1),
            PASS.replace('DMA_EXPORT_CASE_PASS mode=0 live=0','DMA_EXPORT_CASE_PASS mode=0 live=1'),
            PASS.replace('DMA_EXPORT_LAST_UNMAP mode=0\nDMA_EXPORT_RELEASE id=1 mode=0',
                         'DMA_EXPORT_RELEASE id=1 mode=0\nDMA_EXPORT_LAST_UNMAP mode=0'),
            PASS.replace('DMA_EXPORT_MMAP id=1 mode=0 bytes=65536','DMA_EXPORT_MMAP id=2 mode=0 bytes=65536'),
            PASS+'\nDMA_EXPORT_ALIGN mode=0 bytes=65536 mask=65535 aligned=1 hint_checked=1',
        )
        for index, text in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(ValueError):
                module.check_log(text)

    def fixture(self, folder):
        image = bytearray(64)
        image[56:60] = b'ARMd'
        (folder/'Image').write_bytes(image)
        (folder/'config').write_text('\n'.join('CONFIG_' + name + '=y' for name in module.REQUIRED))
        (folder/'initramfs').write_bytes(b'070701')
        return SimpleNamespace(kernel=folder/'Image', config=folder/'config',
                               initramfs=folder/'initramfs', output=folder/'evidence', timeout=30)

    def test_mock_process_success_and_refuse_overwrite(self):
        with tempfile.TemporaryDirectory(prefix='dma-vm-runner-test-') as temporary:
            args = self.fixture(Path(temporary))
            result = subprocess.CompletedProcess([], 0, stdout=PASS.encode())
            with patch.object(module.subprocess, 'run', return_value=result) as process:
                module.run(args)
                self.assertEqual(process.call_args.kwargs['timeout'], 30)
                with self.assertRaises(ValueError):
                    module.run(args)
                self.assertEqual(process.call_count, 1)
            self.assertEqual(json.loads((args.output/'report.json').read_text())['status'],
                             'BASIC_GUEST_WORKLOAD_PASS_NOT_FULL_DMA_PROOF')

    def test_timeout_and_nonzero_preserve_failure(self):
        for failure in (subprocess.CompletedProcess([], 1, stdout=PASS.encode()),
                        subprocess.TimeoutExpired([], 30, output=b'boot still running')):
            with tempfile.TemporaryDirectory(prefix='dma-vm-runner-test-') as temporary:
                args = self.fixture(Path(temporary))
                parameters = {'side_effect': failure} if isinstance(failure, Exception) else {'return_value': failure}
                with patch.object(module.subprocess, 'run', **parameters), self.assertRaises(RuntimeError):
                    module.run(args)
                report = json.loads((args.output/'report.json').read_text())
                self.assertEqual(report['status'], 'GUEST_FAILED')
                self.assertTrue(report['failure'])
                self.assertTrue((args.output/'serial.log').exists())

    def test_markers_and_errors(self):
        module.check_log(PASS)
        for marker in ('DMA_GUEST_CASE_PASS:', 'DMA_GUEST_PASS:', 'DMA_VM_RESULT_PASS:'):
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                module.check_log(PASS.replace(marker, 'missing', 1))
        for error in ('DMA_GUEST_FAIL: x', 'DMA_VM_RESULT_FAIL: x', 'BUG: x',
                      'WARNING: x', 'Oops: x', 'Kernel panic', 'Call trace:', 'DMA_AUDIT_FAULT_FAIL: x',
                      'DMA_AUDIT_ACCOUNTING_FAIL: x'):
            with self.subTest(error=error), self.assertRaises(ValueError):
                module.check_log(PASS + '\n' + error)
        with self.assertRaises(ValueError):
            module.check_log(PASS + '\nDMA_GUEST_PASS: duplicate')

    def test_config_gate(self):
        config = '\n'.join('CONFIG_' + name + '=y' for name in module.REQUIRED)
        module.check_config(config)
        for name in module.REQUIRED:
            with self.subTest(name=name), self.assertRaises(ValueError):
                module.check_config(config.replace('CONFIG_' + name + '=y', 'CONFIG_' + name + '=m'))

    def test_final_release_rejects_incomplete_or_wrong_lifetime(self):
        mutations = (
            PASS.replace('DMA_AUDIT_RELEASE id=1 mode=0\n', ''),
            PASS + '\nDMA_AUDIT_RELEASE id=1 mode=0\n',
            PASS.replace('RELEASE id=1', 'RELEASE id=3'),
            PASS.replace('ALLOC id=2', 'ALLOC id=1'),
            PASS.replace('ALLOC id=1 mode=0', 'ALLOC id=1 mode=1'),
            PASS.replace('bytes=4194304', 'bytes=4096', 1),
            PASS.replace('DMA_GUEST_LAST_UNMAP: /dev/recovered-dma-audit-pmd\nDMA_AUDIT_RELEASE id=1 mode=0',
                         'DMA_AUDIT_RELEASE id=1 mode=0\nDMA_GUEST_LAST_UNMAP: /dev/recovered-dma-audit-pmd'),
            PASS.replace('DMA_AUDIT_RELEASE id=1 mode=0\nDMA_GUEST_CASE_PASS: /dev/recovered-dma-audit-pmd reader_passes=1',
                         'DMA_GUEST_CASE_PASS: /dev/recovered-dma-audit-pmd reader_passes=1\nDMA_AUDIT_RELEASE id=1 mode=0'),
        )
        for index, text in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(ValueError):
                module.check_log(text)

    def test_kernel_timestamp_prefix_and_crlf(self):
        prefixed = '\n'.join('[    1.000] ' + line if line.startswith('DMA_AUDIT_') else line
                             for line in PASS.splitlines())
        module.check_log(prefixed.replace('\n', '\r\n'))

    def test_partial_enomem_evidence_negative_mutations(self):
        for before, after in (('ordinal=2', 'ordinal=1'), ('published=1', 'published=0'), ('table=1', 'table=0'),
                              ('result=-12', 'result=0'), ('fired=1', 'fired=0'),
                              ('FAULT id=3', 'FAULT id=1'), ('FAULT id=3 mode=0', 'FAULT id=3 mode=1'),
                              ('same_address_retry=1', 'same_address_retry=0'),
                              ('DMA_GUEST_ENOMEM_PASS:', 'missing')):
            with self.subTest(before=before), self.assertRaises(ValueError):
                module.check_log(PASS.replace(before, after, 1))
        with self.assertRaises(ValueError):
            module.check_log(PASS + '\nDMA_AUDIT_FAULT id=3 mode=0 ordinal=2 published=1\n')
        with self.assertRaises(ValueError):
            module.check_log('DMA_GUEST_PASS: early\n' + PASS.replace('DMA_GUEST_PASS: basic tests', 'removed'))

    def test_ram_only_command(self):
        args = SimpleNamespace(kernel=Path('/tmp/audit/Image'), initramfs=Path('/tmp/audit/initramfs.cpio'))
        cmd = module.command(args)
        self.assertEqual(cmd[0], 'qemu-system-aarch64')
        for flag in ('-monitor', '-nic'):
            self.assertEqual(cmd[cmd.index(flag) + 1], 'none')
        self.assertEqual(cmd[cmd.index('-smp') + 1], '4')
        self.assertFalse(any(word in cmd for word in ('-drive', '-hda', '-device', '-netdev', '-virtfs')))

    def test_accounting_rejects_leak_underflow_wrong_identity_and_order(self):
        for before, after in (('retry=12288', 'retry=16384'), ('partial=16384', 'partial=12288'),
                              ('partial=16384', 'partial=8192'), ('partial=16384', 'partial=24576'),
                              ('before=12288', 'before=12289'), ('UNWIND id=3', 'UNWIND id=1'),
                              ('UNWIND id=3 mode=0', 'UNWIND id=3 mode=1'), ('DMA_AUDIT_UNWIND', 'missing')):
            with self.subTest(before=before), self.assertRaises(ValueError):
                module.check_log(PASS.replace(before, after, 1))
        module.check_log(PASS.replace('partial=16384', 'partial=20480'))  # PTE + PMD pages.
        with self.assertRaises(ValueError):
            module.check_log(PASS + '\nDMA_AUDIT_UNWIND id=3 mode=0 before=12288 partial=16384 retry=12288\n')
        returned = 'DMA_AUDIT_FAULT_RETURN id=3 mode=0 result=-12 fired=1'
        unwound = 'DMA_AUDIT_UNWIND id=3 mode=0 before=12288 partial=16384 retry=12288'
        with self.assertRaises(ValueError):
            module.check_log(PASS.replace(returned + '\n' + unwound, unwound + '\n' + returned))


if __name__ == '__main__':
    unittest.main()
