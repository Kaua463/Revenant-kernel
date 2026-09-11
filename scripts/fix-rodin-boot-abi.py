#!/usr/bin/env python3
"""Restore ROM-required exports and the filemap hook on pinned ACK 6.6.77.

Hook semantics from rodin source 25920d57fb543470803749031b506c0d23d341d7.
No loader, CRC, signature, or global KMI enforcement changes.
"""
from pathlib import Path
import sys


def replace_once(path, old, new):
    text = path.read_text()
    if text.count(old) != 1:
        raise ValueError(f"unexpected source context: {path}")
    path.write_text(text.replace(old, new, 1))


def main():
    root = Path(sys.argv[1])
    replace_once(root / 'include/trace/hooks/mm.h',
        '#endif /* _TRACE_HOOK_MM_H */',
        'DECLARE_HOOK(android_vh_filemap_map_pages_range,\n'
        '\tTP_PROTO(struct file *file, pgoff_t orig_start_pgoff,\n'
        '\t\tpgoff_t last_pgoff, vm_fault_t ret),\n'
        '\tTP_ARGS(file, orig_start_pgoff, last_pgoff, ret));\n'
        '#endif /* _TRACE_HOOK_MM_H */')
    replace_once(root / 'drivers/android/vendor_hooks.c',
        'EXPORT_TRACEPOINT_SYMBOL_GPL(android_vh_page_private_mod);',
        'EXPORT_TRACEPOINT_SYMBOL_GPL(android_vh_page_private_mod);\n'
        'EXPORT_TRACEPOINT_SYMBOL_GPL(android_vh_filemap_map_pages_range);')
    replace_once(root / 'mm/filemap.c',
        '\tpgoff_t last_pgoff = start_pgoff;',
        '\tpgoff_t last_pgoff = start_pgoff;\n'
        '\tpgoff_t orig_start_pgoff = start_pgoff;')
    replace_once(root / 'mm/filemap.c',
        '\tfirst_pgoff = xas.xa_index;',
        '\tfirst_pgoff = xas.xa_index;\n\torig_start_pgoff = xas.xa_index;')
    replace_once(root / 'mm/filemap.c',
        '\ttrace_android_vh_filemap_map_pages(file, first_pgoff, last_pgoff, ret);',
        '\ttrace_android_vh_filemap_map_pages(file, first_pgoff, last_pgoff, ret);\n'
        '\ttrace_android_vh_filemap_map_pages_range(file, orig_start_pgoff, last_pgoff, ret);')
    replace_once(root / 'BUILD.bazel',
        '        "android/abi_gki_aarch64_amlogic",',
        '        "android/abi_gki_aarch64_rodin_boot",\n'
        '        "android/abi_gki_aarch64_amlogic",')
    symbols = Path(__file__).resolve().parent.parent / 'configs/rodin-6.6.77-boot-symbols'
    (root / 'android/abi_gki_aarch64_rodin_boot').write_bytes(symbols.read_bytes())
    print('ROM boot exports and filemap hook integrated; loader checks preserved')


if __name__ == '__main__':
    main()
