#!/usr/bin/env python3
"""Exact, audit-only VMA duplication fault edges. Never a shipping overlay."""
import hashlib

PINS = {
    'mm/mmap.c': '13ec3072b605db7a01b6faa38d57bb242a098cd90af0312ce0cefda8803d74b0',
    'kernel/fork.c': '36d67fea8bd50ed0ee3416a110d39e3332f81ba81f002ebb9b8ec718f81bc395',
}


def transform(name, before):
    if name not in PINS or hashlib.sha256(before).hexdigest() != PINS[name]:
        raise ValueError('VMA fault preimage drift: ' + name)
    text = before.decode()
    declaration = ('\n#ifdef CONFIG_XIAOMI_DMABUF_RUNTIME_AUDIT\n'
                   'extern bool recovered_dma_audit_vma_fail(struct vm_area_struct *, unsigned int);\n'
                   '#endif\n')
    # Scope each replacement to a unique complete function region, retaining
    # the real allocator and error path for every non-owned mapping.
    sites = [('int __split_vma(', 'new = vm_area_dup(vma);', 'vma', 0),
             ('struct vm_area_struct *copy_vma(', 'new_vma = vm_area_dup(vma);', 'vma', 1)] if name == 'mm/mmap.c' else [
             ('static __latent_entropy int dup_mmap(', 'tmp = vm_area_dup(mpnt);', 'mpnt', 2)]
    for function, anchor, vma, site in sites:
        if text.count(function) != 1:
            raise ValueError('VMA function anchor drift: ' + function)
        start = text.index(function)
        # Assignment must be the first matching anchor after the function.
        pos = text.index(anchor, start)
        variable = anchor.split(' = ')[0]
        replacement = ('#ifdef CONFIG_XIAOMI_DMABUF_RUNTIME_AUDIT\n'
                       f'\t{variable} = recovered_dma_audit_vma_fail({vma}, {site}) ? NULL : vm_area_dup({vma});\n'
                       '#else\n\t' + anchor + '\n#endif')
        text = text[:pos] + replacement + text[pos + len(anchor):]
    # Declaration before all C code; no headers/structures/ABI change.
    anchor = '#include <linux/mm.h>\n'
    if text.count(anchor) != 1:
        raise ValueError('VMA include anchor drift')
    text = text.replace(anchor, anchor + declaration)
    return text.encode()
