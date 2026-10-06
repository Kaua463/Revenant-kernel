#!/usr/bin/env python3
"""Audit-only successful PMD move/split events; exact canonical fault input only."""
import hashlib
from importlib.machinery import SourceFileLoader
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
sites=SourceFileLoader('dma_trace_fault_sites',str(HERE/'prepare-dmabuf-fault-sites.py')).load_module()
extract=SourceFileLoader('dma_trace_extract',str(HERE/'test-dmabuf-stock-deposit.py')).load_module().body
EVENTS=(
    ('bool move_dmabuf_huge_pmd(', '\tmoved = true;', 'DMA_AUDIT_HUGE_MOVE'),
    ('void __split_dmabuf_huge_pmd(', '\tatomic64_inc(&dmabuf_hugetlb_pmd_split);', 'DMA_AUDIT_HUGE_SPLIT'),
)


def transform(data):
    text=data.decode()
    if text.count(sites.DECLARATION)!=1:
        raise ValueError('exact canonical fault-instrumented source required')
    restored=text.replace(sites.DECLARATION,'',1)
    for before,after in sites.SITES:
        if restored.count(after)!=1:raise ValueError('fault site drift')
        restored=restored.replace(after,before,1)
    expected=json.loads(sites.MANIFEST.read_text())['changes']['mm/huge_memory.c']['after']
    if hashlib.sha256(restored.encode()).hexdigest()!=expected:
        raise ValueError('canonical trace input drift')
    for signature,anchor,event in EVENTS:
        body=extract(text,signature)
        if body.count(anchor)!=1:raise ValueError('trace anchor drift')
        marker='\n#ifdef CONFIG_XIAOMI_DMABUF_RUNTIME_AUDIT\n\tpr_info("'+event+'\\n");\n#endif'
        text=text.replace(body,body.replace(anchor,anchor+marker,1),1)
    return text.encode()
