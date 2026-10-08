# DMA: failure coverage and activation evidence

Scope: T20; V20,V21,V33,V35,V39,V40. No phone access or shipping overlay change.

## New disposable VM cases

Five VMA allocation failures per PMD/PTE mode (10 total):

- `__split_vma`: first and second owned `vm_area_dup` call.
- `copy_vma`: owned `vm_area_dup` while moving to a separate cold-PGD slot.
- `dup_mmap`: first and second owned `vm_area_dup`; second occurs after one exported VMA was copied.

Inject only for the exact audit exporter ops, arming task and mm. One-shot,
fixed root-only commands; no pointer, PFN or memory-read interface. Hash-gate
both complete input files before any write. Disabled-audit builds retain the
original allocator statements.

Each case requires real ENOMEM, a kernel-owned firing event, both aliases'
complete data integrity, retry, final DMA-BUF release exactly once, live=0,
and restored parent page-table accounting. Strict serial parser rejects
missing/duplicate/foreign events and unowned huge-helper traces.

Limits: these are VMA duplication edges, not all allocation failures. In
particular, no targeted maple-tree preallocation, policy allocation,
anon_vma_clone, vma_link, or copy_page_range allocation failure yet. Parent
accounting does not independently prove every failed child mm was leak-free.
Not a real Mali/GPU/device stress test.

## Current validation

- 61 cached offline test groups passed; production ABI/config checks retained.
- Linux native and AArch64 guest compile: Actions 37716356757, success.
- Root+DMA kernel and new VM workload: Actions 37716356798, started on commit
  `05ae807419ee9a00024073b8a2b707a2fc640f55`; no runtime completion asserted here.
- Earlier VM run 37713012839 passed the previous workload, not the 10 new cases.

## Stock mapper activation

Pinned DyperOS 3.0.304 Image SHA256:
`99485b0132e3aa28f4e965119591c8149fe3c20e7e0fd10d753ef014a582472e`.

`dmabuf_huge_remap_pfn_range` exists at `0xffffffc0803bb89c`.
Actual 8,722 PREL32 exports checked against stock names, addresses and CRCs:
no mapper export. `dma_buf_mmap` and `remap_pfn_range` are exported.

Full aligned PREL32 scan finds one target reference, at
`0xffffffc081e2131c`: decoded EH_FRAME FDE initial_location, not a callback.
FDE range is 1,196 bytes; CIE encoding is PC-relative signed 32-bit.

Earlier full text/inittext scan: no direct branch to mapper entry, no bounded
ADRP+ADD materialization or absolute pointer. Alternative-instruction
continuations are not external callers. All 610 stock module rows / 574
distinct binaries: no mapper symbol and no literal mapper name.

Exact ELF relocation routes and callback registrations:

- Mali `kbase_fops.mmap` -> `kbase_mmap`; `kbase_context_mmap` calls `dma_buf_mmap`.
- `mtk_mm_heap_buf_ops.mmap` -> `mtk_mm_heap_mmap` -> `remap_pfn_range`.
- `system_heap_buf_ops.mmap` and `mtk_slc_heap_buf_ops.mmap` ->
  `system_heap_mmap` -> `remap_pfn_range`.

These prove static registrations/call sites, not runtime execution or every
branch. Do not claim Xiaomi activates the special mapper, nor that it can
never be activated. Register-built pointers, alternate producer paths and
runtime hooks remain unresolved. The VM producer intentionally calls the
recovered mapper; it is not evidence that stock Mali does so.

## Validator failures considered

- New negative test caught an unowned huge event before VMA allocation; parser
  now rejects it. Existing evidence-ownership invariants suffice; no spec edit.
- Log-format test rejected the new fourth printk; extended exact inventory
  and checked printf types rather than weakening the gate.
- Export audit encountered two stock functions named `dev_open`; PREL32 value
  now must match one actual same-name symbol address, not a guessed unique name.

T20 remains incomplete. No installer/phone approval issued.
