# Disposable DMA runtime audit — preparation, not implemented runtime proof

`audit-map-contract.h` is a **new test-producer preflight**, not Xiaomi code,
not a shipping hook and not wired into any kernel build. It deliberately limits
the future test producer to shared, 2 MiB-aligned mappings within its owned
allocation, ARM64 4 KiB pages and 39-bit VA/PA. It does not restrict or rewrite
the recovered stock remap function.

Host verification:

```sh
python3 scripts/test-dmabuf-audit-map-contract.py
```

This compiles with `-Werror`, ASan and UBSan, checks every rejection reason and
30,240 scalar combinations against a separate modulo/subtraction oracle.
Acceptance is only a scalar preflight. The `destination_empty` argument is a
fact the future kernel producer must establish from the real page tables; it
must never be accepted from userspace.

Requirements before building/running the producer:

1. Disposable ARM64 VM only; opt-in built-in test configuration, default off,
   no external symbol export, no device access or phone installer.
2. Actual contiguous owned allocation, zeroed, stable normal-memory attributes;
   no user-provided PFN, MMIO, reserved memory or arbitrary physical dump.
3. `mmap_write_lock` held by the real mmap call; prove fresh/empty PMDs before
   publishing and reject unexpected page-table entries. Scalar checks do not
   prove locks or emptiness.
4. Retain the backing allocation through all VMA file references, splits,
   forks, moves, partial errors, unmaps and deferred final file release.
5. Verify the failure path before allocating extra driver-owned VMA references.
   In pinned ACK `__mmap_region`, `unmap_and_free_file_vma` first calls
   `fput(vma->vm_file)`, clears that field, **then** unmaps partial mappings and
   frees the VMA. It does not call `vma_close` at that label. Do not assume a
   failed `.mmap` callback gets a balancing `.close`.

For the planned file-owned allocation, the userspace non-anonymous mmap syscall
has an independent `fget(fd)` reference: `ksys_mmap_pgoff` drops it only after
`vm_mmap_pgoff` returns. That source-level relationship can protect backing
during error unwind, even though the VMA's `fput` precedes unmap. It is **not yet
tested as a full runtime sequence**. An in-kernel mmap caller without that
reference must not be assumed safe. A real GPU producer may have a different
ownership contract and remains unverified.

The runtime driver, guest MMU/SMP workload, fault injection and full unwind
verification are still pending. Host preflight success grants no installation
or shipping approval.
