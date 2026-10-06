# Disposable DMA runtime audit — source, not runtime proof

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

`recovered-dma-audit.c` now implements the separate test producer source. Two
0600 misc devices require CAP_SYS_ADMIN to open: `recovered-dma-audit-pmd` uses
map_type=0; `recovered-dma-audit-pte` uses map_type=1. Each open owns a fresh,
zeroed, contiguous 4 MiB order-10 allocation, released by the last file release.
High-order allocation can legitimately fail; no fallback to arbitrary memory.
Mappings may cover aligned 2 or 4 MiB subsets, shared and non-executable only.
The mmap callback validates overflow/bounds, checks every actual destination
PMD under mmap write lock, and rejects even preallocated PTE tables. It invokes
the recovered mapper unchanged. It keeps vm_file and adds no VMA callbacks or
extra VMA references. No ioctl/read/write/physical-address interface exists.

Kconfig/Makefile are **not sourced by any shipping kernel tree or workflow**. Their
built-in, default-off option is for a disposable ARM64 VM build only;
the C guards also reject module, wrong geometry or missing recovered feature.
No shipping overlay/config has changed. `prepare-dmabuf-runtime-audit.py` gates
all pristine reference hashes/canonical recipes, all post-DMA inputs and four
producer source pins before adding six paths in a disposable tree. Drift,
symlinks, existing destination/evidence and repeated application fail closed.
`test-dmabuf-runtime-integration.py` covers those conditions in temporary trees.
The separate `audit-rodin-dma-producer.yml` compiles built-in on exact ACK,
requires config plus producer objects in vmlinux, and uploads evidence only.
It shares the existing audit concurrency group and never cancels a live audit.
Compile results and guest MMU/SMP workload, fault injection and full unwind
verification are still pending. The workflow does not boot or publish a VM image.

```sh
python3 scripts/test-dmabuf-runtime-producer-source.py
```

This is a source-policy check with negative mutations, **not compilation or
semantic verification**. Host checks grant no installation/shipping approval;
the new producer does not establish the original Xiaomi GPU activation route.

Guest workload source: `guest-workload.c` requires explicit
`--disposable-qemu-vm`, ARM64/4K and `linux,dummy-virt` DT compatible; refuses
phones. It tests both producer devices: invalid/private/execute/overrun mmap
rejection, two aliases, every data word, close(fd) with live mappings, fork
shared-write visibility, child partial unmap, mremap, mprotect split/restore,
MAYEXEC refusal, parent partial unmap, cross-CPU verification and concurrent
reader on the surviving alias during other-VMA teardown. Final alias unmaps.
This is **not yet executed in a guest**, does not verify final allocation-free
count or fault-injected partial ENOMEM unwind, and does not prove all lifetimes.

```sh
python3 scripts/test-dmabuf-guest-data.py
```

This host ASan/UBSan oracle detects corruption at each of 1024 page boundaries.
It does not emulate or access page tables. Separate `audit-rodin-dma-guest-source`
workflow compiles Linux-native and static AArch64 workload and checks native
refusal; it does not run QEMU, produce kernel artifacts or access a device.

Pristine reference validation uses a temporary independent Git root so an
unrelated workflow checkout cannot filter patch paths. Seven integration tests
include that runner-specific regression. Canonical patch/path/hash gates remain
unchanged.
