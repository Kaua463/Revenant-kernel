# Disposable DMA runtime audit — bounded VM evidence, not shipping approval

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
during error unwind, even though the VMA's `fput` precedes unmap. Ordinal-two
PMD/PTE failed-mmap sequences passed in run 37494587692; other failure paths
remain unproven. An in-kernel mmap caller without that
reference must not be assumed safe. A real GPU producer may have a different
ownership contract and remains unverified.

`recovered-dma-audit.c` now implements the separate test producer source. Two
0600 misc devices require CAP_SYS_ADMIN to open: `recovered-dma-audit-pmd` uses
map_type=0; `recovered-dma-audit-pte` uses map_type=1. Each open owns a fresh,
zeroed, contiguous 4 MiB order-10 allocation, released by the last file release.
Two additional 0600 devices `recovered-dma-audit-fault-pmd`/`-fault-pte` have
the same restrictions, but inject ordinal-two allocation failure on the first
valid mmap only. The normal devices do not arm failure injection.
`recovered-dma-audit-first-pmd`/`-first-pte` add first-leaf failure cases with
the same capability/0600/ownership limits. They are implemented but not yet
validated in a VM. `recovered-dma-audit-table-pmd`/`-table-pte` add the cold-PUD
`__pmd_alloc` failure case. The guest checks an entire 1 GiB PGD-slot VA range
with PROT_NONE/NO_REPLACE, unmaps it, then maps at 4/6 GiB respectively.
The kernel independently requires the real PUD entry to be zero; a populated
entry fails closed, never silently changes the test to a leaf failure.
`recovered-dma-audit-table-cross-pmd`/`-table-cross-pte` add second-PGD-table
failure after one published block. Both real root entries must initially be
empty, and the 4 MiB mapping must straddle the 1 GiB boundary exactly. The guest
reserves two whole slots without clobbering VMAs; the kernel checks both entries.
At the selected failure, the first block must have owned PFNs, the second root
must still be empty, and temporary accounting must be exactly 8 KiB (one PMD
table plus one deposited/PTE table). Retry must restore the exact baseline.
All ten cases run the full retry/alias/fork/move/SMP workload.
Before creating any worker thread, each also reserves two empty 1 GiB VA slots
with PROT_NONE/NO_REPLACE, removes that reservation, and maps a 4 MiB alias
starting 2 MiB before the 16 GiB boundary. Every data word on both sides is
checked, then the crossing alias is unmapped. No unrelated VMA is overwritten.
The guest and strict serial gates are implemented, not yet VM-validated.
High-order allocation can legitimately fail; no fallback to arbitrary memory.
Mappings may cover aligned 2 or 4 MiB subsets, shared and non-executable only.
The mmap callback validates overflow/bounds, checks every actual destination
PMD under mmap write lock, and rejects even preallocated PTE tables. It invokes
the recovered mapper with the separately declared integration safety guards;
the hash-pinned stock recipe itself remains unchanged. It keeps vm_file and adds no VMA callbacks or
extra VMA references. No ioctl/read/write/physical-address interface exists.

Kconfig/Makefile are **not sourced by any shipping kernel tree or workflow**. Their
built-in, default-off option is for a disposable ARM64 VM build only;
the C guards also reject module, wrong geometry or missing recovered feature.
No shipping overlay/config has changed. `prepare-dmabuf-runtime-audit.py` gates
all pristine reference hashes/canonical recipes, all post-DMA inputs and five
producer source pins before changing eight paths in a disposable tree. Drift,
symlinks, existing destination/evidence and repeated application fail closed.
`test-dmabuf-runtime-integration.py` covers those conditions in temporary trees.
The separate `audit-rodin-dma-producer.yml` compiles built-in on exact ACK,
requires config plus producer objects in vmlinux, and uploads evidence only.
It shares the existing audit concurrency group and never cancels a live audit.
Run 37428061875 compiled and executed the basic ARM64 QEMU guest workload
successfully; composed KSU/SUSFS compile/ABI run 37429423148 also passed.
The workflow boots a RAM-only disposable VM but does not publish a VM image.
Run 37494587692 subsequently passed the scoped ordinal-two ENOMEM,
same-address retry and four final-release gates on the actual four-CPU VM;
downloaded serial/config were checked again locally. Full failure-site/accounting
matrix, stock producer activation and hardware remain unproven.
These tests are not installation/shipping approval.

The audit producer now logs unique allocation IDs and a final release event
after both real backing/storage frees return, without reading freed storage.
The guest marks immediately before its final alias unmap; the runner requires
one matching release per mode between that marker and case completion. Missing,
duplicate, wrong-ID, malformed or out-of-order events fail closed. This is
instrumentation only in the disposable producer; no new userspace control or
shipping overlay change. Run 37494587692 proves this gate for its four tested
buffers, not every possible VMA lifetime.

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

Partial ENOMEM audit integration (selected VM gates passed):
`prepare-dmabuf-fault-sites.py` takes the exact hash-pinned recovered
`mm/huge_memory.c` and emits a separate copy with three audit-config-gated failure
sites: cold-PUD `__pmd_alloc`, deposited-table `pte_alloc_one`, and
`pte_alloc_map_lock`. The cold-PUD callback and guest arm are implemented,
but have not yet been validated in a VM. No PMD-table failure runtime coverage
is claimed from the host tests.
It preserves the rest of the source and never writes input/production overlay.
`audit-fault-plan.h` supplies a bounded, site/task/mm-scoped, one-shot ordinal selector.
Its caller must serialize arm/check/reset; it is not a concurrent allocator or
an ENOMEM model. Host selector tests and generated-site preservation tests:

```sh
python3 scripts/test-dmabuf-audit-fault-plan.py
python3 scripts/test-dmabuf-fault-sites.py
```

The producer supplies callbacks under its audit-only remap mutex. Only
the matching site and armed current task/mm advance the ordinal. Ordinal two
returns ENOMEM after the matching recovered map counter increased exactly once;
ordinal one requires zero published blocks and no first-block mapping.
It also walks the actual first block: present huge PMD with the owned PFN, or
all 512 present/special PTEs with the consecutive owned PFNs. Counter increase
alone cannot prove publication because stock ignores `pmd_set_huge`'s return.
The guest checks ENOMEM, mincore ENOMEM (no VMA), same-address NOREPLACE retry
(including the producer's no-stale-table preflight), every data word and full
basic alias/fork/move/split/SMP workload after retry. The current gate requires
ten allocation/release IDs and eight failure/retry sequences with exact ordinals,
publication state and strict final-unmap ordering. Run 37494587692 passed the
older four-buffer/ordinal-two assertions only, not the new first-leaf cases.
Cold-PUD failure additionally requires cold=1, zero published blocks, no
first-block mapping and exactly zero temporary page-table accounting delta.
The corresponding VA reservation marker must precede the failure callback.
The later-PGD failure guest is now implemented, but still awaits VM execution.
`test-dmabuf-folded-levels.py` additionally compiles the exact pinned native
`pgd_addr_end` macro and the recovered next-boundary expression with an explicit
4K/VA39/three-level profile. Cross-boundary and unsigned-wrap tests pass; using
folded `p4d_addr_end` instead fails. The actual mapper already uses the correct
PGD macro: no production change was made from this hypothesis. This proves
boundary arithmetic only, not MMU/page-table writes or lifecycle.
This deliberately injects the allocation-failure outcome at the exact call
site, not a global allocator failure; other allocation sites/accounting and full
hardware lifetimes still require additional gates.
New accounting gate (runtime pending): read the pinned ACK
`mm_pgtables_bytes()` before the failing remap, after the first block is
published and at entry to the same task/mm's retry. It requires a temporary
increase of one or two 4 KiB table pages, then exact return to the baseline
before allocating for retry. First-leaf failure permits exactly zero or one
4 KiB table page temporarily and also requires exact baseline restoration.
The failed-mmap guest sequence has no worker
threads during this interval. Tokens are compared, never dereferenced after the
callback; this is bounded audit instrumentation, not a production ownership API.
`DMA_AUDIT_UNWIND` must match the fault ID/mode and precede the guest's successful
retry marker. Missing evidence, changed context, leak, underflow or wrong order
fails closed. Run 37494587692 predates this gate and does not prove accounting.
The basic workload executed successfully in run 37428061875. That run does not
verify final allocation-free count or fault-injected partial ENOMEM unwind and
does not prove all lifetimes. The later 37494587692 run proves the selected
final-release and ordinal-two partial-ENOMEM gates, not complete DMA/hardware.

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

`guest-init.c` is static PID1 for the RAM archive only: mounts proc/sysfs,
creates exactly ten mapper misc nodes plus the DMA-BUF exporter factory from
their technical sysfs dev numbers,
executes the workload and powers off. GKI has no built-in devtmpfs here, so the
archive includes only the standard 5:1 console node; audit nodes are discovered,
not guessed. `build-dmabuf-vm-initramfs.py` requires static AArch64 ELF executables,
uses deterministic newc/root metadata, and refuses existing output. Four tests
decode the archive independently and reject dynamic/wrong/truncated ELF/overwrite.

`run-dmabuf-vm-audit.py` checks built-in VM prerequisites and ARM64 Image magic,
then runs four-CPU QEMU virt with no network, disks, monitor or host-directory
shares, with bounded timeout. It saves serial logs on timeout/failure and
requires all ten mapper-case markers, both exporter cases, guest and PID1 completion, no panic/BUG/Oops/
warning, plus QEMU zero exit. Runner mock tests are **not VM execution**.
Producer workflow now includes this runtime step with ephemeral binaries/archive;
only logs/config/reports/tool versions are uploaded, never kernel or flash files.
Actual serial evidence from run 37428061875 proves the basic workload only;
new or expanded gates require their own real execution evidence.
# Real DMA-BUF route extension (runtime pending)

`recovered-dma-export-audit.c` adds a built-in, default-off, root-only VM
factory. Fixed `_IO` commands create a 4 MiB zeroed, file-owned DMA-BUF in
PMD/PTE mode; one command reports only the live-buffer count. No pointer,
PFN, address, size, read/write/dump interface. At most eight live buffers.
This interface is test instrumentation, never part of the shipping overlay.

Export uses the real DMA-BUF framework and fd installation. Its SG map/unmap
callbacks use owned pages and normal DMA API, but physical DMA attachments
are **not** tested by this CPU-mapping workload. Export/error/fd-failure paths
release ownership rather than forcing framework validation.

Guest tests 4K/64K/2M/4M mappings, deliberately unaligned hints for 64K/2M,
core extent rejection, shared aliases, fd-close retention, fork/shared writes,
partial child unmap, full mremap, CPU migration and final-unmap release.
Small maps use normal `remap_pfn_range`; 2M/4M use the recovered mapper.
Only the recovered mapper is fault-site-instrumented; the new plain route
shares its mutex so scoped injection cannot leak into an unrelated remap.

The runner requires all core/export events and matching allocation/release
IDs. Live count must remain one with mappings and become zero only after the
actual backing frees. Queries have a bounded 500 ms release wait; timeout
fails, never silently treats an outstanding DMA-BUF as released.

New guards do not retroactively validate old VM logs. Builds before this
extension have no exporter/core-route runtime proof. Source-policy tests,
format compilation and mocked runner tests remain distinct from real QEMU.
