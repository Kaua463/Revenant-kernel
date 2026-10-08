# DMA: staged OrangeFox test

Prepared 2026-10-08, local only. Skill build, T16/T19/T20 subset. Whole tasks
remain open. No new kernel source/config change, no phone access, no flash.

## Artifacts

`outputs/dma-orangefox-staged-20261008-v2/`:

1. `Revenant-rodin-no-DMA-RESTORE-OrangeFox.zip`: exact full working custom
   boot backup, NOT stock. Generated and checksum-verified first.
2. `Revenant-rodin-DMA-PRECHECK-NO-FLASH-OrangeFox.zip`: checks device/slot,
   snapshot state, partition/free space, exact current boot and persistent
   rollback, then uses pinned AArch64 magiskboot to repack and verify kernel,
   header and footer. Exits before any blockdev-write enable or partition write.
   It does create a technical rollback file alongside the ZIP.
3. `Revenant-rodin-DMA-EXPERIMENTAL-OrangeFox.zip`: same preparation then writes
   only boot_a, syncs and verifies the complete partition readback hash.

For the first device stage, use only PRECHECK; report its screen/result before
using FLASH. Transfer RESTORE and keep a second backup on the Mac first.
Use persistent storage, not adb sideload. No automatic reboot or data wipe.
Unknown snapshot state, wrong slot or a changed boot aborts closed; do not
remove the guards merely to make installation proceed.

The recovery backup is validated but is NOT bundled/written: OrangeFox in
vendor_boot is left alone. Neither init_boot nor vendor/system_dlkm is touched.

## Identity and verified scope

- Candidate run 37703159922, successful `c25cec6dd25aaeecdf70f86685c9d0f18bb8b715`.
- Candidate Image SHA256 `85edf0c274cf26db611e46b014a2070284587bbc0b5ac3f2d7b5fc09b437517f`.
- Working boot_a SHA256 `e99184cfed1bdd747a9b2d63fcf30398e71c3e2529ca418432df7992a9bb7f24`.
- OrangeFox vendor_boot_a SHA256 `ba23ef2949f9f9671c68be6b129d97e670b23ab1c7e416ceb3c6333d236f5770`.
- Exact embedded config delta: DMA=y only; KFENCE and root kept as installed.
- Production ABI gate: 610 module rows, 3,506 imports/CRCs, 78 signatures;
  stock certificate still embedded. VM producer forbidden in candidate.
- New owned-VMA tests passed root VM 37716356798. Serial downloaded and strict
  parser rechecked. This is not hardware/Mali activation proof.
- ZIP CRC/checksums/modes and shell syntax checked locally. Installer tests
  check source gates/ordering, not real recovery execution.

Boot reconstruction must still execute in PRECHECK: Linux AArch64 magiskboot
cannot run natively on macOS. A failed PRECHECK never intentionally writes a
partition. A passed PRECHECK still does not prove bootloader acceptance.

## AVB caveat

The working backup's signed vbmeta structure verifies, but its boot descriptor
has an old mismatching content digest (the existing root-modified boot already
has this condition). No Xiaomi private key or valid new stock signature is
claimed. Installer sets PATCHVBMETAFLAG=false, never writes vbmeta partitions,
and refuses an unexpectedly missing/moved footer. Keep stock restore separate
from this requested custom no-DMA rollback; do not equate them.

## Recovery if a later authorized flash fails

Primary fallback: exact working no-DMA boot in RESTORE ZIP. If recovery cannot
start, enter fastboot manually and use the Mac backup (slot A only):

```sh
fastboot flash boot_a "/Users/kaua/Documents/Codex/2026-09-06/github-plugin-github-openai-curated-remote/outputs/dma-hardware-rollback-20261007/boot_a-current-no-dma.img"
```

Do not flash vendor_boot unless recovery itself needs restoration and that
additional action is explicitly authorized. Do not switch slots blindly.

## Read-only logs after an authorized test

`scripts/collect-dmabuf-device-evidence.py --output <new-report.json>` collects
technical properties, kernel/memory totals and filtered Mali/DMA/kernel faults.
System mode needs existing shell root; `--recovery` uses recovery ADB instead.
No logcat/application list, personal storage, SELinux change, reboot or writes.
Collector was prepared but not run. Mapper activation needs a separate scoped
runtime trace; these diagnostics alone cannot establish it.
