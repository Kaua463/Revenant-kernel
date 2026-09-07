# Revenant Kernel
### For Poco X7 Pro (rodin)

## Details
- **ROM alvo:** DyperOS 3.0.304 | Android 16
- **Base:** Linux 6.6.77 GKI (`android15-8-4k`)
- **OS:** HyperOS 3 | Android 16
- **Device:** Poco X7 Pro (rodin)

## Changelog Beta-v1.0
- AOSP `common-android15-6.6` pinned at `android15-6.6.77_r00`, matching the DyperOS 3.0.304 boot image
- KernelSU-Next `v3.2.0-22-g1d919700` (33151) integrated
- SuSFS v2.1.0 with SUS_PATH, SUS_MOUNT, SUS_KSTAT, SPOOF_UNAME, SPOOF_CMDLINE
- Kyber I/O scheduler as default
- ZSWAP with LZ4 compression
- ZRAM with lzo-rle and writeback
- Multi-gen LRU enabled at boot
- PSI always on
- BBR TCP congestion control
- CRC32 hardware acceleration
- Built with PGO + BOLT + LTO + MLGO

## Coming next
- **Beta-v1.1** — CAKE qdisc, TLS-in-kernel, BPF JIT, F2FS compression, autogroup scheduler, CFS bandwidth, RT group sched, io_uring
- **Beta-v1.2** — SUS_MAP + RASP defense patches (boot-state prop spoofing, vbmeta read intercept)
- **Beta-v1.3** — everything from v1.1 and v1.2 combined

## Requirements
- Unlocked bootloader
- KernelSU-Next or Magisk

## Installation
No custom recovery needed for rodin (none exists). Flash from your phone:

1. Download the `Revenant-DyperOS-3.0.304-*-flashable` artifact from the successful GitHub Actions run
2. Open Horizon Kernel Flasher or Franco Kernel Manager
3. Select the zip and flash
4. Reboot

## KernelSU Next manager compatibility

The integrated kernel source is version 33151. Use the official KernelSU Next v3.2.0 manager (33129), or another manager that explicitly supports kernel 33151. The v3.3.0 manager requires kernel 33188 or newer and is therefore not compatible with this SuSFS-integrated build. Updating the kernel-side code to v3.3.0 is intentionally blocked until a matching SuSFS patch applies cleanly.

## Rollback

Keep the exact DyperOS 3.0.304 `boot.img` before flashing:

- SHA-256: `3c555f2f5dda7b6085dd38a2869d23ffe680c05d5bcc59625885b726690a00ce`
- Kernel banner: `6.6.77-android15-8-gca30f3b4bef6-abogki440974771-4k`

The repository's `stock_boot.img` is from a different 6.6.89 build and must not be used as the primary 3.0.304 rollback image. Determine the active slot in bootloader mode with `fastboot getvar current-slot`, then flash the saved image to that exact partition, for example `fastboot flash boot_a boot-dyperos-3.0.304.img` when slot A is active.
