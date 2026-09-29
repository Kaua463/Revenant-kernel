# Revenant Kernel
### For Poco X7 Pro (rodin)

## Details
- **Base:** Linux 6.6.127 GKI
- **OS:** HyperOS 3 | Android 16
- **Device:** Poco X7 Pro (rodin)

## Changelog Beta-v1.0
- AOSP `common-android15-6.6` pinned at 6.6.127
- KernelSU-Next v3.2.0 (33129) integrated
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
Flash from your phone:

1. Download the AnyKernel3 zip from the Releases page
2. Open Horizon Kernel Flasher or Franco Kernel Manager
3. Select the zip and flash
4. Reboot

If anything goes wrong: `fastboot flash boot boot_a.img` (your stock backup).
