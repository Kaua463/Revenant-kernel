# Rodin DyperOS 3.0.304 ABI baseline

Reference boot SHA-256: `3c555f2f5dda7b6085dd38a2869d23ffe680c05d5bcc59625885b726690a00ce`

Stock kernel:

- `6.6.77-android15-8-gca30f3b4bef6-abogki440974771-4k`
- ARM64 boot Image, 4 KiB pages, boot header v4, empty boot ramdisk
- 352 modules across `system_dlkm_a` and `vendor_dlkm_a`

Clean control build:

- ACK tag: `android15-6.6.77_r00`
- Tag object: `79d26ca363880c3c6f7841045e46427bee6c3c3b`
- Peeled commit: `f7ebe251035c0d15ff90c6a0a320697932785fad`
- Workflow run: `34409450232`
- Build mode: 4 KiB, thin LTO ABI audit
- `Module.symvers`: 8,784 entries

Stock-module requirement comparison:

- 4,513 unique kernel-provided symbols compared
- 4,513 CRC matches
- 0 CRC mismatches
- 431 unresolved names belong to private module/partition dependency closure and are not treated as kernel CRC mismatches

Conclusion: exact ACK 6.6.77 control preserves every comparable stock module CRC. Port must use this base and retain stock DLKM modules. Any KernelSU/SUSFS candidate must be compared against this control; nonzero CRC changes imported by critical stock modules block packaging unless proven ABI-compatible or rebuilt from exact source.
