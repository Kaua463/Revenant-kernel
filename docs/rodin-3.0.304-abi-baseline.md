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

## Pinned root integration candidate

The ROM userspace is Android 16, while its kernel ABI branch is Android 15 GKI 6.6. Kernel patches therefore target `gki-android15-6.6`, not `android16-6.12`.

- KernelSU Next: `234f6e040fcbca18b16d2398e1aa225712ec99ad`, kernel version `33239`, 25 commits after v3.3.0
- SUSFS: `be7b7ef49a1e1b189c3abf00eacaa7ebdb4168c1`, `gki-android15-6.6`, version 2.2.0
- KernelSU/SUSFS fix set: `cd63f371d91fb7fc32014c75728fbb9b686d9ae9`
- KernelSU UAPI tree and Manager native bridge are byte-identical to v3.3.0; Manager minimum supported kernel is `33188`
- Clean-room GNU patch integration on exact ACK 6.6.77: pass, zero residual rejects/originals
- Deterministic KernelSU source delta SHA-256: `c03c8d90c9690080786425d6204e1e19007f4a7cfd94bcae4916eb2b3e0d53e0`
- Deterministic tracked ACK source delta SHA-256: `3cb6faaa3e9b98d02b953685f50f2af902f37ac61b6e9e06964ac1daac22667d`
- Platform-independent 26-file content manifest SHA-256: `ceb50cf610affc7a7a671fb07568e5ec033e9d63ad12b7de1a51994f6c935fd2`

Final offline candidate evidence:

- GitHub Actions run: `34438390462`, success
- Kernel `Image` SHA-256: `3d632d2d7c89e91dd6d19289eb527c1130caf4d2dcf6ed245a233df45ae57417`
- Embedded release: exact stock `6.6.77-android15-8-gca30f3b4bef6-abogki440974771-4k`
- Embedded KernelSU metadata: `33239`, `v3.3.0`; fallback `1`/`v0.0.1` absent
- Candidate-vs-control module audit: 352 stock modules, 21,125 matching import records, 4,513 matching unique kernel symbols, zero changed symbol rows
- The 431 unresolved unique names and 771 records are identical in candidate and control and belong to the private module-to-module dependency closure
- OrangeFox installer SHA-256: `cfb2003a4afba45ec31be6164d216814da611624019272546e5271288530d488`
- OrangeFox stock-kernel restore SHA-256: `1cfafdb9e12a7972854d2a002123a7014557f1b86f2caf606186363dfdeba6ad`
- Installer verifies its embedded Image and requires exact pre-flash boot SHA-256 `3c555f2f5dda7b6085dd38a2869d23ffe680c05d5bcc59625885b726690a00ce`; mismatch aborts before writing

Offline compilation, metadata, archive, and ABI gates pass. Hardware boot and subsystem smoke tests remain mandatory before calling the candidate fully proven on-device.
