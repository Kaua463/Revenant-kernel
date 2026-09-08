# SPEC

## §G

G1 | Port the complete POCO X7 Pro `rodin`/MT6899 kernel+module tree to Linux 6.6.156 LTS for DyperOS 3.0.304, with KernelSU Next and one measured network feature, producing validated recoverable artifacts.

## §C

C1 | ROM reference boot SHA-256=`3c555f2f5dda7b6085dd38a2869d23ffe680c05d5bcc59625885b726690a00ce`.
C2 | ROM kernel=`6.6.77-android15-8-gca30f3b4bef6-abogki440974771-4k`; port source must include the matching `mediatek/mt6899` device-module tree and advance within Android `android15-6.6` to Linux 6.6.156 LTS.
C3 | boot header v4; 64 MiB image; kernel in `boot`; boot ramdisk size 0; device uses 4 KiB pages.
C4 | Device access is limited to kernel/recovery facts and explicit staged validation; no personal-file inspection. No flash until offline gates pass and exact rollback images are verified.
C5 | KernelSU-Next and Google BBRv3 stay commit-pinned and reproducible; SuSFS and unrelated scheduler/memory/filesystem/network tweaks are excluded. Sole network feature set=`BBRv3 + TCP pacing + fq`, with BBRv1 retained for A/B fallback and runtime evidence required.
C6 | No automatic release or device flash; only branch artifacts unless explicitly requested.

## §I

I1 | `.github/workflows/build-kernel.yml` → reproducible full rodin/MT6899 kernel+module build.
I2 | kernel config fragment → KernelSU Next + BBR/fq only above the rodin baseline.
I3 | installer → atomically updates current-slot `boot`, matching `vendor_dlkm`, and required DTB/DTBO; emits a restore package first.
I4 | GitHub Actions artifacts → `Image`, modules, boot/vendor_dlkm/dtbo candidates, manifests, validation evidence, flashable and restore packages.

## §V

V1 | Base contains the complete rodin `mediatek/mt6899` kernel-module sources; source origins and immutable commits are recorded.
V2 | Linux 6.6.y updates apply incrementally through 6.6.156 without replacing MediaTek drivers/config; every conflict is reviewed and recorded.
V3 | Kernel and every shipped `.ko` are built together with one toolchain/config; release/vermagic, modversions, symbol CRCs, dependencies, and unresolved symbols pass gates.
V4 | No global bypass of KMI protected symbols, CRC, vermagic, module signatures, or ABI checks is present.
V5 | KernelSU-Next release commit/version and manager signer identity are pinned and validated; SuSFS excluded initially.
V6 | Only network change set is commit-pinned official Google BBRv3 plus TCP pacing and per-flow `fq`; BBRv1 remains selectable, algorithm constants stay upstream, and runtime activation requires measured Wi-Fi/5G smoke tests.
V7 | Every bundled AnyKernel executable is AArch64 and its source archive is checksum-pinned.
V8 | No workflow event flashes a device; release creation defaults off.
V9 | Rollback documentation identifies the exact 3.0.304 `boot.img`; the repository's older 6.6.89 `stock_boot.img` is not presented as a 3.0.304 rollback image.
V10 | Repository validation runs with the Ruby/Psych version shipped by macOS and checks workflow constants plus shell patch markers.
V11 | No artifact is called rodin-compatible from release-string similarity alone; full module/ABI validation and hardware boot evidence are required.
V12 | Installer validates device, ROM/kernel family, slot, snapshot state, partition sizes and free space; creates hash-verified rollback before writes and aborts closed on mismatch.
V13 | Offline gate validates Android boot header v4, 4 KiB pages, 64 MiB boot limit, DTB/DTBO structure, vendor_dlkm filesystem/SELinux metadata, archive integrity, and exact written-file manifest.
V14 | Hardware gate proves boot completion plus Wi-Fi, Bluetooth, GPU, audio, camera, modem, sensors, storage and BBR availability; panic/watchdog/pstore evidence fails release.
V15 | Artifact checksum manifests use artifact-relative paths, exclude themselves, and pass an immediate clean-room verification before upload.

## §T

| ID | Task | Status |
|---|---|---|
| T1 | Record ROM evidence, constraints, and safety invariants | done |
| T2 | Align stock-like workflow to 6.6.77 + KSU Next v3.3.0 and add strict gates | done |
| T3 | Correct KernelSU/rollback documentation and artifact naming | done |
| T4 | Run local static validation; commit and push isolated branch | done |
| T5 | Dispatch GitHub Actions and follow build through completion | done |
| T6 | Inspect produced kernel/artifacts and report flash/rollback guidance | done |
| T7 | Import and provenance-pin complete rodin/MT6899 source and build inputs | x |
| T8 | Establish reproducible baseline build for kernel + all device modules | ~ |
| T9 | Incrementally port Android 15 kernel to Linux 6.6.156 LTS | . |
| T10 | Integrate pinned KernelSU Next and BBR/fq-only fragment | . |
| T11 | Build safe installer, complete rollback package, and offline validation gates | . |
| T12 | Run GitHub Actions; audit artifacts, ABI, modules, images and manifests | . |
| T13 | Present offline evidence; perform explicit staged hardware validation only after gates pass | . |

## §B

| ID | Bug | Cause | Prevent recurrence |
|---|---|---|---|
| B1 | Existing workflow builds 6.6.127 for a ROM shipping 6.6.77 | Base selected from a different kernel package | V1-V2 pin and verify the ROM-matched release |
| B2 | Wi-Fi/Bluetooth failed in earlier builds | Rodin vendor modules were not co-built against the exact kernel ABI | V3-V4 require the complete co-built module set without bypasses |
| B3 | Existing README treats a 6.6.89 boot as universal stock recovery | Rollback image provenance was not tied to ROM version | V9 requires exact ROM-version identity |
| B4 | 2026-09-07 local YAML check failed before parsing | macOS Ruby 2.6/Psych does not support `aliases:` on `YAML.load_file` | V10 uses a compatible validator script |
| B5 | 2026-09-08 custom GKI bootlooped during init | Public AOSP kernel replaced private Xiaomi kernel while workflow forced incompatible vendor modules past KMI/CRC/vermagic guards | V3-V4,V11 require co-built modules and forbid compatibility bypasses |
| B6 | Baseline artifact checksum audit could not validate `SHA256SUMS` | Manifest generator included the manifest itself and retained runner-only `dist/` paths | V15 excludes self-reference, emits artifact-relative paths, and verifies before upload |
| B7 | BBR/fq config gate failed before compilation | `DEFAULT_FQ` is conditional on `NET_SCH_DEFAULT`; the planned built-in BBR check incorrectly targeted exported module symbols | Enable/verify `NET_SCH_DEFAULT`; validate `tcp_bbr.o` and its `bbr_register` symbol |
| B8 | String-valued config gate failed despite correct config | This vendor tree's `scripts/config` lacks the newer `--get-str` command | Match the exact quoted `.config` assignments with `grep -x` |
