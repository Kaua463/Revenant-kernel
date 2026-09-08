# SPEC

## §G

G1 | Build the DyperOS 3.0.304 stock-like kernel for POCO X7 Pro `rodin` with official KernelSU Next v3.3.0 only, preserving boot layout and providing a recoverable GitHub Actions artifact.

## §C

C1 | ROM reference boot SHA-256=`3c555f2f5dda7b6085dd38a2869d23ffe680c05d5bcc59625885b726690a00ce`.
C2 | ROM kernel=`6.6.77-android15-8-gca30f3b4bef6-abogki440974771-4k`; AOSP build base=`android15-6.6.77_r00`.
C3 | boot header v4; 64 MiB image; kernel in `boot`; boot ramdisk size 0; device uses 4 KiB pages.
C4 | No phone reads, writes, reboot, or flash during build work.
C5 | KernelSU-Next stays release-commit-pinned and reproducible; SuSFS and Revenant performance/network tweaks are excluded.
C6 | No automatic release or device flash; only branch artifacts unless explicitly requested.

## §I

I1 | `.github/workflows/build-kernel.yml` → reproducible GKI build and AnyKernel3 artifact.
I2 | `configs/dyperos-stock-ksun.fragment` → minimal KernelSU-only configuration.
I3 | AnyKernel3 installer → patches the current slot `boot` image while preserving its non-kernel contents.
I4 | GitHub Actions artifact → user-downloadable flashable package plus raw `Image` for inspection.

## §V

V1 | Build source tag is exactly `android15-6.6.77_r00`.
V2 | Built `Image` release starts with `6.6.77-android15-8` and ends in `-4k`; workflow fails otherwise.
V3 | Installer target remains `boot`, uses slot autodetection, and handles header-v4/empty-ramdisk layout through `split_boot` + `flash_boot`.
V4 | Preserve the proven Wi-Fi/Bluetooth KMI, protected-symbol, CRC, and vermagic compatibility patches; strict source-marker gates must prove every intended patch applied.
V5 | KernelSU-Next v3.3.0 commit, derived version code 33214/name, and official manager signer identity are logged and validated.
V6 | SuSFS, `/proc/rodin`, and scheduler/memory/filesystem/network performance tweaks are absent from the selected fragment and integration steps.
V7 | Every bundled AnyKernel executable is AArch64 and its source archive is checksum-pinned.
V8 | No workflow event flashes a device; release creation defaults off.
V9 | Rollback documentation identifies the exact 3.0.304 `boot.img`; the repository's older 6.6.89 `stock_boot.img` is not presented as a 3.0.304 rollback image.
V10 | Repository validation runs with the Ruby/Psych version shipped by macOS and checks workflow constants plus shell patch markers.

## §T

| ID | Task | Status |
|---|---|---|
| T1 | Record ROM evidence, constraints, and safety invariants | done |
| T2 | Align stock-like workflow to 6.6.77 + KSU Next v3.3.0 and add strict gates | done |
| T3 | Correct KernelSU/rollback documentation and artifact naming | done |
| T4 | Run local static validation; commit and push isolated branch | done |
| T5 | Dispatch GitHub Actions and follow build through completion | done |
| T6 | Inspect produced kernel/artifacts and report flash/rollback guidance | done |

## §B

| ID | Bug | Cause | Prevent recurrence |
|---|---|---|---|
| B1 | Existing workflow builds 6.6.127 for a ROM shipping 6.6.77 | Base selected from a different kernel package | V1-V2 pin and verify the ROM-matched release |
| B2 | Wi-Fi/Bluetooth failed in earlier builds | Rodin vendor modules hit protected-symbol and CRC/vermagic gates | V4 preserves the proven compatibility patches and verifies their application |
| B3 | Existing README treats a 6.6.89 boot as universal stock recovery | Rollback image provenance was not tied to ROM version | V9 requires exact ROM-version identity |
| B4 | 2026-09-07 local YAML check failed before parsing | macOS Ruby 2.6/Psych does not support `aliases:` on `YAML.load_file` | V10 uses a compatible validator script |
