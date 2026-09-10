# SPEC

## §G

G1 | Build complete pinned POCO X7 Pro `rodin`/MT6899 kernel+module tree for DyperOS 3.0.304, preserving existing mods and adding KernelSU Next + SUSFS + requested network set.

## §C

C1 | ROM reference boot SHA-256=`3c555f2f5dda7b6085dd38a2869d23ffe680c05d5bcc59625885b726690a00ce`.
C2 | ROM kernel=`6.6.77-android15-8-gca30f3b4bef6-abogki440974771-4k`; source is pinned complete `rodin-gpu` 6.6.102 with `mediatek/mt6899` modules. No ACK/stable version uplift.
C3 | boot header v4; 64 MiB image; kernel in `boot`; boot ramdisk size 0; device uses 4 KiB pages.
C4 | Device access is limited to kernel/recovery facts and explicit staged validation; no personal-file inspection. No flash until offline gates pass and exact rollback images are verified.
C5 | Preserve complete pinned `rodin-gpu` baseline and existing mods. Add no unrelated tweak; network delta limited to pinned Google BBRv3 + TCP pacing + `fq`, retaining BBRv1. Root-hiding delta limited to pinned KernelSU Next-compatible SUSFS and documented userspace controls.
C6 | No automatic release or device flash; only branch artifacts unless explicitly requested.

## §I

I1 | `.github/workflows/build-kernel.yml` → reproducible full rodin/MT6899 kernel+module build.
I2 | kernel config fragment → KernelSU Next + BBR/fq only above the rodin baseline.
I3 | installer → atomically updates current-slot `boot`, matching `vendor_dlkm`, and required DTB/DTBO; emits a restore package first.
I4 | GitHub Actions artifacts → `Image`, modules, boot/vendor_dlkm/dtbo candidates, manifests, validation evidence, flashable and restore packages.

## §V

V1 | Base contains the complete rodin `mediatek/mt6899` kernel-module sources; source origins and immutable commits are recorded.
V2 | Kernel stays at pinned rodin 6.6.102; active workflow fetches no newer ACK/stable revision and preserves MediaTek drivers/config plus existing baseline mods.
V3 | Kernel and every shipped `.ko` are built together with one toolchain/config; release/vermagic, modversions, symbol CRCs, dependencies, and unresolved symbols pass gates.
V4 | No global bypass of KMI protected symbols, CRC, vermagic, module signatures, or ABI checks is present.
V5 | KernelSU Next, SUSFS patch set, manager version, commits, checksums, signer identity pinned & validated as mutually compatible.
V6 | Relative to the pinned complete `rodin-gpu` baseline, only the network change set is official Google BBRv3 plus TCP pacing and per-flow `fq`; BBRv1 remains selectable, algorithm constants stay upstream, and runtime activation requires measured Wi-Fi/5G smoke tests.
V7 | Every bundled AnyKernel executable is AArch64 and its source archive is checksum-pinned.
V8 | No workflow event flashes a device; release creation defaults off.
V9 | Rollback documentation identifies the exact 3.0.304 `boot.img`; the repository's older 6.6.89 `stock_boot.img` is not presented as a 3.0.304 rollback image.
V10 | Repository validation runs with the Ruby/Psych version shipped by macOS and checks workflow constants plus shell patch markers.
V11 | No artifact is called rodin-compatible from release-string similarity alone; full module/ABI validation and hardware boot evidence are required.
V12 | Installer validates device, ROM/kernel family, slot, snapshot state, partition sizes and free space; creates hash-verified rollback before writes and aborts closed on mismatch.
V13 | Offline gate validates Android boot header v4, 4 KiB pages, 64 MiB boot limit, DTB/DTBO structure, vendor_dlkm filesystem/SELinux metadata, archive integrity, and exact written-file manifest.
V14 | Hardware gate proves boot completion plus Wi-Fi, Bluetooth, GPU, audio, camera, modem, sensors, storage and BBR availability; panic/watchdog/pstore evidence fails release.
V15 | Artifact checksum manifests use artifact-relative paths, exclude themselves, and pass an immediate clean-room verification before upload.
V16 | BBRv3 integration matches rodin's native two-argument `cong_control` and `BTF_SET8` API while preserving rodin's generic `bpf_tcp_ca.c` byte-for-byte before any final build.
V17 | BBRv1 fallback is built-in while it calls rodin-internal non-exported TCP helpers; config and artifacts reject a `tcp_bbr1.ko` module boundary.
V18 | SUSFS changes limited to upstream/pinned integration; no ABI/KMI/CRC/vermagic/signature bypass, no unreviewed concealment patch, no claim of undetectable root.
V19 | Root persists via current-slot `boot`; installer preserves ramdisk/DTB layout, validates rebuilt image, and emits hash-verified stock restore ZIP before flash ZIP.
V20 | Port starts from exhaustive stock-vs-Revenant matrix: release/config, exported+required symbols, MODVERSIONS CRC, vermagic, module deps, namespaces, signatures, DTB/DTBO, boot layout; unresolved critical delta blocks installer.
V21 | Fixes preserve stock ABI or rebuild exact dependent module set; forced module loading and KMI/protected-symbol bypass remain forbidden.
V22 | New audit workflow absent from default branch ! narrow push trigger on `dyperos-3.0.304`; manual dispatch alone forbidden for initial run.
V23 | Annotated source tag ! pin+validate tag object and peeled commit separately before build.
V24 | ABI-audit build ! finish within runner cap; thin LTO allowed because MODVERSIONS CRC derives declarations/config, while final release retains production LTO validation.
V25 | Final pinned KSU/SUSFS compatibility fixes apply with zero fuzz after exact audited normalization; any unexpected reject, duplicate hook/include, or ignored patch blocks build.
V26 | Clean-room validation uses an independent checkout and fail-fast shell; success marker is emitted only after the full integration command returns zero.
V27 | Every post-patch integration gate emits a named checkpoint; final ACK delta is validated by a platform-independent ordered content manifest, not textual `git diff` serialization.
V28 | Candidate embeds exact stock kernel release plus pinned KernelSU numeric/tag metadata; fallback version, `maybe-dirty`, or any other vermagic blocks packaging.
V29 | Module ABI audit runs with an explicit ELF parser dependency and compares candidate results to the stock ACK control; identical unresolved module-to-module closure is not mislabeled as a kernel regression.

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
| T8 | Establish reproducible baseline build for kernel + all device modules | x |
| T9 | Remove 6.6.156 uplift from active build; freeze complete rodin 6.6.102 baseline | x |
| T10 | Integrate pinned KernelSU Next and BBRv3/pacing/fq-only delta | x |
| T11 | Build safe installer, complete rollback package, and offline validation gates | . |
| T12 | Run GitHub Actions; audit artifacts, ABI, modules, images and manifests | x |
| T13 | Present offline evidence; perform explicit staged hardware validation only after gates pass | . |
| T14 | Pin and audit KernelSU Next + compatible SUSFS integration | ~ |
| T15 | Integrate SUSFS; add config/source/version/security gates | . |
| T16 | Build OrangeFox flash+restore ZIPs; run offline boot/ABI/module gates | . |
| T17 | Extract stock 6.6.77 technical evidence and build compatibility matrix | x |
| T18 | Fix every resolvable critical incompatibility without bypasses | . |
| T19 | Rebuild; run clean-room ABI/module/boot-image validation | . |

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
| B9 | Build step appeared successful but produced no `modules.order` | `tee` hid kbuild's nonzero exit; `-X theirs` replaced 6.6 `tcp_sock` layout with incompatible 6.13 layout | Use `pipefail`; resolve three BBR layout conflicts semantically while retaining 6.6 layout and consuming existing padding bits |
| B10 | Post-port compile found split revisions in certs, BPF verifier, and seq_buf/trace | Recursive merge resolution retained one side of coupled stable changes while accepting dependent hunks from the other | Restore each proven coupled implementation set from the exact pinned stable 6.6.156 tree and keep the full build as gate |
| B11 | Fail-fast compilation exposed one independent port error per remote run | Normal kbuild stops dependent directory traversal after the first failed object | Run one temporary `make -k` diagnostic sweep, batch-review all unique failures, then restore fail-fast mode for the final build |
| B12 | 6.6.156 diagnostic sweep produced 628 errors across core and MediaTek subsystems | Uplift combined incompatible Android/vendor and stable interfaces, violating the requested network-only scope | Freeze proven rodin 6.6.102 baseline; reject any active ACK/stable uplift before network integration |
| B13 | Frozen 6.6.102 diagnostic sweep found six errors, all in BBR/BPF objects | Google's BBR v3 history uses a four-argument congestion callback, local-only struct-ops declaration, and newer `BTF_KFUNCS` spelling than rodin 6.6.102 | V16 adapts and asserts the three native APIs as one batch before rerunning the full diagnostic sweep |
| B14 | First BBR API adaptation run stopped after porting but before compilation | The exact-count assertion omitted the definition's opening brace, so it rejected the correctly rewritten BPF declaration | Keep V16's closed assertions but match the complete generated declaration and test it against the pinned BBR revision |
| B15 | Second frozen 6.6.102 sweep left one `-Wunused-variable` error in `bpf_tcp_ca.c` | Google's newer CFI stub table has no consumer in rodin's native global BPF struct-ops registration | Remove exactly that incompatible stub table and assert it is absent while preserving rodin's global ops definition |
| B16 | Audit rerun stopped before source fetch with APT hash mismatch | GitHub's Ubuntu image exposed a stale Google Chrome package index unrelated to kernel dependencies | Remove that extraneous runner source before refreshing required Ubuntu package indexes |
| B17 | Removing `/etc/apt/sources.list.d/google-chrome.list` did not isolate the stale index | Hosted-runner source filenames vary and the Chrome entry was stored under another supported extension | Discover Chrome source files by repository URL, remove every match, and assert no reference remains before APT refresh |
| B18 | Third frozen 6.6.102 sweep reported 12 unused BPF callback stubs | Partially adapting Google's generic CFI struct-ops rewrite removed its table but left all callbacks, while BBR itself does not require that rewrite | Preserve rodin's proven `bpf_tcp_ca.c` byte-for-byte and restrict compatibility edits to the two BBR algorithm files |
| B19 | Fourth frozen 6.6.102 sweep compiled every object but failed modpost on `tcp_tso_autosize` from `tcp_bbr1.ko` | BBRv1 was modular although it calls a TCP core helper intentionally not exported by rodin | V17 keeps BBRv1 built-in and gates both its object and absence of a fallback module |
| B20 | Initial ABI workflow dispatch returned HTTP 404 | GitHub exposes `workflow_dispatch` only after workflow exists on default branch | V22 adds narrow initial push trigger |
| B21 | Baseline source gate rejected correct `android15-6.6.77_r00` checkout | Gate compared annotated-tag object hash against peeled commit hash | V23 validates both identities |
| B22 | Full-LTO ABI baseline cancelled after 29 minutes | Hosted runner terminated long link near execution cap | V24 uses thin LTO for ABI control build |
| B23 | SUSFS v2.2.0 patch rejected many KernelSU Next v3.3.0 hunks | SUSFS patch and KSU release evolved on different source layouts | V5 pins compatible post-v3.3 KSUN 33239 + SUSFS v2.2.0 + dedicated fix-set tuple |
| B24 | Pinned KSUN/SUSFS integration passed macOS patch but failed before Actions compilation | BSD patch and GNU patch handled two already-present `init.c` hunks differently | V25 reproduces GNU behavior and canonicalizes those exact lines before strict fixes |
| B25 | Initially pinned SUSFS SHA lacked the Android 15/6.6 kernel patch | WildKernels provenance named an equivalent Android 16/6.12 cherry-pick instead of the same change on the 6.6 branch | V5 pins the verified 6.6 sibling commit and checks branch-specific patch presence before integration |
| B26 | SUSFS 6.6 patch left three rejects on exact ACK 6.6.77 | Patch was authored against a later 6.6 point release with different include and padded-VMA context | V25 permits only three exact audited adaptations and rejects any changed reject set |
| B27 | Post-v3.3 KSU kernel pin could be paired with an incompatible manager | Kernel and manager may evolve their UAPI independently | V5 gates ancestry, identical v3.3 UAPI tree/native bridge, and manager minimum kernel version |
| B28 | First local clean-room command printed PASS after its shared clone failed | Partial/promisor Git repository could not serve a shared clone, and the outer diagnostic shell was not fail-fast | V26 requires independent checkout plus `set -euo pipefail` before any success marker |
| B29 | Remote integration exited after patch output without identifying its failed gate | Post-patch assertions were silent and final delta used Git diff serialization | V27 labels each gate and hashes ordered file contents directly |
| B30 | First successful candidate exposed `maybe-dirty` release and KernelSU `1/v0.0.1` fallback | Unstamped Kleaf generated placeholder SCM metadata and its sandbox hid the separately cloned KernelSU Git repository | V28 pins stock SCM release and passes verified KSU count/tag into the hermetic action, then rejects fallback strings |
| B31 | Local stock-provider ABI audit stopped before reading modules | Host Python lacked the optional `pyelftools` parser | V29 uses a pinned isolated parser environment and requires baseline-vs-candidate report equivalence |
