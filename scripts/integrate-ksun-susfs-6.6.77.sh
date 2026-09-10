#!/bin/bash
set -euo pipefail

: "${KERNEL_DIR:?}"
: "${KSU_DIR:?}"
: "${SUSFS_DIR:?}"
: "${FIX_DIR:?}"

test "$(git -C "$KSU_DIR" rev-parse HEAD)" = 234f6e040fcbca18b16d2398e1aa225712ec99ad
test "$(git -C "$SUSFS_DIR" rev-parse HEAD)" = be7b7ef49a1e1b189c3abf00eacaa7ebdb4168c1
test "$(git -C "$FIX_DIR" rev-parse HEAD)" = cd63f371d91fb7fc32014c75728fbb9b686d9ae9

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

assert_sha256() {
  expected=$1
  file=$2
  test "$(sha256_file "$file")" = "$expected"
}

assert_sha256 06cc0da78e7fca4ca4cb1787cab53d7c546b421d55ba23b0a5f8a1a3dbc09306 \
  "$SUSFS_DIR/kernel_patches/KernelSU/10_enable_susfs_for_ksu.patch"
assert_sha256 fb8ed4e7fcd95b01a1bb275c1dd1985f32c72d2997475b94dd39ab4f90775792 \
  "$SUSFS_DIR/kernel_patches/50_add_susfs_in_gki-android15-6.6.patch"
assert_sha256 c556c644dcb345bbe7814812c6ff084e22762d4d0381c8ee331ada1b25cd6770 \
  "$SUSFS_DIR/kernel_patches/fs/susfs.c"
assert_sha256 05d4ec96ba75d459612d6269614bc7e1948c4e7b1ecd4dfaf47fbd4ec4a3fcfb \
  "$SUSFS_DIR/kernel_patches/include/linux/susfs.h"
assert_sha256 4eef49b81b6d8320194284adf02987b7e89df81495f7cdf9de9b29072dd9d87a \
  "$SUSFS_DIR/kernel_patches/include/linux/susfs_def.h"

cp "$SUSFS_DIR/kernel_patches/KernelSU/10_enable_susfs_for_ksu.patch" "$KSU_DIR/"
set +e
(cd "$KSU_DIR" && patch --batch --forward --fuzz=3 -p1 < 10_enable_susfs_for_ksu.patch)
base_status=$?
set -e
test "$base_status" -ne 0

expected_rejects='kernel/Kbuild.rej
kernel/core/init.c.rej
kernel/feature/kernel_umount.c.rej
kernel/feature/sucompat.c.rej
kernel/hook/setuid_hook.c.rej
kernel/supercall/supercall.c.rej'
actual_rejects=$(cd "$KSU_DIR" && find kernel -type f -name '*.rej' -print | sort)
test "$actual_rejects" = "$expected_rejects"

# The pinned SUSFS base patch already inserts two lines which the pinned
# compatibility fix also inserts, but at the canonical locations expected by
# its source context. Normalize only those two exact, already-audited lines so
# every compatibility patch can then apply with zero fuzz under GNU patch.
python3 - "$KSU_DIR/kernel/core/init.c" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()
include_block = (
    "#include <linux/workqueue.h>\n\n"
    "#include <linux/susfs.h>\n"
    "#include \"policy/allowlist.h\"\n"
)
normalized_include_block = (
    "#include <linux/workqueue.h>\n\n"
    "#include \"policy/allowlist.h\"\n"
)
debug_boundary = (
    'pr_alert("*************************************************************");\n'
    "#endif\n\n\tif (allow_shell) {"
)
normalized_debug_boundary = (
    'pr_alert("*************************************************************");\n'
    "#endif\n\tif (allow_shell) {"
)
x86_guard = "#if defined(__x86_64__) && !defined(CONFIG_KSU_X86_PATCH_SYSCALL_DISPATCHER)"
x86_guard_compat = "#if defined(__x86_64__)"
x86_comment = "// If the kernel has the hardening patch, X86_FEATURE_INDIRECT_SAFE must be set\n"
x86_comment_compat = "// If the kernel has the hardening patch, X86_FEATURE_INDIRECT_SAFE must be set \n"
assert text.count(include_block) == 1
assert text.count(debug_boundary) == 1
assert text.count(x86_guard) == 2
assert text.count(x86_comment) == 1
text = text.replace(include_block, normalized_include_block, 1)
text = text.replace(debug_boundary, normalized_debug_boundary, 1)
text = text.replace(x86_guard, x86_guard_compat)
text = text.replace(x86_comment, x86_comment_compat, 1)
path.write_text(text)
PY

find "$KSU_DIR/kernel" -type f \( -name '*.orig' -o -name '*.rej' \) -delete

for name in \
  fix_Kbuild.patch fix_init.c.patch fix_kernel_umount.c.patch \
  fix_setuid_hook.c.patch fix_sucompat.c.patch fix_supercall.c.patch \
  ksu_toolkit.patch overwrite_hook_mode.patch; do
  patch_file="$FIX_DIR/next/susfs_fix_patches/stable/v2.2.0/$name"
  test -s "$patch_file"
  (cd "$KSU_DIR" && patch --batch --forward --fuzz=0 -p1 < "$patch_file")
done

find "$KSU_DIR/kernel" -type f \( -name '*.orig' -o -name '*.rej' \) -delete
rm -f "$KSU_DIR/10_enable_susfs_for_ksu.patch"

python3 - "$KSU_DIR/kernel/Kbuild" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()
anchor = (
    'LPATH := /usr/bin/env PATH="$$PATH":/usr/bin:/usr/local/bin\n'
    'MDIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))\n'
)
versioned = anchor + (
    '\nKSU_GIT_VERSION ?= 3239\n'
    'KSU_GIT_TAG ?= v3.3.0\n'
    'KSU_GIT_VERSION_VALID ?= 1\n'
)
assert text.count(anchor) == 1
assert 'KSU_GIT_VERSION ?=' not in text
assert 'KSU_GIT_TAG ?=' not in text
assert 'KSU_GIT_VERSION_VALID ?=' not in text
path.write_text(text.replace(anchor, versioned, 1))
PY

if command -v sha256sum >/dev/null 2>&1; then
  ksu_diff_sha=$(git -C "$KSU_DIR" diff --binary -- kernel | sha256sum | awk '{print $1}')
else
  ksu_diff_sha=$(git -C "$KSU_DIR" diff --binary -- kernel | shasum -a 256 | awk '{print $1}')
fi
test "$ksu_diff_sha" = c03c8d90c9690080786425d6204e1e19007f4a7cfd94bcae4916eb2b3e0d53e0

cp "$SUSFS_DIR"/kernel_patches/fs/* "$KERNEL_DIR/fs/"
cp "$SUSFS_DIR"/kernel_patches/include/linux/* "$KERNEL_DIR/include/linux/"
cp "$SUSFS_DIR/kernel_patches/50_add_susfs_in_gki-android15-6.6.patch" "$KERNEL_DIR/"
set +e
(cd "$KERNEL_DIR" && patch --batch --forward --fuzz=0 -p1 < 50_add_susfs_in_gki-android15-6.6.patch)
kernel_patch_status=$?
set -e
test "$kernel_patch_status" -ne 0

expected_kernel_rejects='fs/exec.c.rej
fs/proc/base.c.rej
fs/proc/task_mmu.c.rej'
actual_kernel_rejects=$(cd "$KERNEL_DIR" && find fs -type f -name '*.rej' -print | sort)
if test "$actual_kernel_rejects" != "$expected_kernel_rejects"; then
  printf 'unexpected kernel rejects:\n%s\n' "$actual_kernel_rejects" >&2
  exit 1
fi
echo 'kernel base patch produced only the three audited ACK 6.6.77 rejects'

python3 - "$KERNEL_DIR" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
replacements = {
    root / "fs/exec.c": (
        "#include <linux/page_size_compat.h>\n\n#include <linux/uaccess.h>",
        "#include <linux/page_size_compat.h>\n"
        "#ifdef CONFIG_KSU_SUSFS\n#include <linux/susfs_def.h>\n#endif\n\n"
        "#include <linux/uaccess.h>",
    ),
    root / "fs/proc/base.c": (
        "#include <linux/cpufreq_times.h>\n#include <trace/events/oom.h>",
        "#include <linux/cpufreq_times.h>\n"
        "#if defined(CONFIG_KSU_SUSFS_SUS_MAP) || defined(CONFIG_KSU_SUSFS_OPEN_REDIRECT)\n"
        "#include <linux/susfs_def.h>\n"
        "#endif // #if defined(CONFIG_KSU_SUSFS_SUS_MAP) || defined(CONFIG_KSU_SUSFS_OPEN_REDIRECT)\n\n"
        "#include <trace/events/oom.h>",
    ),
    root / "fs/proc/task_mmu.c": (
        "\tstruct vm_area_struct *vma = get_data_vma(v);\n\tstruct mem_size_stats mss;\n\n"
        "\tmemset(&mss, 0, sizeof(mss));",
        "\tstruct vm_area_struct *vma = get_data_vma(v);\n\tstruct mem_size_stats mss;\n\n"
        "#ifdef CONFIG_KSU_SUSFS_SUS_MAP\n"
        "\tif (vma->vm_file) {\n"
        "\t\tif (SUSFS_IS_INODE_SUS_MAP(file_inode(vma->vm_file)))\n"
        "\t\t\treturn 0;\n"
        "\t}\n"
        "#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MAP\n\n"
        "\tmemset(&mss, 0, sizeof(mss));",
    ),
}
for path, (old, new) in replacements.items():
    text = path.read_text()
    assert text.count(old) == 1, path
    path.write_text(text.replace(old, new, 1))
PY
echo 'three audited ACK 6.6.77 adaptations applied'

find "$KERNEL_DIR" -type f \( -name '*.orig' -o -name '*.rej' \) -delete
rm -f "$KERNEL_DIR/50_add_susfs_in_gki-android15-6.6.patch"

ksu_relative=$(python3 - "$KERNEL_DIR/drivers" "$KSU_DIR/kernel" <<'PY'
import os
import sys
print(os.path.relpath(sys.argv[2], sys.argv[1]))
PY
)
ln -sfn "$ksu_relative" "$KERNEL_DIR/drivers/kernelsu"
grep -q "obj-\$(CONFIG_KSU) += kernelsu/" "$KERNEL_DIR/drivers/Makefile" || \
  printf "\nobj-\$(CONFIG_KSU) += kernelsu/\n" >> "$KERNEL_DIR/drivers/Makefile"
grep -q 'source "drivers/kernelsu/Kconfig"' "$KERNEL_DIR/drivers/Kconfig" || \
  printf '\nsource "drivers/kernelsu/Kconfig"\n' >> "$KERNEL_DIR/drivers/Kconfig"

test -f "$KERNEL_DIR/fs/susfs.c"
grep -q '^#define SUSFS_VERSION "v2.2.0"' "$KERNEL_DIR/include/linux/susfs.h"
grep -q 'config KSU_SUSFS' "$KSU_DIR/kernel/Kconfig"
test "$(grep -c '^KSU_GIT_VERSION ?= 3239$' "$KSU_DIR/kernel/Kbuild")" -eq 1
test "$(grep -c '^KSU_GIT_TAG ?= v3.3.0$' "$KSU_DIR/kernel/Kbuild")" -eq 1
test "$(grep -c '^KSU_GIT_VERSION_VALID ?= 1$' "$KSU_DIR/kernel/Kbuild")" -eq 1
test "$(grep -c '^#include <linux/susfs.h>$' "$KSU_DIR/kernel/core/init.c")" -eq 1
if grep -q 'ksu_late_loaded' "$KSU_DIR/kernel/core/init.c"; then
  exit 1
fi
grep -q 'susfs_open_redirect_spoof_show_map_vma_srcu' "$KERNEL_DIR/fs/susfs.c"
test "$(grep -c 'source "drivers/kernelsu/Kconfig"' "$KERNEL_DIR/drivers/Kconfig")" -eq 1
if find "$KSU_DIR" "$KERNEL_DIR" -type f -name '*.rej' -print -quit | grep -q .; then
  exit 1
fi
echo 'root integration semantic gates passed with zero residual rejects'

kernel_manifest_sha=$(python3 - "$KERNEL_DIR" <<'PY'
from pathlib import Path
import hashlib
import subprocess
import sys

root = Path(sys.argv[1])
paths = subprocess.check_output(
    ["git", "-C", str(root), "diff", "--name-only", "--diff-filter=ACMRTUXB"],
    text=True,
).splitlines()
assert len(paths) == 26, paths
digest = hashlib.sha256()
for relative in sorted(paths):
    digest.update(relative.encode() + b"\0")
    digest.update(hashlib.sha256((root / relative).read_bytes()).digest())
print(digest.hexdigest())
PY
)
echo "tracked kernel source manifest SHA-256: $kernel_manifest_sha"
test "$kernel_manifest_sha" = ceb50cf610affc7a7a671fb07568e5ec033e9d63ad12b7de1a51994f6c935fd2
echo 'pinned KSUN 33239 + SUSFS 2.2 integration complete'
