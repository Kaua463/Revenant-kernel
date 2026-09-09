#!/bin/bash
set -euo pipefail

: "${KERNEL_DIR:?}"
: "${KSU_DIR:?}"
: "${SUSFS_DIR:?}"
: "${FIX_DIR:?}"

test "$(git -C "$KSU_DIR" rev-parse HEAD)" = 30802e7260e2387176b9301377e88fc6fb0356b7
test "$(git -C "$SUSFS_DIR" rev-parse HEAD)" = b03e1a9da3d24eea766b48871c71a6aed9ac98a6
test "$(git -C "$FIX_DIR" rev-parse HEAD)" = 35fac8ee31035fb73a8b9301b50c2bdb4ff7feb7

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

cp "$SUSFS_DIR"/kernel_patches/fs/* "$KERNEL_DIR/fs/"
cp "$SUSFS_DIR"/kernel_patches/include/linux/* "$KERNEL_DIR/include/linux/"
cp "$SUSFS_DIR/kernel_patches/50_add_susfs_in_gki-android15-6.6.patch" "$KERNEL_DIR/"
(cd "$KERNEL_DIR" && patch --batch --forward --fuzz=0 -p1 < 50_add_susfs_in_gki-android15-6.6.patch)
rm -f "$KERNEL_DIR/50_add_susfs_in_gki-android15-6.6.patch"

ln -sfn "$(realpath --relative-to="$KERNEL_DIR/drivers" "$KSU_DIR/kernel")" "$KERNEL_DIR/drivers/kernelsu"
grep -q 'obj-$(CONFIG_KSU) += kernelsu/' "$KERNEL_DIR/drivers/Makefile" || \
  printf '\nobj-$(CONFIG_KSU) += kernelsu/\n' >> "$KERNEL_DIR/drivers/Makefile"
grep -q 'source "drivers/kernelsu/Kconfig"' "$KERNEL_DIR/drivers/Kconfig" || \
  sed -i '/endmenu/i\source "drivers/kernelsu/Kconfig"' "$KERNEL_DIR/drivers/Kconfig"

test -f "$KERNEL_DIR/fs/susfs.c"
grep -q '^#define SUSFS_VERSION "v2.2.0"' "$KERNEL_DIR/include/linux/susfs.h"
grep -q 'config KSU_SUSFS' "$KSU_DIR/kernel/Kconfig"
! find "$KSU_DIR" "$KERNEL_DIR" -type f -name '*.rej' -print -quit | grep -q .
