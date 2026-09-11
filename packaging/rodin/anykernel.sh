### AnyKernel3 — Revenant DyperOS 3.0.304 KSUN/SUSFS
properties() { '
kernel.string=Revenant 6.6.77 KSUN 33239 + SUSFS 2.2 for rodin
do.devicecheck=1
device.name1=rodin
do.modules=0
do.systemless=1
do.cleanup=1
do.cleanuponabort=0
supported.versions=
'; }
# rodin layout: kernel mora em /dev/block/by-name/boot
# boot.img tem kernel_size>0 ramdisk_size=0; init_boot tem ramdisk separado
# AnyKernel dump_boot chama unpack_ramdisk → abort se ramdisk_size=0
# Fix: copiar logic EVONIX literal (auditor claim 2)
block=boot;
is_slot_device=auto;
ramdisk_compression=auto;
patch_vbmeta_flag=0;
no_magisk_check=1;
# This bundled ak3-core consumes the uppercase runtime variables directly.
# Keep the conventional lowercase values above and explicitly bridge them.
BLOCK=$block;
IS_SLOT_DEVICE=$is_slot_device;
RAMDISK_COMPRESSION=$ramdisk_compression;
PATCH_VBMETA_FLAG=$patch_vbmeta_flag;
NO_MAGISK_CHECK=$no_magisk_check;
. tools/ak3-core.sh;
expected_image=@IMAGE_SHA256@;
expected_boot=3c555f2f5dda7b6085dd38a2869d23ffe680c05d5bcc59625885b726690a00ce;
actual_image=$($BIN/busybox sha256sum "$AKHOME/Image" | $BIN/busybox awk '{print $1}');
[ "$actual_image" = "$expected_image" ] || abort "Candidate Image checksum mismatch. Aborting...";
[ ! -d /postinstall/tmp ] || abort "OTA environment unsupported. Nothing flashed.";
case "$SLOT" in _a|_b) ;; *) abort "Unknown slot. Nothing flashed.";; esac;
case "$BLOCK" in */boot_a|*/boot_b) ;; *) abort "Unexpected boot target. Nothing flashed.";; esac;
[ "$(blockdev --getsize64 "$BLOCK")" = 67108864 ] || abort "Unexpected boot partition size.";
case "$(getprop ro.boot.snapshot_merge.status)" in ""|none) ;; *) abort "Snapshot operation active. Nothing flashed.";; esac;
ui_print "Experimental build @RUN_ID@: hardware boot is NOT yet verified.";
split_boot;
actual_boot=$($BIN/busybox sha256sum "$BOOTIMG" | $BIN/busybox awk '{print $1}');
[ "$actual_boot" = "$expected_boot" ] || abort "Current boot is not exact DyperOS 3.0.304 stock. Nothing was flashed.";
flash_boot;
