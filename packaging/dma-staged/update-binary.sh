#!/sbin/sh
# Experimental boot-only test. No mounts, SELinux changes, modules or data wipe.
set -eu
OUTFD=${2:?missing recovery output fd}
ZIPFILE=${3:?missing package path}
case "$OUTFD" in *[!0-9]*|'') exit 1;; esac
ui_print() { printf 'ui_print %s\nui_print\n' "$*" > "/proc/self/fd/$OUTFD"; }
fail() { ui_print "ABORT: $*"; exit 1; }
[ -d /twres ] || fail "TWRP/OrangeFox recovery required."
[ "$(getprop ro.product.device)" = rodin ] ||
  [ "$(getprop ro.product.vendor.device)" = rodin ] || fail "Not rodin."
[ "$(getprop ro.boot.slot_suffix)" = _a ] || fail "Only verified slot A is supported."
[ "$(getprop ro.boot.snapshot_merge.status)" = none ] || fail "Snapshot state unknown or active."
[ ! -d /postinstall/tmp ] || fail "OTA environment unsupported."
BLOCK=/dev/block/by-name/boot_a
[ -b "$BLOCK" ] || BLOCK=/dev/block/bootdevice/by-name/boot_a
[ -b "$BLOCK" ] || fail "boot_a block partition absent."
[ "$(blockdev --getsize64 "$BLOCK")" = 67108864 ] || fail "Unexpected boot size."
WORK=$(mktemp -d /tmp/revenant-dma.XXXXXX) || fail "Cannot create workspace."
trap 'rm -rf "$WORK"' EXIT
available=$(df -Pk "$WORK" | tail -n 1 | awk '{print $4}')
case "$available" in *[!0-9]*|'') fail "Free-space check failed.";; esac
[ "$available" -ge 524288 ] || fail "Need 512 MiB free in recovery workspace."
unzip -p "$ZIPFILE" tools/busybox > "$WORK/busybox" || fail "Cannot extract busybox."
[ "$(sha256sum "$WORK/busybox" | awk '{print $1}')" = '@BUSYBOX_SHA@' ] || fail "busybox checksum."
chmod 700 "$WORK/busybox"
BB=$WORK/busybox
hash() { "$BB" sha256sum "$1" | "$BB" awk '{print $1}'; }
extract() { "$BB" unzip -p "$ZIPFILE" "$1" > "$WORK/$2" || fail "Payload extraction failed."; }
MODE=@MODE@
EXPECTED_BASE=@BOOT_SHA@
EXPECTED_PAYLOAD=@PAYLOAD_SHA@
extract @PAYLOAD_NAME@ payload
[ "$(hash "$WORK/payload")" = "$EXPECTED_PAYLOAD" ] || fail "Payload checksum mismatch."
# Read only this technical boot partition; never inspect personal files.
"$BB" dd if="$BLOCK" of="$WORK/current.img" bs=1048576 count=64 || fail "Boot read failed."
[ "$("$BB" wc -c < "$WORK/current.img")" = 67108864 ] || fail "Truncated boot read."
if [ "$MODE" = flash ] || [ "$MODE" = preflight ]; then
  [ "$(hash "$WORK/current.img")" = "$EXPECTED_BASE" ] || fail "Current kernel is not the verified working no-DMA boot."
  ZIPDIR=$(dirname "$ZIPFILE")
  case "$ZIPDIR" in /tmp|/tmp/*|/sideload|/sideload/*) fail "Use a ZIP on persistent storage, not sideload.";; esac
  [ -d "$ZIPDIR" ] && [ -w "$ZIPDIR" ] || fail "Backup directory unavailable."
  BACKUP=$ZIPDIR/Revenant-before-DMA-boot-a-@BOOT_SHA@.img
  [ ! -L "$BACKUP" ] || fail "Backup path is a symlink."
  if [ ! -e "$BACKUP" ]; then
    available=$(df -Pk "$ZIPDIR" | tail -n 1 | awk '{print $4}')
    case "$available" in *[!0-9]*|'') fail "Backup free-space check failed.";; esac
    [ "$available" -ge 69632 ] || fail "Need 68 MiB free for persistent rollback."
    saved=$(mktemp "$ZIPDIR/.revenant-rollback.XXXXXX") || fail "Cannot create persistent backup."
    "$BB" cp "$WORK/current.img" "$saved" || fail "Backup copy failed."
    [ "$(hash "$saved")" = "$EXPECTED_BASE" ] || fail "Backup hash mismatch."
    "$BB" mv -n "$saved" "$BACKUP" || fail "Cannot publish backup."
  fi
  "$BB" sync
  [ -f "$BACKUP" ] && [ "$(hash "$BACKUP")" = "$EXPECTED_BASE" ] || fail "Persistent rollback verification failed."
  ui_print "Verified persistent no-DMA rollback: $BACKUP"
  extract tools/magiskboot magiskboot
  [ "$(hash "$WORK/magiskboot")" = '@MAGISKBOOT_SHA@' ] || fail "magiskboot checksum."
  chmod 700 "$WORK/magiskboot"
  cd "$WORK"
  export PATCHVBMETAFLAG=false KEEPVERITY=true KEEPFORCEENCRYPT=true
  "$WORK/magiskboot" unpack -h current.img || fail "Cannot unpack current boot."
  [ ! -s ramdisk.cpio ] || fail "Unexpected boot ramdisk."
  "$BB" cp payload kernel
  "$WORK/magiskboot" repack current.img boot-new.img || fail "Repack failed."
  mkdir verify
  cd verify
  "$WORK/magiskboot" unpack -h ../boot-new.img || fail "Cannot verify repacked boot."
  "$BB" cmp -s kernel ../payload || fail "Repacked kernel mismatch."
  [ ! -s ramdisk.cpio ] || fail "New boot ramdisk unexpected."
  cd "$WORK"
  # Only kernel_size may change in this pinned v4 header. No cmdline/version change.
  "$BB" dd if=current.img of=magic-before bs=1 count=8
  "$BB" dd if=boot-new.img of=magic-after bs=1 count=8
  "$BB" cmp -s magic-before magic-after || fail "Boot magic changed unexpectedly."
  "$BB" dd if=current.img of=header-before bs=1 skip=12 count=4084
  "$BB" dd if=boot-new.img of=header-after bs=1 skip=12 count=4084
  "$BB" cmp -s header-before header-after || fail "Boot header/layout changed unexpectedly."
  newsize=$("$BB" wc -c < boot-new.img)
  [ "$newsize" -le 67108864 ] || fail "Repacked boot exceeds partition."
  [ "$newsize" -ge 4096 ] || fail "Repacked boot truncated."
  "$BB" truncate -s 67108864 boot-new.img || fail "Cannot pad boot."
  [ "$("$BB" dd if=boot-new.img bs=1 skip=67108800 count=4 2>/dev/null)" = AVBf ] || fail "AVB footer missing/moved; refusing to guess."
else
  [ "$MODE" = restore ] || fail "Unknown operation."
  [ "$("$BB" wc -c < "$WORK/payload")" = 67108864 ] || fail "Rollback payload truncated."
  "$BB" mv "$WORK/payload" "$WORK/boot-new.img"
fi
NEW_HASH=$(hash "$WORK/boot-new.img")
if [ "$MODE" = preflight ]; then
  ui_print "PREFLIGHT PASS: repacked kernel, header and footer checked; SHA256=$NEW_HASH"
  ui_print "No partition was written. Keep the persistent no-DMA backup."
  exit 0
fi
ui_print "Experimental boot-only write; bootloader/hardware acceptance is NOT guaranteed."
blockdev --setrw "$BLOCK" || fail "Cannot enable boot writes."
"$BB" dd if="$WORK/boot-new.img" of="$BLOCK" bs=1048576 conv=fsync || fail "Write failed: restore verified no-DMA boot via fastboot."
"$BB" sync
[ "$(hash "$BLOCK")" = "$NEW_HASH" ] || fail "Readback mismatch: use verified rollback before reboot."
ui_print "boot_a readback SHA-256 verified. No other partition changed."
