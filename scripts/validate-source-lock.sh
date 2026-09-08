#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
lock_file="$repo_root/configs/rodin-source.lock"

test -f "$lock_file"

required_keys='RODIN_SOURCE_URL RODIN_SOURCE_BRANCH RODIN_SOURCE_COMMIT RODIN_SOURCE_VERSION LINUX_STABLE_URL LINUX_STABLE_TAG LINUX_STABLE_COMMIT KSU_SOURCE_URL KSU_VERSION_TAG KSU_COMMIT ANDROID_KMI_BRANCH ANDROID_KMI_GENERATION TARGET_ARCH TARGET_PAGE_SIZE TARGET_DEVICE TARGET_PLATFORM'

for key in $required_keys; do
    value=$(sed -n "s/^${key}=//p" "$lock_file")
    test -n "$value" || {
        echo "missing source lock key: $key" >&2
        exit 1
    }
done

assert_sha() {
    key=$1
    value=$(sed -n "s/^${key}=//p" "$lock_file")
    test "${#value}" -eq 40 || {
        echo "$key is not 40 characters" >&2
        exit 1
    }
    printf '%s\n' "$value" | grep -Eq '^[0-9a-f]{40}$' || {
        echo "$key is not a full lowercase SHA-1" >&2
        exit 1
    }
}

assert_sha RODIN_SOURCE_COMMIT
assert_sha LINUX_STABLE_COMMIT
assert_sha KSU_COMMIT

grep -qx 'RODIN_SOURCE_VERSION=6.6.102' "$lock_file"
grep -qx 'LINUX_STABLE_TAG=v6.6.156' "$lock_file"
grep -qx 'ANDROID_KMI_BRANCH=android15-6.6' "$lock_file"
grep -qx 'ANDROID_KMI_GENERATION=8' "$lock_file"
grep -qx 'TARGET_ARCH=arm64' "$lock_file"
grep -qx 'TARGET_PAGE_SIZE=4096' "$lock_file"
grep -qx 'TARGET_DEVICE=rodin' "$lock_file"
grep -qx 'TARGET_PLATFORM=mt6899' "$lock_file"

echo 'source lock validation passed'
