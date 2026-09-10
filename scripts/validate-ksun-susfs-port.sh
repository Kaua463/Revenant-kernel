#!/bin/sh
set -eu

script=scripts/integrate-ksun-susfs-6.6.77.sh
fragment=configs/rodin-6.6.77-ksun-susfs.fragment
workflow=.github/workflows/audit-rodin-6.6.77-ksun-susfs.yml
grep -q '234f6e040fcbca18b16d2398e1aa225712ec99ad' "$script"
grep -q 'be7b7ef49a1e1b189c3abf00eacaa7ebdb4168c1' "$script"
grep -q 'cd63f371d91fb7fc32014c75728fbb9b686d9ae9' "$script"
grep -q -- '--fuzz=0' "$script"
grep -q 'already-audited lines' "$script"
grep -q 'susfs_open_redirect_spoof_show_map_vma_srcu' "$script"
grep -q "KSU_GIT_VERSION: '3239'" "$workflow"
grep -q "KSU_VERSION: '33239'" "$workflow"
grep -q 'KSU_GIT_TAG: v3.3.0' "$workflow"
grep -q 'STOCK_SCMVERSION: -gca30f3b4bef6-abogki440974771' "$workflow"
grep -q 'STOCK_KERNEL_RELEASE: 6.6.77-android15-8-gca30f3b4bef6-abogki440974771-4k' "$workflow"
grep -q 'KSU_GIT_VERSION ?= 3239' "$script"
grep -q 'KSU_GIT_TAG ?= v3.3.0' "$script"
grep -q 'KSU_GIT_VERSION_VALID ?= 1' "$script"
grep -q 'KernelSU-Next version fallback:' "$workflow"
grep -Fq "Linux version \$STOCK_KERNEL_RELEASE " "$workflow"
if grep -Eq '\|\|[[:space:]]*true|MODULE_FORCE_LOAD' "$script" "$fragment"; then
  exit 1
fi
if grep -Eq 'KMI bypass|force load|MODULE_FORCE_LOAD' "$script" "$fragment"; then
  exit 1
fi
grep -qx 'CONFIG_KSU=y' "$fragment"
grep -qx 'CONFIG_KSU_SUSFS=y' "$fragment"
grep -qx '# CONFIG_KSU_SUSFS_ENABLE_LOG is not set' "$fragment"
echo 'KSUN/SUSFS port pins and gates ok'
