#!/bin/sh
set -eu

script=scripts/integrate-ksun-susfs-6.6.77.sh
fragment=configs/rodin-6.6.77-ksun-susfs.fragment
grep -q '234f6e040fcbca18b16d2398e1aa225712ec99ad' "$script"
grep -q 'be7b7ef49a1e1b189c3abf00eacaa7ebdb4168c1' "$script"
grep -q 'cd63f371d91fb7fc32014c75728fbb9b686d9ae9' "$script"
grep -q -- '--fuzz=0' "$script"
grep -q 'already-audited lines' "$script"
grep -q 'susfs_open_redirect_spoof_show_map_vma_srcu' "$script"
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
