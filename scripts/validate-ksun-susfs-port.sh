#!/bin/sh
set -eu

script=scripts/integrate-ksun-susfs-6.6.77.sh
fragment=configs/rodin-6.6.77-ksun-susfs.fragment
grep -q '30802e7260e2387176b9301377e88fc6fb0356b7' "$script"
grep -q 'b03e1a9da3d24eea766b48871c71a6aed9ac98a6' "$script"
grep -q '35fac8ee31035fb73a8b9301b50c2bdb4ff7feb7' "$script"
grep -q -- '--fuzz=0' "$script"
! grep -Eq 'KMI bypass|force load|MODULE_FORCE_LOAD' "$script" "$fragment"
grep -qx 'CONFIG_KSU=y' "$fragment"
grep -qx 'CONFIG_KSU_SUSFS=y' "$fragment"
grep -qx '# CONFIG_KSU_SUSFS_ENABLE_LOG is not set' "$fragment"
echo 'KSUN/SUSFS port pins and gates ok'
