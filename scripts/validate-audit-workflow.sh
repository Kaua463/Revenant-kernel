#!/bin/sh
set -eu

workflow=.github/workflows/audit-rodin-6.6.77-abi.yml
grep -q 'branches: \[dyperos-3.0.304\]' "$workflow"
grep -q 'KMI_TAG: android15-6.6.77_r00' "$workflow"
grep -q 'KMI_COMMIT: 79d26ca36388' "$workflow"
! grep -Eq 'force load|KMI bypass|protected.exports.*(empty|remove|delete)' "$workflow"
echo 'audit workflow gates ok'
