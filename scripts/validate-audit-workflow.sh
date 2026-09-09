#!/bin/sh
set -eu

workflow=.github/workflows/audit-rodin-6.6.77-abi.yml
grep -q 'branches: \[dyperos-3.0.304\]' "$workflow"
grep -q 'KMI_TAG: android15-6.6.77_r00' "$workflow"
grep -q 'KMI_TAG_OBJECT: 79d26ca363880c3c6f7841045e46427bee6c3c3b' "$workflow"
grep -q 'KMI_COMMIT: f7ebe251035c0d15ff90c6a0a320697932785fad' "$workflow"
! grep -Eq 'force load|KMI bypass|protected.exports.*(empty|remove|delete)' "$workflow"
echo 'audit workflow gates ok'
