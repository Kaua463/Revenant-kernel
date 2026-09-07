#!/bin/sh
set -eu

workflow=.github/workflows/build-kernel.yml

ruby -e 'require "yaml"; YAML.load_file(ARGV.fetch(0)); puts "YAML OK"' "$workflow"

grep -q 'KMI_TAG: android15-6.6.77_r00' "$workflow"
grep -q 'EXPECTED_KERNEL_RELEASE: 6.6.77-android15-8' "$workflow"
grep -q 'KSU_VERSION_FORCED: 33151' "$workflow"
grep -q 'KSU_VERSION_TAG: v3.2.0-22-g1d919700' "$workflow"
grep -q 'CRC compatibility patch missing' "$workflow"
grep -q 'vermagic compatibility patch missing' "$workflow"
grep -q '12215bb52d68d6daaf408de6dcc5623ab5e5ca7483342a70b3302598616f9a23' "$workflow"

if grep -q 'KMI_TAG: android15-6.6.127_r00' "$workflow"; then
  echo 'unexpected old KMI tag' >&2
  exit 1
fi

echo 'Workflow compatibility gates OK'
