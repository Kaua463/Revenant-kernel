#!/usr/bin/env ruby
# Experimental export must retain the canonical audited compilation verbatim.
require_relative 'validate-dmabuf-root-build'
ROOT = File.expand_path('..', __dir__)
EXPORT_STEPS = "\n      - name: Gate current VM proofs and export experimental Image\n        env:\n          GH_TOKEN: ${{ github.token }}\n        run: |\n          set -euo pipefail\n          python3 scripts/export-dmabuf-hardware-test.py\n      - name: Upload experimental hardware candidate (no installer)\n        uses: actions/upload-artifact@v4\n        with:\n          name: rodin-dma-hardware-test-${{ github.run_number }}\n          path: dma-hardware-test/\n          if-no-files-found: error\n"
def validate_hardware(text, original)
  validate_build(YAML.load(original))
  expected = original.sub('name: Audit rodin root DMA compiled ABI (not flashable)',
                          'name: Build rodin DMA experimental hardware candidate')
  expected = expected.sub('      - .github/workflows/audit-rodin-dma-root-build.yml',
    "      - .github/workflows/build-rodin-dma-hardware-test.yml\n      - scripts/validate-dmabuf-hardware-test.rb\n      - scripts/export-dmabuf-hardware-test.py\n      - scripts/test-dmabuf-hardware-export.py")
  expected = expected.sub('          ruby scripts/validate-dmabuf-root-build.rb',
    "          ruby scripts/validate-dmabuf-root-build.rb\n          ruby scripts/validate-dmabuf-hardware-test.rb\n          python3 scripts/test-dmabuf-hardware-export.py")
  expected = expected.sub('      - name: Preserve audit evidence (no image or installer)',
    EXPORT_STEPS + '      - name: Preserve audit evidence (no image or installer)')
  raise 'hardware workflow differs from audited build plus gated export' unless text == expected
end
if __FILE__ == $0
  original = File.read(File.join(ROOT, '.github/workflows/audit-rodin-dma-root-build.yml'))
  text = File.read(File.join(ROOT, '.github/workflows/build-rodin-dma-hardware-test.yml'))
  validate_hardware(text, original)
  ['check-dmabuf-address-build.py', '--lto=none', 'rom-module-reference.py',
   'check-stock-kfence.py', 'export-dmabuf-hardware-test.py',
   'if-no-files-found: error', 'actions/upload-artifact@v4'].each do |token|
    begin
      validate_hardware(text.sub(token, 'UNSAFE_REMOVED'), original)
    rescue RuntimeError
      next
    end
    raise 'negative hardware gate accepted: ' + token
  end
  puts 'PASS: experimental build preserves all audited gates; seven mutations rejected'
end
