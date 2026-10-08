#!/usr/bin/env ruby
require_relative 'validate-dmabuf-root-build'

def validate_root_vm(workflow)
  copy = Marshal.load(Marshal.dump(workflow))
  steps = copy['jobs']['compile']['steps']
  runtime = steps.delete_at(7)
  raise 'missing bounded root VM stage' unless runtime['name'] == 'Run composed root DMA RAM-only ARM64 VM'
  %w[set\ -euo\ pipefail run-dmabuf-vm-audit.py --timeout\ 300 --kernel build-dmabuf-vm-initramfs.py].each do |token|
    raise 'root runtime safety gate missing: ' + token unless runtime['run'].include?(token)
  end
  ['CONFIG_KSU=y', 'CONFIG_KSU_SUSFS=y'].each do |token|
    raise 'root absent in runtime config gate' unless runtime['run'].include?(token)
  end
  source = steps[4]['run']
  ['prepare-dmabuf-root-runtime.py', '--composition dma-root-build-evidence/composition.json',
   '--enable XIAOMI_DMABUF_RUNTIME_AUDIT', '--enable DMA_SHARED_BUFFER',
   'dma-root-guest-preflight'].each do |token|
    raise 'root runtime composition/instrumentation gate missing' unless source.include?(token)
  end
  raise 'unsafe runtime command' if runtime['run'].match(/\b(?:adb|fastboot|kexec)\b|gh release/)
  triggers = copy['on'] || copy[true]
  raise 'root VM initial trigger missing' unless triggers['push']['paths'].include?('.github/workflows/audit-rodin-dma-root-vm.yml')
  triggers['push']['paths'] << '.github/workflows/audit-rodin-dma-root-build.yml'
  allowed = "dma-root-build.log\ndma-root-source.log\ndma-root-build-evidence/*.json\ndma-root-build-evidence/*.txt\ndma-root-build-evidence/config\ndma-root-build-evidence/Module.symvers\ndma-root-build-evidence/vm/serial.log\ndma-root-build-evidence/vm/report.json\n"
  raise 'root VM binary/kernel upload forbidden even on failure' unless steps[7]['with']['path'] == allowed
  # Existing canonical root/ABI/cert/config/version gates remain mandatory.
  steps[7]['with']['path'] = "dma-root-build.log\ndma-root-source.log\ndma-root-build-evidence/\n"
  validate_build(copy)
end

if __FILE__ == $0
  path = File.expand_path('../.github/workflows/audit-rodin-dma-root-vm.yml', __dir__)
  workflow = YAML.load_file(path)
  validate_root_vm(workflow)
  [lambda { |w| w['env']['KSU_COMMIT'] = 'wrong' },
   lambda { |w| w['jobs']['compile']['steps'][7]['run'].sub!('CONFIG_KSU=y', 'CONFIG_KSU=n') },
   lambda { |w| w['jobs']['compile']['steps'][4]['run'].sub!('prepare-dmabuf-root-runtime.py', 'wrong.py') },
   lambda { |w| w['jobs']['compile']['steps'][8]['with']['path'] += "dma-root-build-evidence/Image\n" },
   lambda { |w| w['jobs']['compile']['steps'][7]['run'] += "fastboot flash boot kernel\n" }].each do |change|
    candidate = Marshal.load(Marshal.dump(workflow)); change.call(candidate)
    begin
      validate_root_vm(candidate)
    rescue RuntimeError
      next
    end
    raise 'negative root runtime gate accepted'
  end
  puts 'PASS: exact root pins/ABI controls plus bounded root VM; five negative gates'
end
