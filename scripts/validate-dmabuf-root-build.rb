#!/usr/bin/env ruby
require 'yaml'

def validate_build(workflow)
  expected = {
    'KMI_BRANCH' => 'common-android15-6.6', 'KMI_TAG' => 'android15-6.6.77_r00',
    'KMI_TAG_OBJECT' => '79d26ca363880c3c6f7841045e46427bee6c3c3b',
    'KMI_COMMIT' => 'f7ebe251035c0d15ff90c6a0a320697932785fad',
    'KSU_COMMIT' => '234f6e040fcbca18b16d2398e1aa225712ec99ad',
    'SUSFS_COMMIT' => 'be7b7ef49a1e1b189c3abf00eacaa7ebdb4168c1',
    'SUSFS_FIX_COMMIT' => 'cd63f371d91fb7fc32014c75728fbb9b686d9ae9',
    'STOCK_SCMVERSION' => '-gca30f3b4bef6-abogki440974771',
    'STOCK_KERNEL_RELEASE' => '6.6.77-android15-8-gca30f3b4bef6-abogki440974771-4k',
    'CONTROL_ACK_RUN' => '37406739074', 'CONTROL_ACK_HEAD' => '96eaa013b59c682058a168be65b2109810944e8a',
    'CONTROL_ROOT_SOURCE_RUN' => '37407816068', 'CONTROL_ROOT_SOURCE_HEAD' => '4f8f9e5aff784bdef7bae7ca5ce3770b83f094b8'
  }
  raise 'composed build pins changed' unless workflow['env'] == expected
  raise 'write permission in audit' unless workflow['permissions'] == {'contents' => 'read', 'actions' => 'read'}
  raise 'concurrent/cancelled audit' unless workflow['concurrency'] == {'group' => 'rodin-dma-${{ github.ref }}', 'cancel-in-progress' => false}
  triggers = workflow['on'] || workflow[true]
  raise 'wrong branch/initial trigger' unless triggers['push']['branches'] == ['dyperos-3.0.304'] && triggers['push']['paths'].include?('.github/workflows/audit-rodin-dma-root-build.yml')
  raise 'unexpected jobs' unless workflow['jobs'].keys == ['compile']
  job = workflow['jobs']['compile']
  raise 'unexpected runner/bound' unless job['runs-on'] == 'ubuntu-24.04' && job['timeout-minutes'] == 180
  steps = job['steps']
  names = [nil, 'Validate completed controls and local gates', 'Install build dependencies',
           'Fetch exact ACK and root integration sources', 'Integrate verified root DMA then ROM ABI controls',
           'Compile composed DMA audit', 'Check DMA providers and ROM module ABI', 'Preserve audit evidence (no image or installer)']
  raise 'step sequence changed' unless steps.map { |s| s['name'] } == names
  raise 'unsafe action' unless steps.select { |s| s['uses'] }.map { |s| s['uses'] } == ['actions/checkout@v4', 'actions/upload-artifact@v4']
  steps[1..6].each { |s| raise 'pipefail missing' unless s['run'].start_with?("set -euo pipefail\n") }
  controls = steps[1]['run']
  %w[CONTROL_ completed success head_sha].each { |token| raise 'completed control gate missing' unless controls.include?(token) }
  source = steps[4]['run']
  %w[integrate-dmabuf-after-root.py prepare-dmabuf-root-fragment.py fix-rodin-boot-abi.py align-rodin-kmi.py check-stock-module-trust.py].each do |token|
    raise 'root/ROM source gate missing' unless source.include?(token)
  end
  build = steps[5]['run']
  %w[--lto=none --page_size=4k dma_root_audit.fragment kernel_aarch64_dist].each { |token| raise 'build control missing' unless build.include?(token) }
  raise 'root version gate missing' unless build.include?('-- KernelSU-Next version: 33239') && build.include?('fallback:')
  check = steps[6]['run']
  %w[select_equal check-dmabuf-build.py rom-module-reference.py check-stock-kfence.py check-stock-config-alignment.py check-stock-release-banner.py test-stock-release-banner.py].each do |token|
    raise 'compiled ABI/config gate missing' unless check.include?(token)
  end
  raise 'release pin not checked' unless check.include?('--expected-release "$STOCK_KERNEL_RELEASE"')
  commands = steps.map { |s| s['run'].to_s }.join("\n")
  raise 'device/installer in audit' if commands.match(/\b(?:adb|fastboot|kexec)\b|package-rodin|gh release|upload-release/)
  raise 'logs not retained' unless steps[7]['if'] == 'always()'
  raise 'unexpected upload' unless steps[7]['with']['path'] == "dma-root-build.log\ndma-root-source.log\ndma-root-build-evidence/\n"
end

if __FILE__ == $0
  workflow = YAML.load_file(File.expand_path('../.github/workflows/audit-rodin-dma-root-build.yml', __dir__))
  validate_build(workflow)
  [lambda { |w| w['env']['CONTROL_ACK_HEAD'] = 'wrong' },
   lambda { |w| w['concurrency']['cancel-in-progress'] = true },
   lambda { |w| w['permissions']['contents'] = 'write' },
   lambda { |w| w['jobs']['compile']['steps'][6]['run'] = "set -euo pipefail\nadb reboot\n" },
   lambda { |w| w['jobs']['compile']['steps'][6]['run'].sub!('check-stock-release-banner.py', 'wrong-checker.py') }].each do |change|
    candidate = Marshal.load(Marshal.dump(workflow)); change.call(candidate)
    begin
      validate_build(candidate)
    rescue RuntimeError
      next
    end
    raise 'negative compiled-audit gate did not reject'
  end
  puts 'PASS: composed DMA build pins, completed controls, serial audit, ABI/config/release gates and no installer/device; five negative gates'
end
