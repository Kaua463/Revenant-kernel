#!/usr/bin/env ruby
# Compatible with macOS Ruby/Psych. Source audit must never become a flash job.
require 'yaml'

def validate_workflow(workflow)
  pins = {
    'KMI_TAG' => 'android15-6.6.77_r00',
    'KMI_TAG_OBJECT' => '79d26ca363880c3c6f7841045e46427bee6c3c3b',
    'KMI_COMMIT' => 'f7ebe251035c0d15ff90c6a0a320697932785fad',
    'KSU_COMMIT' => '234f6e040fcbca18b16d2398e1aa225712ec99ad',
    'SUSFS_COMMIT' => 'be7b7ef49a1e1b189c3abf00eacaa7ebdb4168c1',
    'SUSFS_FIX_COMMIT' => 'cd63f371d91fb7fc32014c75728fbb9b686d9ae9'
  }
  raise 'integration pins changed' unless workflow['env'] == pins
  raise 'write permission in source audit' unless workflow['permissions'] == {'contents' => 'read'}
  triggers = workflow['on'] || workflow[true]
  raise 'wrong source audit branch' unless triggers['push']['branches'] == ['dyperos-3.0.304']
  raise 'missing narrow initial trigger' unless triggers['push']['paths'].include?('.github/workflows/audit-rodin-dma-root-sources.yml')
  raise 'running audit must not be cancelled' unless workflow['concurrency']['cancel-in-progress'] == false
  raise 'unexpected source audit jobs' unless workflow['jobs'].keys == ['sources']
  job = workflow['jobs']['sources']
  raise 'unexpected source runner/bound' unless job['runs-on'] == 'ubuntu-24.04' && job['timeout-minutes'] == 45
  steps = job['steps']
  expected_names = [nil, 'Validate source audit gates', 'Fetch pinned integration sources (no toolchain)',
                    'Execute exact root then DMA integration', 'Preserve source evidence (not a build or installer)']
  raise 'source audit steps changed' unless steps.map { |s| s['name'] } == expected_names
  raise 'checkout missing' unless steps[0]['uses'] == 'actions/checkout@v4'
  steps[1..3].each { |s| raise 'pipefail missing' unless s['run'].start_with?("set -euo pipefail\n") }
  fetch = steps[2]['run']
  raise 'tag object/commit checks missing' unless fetch.include?('= "$KMI_TAG_OBJECT"') && fetch.include?('= "$KMI_COMMIT"')
  integration = steps[3]['run']
  %w[integrate-dmabuf-after-root.py --source --ksu-source --susfs-source --fix-source --overlay --output].each do |token|
    raise 'composed integration interface missing' unless integration.include?(token)
  end
  commands = steps.map { |s| s['run'].to_s }.join("\n")
  raise 'build/device/installer command in source audit' if commands.match(/\b(?:adb|fastboot|bazel|make|kexec)\b|package-rodin|gh release|upload-release/)
  raise 'unsafe action in source audit' unless steps.select { |s| s['uses'] }.map { |s| s['uses'] } == ['actions/checkout@v4', 'actions/upload-artifact@v4']
  raise 'logs not retained on failure' unless steps[4]['if'] == 'always()'
  raise 'unexpected uploaded payload' unless steps[4]['with']['path'] == "dma-root-integration.log\ndma-root-evidence/\n"
end

if __FILE__ == $0
  path = File.expand_path('../.github/workflows/audit-rodin-dma-root-sources.yml', __dir__)
  workflow = YAML.load_file(path)
  validate_workflow(workflow)
  # Negative checks exercise parsed YAML objects rather than string searches.
  [lambda { |w| w['env']['KMI_COMMIT'] = 'wrong' },
   lambda { |w| w['permissions']['contents'] = 'write' },
   lambda { |w| w['jobs']['sources']['steps'][3]['run'] += "adb reboot\n" }].each do |change|
    candidate = Marshal.load(Marshal.dump(workflow)); change.call(candidate)
    begin
      validate_workflow(candidate)
    rescue RuntimeError
      next
    end
    raise 'negative source-audit gate did not reject'
  end
  puts 'PASS: source-only DMA/root workflow pins, fail-fast, narrow trigger and no device/build; three negative gates'
end
