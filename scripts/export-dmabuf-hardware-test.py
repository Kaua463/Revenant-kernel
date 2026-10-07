#!/usr/bin/env python3
"""Export a gated candidate, never an installer or hardware safety approval."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

COMPOSITION = '73db391ccb9ab268e92854ff218df4ee311595596c6250d6a922cb8065b313b6'
PROOFS = {
    'root_dma': (37536101164, 'ba612f6232173b8e0630405b4061ca47e1ad0bf1', 'audit-rodin-dma-root-build.yml'),
    'ack_matrix': (37536101129, 'ba612f6232173b8e0630405b4061ca47e1ad0bf1', 'audit-rodin-dma.yml'),
    'vm': (37541921953, '3d2eac98f56e84809ce57474ea99510a82bf6ec7', 'audit-rodin-dma-producer.yml'),
}


def validate_proof(run, pin):
    run_id, head, workflow = pin
    if not (run['id'] == run_id and run['status'] == 'completed'
            and run['conclusion'] == 'success' and run['head_sha'] == head
            and run['path'] == '.github/workflows/' + workflow):
        raise ValueError('pinned proof identity/completion mismatch')


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def validate_evidence(evidence, image):
    composition = json.loads((evidence / 'composition.json').read_text())
    if composition['composed_tracked_manifest_sha256'] != COMPOSITION:
        raise ValueError('source composition drift')
    providers = json.loads((evidence / 'providers.json').read_text())
    config = evidence / 'config'
    if providers['enabled'] != 'y' or len(providers['providers']) != 14:
        raise ValueError('missing DMA providers')
    if providers['config_sha256'] != digest(config):
        raise ValueError('config/evidence mismatch')
    settings = dict(line.split('=', 1) for line in config.read_text().splitlines()
                    if line.startswith('CONFIG_') and '=' in line)
    for key in ['CONFIG_XIAOMI_DMABUF_HUGETLB', 'CONFIG_KSU', 'CONFIG_KSU_SUSFS', 'CONFIG_ARM64_4K_PAGES']:
        if settings.get(key) != 'y':
            raise ValueError('required hardware config missing: ' + key)
    if settings.get('CONFIG_XIAOMI_DMABUF_RUNTIME_AUDIT') in ('y', 'm'):
        raise ValueError('disposable VM producer forbidden in phone candidate')
    with image.open('rb') as stream:
        header = stream.read(64)
    if len(header) != 64 or struct.unpack_from('<I', header, 56)[0] != 0x644D5241:
        raise ValueError('not a raw ARM64 Image')
    if not 64 < image.stat().st_size < 64 * 1024 * 1024:
        raise ValueError('Image exceeds boot partition limit')


def export(evidence, image, output, proofs, commit):
    validate_evidence(evidence, image)
    for name, pin in PROOFS.items():
        validate_proof(proofs[name], pin)
    output.mkdir()  # refuse an existing/stale artifact directory
    shutil.copyfile(image, output / 'Image')
    for name in ['config', 'Module.symvers', 'composition.json', 'providers.json',
                 'address-registration.json', 'kernel-banner.txt', 'build-manifest.commit']:
        shutil.copyfile(evidence / name, output / name)
    report = {'status': 'EXPERIMENTAL_CANDIDATE_NOT_CLEARED_FOR_FLASH',
              'repository_commit': commit, 'proof_runs': proofs,
              'composition_sha256': COMPOSITION,
              'pending': ['exact boot container packaging and rollback verification',
                          'remaining MM lifetime/allocator safety gates',
                          'staged device boot and stock producer activation'],
              'no_installer': True, 'no_hardware_approval': True}
    (output / 'hardware-test.json').write_text(json.dumps(report, indent=2) + '\n')
    files = sorted(path for path in output.iterdir() if path.is_file())
    manifest = ''.join(digest(path) + '  ' + path.name + '\n' for path in files)
    (output / 'SHA256SUMS').write_text(manifest)
    # Independent copied directory; no runner absolute paths in checksums.
    with tempfile.TemporaryDirectory() as temp:
        clean = Path(temp) / 'artifact'
        shutil.copytree(output, clean)
        for line in (clean / 'SHA256SUMS').read_text().splitlines():
            expected, name = line.split('  ', 1)
            if Path(name).name != name or digest(clean / name) != expected:
                raise ValueError('clean-room checksum mismatch')


def main():
    repository = os.environ['GITHUB_REPOSITORY']
    if repository != 'Kaua463/Revenant-kernel':
        raise ValueError('unexpected repository')
    proofs = {name: json.loads(subprocess.check_output(
        ['gh', 'api', f'repos/{repository}/actions/runs/{pin[0]}']))
        for name, pin in PROOFS.items()}
    evidence = Path('dma-root-build-evidence')
    image = Path((evidence / 'image-path').read_text().strip())
    export(evidence, image, Path('dma-hardware-test'), proofs, os.environ['GITHUB_SHA'])
    print('PASS: gated experimental Image exported; no installer or hardware approval')


if __name__ == '__main__':
    main()
