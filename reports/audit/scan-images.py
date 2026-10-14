#!/usr/bin/env python3
"""Rescan recovered baseline digests and explicitly configured bumped tags."""
import concurrent.futures
import csv
import hashlib
import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / 'reports/audit/latest'
OUT.mkdir(parents=True, exist_ok=True)
TRIVY = '/workspace/.cache/cve-audit/trivy'
CACHE = '/workspace/.cache/cve-audit/trivy-cache'
rows = list(csv.DictReader((ROOT / 'reports/before/images.tsv').open(), delimiter='\t'))
bumps = {
    'ghcr.io/kyverno/readiness-checker:latest': 'ghcr.io/kyverno/readiness-checker:v1.19.1',
    'docker.io/nginxinc/nginx-unprivileged:1.29-alpine': 'docker.io/nginxinc/nginx-unprivileged:1.31-alpine',
    'docker.io/falcosecurity/falcosidekick:2.32.0': 'docker.io/falcosecurity/falcosidekick:2.35.0',
    'docker.io/falcosecurity/falcosidekick-ui:2.2.0': 'docker.io/falcosecurity/falcosidekick-ui:2.3.1',
    'docker.io/falcosecurity/falcoctl:0.12.2': 'docker.io/falcosecurity/falcoctl:0.14.2',
    'docker.io/falcosecurity/falco-exporter:0.8.3': 'docker.io/falcosecurity/falco-exporter:0.8.7',
    'docker.io/pgsty/silo:RELEASE.2026-09-03T13-18-01Z': 'docker.io/pgsty/silo:RELEASE.2026-09-16T00-00-00Z',
    'docker.io/velero/velero:v1.18.2': 'docker.io/velero/velero:v1.18.4',
    'velero/velero-plugin-for-aws:v1.14.0': 'velero/velero-plugin-for-aws:v1.14.4',
    'ecr-public.aws.com/docker/library/redis:8.6.4-alpine': 'ecr-public.aws.com/docker/library/redis:8.6.7-alpine',
}
for r in csv.DictReader((ROOT / 'reports/after/images.tsv').open(), delimiter='\t'):
    repo = r['image'].rsplit(':', 1)[0]
    for baseline in rows:
        if baseline['image'].rsplit(':', 1)[0] == repo and baseline['image'] != r['image']:
            bumps.setdefault(baseline['image'], r['image'])


def remote_name(image):
    if image.startswith('docker.io/'):
        return 'registry-1.docker.io/' + image[len('docker.io/'):]
    first = image.split('@')[0].split('/')[0]
    if '.' not in first and (':' not in first or '/' not in image.split('@')[0]):
        return 'registry-1.docker.io/' + ('library/' if '/' not in image else '') + image
    return image


def scan(task):
    kind, original, image = task
    key = hashlib.sha256((kind + image).encode()).hexdigest()[:16]
    report = OUT / (key + '.json')
    log = OUT / (key + '.log')
    command = [TRIVY, 'image', '--cache-dir', CACHE, '--cache-backend', 'memory', '--skip-db-update',
               '--skip-java-db-update', '--image-src', 'remote', '--scanners', 'vuln',
               '--severity', 'HIGH,CRITICAL', '--timeout', '5m', '--format', 'json',
               '--output', str(report), remote_name(image)]
    with log.open('w') as stream:
        try:
            result = subprocess.run(command, stdout=stream, stderr=stream, timeout=330)
            status = 'OK' if result.returncode == 0 and report.exists() else 'FAILED'
        except subprocess.TimeoutExpired:
            status = 'TIMEOUT'
    print(kind, original, status, flush=True)
    return dict(kind=kind, baseline_image=original, scanned_image=image, status=status,
                report=str(report.relative_to(ROOT)), log=str(log.relative_to(ROOT)))


if __name__ == '__main__':
    tasks = []
    for row in rows:
        j = json.loads((ROOT / row['report']).read_text())
        digests = j.get('Metadata', {}).get('RepoDigests', [])
        if digests:
            tasks.append(('baseline', row['image'], digests[0]))
        else:
            print('MISSING_DIGEST', row['image'], flush=True)
        if row['image'] in bumps:
            tasks.append(('configured', row['image'], bumps[row['image']]))
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(scan, tasks))
    with (OUT / 'scans.tsv').open('w') as stream:
        writer = csv.DictWriter(stream, fieldnames=['kind', 'baseline_image', 'scanned_image',
                                                   'status', 'report', 'log'], delimiter='\t', lineterminator='\n')
        writer.writeheader()
        writer.writerows(results)
