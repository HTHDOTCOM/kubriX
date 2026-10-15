#!/usr/bin/env python3
"""Retry the audit's failed scans against the frozen local Trivy DB.

Reads reports/audit/latest/scans.tsv, selects rows whose status != OK, and
re-scans the exact scanned_image (digest for baseline, tag for configured)
using the same flags as the audit baseline. Results are written to
reports/audit/remediation-2026-10-15/scans/ so the original audit reports are
never modified.
"""
import concurrent.futures
import csv
import hashlib
import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[3]
AUDIT_SCANS = ROOT / 'reports/audit/latest/scans.tsv'
OUT = ROOT / 'reports/audit/remediation-2026-10-15/scans'
OUT.mkdir(parents=True, exist_ok=True)
TRIVY = '/home/c1023447/bin/trivy'
CACHE = '/home/c1023447/.cache/trivy'


def remote_name(image):
    if image.startswith('docker.io/'):
        return 'registry-1.docker.io/' + image[len('docker.io/'):]
    first = image.split('@')[0].split('/')[0]
    if '.' not in first and (':' not in first or '/' not in image.split('@')[0]):
        return 'registry-1.docker.io/' + ('library/' if '/' not in image else '') + image
    return image


def scan(task):
    kind, baseline_image, image = task
    key = hashlib.sha256((kind + image).encode()).hexdigest()[:16]
    report = OUT / (key + '.json')
    log = OUT / (key + '.log')
    command = [TRIVY, 'image', '--cache-dir', CACHE, '--cache-backend', 'memory',
               '--skip-db-update', '--skip-java-db-update', '--image-src', 'remote',
               '--scanners', 'vuln', '--severity', 'HIGH,CRITICAL', '--timeout', '5m',
               '--format', 'json', '--output', str(report), remote_name(image)]
    with log.open('w') as stream:
        try:
            result = subprocess.run(command, stdout=stream, stderr=stream, timeout=330)
            status = 'OK' if result.returncode == 0 and report.exists() else 'FAILED'
        except subprocess.TimeoutExpired:
            status = 'TIMEOUT'
    print(kind, baseline_image, image, status, flush=True)
    return dict(kind=kind, baseline_image=baseline_image, scanned_image=image,
                status=status, report=str(report.relative_to(ROOT)),
                log=str(log.relative_to(ROOT)))


def main():
    rows = list(csv.DictReader(AUDIT_SCANS.open(), delimiter='\t'))
    tasks = [(r['kind'], r['baseline_image'], r['scanned_image'])
             for r in rows if r['status'] != 'OK']
    print(f'Retrying {len(tasks)} failed scans', flush=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(scan, tasks))
    with (OUT / 'retry-scans.tsv').open('w') as stream:
        writer = csv.DictWriter(stream, fieldnames=['kind', 'baseline_image', 'scanned_image',
                                                    'status', 'report', 'log'],
                                delimiter='\t', lineterminator='\n')
        writer.writeheader()
        writer.writerows(results)
    ok = sum(1 for r in results if r['status'] == 'OK')
    print(f'Done: {ok}/{len(results)} OK', flush=True)


if __name__ == '__main__':
    main()
