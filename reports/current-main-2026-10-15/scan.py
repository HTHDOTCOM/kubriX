#!/usr/bin/env python3
"""Scan the explicitly scoped image references from main, without deployment."""
import concurrent.futures
import csv
import hashlib
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = pathlib.Path(__file__).resolve().parent
TRIVY = '/workspace/.cache/cve-audit/trivy'
CACHE = pathlib.Path('/workspace/.cache/current-main-scan/cache')
SOURCE = pathlib.Path('/workspace/.cache/current-main-scan/chart-source/platform-apps/charts')
YQ = '/workspace/.local/bin/yq'


def yaml(path):
    return json.loads(subprocess.check_output([YQ, '-o=json', '.', str(path)], text=True))


def values(chart):
    return yaml(SOURCE / chart / 'values-kubrix-default.yaml')


def write_tsv(name, rows):
    with (OUT / name).open('w') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]), delimiter='\t', lineterminator='\n')
        w.writeheader()
        w.writerows(rows)


inventory = []


def add(product, image, source, kind='explicit main override'):
    inventory.append(dict(product=product, image=image, source=source, source_kind=kind))


kc = values('keycloak')['keycloak-operator-helm']['operator']
add('keycloak-operator', kc['image'], 'platform-apps/charts/keycloak/values-kubrix-default.yaml')
add('keycloak', kc['envs']['RELATED_IMAGE_KEYCLOAK'], 'platform-apps/charts/keycloak/values-kubrix-default.yaml (operator related image)')
add('metallb-frr', 'quay.io/frrouting/frr:' + values('metallb')['metallb']['frr-k8s']['frrk8s']['frr']['image']['tag'], 'platform-apps/charts/metallb/values-kubrix-default.yaml')
add('kubecost-prometheus', 'quay.io/prometheus/prometheus:' + values('kubecost')['cost-analyzer']['prometheus']['server']['image']['tag'], 'platform-apps/charts/kubecost/values-kubrix-default.yaml')
add('testkube-nats', 'nats:' + values('testkube')['testkube']['nats']['container']['image']['tag'], 'platform-apps/charts/testkube/values-kubrix-default.yaml')
velero = values('velero')['velero']
add('velero', 'docker.io/velero/velero:' + velero['image']['tag'], 'platform-apps/charts/velero/values-kubrix-default.yaml')
add('velero-aws-plugin', next(c['image'] for c in velero['initContainers'] if c['name'] == 'velero-plugin-for-aws'), 'platform-apps/charts/velero/values-kubrix-default.yaml')
silo = values('minio')['minio']['image']
add('silo-minio-loki-mimir', silo['repository'] + ':' + silo['tag'], 'platform-apps/charts/{minio,loki,mimir}/values-kubrix-default.yaml')
falco = values('falco')['falco']
for name, image in [('falcoctl', falco['falcoctl']['image']), ('falcosidekick', falco['falcosidekick']['image']), ('falcosidekick-ui', falco['falcosidekick']['webui']['image'])]:
    add(name, 'docker.io/falcosecurity/' + name + ':' + str(image['tag']), 'platform-apps/charts/falco/values-kubrix-default.yaml')
add('falco-exporter', 'docker.io/falcosecurity/falco-exporter:' + values('falco')['falco-exporter']['image']['tag'], 'platform-apps/charts/falco/values-kubrix-default.yaml')
falco_chart = yaml(pathlib.Path('/workspace/.cache/cve-audit/charts/falco/Chart.yaml'))
assert falco_chart['version'] == next(d['version'] for d in yaml(SOURCE / 'falco/Chart.yaml')['dependencies'] if d['name'] == 'falco')
add('falco', 'docker.io/falcosecurity/falco:' + falco_chart['appVersion'], 'Falco 8.0.5 upstream Chart.yaml appVersion', 'locked chart default; cached upstream chart')
bs = values('backstage')['backstage']['image'] if 'image' in values('backstage').get('backstage', {}) else values('backstage')['backstage']['backstage']['image']
add('backstage', bs['registry'] + '/' + bs['repository'] + ':' + bs['tag'], 'platform-apps/charts/backstage/values-kubrix-default.yaml')
vui = yaml(pathlib.Path('/workspace/.cache/cve-audit/velero-helm-source/chart/values.yaml'))
for product, key in [('velero-api', 'apiService'), ('velero-ui', 'uiService'), ('velero-watchdog', 'watchdogService')]:
    # Read the actual upstream key names, not guessed repository tags.
    matching = [v['deployment']['image'] for v in vui.values() if isinstance(v, dict)
                and isinstance(v.get('deployment'), dict) and isinstance(v['deployment'].get('image'), dict)
                and v['deployment']['image'].get('repository') == 'dserio83/' + product]
    assert matching, product
    image = matching[0]
    add(product, image['registry'] + '/' + image['repository'] + ':' + image['tag'], 'vui 1.0.6 upstream values.yaml', 'cached upstream default; full render not revalidated')
tk = yaml(pathlib.Path('/workspace/.cache/cve-audit/testkube-artifacts/minio/helm/values.yaml'))['image']
add('testkube-minio', tk['registry'] + '/' + tk['repository'] + ':' + tk['tag'], 'Testkube thirdparty MinIO values.yaml; matches recovered Testkube 2.14.1 inventory', 'cached upstream default; full render not revalidated')


def remote(image):
    if image.startswith('docker.io/'):
        return 'registry-1.docker.io/' + image[len('docker.io/'):]
    if '/' not in image:
        return 'registry-1.docker.io/library/' + image
    if '.' not in image.split('/')[0]:
        return 'registry-1.docker.io/' + image
    return image


def scan(row, backend='remote'):
    key = hashlib.sha256(row['image'].encode()).hexdigest()[:16] + ('-docker' if backend == 'docker' else '')
    report = OUT / 'images' / (key + '.json')
    log = OUT / 'images' / (key + '.log')
    report.unlink(missing_ok=True)
    command = [TRIVY, 'image', '--cache-dir', str(CACHE), '--cache-backend', 'memory',
               '--skip-db-update', '--skip-java-db-update', '--image-src', backend,
               '--scanners', 'vuln', '--severity', 'HIGH,CRITICAL', '--timeout', '4m',
               '--format', 'json', '--output', str(report), remote(row['image']) if backend == 'remote' else row['image']]
    with log.open('w') as stream:
        try:
            completed = subprocess.run(command, stdout=stream, stderr=stream, timeout=260)
            code = completed.returncode
        except subprocess.TimeoutExpired:
            code = 'TIMEOUT'
    result = row | dict(image_source=backend, status='UNVERIFIED', critical='UNVERIFIED', high='UNVERIFIED',
                        unfixed_ids='UNVERIFIED', digest='UNVERIFIED', exit_code=code,
                        report=str(report.relative_to(ROOT)) if report.exists() else '', log=str(log.relative_to(ROOT)))
    if code == 0 and report.exists():
        j = json.loads(report.read_text())
        vulns = [v for r in j.get('Results', []) for v in r.get('Vulnerabilities', [])]
        result.update(status='SCANNED', critical=len({v['VulnerabilityID'] for v in vulns if v['Severity'] == 'CRITICAL'}),
                      high=len({v['VulnerabilityID'] for v in vulns if v['Severity'] == 'HIGH'}),
                      unfixed_ids=len({v['VulnerabilityID'] for v in vulns if not v.get('FixedVersion')}),
                      digest=';'.join(j.get('Metadata', {}).get('RepoDigests', [])))
    print(row['product'], result['status'], result['critical'], result['high'], flush=True)
    return result


if __name__ == '__main__':
    (OUT / 'images').mkdir(exist_ok=True)
    write_tsv('inventory.tsv', inventory)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(scan, inventory))
    if '--docker-fallback' in sys.argv:
        for i, result in enumerate(results):
            if result['status'] == 'SCANNED':
                continue
            pull_log = OUT / 'images' / (result['product'] + '-docker-pull.log')
            with pull_log.open('w') as f:
                try:
                    pulled = subprocess.run(['docker', 'pull', result['image']], stdout=f, stderr=f, timeout=180)
                except subprocess.TimeoutExpired:
                    continue
            if pulled.returncode == 0:
                results[i] = scan(inventory[i], 'docker')
    write_tsv('summary.tsv', results)
