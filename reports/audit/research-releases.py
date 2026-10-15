#!/usr/bin/env python3
"""Capture official release feeds; availability alone does not prove CVE fixes."""
import concurrent.futures
import csv
import datetime
import json
import pathlib
import subprocess
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / 'reports/audit/upstream'
OUT.mkdir(parents=True, exist_ok=True)
cutoff = datetime.datetime(2026, 10, 14, 23, 59, 59, tzinfo=datetime.timezone.utc)
overrides = {
    'suxess-it/sx-backstage': 'suxess-it/backstage',
    'dserio83/velero-api': 'seriohub/velero-api',
    'dserio83/velero-ui': 'seriohub/velero-ui',
    'dserio83/velero-watchdog': 'seriohub/velero-watchdog',
    'falcosecurity/falcoctl': 'falcosecurity/falcoctl',
    'falcosecurity/falcosidekick-ui': 'falcosecurity/falcosidekick-ui',
    'falcosecurity/falcosidekick': 'falcosecurity/falcosidekick',
    'falcosecurity/falco-exporter': 'falcosecurity/falco-exporter',
    'grafana/loki': 'grafana/loki',
    'grafana/tempo': 'grafana/tempo',
    'velero/velero:': 'vmware-tanzu/velero',
    'kubevirt/cdi-operator': 'kubevirt/containerized-data-importer',
    'kubevirt/virt-operator': 'kubevirt/kubevirt',
    'kubevirt/kubevirt-velero-plugin': 'kubevirt/kubevirt-velero-plugin',
    'kubevirtmanager/kubevirt-manager': 'kubevirt-manager/kubevirt-manager',
    'keycloak/keycloak-operator': 'keycloak/keycloak',
    'kyverno/': 'kyverno/kyverno',
    'external-secrets/': 'external-secrets/external-secrets',
    'akuity/kargo': 'akuity/kargo',
    'argoproj/argo-rollouts': 'argoproj/argo-rollouts',
    'frrouting/frr': 'FRRouting/frr',
    'prom/memcached-exporter': 'prometheus/memcached_exporter',
    'natsio/nats-server-config-reloader': 'nats-io/nats-server-config-reloader',
    'redis/redis-stack': 'redis-stack/redis-stack',
    'docker/library/redis': 'redis/redis',
    'library/memcached': 'memcached/memcached',
    'kube-state-metrics': 'kubernetes/kube-state-metrics',
    'appropriate/curl': 'appropriate/docker-curl',
    'alpine:': 'alpinelinux/docker-alpine',
    'busybox': 'docker-library/busybox',
}
products = []
for r in csv.DictReader((ROOT / 'reports/before/images.tsv').open(), delimiter='\t'):
    j = json.loads((ROOT / r['report']).read_text())
    labels = j.get('Metadata', {}).get('ImageConfig', {}).get('config', {}).get('Labels', {}) or {}
    source = labels.get('org.opencontainers.image.source', '')
    repo = '/'.join(source.removeprefix('https://github.com/').split('/')[:2]) if source.startswith('https://github.com/') else ''
    for needle, replacement in overrides.items():
        if needle in r['image']:
            repo = replacement
            break
    if repo.startswith('chainguard-images/'):
        repo = ''  # Inherited base-image metadata is not application source.
    products.append((r['image'], repo))


def fetch(repo):
    path = OUT / (repo.replace('/', '--') + '.atom')
    url = 'https://github.com/' + repo + '/releases.atom'
    result = subprocess.run(['curl', '-fsSL', '--max-time', '30', url, '-o', str(path)],
                            capture_output=True, text=True)
    if result.returncode and not path.exists():
        return repo, [('UNVERIFIED', '', '', url, result.stderr.strip())]
    ns = {'a': 'http://www.w3.org/2005/Atom'}
    entries = []
    for e in ET.parse(path).getroot().findall('a:entry', ns):
        link = e.find('a:link', ns).attrib['href']
        date = e.findtext('a:updated', '', ns)
        if datetime.datetime.fromisoformat(date.replace('Z', '+00:00')) <= cutoff:
            entries.append(('AVAILABLE_NOT_FIX_VERIFIED', link.rsplit('/', 1)[-1], date,
                            link, e.findtext('a:title', '', ns) + (' [cached successful fetch from this audit; refresh failed]' if result.returncode else '')))
    return repo, entries or [('UNVERIFIED', '', '', url, 'No release in bounded feed')]


if __name__ == '__main__':
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        releases = dict(pool.map(fetch, sorted({repo for _, repo in products if repo})))
    with (ROOT / 'reports/audit/upstream-releases.tsv').open('w') as stream:
        w = csv.writer(stream, delimiter='\t', lineterminator='\n')
        w.writerow(['image', 'upstream_repository', 'status', 'release_tag', 'release_date', 'official_url', 'title_or_error'])
        for image, repo in products:
            for row in releases.get(repo, [('UNVERIFIED', '', '', '', 'Application source not established')]):
                w.writerow([image, repo, *row])
