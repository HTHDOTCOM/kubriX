#!/usr/bin/env python3
"""Generate traceable provisional audit tables without assuming patched images."""
import csv
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys
from collections import defaultdict

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(pathlib.Path(__file__).parent))
spec = importlib.util.spec_from_file_location('audit_scanner', pathlib.Path(__file__).with_name('scan-images.py'))
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)
bumps = scanner.bumps


def read_tsv(path):
    return list(csv.DictReader((ROOT / path).open(), delimiter='\t'))


def write_tsv(path, fields, rows):
    with (ROOT / path).open('w') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, delimiter='\t', lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)


def findings(j):
    return [(r, v) for r in j.get('Results', []) for v in r.get('Vulnerabilities', [])]


def ids(j, severity=None):
    return {v['VulnerabilityID'] for _, v in findings(j) if not severity or v['Severity'] == severity}


def digest(j):
    return ';'.join(j.get('Metadata', {}).get('RepoDigests', [])) or 'UNVERIFIED'


baseline = read_tsv('reports/before/images.tsv')
scans = {(r['kind'], r['baseline_image']): r for r in read_tsv('reports/audit/latest/scans.tsv')}
applications = read_tsv('reports/audit/argo-applications.tsv')
releases = defaultdict(list)
for r in read_tsv('reports/audit/upstream-releases.tsv'):
    releases[r['image']].append(r)
chart_images = defaultdict(list)
for path in (ROOT / 'reports/before').glob('*.images.txt'):
    for image in path.read_text().splitlines():
        chart_images[image].append(path.name.removesuffix('.images.txt'))
files = subprocess.check_output(['git', 'ls-files'], cwd=ROOT, text=True).splitlines()
config = {}
for name in files:
    if name.startswith(('reports/', 'trivy-scan-reports/', 'image-list/', 'kubeconform-schemas/', 'helm-chart-list/')):
        continue
    if pathlib.Path(name).suffix in {'.yaml', '.yml', '.tmpl', '.sh'} or 'Dockerfile' in name:
        try:
            config[name] = (ROOT / name).read_text().splitlines()
        except UnicodeDecodeError:
            continue
kev_path = pathlib.Path('/workspace/.cache/cve-audit/upstream/kev.json')
kev = {v['cveID'] for v in json.loads(kev_path.read_text()).get('vulnerabilities', [])
       if v.get('dateAdded', '9999') <= '2026-10-14'} if kev_path.exists() else None
all_findings, unfixed, plan, comparison, refs = [], [], [], [], []
for row in baseline:
    image = row['image']
    j = json.loads((ROOT / row['report']).read_text())
    assert len(ids(j, 'CRITICAL')) == int(row['critical']), image
    assert len(ids(j, 'HIGH')) == int(row['high']), image
    charts = chart_images[image]
    repo = image.split('@')[0].rsplit(':', 1)[0] if ':' in image.split('/')[-1] else image
    short = repo.removeprefix('docker.io/')
    locations = []
    for filename, lines in config.items():
        for number, line in enumerate(lines, 1):
            if image in line or repo in line or (len(short) > 6 and short in line):
                locations.append(f'{filename}:{number}')
    for chart in charts:
        if chart != 'target-chart':
            locations.append(f'platform-apps/charts/{chart}/Chart.yaml (locked upstream default if no direct override)')
    # Applications are dynamically rendered from target chart profiles; no standalone image override.
    argo = [f"{a['bootstrap_manifest']} -> {a['template']} -> {a['application']}"
            for a in applications if a['chart_path'] in [f'platform-apps/charts/{c}' for c in charts]]
    refs.append(dict(image=image, charts=';'.join(charts), configuration_references=';'.join(sorted(set(locations))),
                     argo_application_sources=';'.join(sorted(set(argo))),
                     dockerfile='NOT_IN_THIS_REPOSITORY' if not any('Dockerfile' in loc for loc in locations) else ';'.join(loc for loc in locations if 'Dockerfile' in loc),
                     mapping_status='UPSTREAM_TEMPLATE_REQUIRES_INSPECTION' if not locations else 'CHART_MEMBERSHIP_VERIFIED;LINE_MATCHES_REQUIRE_CONTEXT'))
    for phase, scan_j, report in [('original', j, row['report'])]:
        for result, v in findings(scan_j):
            source = v.get('DataSource', {})
            entry = dict(product=short, charts=';'.join(charts), phase=phase, image=image,
                         image_digest=digest(scan_j), artifact_id=scan_j.get('ArtifactID', ''),
                         vulnerability_id=v['VulnerabilityID'], package=v['PkgName'],
                         installed_version=v.get('InstalledVersion', ''), fixed_version=v.get('FixedVersion', ''),
                         severity=v['Severity'], status=v.get('Status', 'UNKNOWN'),
                         severity_source=v.get('SeveritySource', ''), advisory_source=source.get('ID', ''),
                         advisory_source_url=source.get('URL', ''), primary_url=v.get('PrimaryURL', ''),
                         target=result.get('Target', ''), package_type=result.get('Type', ''),
                         known_exploited=('YES' if v['VulnerabilityID'] in kev else 'NO_MATCH') if kev is not None else 'UNVERIFIED', report=report)
            all_findings.append(entry)
            if not v.get('FixedVersion'):
                unfixed.append(entry)
    old_latest = scans.get(('baseline', image))
    candidate = scans.get(('configured', image))
    latest_j = json.loads((ROOT / old_latest['report']).read_text()) if old_latest and old_latest['status'] == 'OK' else None
    new_j = json.loads((ROOT / candidate['report']).read_text()) if candidate and candidate['status'] == 'OK' else None
    current = bumps.get(image, image)
    proposed = digest(new_j) if new_j else 'UNVERIFIED'
    recommendation = 'UNVERIFIED: no fixed replacement and compatibility evidence'
    action = 'INVESTIGATE'
    risk = 'UNVERIFIED: image/chart/runtime compatibility not tested'
    if 'sx-backstage' in image or 'dserio83/' in image:
        action = 'REBUILD_CUSTOM_IMAGE'
        risk = 'HIGH: plugins/API/authentication and database schema; exact build source not established'
    elif image == 'appropriate/curl':
        action = 'REPLACE_OBSOLETE_IMAGE'
        proposed = 'curlimages/curl@sha256:a134550be58ab783810e613ae96fd253c38f7bdd16d9bf9be350700c7a29ac06'
        new_j = json.loads((ROOT / 'reports/audit/latest/curl-replacement.json').read_text())
        risk = 'LOW runtime; hook image hardcoded in locked Falcosidekick template, requires supported chart change'
        recommendation = 'SCAN_VERIFIED; hook command compatibility validation pending; test-only exposure'
    elif 'falco-exporter' in image:
        action = 'RETIRE_DEPRECATED_IMAGE'
        risk = 'HIGH: replace event metrics/dashboards/alerts; native metrics are not automatically equivalent'
    elif 'testkube-minio' in image:
        action = 'REBUILD_OR_MIGRATE_STORAGE'
        risk = 'HIGH: Bitnami scripts/env/UID/paths/provisioning; SILO or SeaweedFS is not a tag-only replacement'
    elif 'pgsty/silo' in image:
        action = 'VERIFY_EXISTING_UPGRADE'
        risk = 'HIGH: persistent object data/IAM/replication; snapshot, restore, rollback required'
    elif image in bumps:
        action = 'VERIFY_EXISTING_UPGRADE'
    known = sum(1 for cve in ids(j) if kev and cve in kev)
    privilege = 'HOST_PRIVILEGES' if any(c in charts for c in ['falco', 'metallb', 'kubevirt', 'velero']) else 'UNVERIFIED'
    exposure = 'INGRESS_CONFIGURED_RUNTIME_UNVERIFIED' if any(c in charts for c in ['backstage', 'velero-ui', 'grafana', 'keycloak', 'argocd', 'testkube']) else 'UNVERIFIED'
    release_urls = ';'.join(r['official_url'] for r in releases[image] if r['status'] == 'AVAILABLE_NOT_FIX_VERIFIED')
    eliminated = sorted(ids(latest_j) - ids(new_j)) if latest_j is not None and new_j is not None else None
    introduced = sorted(ids(new_j) - ids(latest_j)) if latest_j is not None and new_j is not None else None
    if new_j is not None and image != 'appropriate/curl':
        recommendation = 'SCAN_VERIFIED; deployment compatibility/migration/rollback UNVERIFIED; remaining findings retained'
    plan.append(dict(product=short, baseline_image=image, current_image=current, proposed_image=proposed,
                     original_critical=row['critical'], original_high=row['high'], known_exploited=known if kev is not None else 'UNVERIFIED',
                     privileges=privilege, exposure=exposure, remediation=action, status='UNVERIFIED',
                     recommendation=recommendation, breaking_change_risk=risk, charts=';'.join(charts),
                     configuration_references=';'.join(sorted(set(locations))), official_release_evidence=release_urls or 'UNVERIFIED',
                     baseline_db_snapshot='UNAVAILABLE', latest_baseline_scan=old_latest['status'] if old_latest else 'UNRUN',
                     latest_candidate_scan=candidate['status'] if candidate else ('OK' if image == 'appropriate/curl' else 'UNRUN')))
    comparison.append(dict(product=short, current_image=current, proposed_image=proposed,
                           original_critical=row['critical'], original_high=row['high'],
                           remaining_critical=len(ids(new_j, 'CRITICAL')) if new_j is not None else 'UNVERIFIED',
                           remaining_high=len(ids(new_j, 'HIGH')) if new_j is not None else 'UNVERIFIED',
                           cves_eliminated=';'.join(eliminated) if eliminated is not None else 'UNVERIFIED',
                           breaking_change_risk=risk, recommendation=recommendation,
                           baseline_image=image, latest_baseline_critical=len(ids(latest_j, 'CRITICAL')) if latest_j is not None else 'UNVERIFIED',
                           latest_baseline_high=len(ids(latest_j, 'HIGH')) if latest_j is not None else 'UNVERIFIED',
                           introduced_cves=';'.join(introduced) if introduced is not None else 'UNVERIFIED',
                           comparison_basis='LATEST_DB_SAME_SNAPSHOT' if eliminated is not None else 'UNVERIFIED',
                           eliminated_count=len(eliminated) if eliminated is not None else 'UNVERIFIED'))
for scan in scans.values():
    if scan['status'] != 'OK':
        continue
    scan_j = json.loads((ROOT / scan['report']).read_text())
    image = scan['baseline_image']
    for result, v in findings(scan_j):
        source = v.get('DataSource', {})
        entry = dict(product=image.rsplit(':', 1)[0], charts=';'.join(chart_images[image]),
                     phase='latest_' + scan['kind'], image=scan['scanned_image'],
                     image_digest=digest(scan_j), artifact_id=scan_j.get('ArtifactID', ''),
                     vulnerability_id=v['VulnerabilityID'], package=v['PkgName'],
                     installed_version=v.get('InstalledVersion', ''), fixed_version=v.get('FixedVersion', ''),
                     severity=v['Severity'], status=v.get('Status', 'UNKNOWN'),
                     severity_source=v.get('SeveritySource', ''), advisory_source=source.get('ID', ''),
                     advisory_source_url=source.get('URL', ''), primary_url=v.get('PrimaryURL', ''),
                     target=result.get('Target', ''), package_type=result.get('Type', ''),
                     known_exploited=('YES' if v['VulnerabilityID'] in kev else 'NO_MATCH') if kev is not None else 'UNVERIFIED',
                     report=scan['report'])
        all_findings.append(entry)
        if not v.get('FixedVersion'):
            unfixed.append(entry)
plan = [r for r in plan if int(r['original_critical']) + int(r['original_high']) > 0]
comparison = [r for r in comparison if int(r['original_critical']) + int(r['original_high']) > 0]
plan.sort(key=lambda r: (-int(r['original_critical']), -int(r['known_exploited'] or 0) if str(r['known_exploited']).isdigit() else 0,
                         0 if r['privileges'] == 'HOST_PRIVILEGES' else 1, -int(r['original_high'])))
for path, rows in [('reports/cve-remediation-plan.tsv', plan), ('reports/cve-before-after.tsv', comparison),
                   ('reports/cve-unfixed.tsv', unfixed), ('reports/audit/cve-findings.tsv', all_findings),
                   ('reports/audit/image-references.tsv', refs)]:
    write_tsv(path, list(rows[0]), rows)
targets = defaultdict(lambda: {'fixed': set(), 'ids': set(), 'severity': set()})
for r in all_findings:
    if r['phase'] != 'original':
        continue
    key = (r['image'], r['package'], r['installed_version'], r['package_type'])
    targets[key]['fixed'].add(r['fixed_version'] or 'UNFIXED')
    targets[key]['ids'].add(r['vulnerability_id'])
    targets[key]['severity'].add(r['severity'])
patch_rows = [dict(image=k[0], package=k[1], installed_version=k[2], package_type=k[3],
                   trivy_fixed_version_alternatives=';'.join(sorted(v['fixed'])),
                   vulnerability_ids=';'.join(sorted(v['ids'])), severities=';'.join(sorted(v['severity'])),
                   deployment_status='UNVERIFIED: patch target only; no rebuilt image validation')
              for k, v in sorted(targets.items())]
write_tsv('reports/audit/package-patch-targets.tsv', list(patch_rows[0]), patch_rows)
print(f'{len(plan)} images; {len(all_findings)} package findings across phases; {len(unfixed)} unfixed findings across phases')
