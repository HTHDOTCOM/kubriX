# Fresh scan of selected main images — October 15, 2026

Source main commit: `927d0ddc533cce786fe1cd93462e8e30fee7a9a6`. Scanner: Trivy 0.76.0. **18/18 selected images successfully scanned**. This covers the updated versions discussed in the conversation and the principal outstanding custom/Falco images; it is not a full rescan of all platform images or a live cluster inventory.

## Results

| Product / component | Image | CRITICAL | HIGH | Unfixed IDs |
|---|---|---:|---:|---:|
| keycloak-operator | `quay.io/keycloak/keycloak-operator:26.7.5` | 0 | 3 | 0 |
| keycloak | `quay.io/keycloak/keycloak:26.7.5` | 0 | 4 | 0 |
| metallb-frr | `quay.io/frrouting/frr:10.4.5` | 0 | 9 | 0 |
| kubecost-prometheus | `quay.io/prometheus/prometheus:v3.13.4` | 0 | 4 | 0 |
| testkube-nats | `nats:2.15.1-alpine` | 0 | 0 | 0 |
| velero | `docker.io/velero/velero:v1.18.4` | 0 | 4 | 0 |
| velero-aws-plugin | `velero/velero-plugin-for-aws:v1.14.4` | 0 | 3 | 0 |
| silo-minio-loki-mimir | `docker.io/pgsty/silo:RELEASE.2026-09-16T00-00-00Z` | 0 | 7 | 1 |
| falcoctl | `docker.io/falcosecurity/falcoctl:0.14.2` | 0 | 5 | 2 |
| falcosidekick | `docker.io/falcosecurity/falcosidekick:2.35.0` | 3 | 14 | 0 |
| falcosidekick-ui | `docker.io/falcosecurity/falcosidekick-ui:2.3.1` | 0 | 20 | 0 |
| falco-exporter | `docker.io/falcosecurity/falco-exporter:0.8.7` | 5 | 54 | 0 |
| falco | `docker.io/falcosecurity/falco:0.43.1` | 1 | 13 | 0 |
| backstage | `ghcr.io/suxess-it/sx-backstage:v1.51.2` | 26 | 108 | 3 |
| velero-api | `docker.io/dserio83/velero-api:0.3.1` | 11 | 124 | 26 |
| velero-ui | `docker.io/dserio83/velero-ui:0.3.1` | 5 | 81 | 2 |
| velero-watchdog | `docker.io/dserio83/velero-watchdog:0.1.8` | 10 | 80 | 24 |
| testkube-minio | `docker.io/kubeshop/testkube-minio:2025.10` | 10 | 91 | 24 |

Across this selected set: 389 distinct vulnerability IDs, assigning each ID its highest severity (50 CRITICAL / 339 HIGH). Per-image counts overlap and must not be summed as globally unique CVEs. Unfixed IDs means vulnerabilities with an empty Trivy FixedVersion, not vulnerabilities hidden from the scan.

## Method and evidence

- Used the fresh DB updated `2026-10-15T07:10:08Z` and Java DB updated `2026-10-15T00:58:48Z`. Metadata and hashes are retained under `evidence/`. Both DBs were frozen during all scans with `--skip-db-update --skip-java-db-update`.
- Flags: `--scanners vuln --severity HIGH,CRITICAL --format json --cache-backend memory`. No `--ignore-unfixed`, ignore list, or disabled vulnerability assertion was used. All findings and unfixed findings are separately exported.
- Four remote-source scans failed with unexpected EOF while reading Quay layers. Docker successfully pulled the exact configured tags, verified their layers, and Trivy scanned the local images using `--image-src docker`. Initial failure logs and successful fallback logs are retained. Other scans used `--image-src remote` through the official Docker Hub registry endpoint where appropriate. Artifact acquisition changed; vulnerability settings and DB snapshot did not.
- Successful reports record immutable image digests and exit status zero. Image tags reflect this scan time and may be mutable. Only redundant Results[].Packages arrays were omitted from retained JSON after checking complete vulnerability-object equality. Raw reports remain in `/workspace/.cache/current-main-scan/raw-reports`, with both hashes recorded.
- Configuration is read from an external archive of fetched main. Explicit overrides are traced in inventory.tsv. Cached upstream defaults are separately labeled for Falco, Velero UI and Testkube MinIO. These defaults match the recovered locked chart inventories, but full dependency rendering was not revalidated: the MetalLB chart repository returned Forbidden. Keycloak server image is the operator configured related image, not a directly rendered Deployment.
- These are amd64 image vulnerability scans, not Kubernetes, kernel/BPF, service, storage migration or rollback tests. No deployment or application configuration was changed. Results do not establish which images are running in a cluster.
- Historical before/after reports remain unchanged. Do not subtract their old-DB counts from these new-DB results to claim exact remediation reductions.

## Reproduce

The retained scan.py reads the main chart snapshot under `/workspace/.cache/current-main-scan/chart-source`, cached upstream chart defaults, and the installed Trivy binary. Run `PYTHONDONTWRITEBYTECODE=1 python3 reports/current-main-2026-10-15/scan.py --docker-fallback` after installing/fetching these prerequisites and freezing the recorded databases. It scans public images only and does not run application containers or deploy charts.

## Validation

Checked all 18 expected results, exit statuses, nonempty image digests, and CRITICAL/HIGH distinct-ID counts against JSON. Exported every reported package finding, including every finding without a fixed version. Retained JSON integrity hashes are checked separately.
