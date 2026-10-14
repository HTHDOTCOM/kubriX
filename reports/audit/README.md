# CVE remediation audit — 2026-10-14

Branch: `audit-cve-remediation-2026-10-14`, based on fetched `main` commit
`58811e60fafa9573d432be14e62868beb5ce68c2`.

## Scope and evidence

`reports/cve-per-product.tsv` is absent from fetched main and local history.
The recovered `reports/before/images.tsv` contains 86 images: **81 with HIGH or
CRITICAL findings and five clean controls**. `reconstructed-cve-per-product.tsv`
records the 81 vulnerable rows without inventing the missing report's contents.
Product labels are image repositories, not a verified copy of the missing TSV's
product names. The three requested deliverables each cover those 81 images;
the unfixed table instead contains individual package findings.

Original JSON exists for every baseline image. There are 3,598 original package
findings and 120 CRITICAL / 1,734 HIGH image-level distinct-ID counts. An ID can
occur in several packages or images: these are not globally unique CVE totals.
Original reports contain HIGH/CRITICAL only; lower severities cannot be recovered
from these files. All full identifiers, package versions, fixed-version strings,
status, severity source, advisory source, target and digests are preserved in
`cve-findings.tsv`. Empty fixed versions remain empty, not “fixed.”

`image-references.tsv` associates all 86 images with their recovered chart image
lists, literal configuration matches and rendered Argo CD Application sources.
Literal substring matches are investigation leads, not proof of a deployed
override. Several images come exclusively from locked upstream chart templates;
their exact template location remains UNVERIFIED when dependencies cannot be
retrieved. `argo-applications.tsv` records 113 Applications rendered across seven
bootstrap profiles, including inherited values. Image-producing Dockerfiles are
generally outside this GitOps repository. Its installer Dockerfile is not the
build source of every platform image.

## Scan method and comparison limits

Trivy **0.76.0** was downloaded from its official release and SHA256 verified.
Flags match the documented baseline: `--image-src remote --scanners vuln
--severity HIGH,CRITICAL --format json`. **No `--ignore-unfixed` was used.**
`--skip-db-update --skip-java-db-update` freeze the newly downloaded databases
during comparisons. `--cache-backend memory` avoids concurrent filesystem-cache
locks; three scans run concurrently. EOF failures were retried sequentially with
`--parallel 1`; failed retries remain failures. Scan scripts, exit statuses and
logs are included, and every successful result retains image digest metadata.
Unqualified Docker Hub names are normalized to its official
`registry-1.docker.io` endpoint; the original identity is retained separately.

The original vulnerability database snapshot and its metadata were not retained
in this checkout. Exact baseline-snapshot rescanning is therefore **UNAVAILABLE**.
The latest DB was updated at `2026-10-14T13:10:32Z`; metadata and database hashes
are in `evidence/`. Original immutable digests were rescanned against this same
latest snapshot before calculating replacement differences. Before/after rows
explicitly distinguish original counts from latest-baseline counts. Historical
`reports/after` results were not substituted for failed fresh scans.

“CVEs eliminated” means IDs no longer reported at HIGH/CRITICAL in the successful
same-database candidate scan. This is scanner evidence within the baseline's
scope, not proof that every vulnerability severity or attack path is eliminated.
Introduced IDs are reported separately. Remaining counts describe the scanned
candidate, not the production deployment. A successful scan is not application,
migration or rollback validation. Blank ID lists mean an empty verified set;
`UNVERIFIED` means the comparison was unavailable. Products without a verified
replacement retain UNVERIFIED replacement/remaining fields.

Full new reports were retained locally under
`/workspace/.cache/cve-audit/raw-reports`. Committed copies omit only redundant
`Results[].Packages`; equality of all vulnerability objects was checked before
removal. `scan-report-integrity.tsv` records both hashes. Existing baseline
reports were not changed. `cve-unfixed.tsv` includes original, latest-baseline and
latest-configured phases; rows with no fixed version are not filtered out.

## Prioritized Git / Helm changes

| Priority | Proposed change | Evidence and validation required |
|---|---|---|
| 1 | Rebuild `sx-backstage:v1.51.2`, then update `platform-apps/charts/backstage/values-kubrix-default.yaml` to its tested immutable digest | 26 CRITICAL / 108 HIGH in the custom image. Patch the application dependency graph as well as the base image; a base-only rebuild cannot fix bundled npm modules. Trivy identifies `vm2` 3.11.6 → 3.11.7 and multiple Undici and Backstage package fixes. The exact custom-image source commit/build pipeline is unverified: inherited Wolfi OCI labels are not application provenance. The discovered `suxess-it/backstage` master Dockerfile uses Node 18/Debian and does not establish provenance for this Wolfi-based image. Require plugin, authentication, catalog, scaffolder, TechDocs and PostgreSQL migration/restore tests. No fabricated replacement tag. |
| 2 | Rebuild or upgrade the three SerioHub Velero UI images as a coordinated release; update the `vui` wrapper only after API compatibility tests | Original API/UI/watchdog counts are 11/124, 5/81 and 10/80 CRITICAL/HIGH. `next` 15.2.3 includes known-exploited CVE-2025-55182; git includes known-exploited CVE-2025-48384. Validate whether the Next.js server exposes the affected React Server Components path, and whether untrusted repositories/submodules reach git. These are not automatically unreachable because ingress is authenticated. Upstream chart sources identify `seriohub/velero-api`, `seriohub/velero-ui`, `seriohub/velero-watchdog`; `otwld/velero-ui` is a different product and must not be substituted. Source retrieval failed with proxy 503s. Require list/backup/restore, RBAC, auth, watchdog and API/UI contract tests. |
| 3 | Rebuild Testkube's existing Bitnami-compatible MinIO image, or migrate its storage dependency with a coordinated chart change | 10 CRITICAL / 91 HIGH. Official `kubeshop/testkube-thirdparty-artifacts` supplies a multi-stage MinIO build and Bitnami initialization scripts. Its inspected builder/dependencies still require the Trivy-reported patches; the same mutable `2025.10` tag is not proof of a rebuild. SILO/SeaweedFS are not direct image-tag substitutions: verify scripts, `/opt/bitnami` layout, env translation, UID, probes, PVC paths, credentials and bucket provisioning. Test S3 signatures, multipart uploads, Testkube artifact upload/download, retention, snapshot restore and rollback on copied data. No production PVC should be used for this validation. |
| 4 | Retire Falco Exporter; migrate dashboards/alerts/event metrics, then upgrade Falco with the matching chart | Official README and chart explicitly deprecate the exporter. Falco 0.38+ offers native metrics, but event counters and alert semantics require comparison. Falco 0.44 removes gRPC output/server; current values enable gRPC and exporter socket access. Official feed shows stable 0.45.0, but that image was not validated and is not a safe independent tag bump. Test modern-BPF driver/kernel support, event delivery, rule loading, sidekick output, dashboard queries and alert behavior. |
| 5 | Replace hardcoded `appropriate/curl` in Falcosidekick's Helm test hook through a supported upstream chart/template change | 11 CRITICAL / 3 HIGH → zero in digest-pinned `curlimages/curl@sha256:a134550be58ab783810e613ae96fd253c38f7bdd16d9bf9be350700c7a29ac06`, against the same latest DB. Exact source: Falco 8.0.5 → Falcosidekick 0.12.1 → `templates/tests/test-connection.yaml`. It executes `curl -X POST SERVICE:2801/ping`; the image is hardcoded and has no tested values override. This is a Helm test Pod, not an always-running public service. Docker command-compatibility validation failed before execution because the image pull returned 503; no replacement is applied. |
| 6 | Retain, then digest-pin the already bumped Falco components after runtime and multi-architecture verification | Fresh latest-DB results: falcoctl 0.14.2 = 0/5, sidekick-ui 2.3.1 = 0/20, sidekick 2.35.0 = 3/14, exporter 0.8.7 = 5/54 CRITICAL/HIGH. They reduce findings but do not justify “CVE-free” claims. Official release feeds verify availability of the component releases; exporter 0.8.7 dates to 2024 and remains deprecated. Immutable candidate digests are recorded. Current wrapper renders/lints successfully; that does not establish running compatibility. |
| 7 | Validate the existing SILO 2026-09-16 upgrade and pin a verified architecture-compatible digest in MinIO, Loki and Mimir values | Original 3/14 → latest candidate 0/7. Official release notes identify security/correctness changes and immutable source commit `2a4d51406b7ed87af5fe6fe0f801f3290f96eb3c`. Seven HIGH findings remain. Test standalone/distributed configuration actually used, IAM revocation, object integrity, presigned/SSE/multipart behavior and all consumers. Verify down-version rollback on a storage snapshot rather than assume on-disk compatibility. |
| 8 | Validate the existing Velero/AWS-plugin bumps together, then pin digests | Velero v1.18.4 rescans at 0/4 rather than original 0/20. AWS-plugin candidate fresh scanning was blocked, so its historical improvement is not counted as verified. Require Kubernetes API compatibility, plugin/server version matrix, backup/restore of Kubernetes resources, volume restore and rollback to the previous server/plugins using copies of backup metadata. |

The remaining products each have a row in the plan. Official bounded release feeds
are captured in `upstream-releases.tsv` and `upstream/`; release availability alone
is never presented as a fix. Missing sources, empty release feeds and blocked
research are UNVERIFIED. Do not treat a base-image OCI source label as the source
of the application binary. `package-patch-targets.tsv` retains complete fixed
version alternatives from Trivy rather than choosing an unsupported branch.

## Unfixed findings and interim mitigation

Restrict ingress to administrative services, require authentication, limit
service-account privileges and restrict unnecessary egress while rebuilds are
pending. For privileged Falco, networking and backup components, validate the
specific required privileges before removing them. For Backstage, isolate
scaffolder execution and review untrusted template/plugin access. For Velero UI,
restrict ingress and audit the affected RSC/git execution paths. Avoid invoking
obsolete Helm test images until replaced. These measures reduce exposure;
**none is counted as eliminating a CVE**. Findings without patches remain in
`cve-unfixed.tsv`; version-looking strings are not proof of deployability.

CISA KEV matches were taken from its official GitHub catalog, bounded to additions
on/before 2026-10-14. The relevant records are retained in `evidence/kev-matches.json`.
`NO_MATCH` means no match in that catalog snapshot, not absence of exploitation.

## Tests, limitations and branch contents

- Passed: existing target compatibility/layering/exclusion/profile tests;
  current Falco wrapper lint and render with its exact chart dependencies;
  113 Argo Application renders across seven profiles; report count/ID integrity.
- Successful latest scans: 53 baseline digests and nine previously configured
  replacements, plus the curl candidate. Thirty-three baseline and six configured
  scans failed; failure logs and statuses remain available.
- Blocked: Kubernetes compatibility, real service integration, kernel/BPF,
  storage migrations and rollback. There is no configured Kubernetes context.
  The Docker curl functional request was blocked by registry 503 before the test
  ran. No container PID or zero-test result is treated as validation.
- Registry access needed: `icr.io`, `reg.kyverno.io`, `registry.k8s.io`,
  `xpkg.crossplane.io`, `mirror.gcr.io`, `ecr-public.aws.com`, and Testkube's
  `us-east1-docker.pkg.dev`. These domain additions were saved in the environment
  draft without changing installation/startup instructions. Review/save settings
  to apply them; publication is separate. Quay and some already-allowed GitHub /
  Docker endpoints returned transport 503s or incomplete layers, so allowlist edits
  alone may not resolve those errors. No credentials were requested or invented.

**No deployment upgrade is applied or committed.** The branch contains audit
deliverables and evidence only. Scan-positive candidates remain UNVERIFIED for
deployment until compatibility/migration/rollback gates pass and changes receive
review. This is a usable audit with explicit blockers, not a completed production
remediation or a claim that all 81 products are patched.

To regenerate with the installed tools, from `/workspace/kubriX` run
`python3 reports/audit/scan-images.py`, then
`python3 reports/audit/research-releases.py` and
`PYTHONDONTWRITEBYTECODE=1 python3 reports/audit/build-reports.py`.
The scripts require the Trivy installation/cache paths documented above and the
retained Argo Application mapping; they do not deploy anything or write lockfiles.
Re-running release research can use the successful official feed captured earlier
in this audit when a refresh fails, and explicitly labels that cached evidence.
