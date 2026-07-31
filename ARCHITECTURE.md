# 📘 kubriX - Comprehensive Architecture Documentation

## 📌 Executive Summary

**kubriX** is an **opinionated, modular, and enterprise-ready Internal Developer Platform (IDP)** for Kubernetes. It bundles best-in-class open-source tools (Argo CD, Backstage, Keycloak, Traefik, Grafana, OpenBao, Kargo, Kyverno, Trivy, Velero, etc.) into a pre-integrated, GitOps-driven stack — ready for production in minutes.

Built with **Helm charts**, **GitOps (Argo CD)**, **value-file overlays**, and **template-driven configuration**, kubriX enables teams to:
- Launch a secure, scalable IDP in minutes.
- Customize via environment-specific values (cluster type, cloud provider, HA, security strictness, etc.).
- Scale from kind/local → dev → prod with the same configuration pattern.
- Use CI/CD, compliance (Kyverno), observability (Grafana/Loki/Mimir), and secrets (OpenBao) out of the box.

It’s open source (**Apache 2.0**) with an enterprise variant called **kubriX Prime**.

---

## 🏗️ Architecture Overview

### High-Level Flow

```
bootstrap-app-kubrix-oss-stack.yaml → Argo CD → platform-apps/target-chart
                                      ↓
                      Helm renders all apps (with layered values)
                                      ↓
                    Argo CD deploys to cluster (synced, self-healing)
```

- **Bootstrap App (`bootstrap-app-*.yaml`)**: Argo CD `Application` CRD that points to `platform-apps/target-chart/` as its source.
- **Target Chart (`platform-apps/target-chart/`)**: Helm chart that generates `Application` CRDs for every platform brick (Argo CD, Backstage, Keycloak, etc.).
- **Platform Apps (`platform-apps/charts/*/`)**: Individual Helm charts for each platform brick (e.g., `argocd/`, `backstage/`, `grafana/`).

### Configuration Layers (Applied in Priority Order)

Values are layered (later overrides earlier):

1. `values-kubrix-default.yaml` — kubriX’s opinionated defaults.
2. `values-cluster-${clusterType}.yaml` — `kind`, `k8s`, etc.
3. `values-provider-${cloudProvider}.yaml` — `on-prem`, `aks`, `peak`, `metalstack`, `aws`, `azure`.
4. `values-ha-enabled.yaml` — HA-specific overrides (kubriX Prime only).
5. `values-size-${tShirtSize}.yaml` — `small`, `medium`, `large`, `xlarge`.
6. `values-security-strict.yaml` — hardened security settings (kubriX Prime).
7. `values-customer-generated.yaml` — template-generated (via `bootstrap/customer-config.yaml`).
8. `values-customer.yaml` — **manually** maintained customer overrides.

This design preserves kubriX defaults (for upgrades) while letting customers safely override only their environment specifics.

---

## 📁 Directory Structure

| Path | Purpose |
|------|---------|
| `platform-apps/charts/*/` | Helm wrapper charts for each platform brick (Argo CD, Backstage, Keycloak, etc.). Each has `Chart.yaml`, `values-*.yaml`, `templates/`, and optionally `dashboard-files/`. |
| `platform-apps/target-chart/` | Helm chart to generate Argo CD `Application` CRDs per stack type (`kubrix-oss-stack`, `kind-*`, `demo-metalstack`, etc.). Supports templated values files (`.yaml.tmpl`). |
| `bootstrap-app-*.yaml` | Argo CD Application manifests for bootstrap. Includes stack-specific versions (`kubrix-oss-stack`, `kind-base`, `kind-delivery`, `kind-observability`, `kind-portal`, `kind-security`, `demo-metalstack`, `peak`). |
| `bootstrap-argocd-values.yaml` | Helm values for installing bootstrap Argo CD (before GitOps takes over). |
| `install-platform.sh` | **Main installer** script (~1000 lines). Handles: tool checks, cluster setup (kind-specific DNS, CA), Argo CD bootstrap, OpenBao config, backstage tokens, wait loops, health checks, and error analysis. |
| `bootstrap/customer-config.yaml` | Customer template config (clusterType, dnsProvider, domain, gitRepo, metalLbIp, tShirtSize, haEnabled, securityStrict). Used by `bootstrap-template-downstream-repo()` to render `.yaml.tmpl` files via `gomplate`. |
| `backstage-resources/` | Backstage templates, documentation, and entity definitions (e.g., `templates/scaffolder-templates.yaml`, `docs/`). |
| `e2e-tests/playwright/` | Playwright e2e tests for Argo CD, Grafana, Keycloak, Kargo, OpenBao, Portal, etc. Uses `otpauth` for 2FA. Configured via `playwright.config.js` and `playwright.base.js`. |
| `image-list/`, `helm-chart-list/`, `trivy-scan-reports/` | Generated security/dependency inventory (not regenerated unless explicitly requested). |
| `kubeconform-schemas/` | Custom CRD schemas for Kubernetes validation. |
| `aws-resources/`, `metalstack-resources/` | Provider-specific assets (IAM policies, Terraform configs). |
| `.devcontainer/` | VS Code Devcontainer setup (Dockerfile, nodeport configs, kind-config.yaml). Supports quickstart dev environments for portal, delivery, security, observability, etc. |
| `.github/` | CI/CD workflows and helper scripts: `kubeconform.sh`, `kube-score.sh`, `create-trivy-scan-report.sh`, `create-helm-dependency-list.sh`, `create-pr-comment-file.sh`, `helm-template-all-apps-from-target-chart.sh`. |

---

## 🔐 Installation Flow (`install-platform.sh`)

### Prerequisites
| Env Var | Required? | Description |
|---------|----------|-------------|
| `KUBRIX_REPO` | ✅ | Git repo for GitOps (e.g., `github.com/org/repo`). |
| `KUBRIX_REPO_BRANCH` | ✅ | Branch for GitOps (default: `main`). |
| `KUBRIX_REPO_USERNAME` | ✅ | Git username for CLI auth. |
| `KUBRIX_REPO_PASSWORD` | ✅ | Git password (PAT) for CLI auth. |
| `KUBRIX_TARGET_TYPE` | ✅ | Stack profile (e.g., `kubrix-oss-stack`, `kind-delivery`). |
| `KUBRIX_CLUSTER_TYPE` | ✅ | Cluster type (`k8s`, `kind`). |
| `KUBRIX_BOOTSTRAP` | ❌ | If `true`, clones upstream and generates downstream repo (GitOps bootstrap). |
| `KUBRIX_BOOTSTRAP_MAX_WAIT_TIME` | ❌ | Max seconds to wait for apps (default: 2400). |
| `KUBRIX_DOMAIN` | (if bootstrap) | Base domain (e.g., `demo.kubrix.cloud`). |
| `KUBRIX_DNS_PROVIDER` | (if bootstrap) | DNS provider (`none`, `aws`, `ionos`, `stackit`, etc.). |
| `KUBRIX_CLOUD_PROVIDER` | (if bootstrap) | Cloud provider (`on-prem`, `aks`, `peak`, `metalstack`). |

### Steps

1. **Check Tools**: `yq`, `jq`, `kubectl`, `helm`, `curl`, `k8sgpt`, `gomplate`.
2. **Bootstrap (if `KUBRIX_BOOTSTRAP=true`)**:
   - Clone upstream repo (`https://github.com/suxess-it/kubriX`).
   - Template `*.yaml.tmpl` files using `gomplate` + `bootstrap/customer-config.yaml`.
   - Commit & push to downstream repo.
3. **Install Bootstrap Argo CD** (Helm):
   - `helm upgrade --install sx-argocd argo-cd ... --namespace argocd -f bootstrap-argocd-values.yaml`.
   - Add customer Git repo to Argo CD (via `argocd repo add` in pod).
4. **Generate Secrets** (`.secrets/createsecret.sh`) → produces `secrets.yaml`, `pushsecrets.yaml`.
5. **Apply Bootstrap App**: `kubectl apply -f bootstrap-app-${KUBRIX_TARGET_TYPE}.yaml`.
6. **Wait for Apps**: `wait_until_apps_synced_healthy()` loop (with health checks, auto-retry, and analysis).
   - Special handling for OpenBao (create group aliases), Backstage (secrets), K8s Monitoring (re-sync).
7. **Kind-Specific Fixes** (if `KUBRIX_CLUSTER_TYPE=kind`):
   - DNS rewrite in CoreDNS (`*.127-0-0-1.nip.io → sx-traefik.traefik.svc.cluster.local`).
   - Install root CA in all relevant namespaces (`cert-manager`, `backstage`, `openbao`, `cnpg`, `argocd`, `kargo`, `grafana`, `vault`, `external-secrets`, `testkube`).
   - Install `metrics-server`.
8. **Final Steps**:
   - Delete `pushsecrets.yaml` (secrets are now managed by OpenBao).
   - Print CA cert (for browser trust).

---

## 🔑 Values Files & Template System

### Why Templates?
To keep **kubriX defaults** upgradable while allowing **customer customization** without modifying upstream values.

### Template Files
- `values-*.yaml.tmpl` (e.g., `platform-apps/target-chart/values-kubrix-oss-stack.yaml.tmpl`, `backstage-resources/templates/*.yaml.tmpl`).
- Rendered via `bootstrap-template-downstream-repo()` using `gomplate`:

```bash
gomplate \
  --context kubriX=bootstrap/customer-config.yaml \
  --input-dir platform-apps \
  --include *.yaml.tmpl \
  --output-map='platform-apps/{{ .in | strings.ReplaceAll ".yaml.tmpl" ".yaml" }}'
```

### Example Template Snippet (`values-kubrix-oss-stack.yaml.tmpl`)
```yaml
default:
  valueFiles:
  - values-kubrix-default.yaml
  - values-cluster-{{ .kubriX.clusterType }}.yaml
  - values-provider-{{ .kubriX.cloudProvider }}.yaml
  {{ if .kubriX.haEnabled }}
  - values-ha-enabled.yaml
  {{ end -}}
  - values-size-{{ .kubriX.tShirtSize }}.yaml
  {{ if .kubriX.securityStrict }}
  - values-security-strict.yaml
  {{ end -}}
  - values-customer-generated.yaml
  - values-customer.yaml
```

### Generated Values: `values-customer-generated.yaml`
Contains customer-specific values (domain, dnsProvider, metalLbIp, gitRepo, etc.), generated during bootstrap.

---

## 🧩 Platform Bricks (Core Components)

### Argo CD (`platform-apps/charts/argocd/`)
- kubriX overrides:  
  - `server.insecure: true` (for local dev).
  - `application.namespaces: "adn-*"` (auto-namespace creation).
  - `resource.customizations` (health checks, ignore differences).
  - RBAC for Backstage (`p, backstage, applications, get, */*, allow`).
  - Argo Rollouts extension.

### Backstage (`platform-apps/charts/backstage/`)
- Git-based scaffolder templates.
- Vault-backed secrets (via `sx-cnp-secret`).
- OAuth2 GitHub (via OpenBao).
- CodeSpaces support (dynamic `APP_CONFIG_*` env vars).

### OpenBao (`platform-apps/charts/openbao/`)
- Root CA stored in `kubrix/` namespace.
- KV secret backend at `kubrix-kv/`.
- OIDC authentication.
- Group aliases (pre-created during bootstrap).
- PushSecrets (for syncing secrets to Kubernetes).

### Keycloak (`platform-apps/charts/keycloak/`)
- Demo users (`demoadmin`, `demoeditor`, `demoviewer`).
- OIDC provider for Argo CD, Grafana, Backstage, etc.

### Grafana / Loki / Mimir / Tempo
- Grafana: K8s dashboard folder (`kubriX`), RBAC.
- Loki: Log aggregation (CRD skip enabled).
- Mimir: Metrics (Prometheus-compatible).
- Tempo: Traces.

### Kyverno (`platform-apps/charts/kyverno/`)
- Policy enforcement (excluded in `kind` clusters by default).
- PolicyReports for audit.

### Velero (`platform-apps/charts/velero/`)
- Backup & restore (S3-compatible via MinIO).
- Excluded in `kind` clusters.

### Kargo (`platform-apps/charts/kargo/`)
- GitOps-based delivery engine.

### Trivy (`platform-apps/charts/trivy/`)
- Vulnerability scanning.

### MinIO (`platform-apps/charts/minio/`)
- S3-compatible storage for Velero, backups.

### MetalLB (`platform-apps/charts/metallb/`)
- Load balancer for `kind` clusters (IP range via `KUBRIX_METALLB_IP`).

### Testkube (`platform-apps/charts/testkube/`)
- Test automation engine.

### KubeVirt (`platform-apps/charts/kubevirt/`)
- VM management.

### Falco (`platform-apps/charts/falco/`)
- Runtime security monitoring (excluded in `kind` clusters).

### KubeCost (`platform-apps/charts/kubecost/`)
- Cost monitoring.

### External Secrets (`platform-apps/charts/external-secrets/`)
- Sync secrets from OpenBao to Kubernetes.

### Argo Rollouts (`platform-apps/charts/argo-rollouts/`)
- Progressive delivery.

### CNPG (`platform-apps/charts/cnpg/`)
- PostgreSQL operator.

### Prometheus Operator CRDs (`platform-apps/charts/prometheus-operator-crds/`)
- CRDs for Prometheus stack (sync wave `-11`).

### Traefik (`platform-apps/charts/traefik/`)
- Ingress controller (sync wave `-11`).

### Cert-Manager (`platform-apps/charts/cert-manager/`)
- TLS certificates (sync wave `-10`).

### Crossplane (`platform-apps/charts/crossplane/`)
- Cloud resource provisioning.

### External DNS (`platform-apps/charts/external-dns/`)
- DNS record management (excluded in `kind` clusters).

### Team Onboarding (`platform-apps/charts/team-onboarding/`)
- Demo apps and self-service provisioning.

---

## 🔄 CI/CD Patterns (`.github/`)

### Validation Scripts
| Script | Purpose |
|--------|---------|
| `kubeconform.sh` | Kubernetes resource validation (with custom schemas in `kubeconform-schemas/`). |
| `kube-score.sh` | Kubernetes best practice checker. |
| `create-pr-comment-file.sh` | Renders GitOps diff for PR comments. |
| `create-trivy-scan-report.sh` | Runs Trivy scan and generates Markdown report. |
| `create-trivy-scan-diff.sh` | Compares Trivy reports across commits. |
| `create-helm-dependency-list.sh` | Generates `helm-chart-list/helm-chart-list.txt`. |
| `create-image-list.sh` | Generates `image-list/image-list.json` and `SBOMs`. |
| `helm-template-all-apps-from-target-chart.sh` | Pre-renders all apps for linting/CI. |

### Workflow Triggers
- PR: lint, kubeconform, kube-score, Helm template, Trivy scan.
- Push to `main`: Release Please → GitHub release + changelog.
- Cron: E2E tests, cluster tests.

---

## 🧪 E2E Tests (`e2e-tests/playwright/`)

### Test Scenarios
| Test | Purpose |
|------|---------|
| `argocd-tests` | Login, app sync, rollback. |
| `grafana-tests` | Dashboard access, query. |
| `keycloak-tests` | User login, password reset, OIDC. |
| `kargo-tests` | Delivery pipeline, artifact promotion. |
| `openbao-tests` | Secret creation, retrieval, revocation. |
| `portal-tests` | Backstage app registration, scaffolding. |
| `vault-tests` | OpenBao secrets flow. |

### Setup
1. Install deps:
   ```bash
   cd e2e-tests/playwright
   npm install otpauth
   ```
2. Set env vars (see `CONTRIBUTING.md` for full list):
   - `E2E_KEYCLOAK_DEMOADMIN_PASSWORD`, `E2E_GRAFANA_ADMIN_PASSWORD`, `E2E_ARGOCD_ADMIN_PASSWORD`, etc.
   - `E2E_TEST_GH_USERNAME`, `E2E_TEST_GH_PASSWORD`, `E2E_TEST_GITHUB_OTP` (for OAuth).
   - `E2E_KUBRIX_REPO`, `E2E_BASE_DOMAIN`.

### Run
```bash
npm run test:smoke   # OSS stack
npm run test:prime   # Prime stack
npm run test:all     # Full suite
```

### Report
```bash
npx playwright show-report
