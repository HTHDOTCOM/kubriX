# kubriX Repository Overview for AI Agents

This document is designed to help AI agents understand the structure, components, and integration points of the kubriX repository. kubriX is an opinionated Internal Developer Platform (IDP) distribution for Kubernetes, primarily based on a GitOps workflow with Helm and Argo CD.

**Important Note:** Always read `AGENTS.md` before making any changes. `AGENTS.md` contains the core behavioral guidelines, validation commands, and workflow rules.

## Core Architecture and Integration

The repository functions as a complete GitOps bootstrap and continuous delivery system. The integration flow typically looks like this:

1. **Bootstrap Script (`install-platform.sh`)**: The entry point for setting up the platform. It relies on `KUBRIX_*` environment variables (e.g., `KUBRIX_TARGET_TYPE`, `KUBRIX_CLUSTER_TYPE`). It installs Argo CD onto the target cluster.
2. **Argo CD Bootstrap**: The script uses `bootstrap-argocd-values.yaml` to configure the initial Argo CD instance.
3. **Root Application**: A root Argo CD Application (e.g., `bootstrap-app-kubrix-oss-stack.yaml` or `bootstrap-app-kind.yaml`) is deployed. This root app points to `platform-apps/target-chart/`.
4. **App of Apps (`platform-apps/target-chart/`)**: This Helm chart acts as an orchestrator. Based on the selected target values (e.g., `values-kind.yaml`), it renders individual Argo CD `Application` custom resources for the various platform components.
5. **Platform Charts (`platform-apps/charts/`)**: The individual Argo CD applications point back to the specific component charts in this directory (e.g., Grafana, Keycloak, Backstage, Kyverno). Each chart uses a layered approach to Helm values to separate kubriX defaults from customer overrides.

## Directory and File Breakdown

### Root-Level Configuration and Scripts

* **`install-platform.sh`**: The main bootstrap shell script. Expects tools like `yq`, `jq`, `kubectl`, `helm`.
* **`install-manifests.yaml`**: Kubernetes manifests applied directly during the installation phase.
* **`bootstrap-app-*.yaml`**: Argo CD Application manifests for various target architectures (e.g., `bootstrap-app-kubrix-oss-stack.yaml`, `bootstrap-app-kind-portal.yaml`).
* **`bootstrap-argocd-values.yaml`**: Helm values used for the initial installation of Argo CD.
* **`AGENTS.md`**: Core rules and directives for AI agents.
* **`README.md`**: Project overview, quick start, and documentation links.
* **`CONTRIBUTING.md`**: Guidelines for human contributors, development setup, and code style.
* **`release-please-config.json` / `.release-please-manifest.json`**: Configuration for automatic semantic versioning and changelog generation via Google's Release Please.
* **`renovate.json`**: Configuration for Renovate bot to automatically update dependencies.

### Platform Components (`platform-apps/`)

* **`platform-apps/charts/`**: The core "bricks" of the IDP. Each directory is a wrapper Helm chart for a specific tool. Examples include:
  * *GitOps/CD:* `argocd`, `argo-rollouts`, `kargo`
  * *Developer Portal:* `backstage`
  * *Security/Secrets:* `openbao`, `external-secrets`, `kyverno`, `falco`, `trivy`
  * *Observability:* `grafana`, `loki`, `mimir`, `tempo`, `prometheus-operator-crds`, `k8s-monitoring`
  * *Infrastructure/Storage:* `cnpg` (CloudNativePG), `minio`, `kubevirt`, `crossplane`, `metallb`, `traefik`
  * *Testing:* `testkube`
  * *Backup:* `velero`
  * **Helm Values Convention**: Within these charts, values are highly modular: `values-kubrix-default.yaml` (defaults), `values-cluster-kind.yaml` (local dev), `values-customer.yaml` (customer overrides).
* **`platform-apps/target-chart/`**: The root chart (App of Apps) that conditionally deploys the charts in `platform-apps/charts/` based on the selected `KUBRIX_TARGET_TYPE`.

### Team Onboarding (`team-apps/`)

* **`team-apps/onboarding-apps-charts/`**: Helm charts designed for tenant teams. These act as workflows, templates, or demo applications for teams onboarding onto the kubriX platform.

### CI/CD and Automation (`.github/`)

* **`.github/workflows/`**: GitHub Actions workflows for continuous integration, cluster testing, release generation, and generating artifacts (SBOMs, Trivy scans).
* **`.github/*.sh` and `.github/*.py`**: A robust set of helper scripts used by the CI pipeline and developers:
  * `kubeconform.sh`: Validates rendered Helm charts against Kubernetes schemas.
  * `kube-score.sh`: Performs static code analysis of Kubernetes object definitions.
  * `create-pr-comment-file.sh` / `render-target-applications.sh`: Renders Helm templates to create readable GitOps diffs for PR reviews.
  * `create-trivy-scan-report.sh` / `create-trivy-scan-diff.sh`: Runs security vulnerability scans.
  * `create-image-list.sh` / `create-helm-dependency-list.sh`: Generates Software Bill of Materials (SBOM) and dependency lists.
  * `crd-extractor.sh`: Extracts Custom Resource Definitions for schema validation.

### Testing (`e2e-tests/`)

* **`e2e-tests/playwright/`**: End-to-End browser tests using Playwright. These tests verify the platform's UI components (like Backstage, Grafana, Argo CD) after a cluster is fully bootstrapped.

### Generated Artifacts and Schemas

* **`kubeconform-schemas/`**: A large collection of JSON schemas for Custom Resource Definitions (CRDs). These are used by `.github/kubeconform.sh` to validate that generated manifests correctly conform to the CRDs defined by tools like Crossplane, Kyverno, cert-manager, etc.
* **`trivy-scan-reports/`**: Automatically generated vulnerability reports.
* **`image-list/`**: Automatically generated inventory of container images used by the platform.
* **`helm-chart-list/`**: Automatically generated inventory of upstream Helm charts used as dependencies.
* **`reports/`**: Additional generated reports (e.g., audits).
* *Note: AI agents should generally not manually edit these generated files unless explicitly instructed to regenerate them.*

### Development and Cloud Resources

* **`.devcontainer/`**: Configurations for VS Code / GitHub Codespaces Dev Containers. Divided into profiles (`portal`, `observability`, `security`, `delivery`) to allow tailored local development environments using `kind` (Kubernetes in Docker).
* **`aws-resources/` / `metalstack-resources/`**: Infrastructure as Code (Terraform) and configurations for specific cloud providers or bare-metal setups.
* **`backstage-resources/`**: Configurations and templates specifically for the Backstage Developer Portal, including entity definitions, software templates, documentation (`docs/`), and Architecture Decision Records (`adr/`).
* **`bootstrap/`**: Contains `customer-config.yaml`, representing how a customer might inject their own configuration during the bootstrap phase.

## Agent Working Tips

* **Understand the Rendered Output**: When modifying a chart in `platform-apps/charts/`, remember that your changes will be rendered by Argo CD. Use the `.github/create-pr-comment-file.sh` or manual `helm template` commands (as defined in `AGENTS.md`) to verify the resulting YAML manifests.
* **Follow the Values Hierarchy**: Do not put customer-specific logic in `values-kubrix-default.yaml`. Do not put base kubriX logic in `values-customer.yaml`. Respect the aspect-oriented values design.
* **Rely on `AGENTS.md`**: This overview explains *what* the repo is. `AGENTS.md` explains *how* you should work within it. Both are essential.
