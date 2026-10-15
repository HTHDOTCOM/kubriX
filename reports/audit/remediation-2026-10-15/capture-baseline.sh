#!/usr/bin/env bash
# Capture current (post-audit) image versions and immutable digests for the
# remediation baseline. Uses the same values-file layering as CI rendering.
set -uo pipefail
ROOT="$(git rev-parse --show-toplevel)"
OUT="$ROOT/reports/audit/remediation-2026-10-15/baseline"
mkdir -p "$OUT"

# 1) Extract current image references per chart (CI layering).
: > "$OUT/current-images.tsv"
printf 'chart\timage\n' > "$OUT/current-images.tsv"
cd "$ROOT/platform-apps/charts"
for chart in $(ls -d */ | sed 's#/##'); do
  valuesFiles=()
  [[ -f ${chart}/values-kubrix-default.yaml ]] && valuesFiles+=( "-f ${chart}/values-kubrix-default.yaml" )
  [[ -f ${chart}/values-cluster-kind.yaml ]] && valuesFiles+=( "-f ${chart}/values-cluster-kind.yaml" )
  helm images get ${chart} ${valuesFiles[@]} --log-level error \
    --kind "Deployment,StatefulSet,DaemonSet,CronJob,Job,ReplicaSet,Pod,Alertmanager,Prometheus,ThanosRuler,Grafana,Thanos,Receiver,Provider,Configuration,Function" \
    2>/dev/null | sort -u | while read -r img; do
      printf '%s\t%s\n' "$chart" "$img" >> "$OUT/current-images.tsv"
    done
done
cd "$ROOT"

# 2) Resolve immutable digests for each unique image (manifest only, no pull).
: > "$OUT/current-digests.tsv"
printf 'image\tdigest\tarchitectures\n' > "$OUT/current-digests.tsv"
resolve() {
  local img="$1" out digest archs
  out=$(docker buildx imagetools inspect "$img" 2>/dev/null)
  if [[ -n "$out" ]]; then
    digest=$(echo "$out" | awk '/^Digest:/{print $2; exit}')
    archs=$(echo "$out" | awk '/Platform:/{print $2}' | sed 's#linux/##' | sort -u | paste -sd, -)
    printf '%s\t%s\t%s\n' "$img" "$digest" "$archs"
  else
    printf '%s\tUNRESOLVED\t\n' "$img"
  fi
}
export -f resolve
cut -f2 "$OUT/current-images.tsv" | sort -u | xargs -P 8 -I{} bash -c 'resolve "$@"' _ {} >> "$OUT/current-digests.tsv"
echo "Baseline captured: $OUT/current-images.tsv, $OUT/current-digests.tsv"
