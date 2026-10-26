#!/usr/bin/env bash
# The serving scale run (ADR 0009 §12, §17), for an operator, never in CI: imports RECORDS
# synthetic records (default 250000) into a store under a fresh store root, activates it,
# then measures loading the active store, and building the API's two deployments over one
# shared data plane and over two separate ones; each run prints its wall times and peak
# resident memory. Usage: scripts/operator/serving_scale.sh [records]
set -euo pipefail
cd "$(dirname "$0")/../.."

record_count="${1:-250000}"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
mkdir "$work_dir/inputs" "$work_dir/stores"
export CVE_KGRAG_STORE_ROOT="$work_dir/stores"

uv run python scripts/operator/build_synthetic_feeds.py "$work_dir/inputs" "$record_count"
uv run cve-kgrag migrate legacy \
  --inputs "$work_dir/inputs/inputs.yaml" --target "$work_dir/stores/synthetic" > /dev/null
uv run cve-kgrag store activate synthetic > /dev/null
echo "store: $(du -sk "$work_dir/stores/synthetic" | cut -f1) KiB"

if [ "$(uname)" = "Darwin" ]; then time_flag="-l"; else time_flag="-v"; fi
for mode in load api api-separate; do
  echo "--- $mode"
  /usr/bin/time "$time_flag" uv run python scripts/operator/measure_serving.py \
    "$mode" "$work_dir/stores" 2> "$work_dir/time-$mode.txt"
  grep -i "maximum resident set size" "$work_dir/time-$mode.txt"
done
