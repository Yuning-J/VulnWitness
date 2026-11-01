#!/usr/bin/env bash
# The importer's scale run (ADR 0008 §8), for an operator, never in CI: imports RECORDS
# synthetic records (default 250000) from gzipped NVD 2.0 feeds and a KEV catalog, and
# prints the run's wall time, peak resident memory and the most temporary disk the run
# directory held. Usage: scripts/operator/migration_scale.sh [records]
set -euo pipefail
cd "$(dirname "$0")/../.."

record_count="${1:-250000}"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
mkdir "$work_dir/inputs" "$work_dir/stores"

uv run python scripts/operator/build_synthetic_feeds.py "$work_dir/inputs" "$record_count"
echo "inputs: $(du -sk "$work_dir/inputs" | cut -f1) KiB"

# The stores directory holds the partial store and the staging database while the run
# lasts; its largest size is the run's temporary disk.
peak_file="$work_dir/peak_kib"
echo 0 > "$peak_file"
(
  while true; do
    current_kib="$(du -sk "$work_dir/stores" 2>/dev/null | cut -f1 || echo 0)"
    if [ "$current_kib" -gt "$(cat "$peak_file")" ]; then echo "$current_kib" > "$peak_file"; fi
    sleep 1
  done
) &
sampler_pid=$!
# Stop the sampler on any exit, a failed import included, before the work dir goes.
trap 'kill "$sampler_pid" 2>/dev/null || true; rm -rf "$work_dir"' EXIT

if [ "$(uname)" = "Darwin" ]; then time_flag="-l"; else time_flag="-v"; fi
start_seconds="$(date +%s)"
/usr/bin/time "$time_flag" uv run vulnwitness migrate legacy \
  --inputs "$work_dir/inputs/inputs.yaml" --target "$work_dir/stores/store" \
  > "$work_dir/report.json" 2> "$work_dir/time.txt"
end_seconds="$(date +%s)"
kill "$sampler_pid" 2>/dev/null || true
wait "$sampler_pid" 2>/dev/null || true

python3 -c "import json,sys; r=json.load(open(sys.argv[1])); print('outcome:', r['outcome'], '| imported:', r['cve_outcomes']['imported'])" "$work_dir/report.json"
echo "wall time: $((end_seconds - start_seconds)) s"
grep -i "maximum resident set size" "$work_dir/time.txt"
echo "peak temporary disk: $(cat "$peak_file") KiB"
echo "store: $(du -sk "$work_dir/stores/store" | cut -f1) KiB"
