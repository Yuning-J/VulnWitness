#!/usr/bin/env bash
# Fetch the raw inputs of a corpus store, for an operator, never in CI: every NVD 2.0 year
# feed from FIRST_YEAR to LAST_YEAR (defaults 2002 and the current UTC year), the NVD
# `modified` feed, and the current CISA KEV catalog, from their official URLs, into a new
# directory DIR. Each NVD feed is checked against the SHA-256 its `.meta` file states for
# the decompressed JSON. Writes `provenance.tsv` (file, URL, retrieval time, file SHA-256,
# payload SHA-256, bytes) and `inputs.yaml`, the input manifest `cve-kgrag migrate legacy`
# reads (ADR 0008), with each file's retrieval time. Both are written under `.partial` names
# and renamed only when every file has arrived and verified, so a failed run never leaves a
# manifest that looks complete. The files are data under NVD's and CISA's terms: keep DIR
# outside every repository (docs/runbook.md).
# Usage: scripts/operator/fetch_feeds.sh DIR [FIRST_YEAR [LAST_YEAR]]
set -euo pipefail

target_dir="${1:?usage: fetch_feeds.sh DIR [FIRST_YEAR [LAST_YEAR]]}"
first_year="${2:-2002}"
last_year="${3:-$(date -u +%Y)}"
nvd_feed_base="https://nvd.nist.gov/feeds/json/cve/2.0"
kev_url="https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
kev_file="known_exploited_vulnerabilities.csv"
# NVD asks automated clients to pace their requests.
pause_seconds=6
# The feed CDN sometimes resets an HTTP/2 stream mid-transfer (curl exit 92), which plain
# --retry does not cover, and NVD answers 503 for minutes at a time. Without --retry-delay,
# curl backs off exponentially from 1 s, so ten retries wait about 17 minutes in all.
curl_options=(-fsS --retry 10 --retry-all-errors)

fetch() {
  curl "${curl_options[@]}" "$@" || {
    local status=$?
    echo "fetch_feeds.sh: ${*: -1} failed (curl exit $status)" >&2
    exit 1
  }
}

if [ -e "$target_dir" ] && [ -n "$(ls -A "$target_dir")" ]; then
  echo "fetch_feeds.sh: $target_dir exists and is not empty; choose a new directory" >&2
  exit 2
fi
mkdir -p "$target_dir"

sha256_of_stdin() {
  if command -v sha256sum > /dev/null; then sha256sum | cut -d' ' -f1; else shasum -a 256 | cut -d' ' -f1; fi
}

now_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

provenance="$target_dir/provenance.tsv.partial"
manifest="$target_dir/inputs.yaml.partial"
printf 'file\turl\tretrieved_at\tfile_sha256\tpayload_sha256\tbytes\n' > "$provenance"
printf 'format_version: 1\ninputs:\n' > "$manifest"

fetch_nvd_feed() {
  local feed_name="$1"
  local file_name="nvdcve-2.0-$feed_name.json.gz"
  local url="$nvd_feed_base/$file_name"
  fetch -o "$target_dir/$file_name" "$url"
  local retrieved_at
  retrieved_at="$(now_utc)"
  local stated_sha256
  stated_sha256="$(fetch "$nvd_feed_base/nvdcve-2.0-$feed_name.meta" \
    | tr -d '\r' | sed -n 's/^sha256://p' | tr 'A-F' 'a-f')"
  local payload_sha256
  payload_sha256="$(gzip -dc "$target_dir/$file_name" | sha256_of_stdin)"
  if [ "$payload_sha256" != "$stated_sha256" ]; then
    echo "fetch_feeds.sh: $file_name does not match the SHA-256 its .meta states" >&2
    exit 1
  fi
  local file_sha256
  file_sha256="$(sha256_of_stdin < "$target_dir/$file_name")"
  local byte_count
  byte_count="$(wc -c < "$target_dir/$file_name" | tr -d ' ')"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$file_name" "$url" "$retrieved_at" "$file_sha256" \
    "$payload_sha256" "$byte_count" >> "$provenance"
  printf '  - source: nvd\n    path: %s\n    retrieved_at: "%s"\n' "$file_name" "$retrieved_at" \
    >> "$manifest"
  echo "$file_name: $byte_count bytes"
  sleep "$pause_seconds"
}

for year in $(seq "$first_year" "$last_year"); do
  fetch_nvd_feed "$year"
done
fetch_nvd_feed modified

fetch -o "$target_dir/$kev_file" "$kev_url"
kev_retrieved_at="$(now_utc)"
kev_sha256="$(sha256_of_stdin < "$target_dir/$kev_file")"
kev_bytes="$(wc -c < "$target_dir/$kev_file" | tr -d ' ')"
printf '%s\t%s\t%s\t%s\t\t%s\n' "$kev_file" "$kev_url" "$kev_retrieved_at" "$kev_sha256" \
  "$kev_bytes" >> "$provenance"
printf '  - source: cisa-kev\n    path: %s\n    retrieved_at: "%s"\n' "$kev_file" \
  "$kev_retrieved_at" >> "$manifest"
echo "$kev_file: $kev_bytes bytes"
mv "$provenance" "$target_dir/provenance.tsv"
mv "$manifest" "$target_dir/inputs.yaml"
echo "wrote $target_dir/provenance.tsv and $target_dir/inputs.yaml"
