#!/usr/bin/env bash
# The core-only lane: the built wheel in a fresh venv, without the dev group or any
# extra. Usage: scripts/ci/core_only_lane.sh [python-version] (default 3.12)
set -euo pipefail
cd "$(dirname "$0")/../.."

python_version="${1:-3.12}"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

uv build --out-dir "$work_dir/dist"
uv venv -p "$python_version" "$work_dir/core-venv"
core_python="$work_dir/core-venv/bin/python"
uv pip install -p "$core_python" "$work_dir"/dist/cve_kgrag-*.whl

"$work_dir/core-venv/bin/cve-kgrag" demo > /dev/null

# Without the mcp extra the MCP server refuses to start: exit status 1 and the
# refusal naming the extra, not some other failure that also exits 1.
mcp_status=0
mcp_stderr="$("$work_dir/core-venv/bin/cve-kgrag" mcp < /dev/null 2>&1 > /dev/null)" || mcp_status=$?
if [ "$mcp_status" -ne 1 ] || ! grep -qF "the 'mcp' extra is not installed" <<< "$mcp_stderr"; then
  echo "cve-kgrag mcp without the mcp extra: expected exit 1 and the missing-extra refusal," \
    "got exit $mcp_status: $mcp_stderr" >&2
  exit 1
fi

# The same refusal for MCP over HTTP, given the token it needs before anything else.
mcp_http_status=0
mcp_http_stderr="$(CVE_KGRAG_HTTP_TOKEN="core-only-lane-token-0123456789abcdefgh" \
  "$work_dir/core-venv/bin/cve-kgrag" mcp --http < /dev/null 2>&1 > /dev/null)" \
  || mcp_http_status=$?
if [ "$mcp_http_status" -ne 1 ] \
  || ! grep -qF "the 'mcp' extra is not installed" <<< "$mcp_http_stderr"; then
  echo "cve-kgrag mcp --http without the mcp extra: expected exit 1 and the missing-extra" \
    "refusal, got exit $mcp_http_status: $mcp_http_stderr" >&2
  exit 1
fi

# The REST API refuses the same way without the api extra.
api_status=0
api_stderr="$(CVE_KGRAG_HTTP_TOKEN="core-only-lane-token-0123456789abcdefgh" \
  "$work_dir/core-venv/bin/cve-kgrag" api < /dev/null 2>&1 > /dev/null)" || api_status=$?
if [ "$api_status" -ne 1 ] || ! grep -qF "the 'api' extra is not installed" <<< "$api_stderr"; then
  echo "cve-kgrag api without the api extra: expected exit 1 and the missing-extra refusal," \
    "got exit $api_status: $api_stderr" >&2
  exit 1
fi

uv pip install -p "$core_python" pytest jsonschema
"$core_python" -m pytest -q tests/unit tests/contract tests/integration \
  --ignore=tests/integration/interfaces/mcp --ignore=tests/integration/interfaces/http \
  --ignore=tests/integration/interfaces/rest
