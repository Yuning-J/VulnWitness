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

# Without the mcp extra the MCP server refuses to start, with exit status 1.
mcp_status=0
"$work_dir/core-venv/bin/cve-kgrag" mcp < /dev/null || mcp_status=$?
if [ "$mcp_status" -ne 1 ]; then
  echo "cve-kgrag mcp exited $mcp_status without the mcp extra; expected 1" >&2
  exit 1
fi

uv pip install -p "$core_python" pytest jsonschema
"$core_python" -m pytest -q tests/unit tests/contract tests/integration \
  --ignore=tests/integration/interfaces/mcp
