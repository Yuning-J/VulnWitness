#!/usr/bin/env bash
# The offline lane: tests, lint, format, types, schema snapshots and the lock, with no
# network service. The Python version comes from uv (UV_PYTHON in CI).
set -euo pipefail
cd "$(dirname "$0")/../.."

uv sync --locked
uv run pytest -q
uv run ruff check
uv run ruff format --check
uv run mypy
uv run cve-kgrag schema check
uv lock --check
