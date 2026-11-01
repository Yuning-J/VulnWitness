# Shared executable discovery and demo-data isolation for plugin entry points.
binary=${VULNWITNESS_BIN:-vulnwitness}
if ! command -v "$binary" >/dev/null 2>&1; then
    echo "VulnWitness CLI not found: $binary. Install it from a checkout (uv sync --locked) and set VULNWITNESS_BIN to <checkout>/.venv/bin/vulnwitness, or put vulnwitness on PATH." >&2
    return 1
fi
if [ "${VULNWITNESS_PLUGIN_REAL_DATA:-}" != 1 ]; then
    unset VULNWITNESS_STORE_ROOT VULNWITNESS_FIGHT_SNAPSHOT_PATH VULNWITNESS_MITRE_SNAPSHOT_PATH
    unset VULNWITNESS_FIGHT_SNAPSHOT_SHA256 VULNWITNESS_MITRE_SNAPSHOT_SHA256
    unset VULNWITNESS_PLANNER_ENABLED VULNWITNESS_PLANNER_BASE_URL VULNWITNESS_PLANNER_MODEL_NAME
    unset VULNWITNESS_PLANNER_API_KEY VULNWITNESS_PLANNER_REASONING_EFFORT
    unset VULNWITNESS_SEMANTIC_ENABLED
fi
return 0
