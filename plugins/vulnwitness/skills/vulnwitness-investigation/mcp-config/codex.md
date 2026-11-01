<!-- Format checked 2026-11-01: https://developers.openai.com/codex/mcp redirects to https://learn.chatgpt.com/docs/extend/mcp?surface=cli -->
# Codex

Merge into `~/.codex/config.toml`. Official OpenAI documentation defines
`mcp_servers.<name>` with stdio `command`, `args`, and an `env` table.
The client format is verified from documentation; application loading is unverified.

Plain stdio:

```toml
[mcp_servers.vulnwitness]
command = "vulnwitness"
args = ["mcp"]

[mcp_servers.vulnwitness.env]
VULNWITNESS_STORE_ROOT = ""
VULNWITNESS_MITRE_SNAPSHOT_PATH = ""
VULNWITNESS_MITRE_SNAPSHOT_SHA256 = ""
VULNWITNESS_FIGHT_SNAPSHOT_PATH = ""
VULNWITNESS_FIGHT_SNAPSHOT_SHA256 = ""
VULNWITNESS_PLANNER_ENABLED = "false"
VULNWITNESS_SEMANTIC_ENABLED = "false"
```

Recording stdio (server option verified through MCP stdio on the packaged fixture):

```toml
[mcp_servers.vulnwitness]
command = "vulnwitness"
args = ["mcp", "--session", "/absolute/path/to/session"]

[mcp_servers.vulnwitness.env]
VULNWITNESS_STORE_ROOT = ""
VULNWITNESS_MITRE_SNAPSHOT_PATH = ""
VULNWITNESS_MITRE_SNAPSHOT_SHA256 = ""
VULNWITNESS_FIGHT_SNAPSHOT_PATH = ""
VULNWITNESS_FIGHT_SNAPSHOT_SHA256 = ""
VULNWITNESS_PLANNER_ENABLED = "false"
VULNWITNESS_SEMANTIC_ENABLED = "false"
```

Workspace stdio (demo): equivalent to
`vulnwitness mcp --workspace ~/.vulnwitness/workspace` in a shell. Replace the
placeholder below with the absolute path to your home workspace; do not rely on
shell tilde expansion in an argument array. Choose this instead of the plain or
recording entry. The empty store/snapshot settings explicitly unset inherited
operator data configuration for a reproducible first run. This workspace variant
is not yet tested inside the clients.

```toml
[mcp_servers.vulnwitness]
command = "vulnwitness"
args = ["mcp", "--workspace", "/absolute/path/to/.vulnwitness/workspace"]

[mcp_servers.vulnwitness.env]
VULNWITNESS_STORE_ROOT = ""
VULNWITNESS_MITRE_SNAPSHOT_PATH = ""
VULNWITNESS_MITRE_SNAPSHOT_SHA256 = ""
VULNWITNESS_FIGHT_SNAPSHOT_PATH = ""
VULNWITNESS_FIGHT_SNAPSHOT_SHA256 = ""
VULNWITNESS_PLANNER_ENABLED = "false"
VULNWITNESS_SEMANTIC_ENABLED = "false"
```
