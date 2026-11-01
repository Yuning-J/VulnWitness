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
