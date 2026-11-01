<!-- Format checked 2026-11-01: https://code.claude.com/docs/en/mcp -->
# Claude Code

For the plugin, run `claude --plugin-dir plugins/vulnwitness` from the repository
root after installing `vulnwitness[mcp]` (acceptance in Claude Code pending).
The plugin supplies the canonical Skill, analyst, MCP server and optional hooks.
The direct configurations below have no plugin hooks.

Merge into project-root `.mcp.json`. The public documentation defines
`mcpServers` entries with stdio `command`, `args`, and `env`.
The client format is verified from documentation; application loading is unverified.

Plain stdio:

```json
{
  "mcpServers": {
    "vulnwitness": {
      "type": "stdio",
      "command": "vulnwitness",
      "args": ["mcp"],
      "env": {
        "VULNWITNESS_STORE_ROOT": "",
        "VULNWITNESS_MITRE_SNAPSHOT_PATH": "",
        "VULNWITNESS_MITRE_SNAPSHOT_SHA256": "",
        "VULNWITNESS_FIGHT_SNAPSHOT_PATH": "",
        "VULNWITNESS_FIGHT_SNAPSHOT_SHA256": "",
        "VULNWITNESS_PLANNER_ENABLED": "false",
        "VULNWITNESS_SEMANTIC_ENABLED": "false"
      }
    }
  }
}
```

Recording stdio (server option verified through MCP stdio on the packaged fixture):

```json
{
  "mcpServers": {
    "vulnwitness": {
      "type": "stdio",
      "command": "vulnwitness",
      "args": ["mcp", "--session", "/absolute/path/to/session"],
      "env": {
        "VULNWITNESS_STORE_ROOT": "",
        "VULNWITNESS_MITRE_SNAPSHOT_PATH": "",
        "VULNWITNESS_MITRE_SNAPSHOT_SHA256": "",
        "VULNWITNESS_FIGHT_SNAPSHOT_PATH": "",
        "VULNWITNESS_FIGHT_SNAPSHOT_SHA256": "",
        "VULNWITNESS_PLANNER_ENABLED": "false",
        "VULNWITNESS_SEMANTIC_ENABLED": "false"
      }
    }
  }
}
```

Workspace stdio (demo): equivalent to
`vulnwitness mcp --workspace ~/.vulnwitness/workspace` in a shell. Replace the
placeholder below with the absolute path to your home workspace; do not rely on
shell tilde expansion in an argument array. Choose this instead of the plain or
recording entry. The empty store/snapshot settings explicitly unset inherited
operator data configuration for a reproducible first run. This workspace variant
is not yet tested inside the clients.

```json
{
  "mcpServers": {
    "vulnwitness": {
      "type": "stdio",
      "command": "vulnwitness",
      "args": [
        "mcp",
        "--workspace",
        "/absolute/path/to/.vulnwitness/workspace"
      ],
      "env": {
        "VULNWITNESS_STORE_ROOT": "",
        "VULNWITNESS_MITRE_SNAPSHOT_PATH": "",
        "VULNWITNESS_MITRE_SNAPSHOT_SHA256": "",
        "VULNWITNESS_FIGHT_SNAPSHOT_PATH": "",
        "VULNWITNESS_FIGHT_SNAPSHOT_SHA256": "",
        "VULNWITNESS_PLANNER_ENABLED": "false",
        "VULNWITNESS_SEMANTIC_ENABLED": "false"
      }
    }
  }
}
```
