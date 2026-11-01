<!-- Format checked 2026-11-01: https://cursor.com/docs/mcp -->
# Cursor

Merge into `.cursor/mcp.json` for this project or `~/.cursor/mcp.json` globally.
The public documentation defines `mcpServers` with stdio `type`, `command`,
`args`, and `env`. The client format is verified from documentation;
application loading is unverified.

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
