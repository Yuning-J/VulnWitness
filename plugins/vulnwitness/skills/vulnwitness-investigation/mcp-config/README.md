# Client configuration snippets

The canonical Skill lives in `plugins/vulnwitness/skills/vulnwitness-investigation/`.
Claude Code can load its containing plugin with
`claude --plugin-dir plugins/vulnwitness` from the repository root
(acceptance in Claude Code pending). The snippets below connect directly without
plugin hooks; Codex and Cursor use the Skill from this same location.

Install the package with its `mcp` extra in the environment that supplies
`vulnwitness`. Use an absolute executable path if the client cannot find it on PATH.
Choose [Claude Code](claude-code.md), [Codex](codex.md), or [Cursor](cursor.md).
Merge one server entry into the indicated config file; do not replace unrelated
settings. The snippets explicitly clear operator data paths and disable optional
model/semantic settings so inherited environment values cannot select a real store.
Empty data-path settings count as unset and serve the packaged synthetic CVEs and
catalogue/FiGHT excerpts. No corpus download, token, or HTTP listener is needed.

Each client file contains plain, recording and workspace stdio variants. Choose
one. For the investigation flow, use the workspace variant, equivalent to
`vulnwitness mcp --workspace ~/.vulnwitness/workspace`. Replace its placeholder
with an absolute home path: argument arrays do not invoke shell tilde expansion.
The server creates the workspace privately; keep it outside any store root and
do not combine it with `--session`. The demo variants explicitly unset the store
and all MITRE/FiGHT snapshot paths and identities so inherited operator settings
cannot change the first run.

The recording option is verified through MCP stdio on the packaged fixture.
Replace its session path with a private absolute directory outside any store root.
Client format verification is documentation-based; these snippets are not yet
tested inside the clients. Server/fixture checks do not establish client discovery,
resource delivery or an end-to-end user flow. See the [Skill](../SKILL.md) for the
workspace evidence and report procedure.
