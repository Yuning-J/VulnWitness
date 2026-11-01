# ADR 0013: Agent workspace over MCP

Status: accepted

Contract: `2.0.0-dev.51`

## Decision and scope

An MCP client can create investigations, run bounded product triage, inspect saved calls,
contribute findings, check the record and render a report without supplying a filesystem
path or using a shell. The application service takes injected storage, clocks, randomness,
recording, workflow and rendering dependencies. The session recorder, triage workflow,
layered checker and report composition remain the shared implementations.

The server has three modes:

| Command | Surface |
|---|---|
| `vulnwitness mcp` | Nine knowledge tools, unrecorded |
| `vulnwitness mcp --session DIR` | Nine knowledge tools, all dispatched calls recorded |
| `vulnwitness mcp --workspace ROOT` | Nine knowledge tools, eight investigation tools, resources and prompt templates |

All modes support stdio and `--http`. `--session` and `--workspace` are mutually exclusive.
The workspace root is fixed at startup, private (0700), and created if absent. A symlink
root or a root inside the configured store root is refused before loading deployment data.
Files are private (0600), published with the existing atomic, synced writer. Workspace
mode uses the ordinary per-investigation call limit (100 by default, lowered by
`--session-call-limit`) and a workspace limit of 200, configurable with `--workspace-limit`.
Operators prune investigations when the workspace is full.

REST requests and core knowledge request models do not acquire a `session_id`. The
workspace MCP schemas add it at the transport boundary, and strip it before knowledge
execution and recording. With `session_id`, a knowledge call appends its exact answer using
the existing recorder, dataset identity binding and call limit. Without it, the knowledge
call is unrecorded. Supplying it outside workspace mode returns `investigations_not_enabled`;
the listed read-only and recording-mode schemas and annotations remain those modes' own
contracts. Workspace tools are not listed in the other modes.

## Identity, paths and creation

An investigation ID is `inv_` followed by 20 lowercase base32 characters, generated from
injected random bytes. It is also its directory name. Inputs must match
`^inv_[a-z2-7]{20}$` before storage access. Each access also resolves the investigation
and requires a direct, non-symlink child of the fixed workspace root. No tool accepts a
file path. Stored response filenames are not used as path authority.

### Threat model

Path validation prevents model-supplied paths and static symlinks. At startup and before
investigation writes, the workspace root must be owned by the current user, must not be
a symlink, and must have no group or other write permission (`mode & 0o022 == 0`).
Investigation directories are created 0700 and must also be owned by the user and not
group or other writable. Concurrent filesystem manipulation by another process of the
same user is outside this protection: that process can modify records directly. The
check layers report the tampering they can observe; pathname checks do not pin directories
against concurrent replacement.

`start_investigation` creates a manual record with empty findings. `triage_product` creates
a triage record, then runs the existing bounded workflow. `session.json` holds immutable
`origin` (`manual` or `triage`), the normalized triage request where applicable, and the
creation request key where supplied. Ordinary recording does not rewrite this metadata.

Both creation tools accept optional `request_key`, matching `[A-Za-z0-9._-]{1,64}`.
Comparison uses the tool name, canonical JSON of normalized arguments excluding the key,
and the full served dataset identity. Defaults participate in comparison. Product identity
normalization is the existing product request's normalization.

Creation holds an exclusive `flock` on `ROOT/.workspace.lock`:

1. Read `ROOT/requests/<key>.json`, if a key was supplied. An exact match returns the
   existing investigation and its current status without executing any calls.
2. The same key with a different tool, arguments or dataset gives `request_key_conflict`.
3. Check the workspace quota under the same lock.
4. Create the directory, `session.json`, call and response directories, and empty findings.
5. Atomically publish the request record, then release the workspace lock and run triage.

The default bounded lock wait is 250 ms; exhaustion returns `workspace_busy`. The lock
covers quota admission and indexing across threads and processes, not the triage runtime.
Running, failed and interrupted retries return their existing record; they never rerun.
A crash after creating metadata but before publishing the request record leaves an orphan.
The listing includes that investigation with `orphan: true`; it never satisfies a key retry.
Investigations created without a key are ordinary unindexed records, not orphans.

## Lifecycle and concurrency

A nonblocking exclusive per-investigation lock covers each mutation and the entire triage.
The workspace recorder is called while that lock is held, avoiding nested acquisition.
Contending operations return `investigation_busy` and may be retried. Different
investigations can run concurrently. `get_investigation` can observe a running workflow;
its status is a live view rather than a transaction spanning several files.

`triage.started.json` is atomically written before the first workflow call. `triage.json`
is atomically published on completion. The existing workflow retains page, lookup, call
and time caps, and records completed calls and failures. MCP exposes outcomes
`complete`, `stopped_at_cap`, `no_match` and `failed`; it exposes no process exit code.
The outcome is null when a retried investigation has no completion summary yet.

Status has three separate dimensions:

| Dimension | Values |
|---|---|
| Workflow | `none` for manual; `running` while incomplete and locked; `interrupted` while incomplete and unlocked; `complete`, `stopped_at_cap`, `no_match`, `failed` from completion metadata |
| Record | The checker's record-consistency result, including located violations |
| Report | `none`, `current`, `stale` |

An interrupted triage retains its completed calls and planned-step information. Completed
capability, inventory and lookup stages are removed from its remaining steps using the saved
calls, without retrieval. It cannot
accept manual calls or findings. There is no resume; create another investigation. An
unpaired response is a record violation and prevents appends through the existing recorder
and workspace admission checks. No code repairs or silently skips an incomplete record.

## Report binding and delivery

Rendering reads the checked record and performs no retrieval. Its input digest binds
`session.json`, `findings.yaml` and the ordered call files, with filenames and lengths
framing the bytes. The report embeds this digest and `report.json` stores it. A later
call or finding changes the digest and makes the report stale. Rendering the same inputs
and format gives identical bytes. Each saved workspace call also carries a response-byte digest,
which the checker compares on replay to detect edits even when the response still parses.
These digests serve input integrity and replay; they do not establish authenticity against
an operator who can rewrite the entire record.

`render_report` writes `report.html` or `report.md` inside the investigation. It returns a
local path, resource URI, byte size, input digest and check layers. Markdown below 200 KiB
is also inline. A resource URI is readable through the workspace resource handler. Each
report format has its own freshness description: rendering a new Markdown report does not
refresh an older HTML report. Both formats remain current when rendered from the same inputs.
The report retains record consistency, citation resolution and
structured field agreement as separate layers. Free narrative is never checked, and a
passing check establishes neither source support, real-world truth nor applicability.

`read_call(session_id, call)` returns typed call metadata and the exact saved UTF-8 JSON
text, preserving whitespace and final newlines. Reads are bounded at 1 MiB plus one byte.
Above 1 MiB, the error answer retains the call metadata, omits response text and carries
`response_too_large`. Raw responses are not individually listed as resources.

## Findings and supersession

`add_findings` permits an agent without filesystem access to contribute findings. The
server's input contract fixes `author: agent`; omission supplies that value and another
author is refused. The recorder never authors narrative, and workflow findings remain
only deterministic, unconfirmed claims.

A findings batch is atomic under the investigation lock. Each finding requires a client
ID. An identical existing ID is a no-op; different content for an existing ID rejects the
whole batch with `finding_id_conflict`. Schema errors, claim-kind shape errors, unknown
call numbers and invalid supersession reject the entire batch without publishing bytes.

Agent statements are limited to 8 KiB of UTF-8, batches to 200 findings, and normalized
serialized findings requests to 1 MiB. Every workspace tool, including knowledge calls
with `session_id`, also obeys the knowledge toolbox's argument-byte limit on every
transport, including stdio (64 KiB by default, measured as UTF-8 JSON with unescaped
Unicode). This transport limit can be stricter than the findings request limit.
Before publishing `findings.yaml`, the complete combined YAML document is serialized;
above 16 MiB the whole batch fails with `findings_too_large`, leaving existing bytes
intact. This storage bound is below the session reader's 64 MiB cap.

Well-formed but wrong content is saved. An unresolved citation or a contradicted or
unverifiable claim returns `written: true` together with the batch and whole-record layered
checks. “Written” never means “passed”. An all-retry batch reports `written: false` and
an empty list of written IDs.

A revision supplies a new ID and `supersedes: <earlier-id>`. Targets must occur earlier in
the stored or supplied batch, and each target can be superseded once. Revision chains are
allowed; forks and cycles are refused. All entries remain on disk. Checks, finding counts
and reports use the effective set only and expose the superseded count. Findings bytes are
still part of report freshness, so revisions make existing reports stale.

## Tool annotations and failures

Annotations are static for each server mode. All workspace tools have
`destructiveHint=false` and `openWorldHint=false`.

| Workspace tools | `readOnlyHint` | `idempotentHint` |
|---|---|---|
| Nine knowledge tools | false | false |
| `start_investigation`, `triage_product` | false | false |
| `add_findings` | false | false |
| `render_report` | false | true |
| `get_investigation`, `read_call`, `check_investigation`, `list_investigations` | true | true |

Knowledge descriptions state that `session_id` appends a record and consumes the call
limit. Creation descriptions state the conditional `request_key` guarantee. This guarantee
does not make the creation tools statically idempotent. All descriptions state their
writes or read behavior.

Failures use fixed-message `ToolFailure` values, with no exception text. Workspace codes
are `investigations_not_enabled`, `unknown_investigation`, `investigation_busy`,
`workspace_busy`, `request_key_conflict`, `workspace_full`, `investigation_interrupted`
and `finding_id_conflict`, plus `findings_too_large` for combined findings storage,
alongside existing argument, recording and size failures.
Request and answer schemas, workspace knowledge-input schemas and artifact schemas are
exported under `schemas/v2`.

## Client integration decisions

The agent workflow is triage, inspect, optional knowledge calls with `session_id`, add
findings, check, render and present the report. Manual investigations start with
`start_investigation`. Shell users retain `vulnwitness triage`, `session check` and `report`.

Workspace mode registers the SDK's low-level resource and prompt handlers. The other
modes register only tool handlers and advertise neither resources nor prompts.

`resources/list` lists packaged topic cards, committed contract schemas and each local
investigation's summary, findings and existing rendered reports. The investigation count
is bounded by the workspace quota, so listing these artifacts makes them discoverable
without requiring an agent to invent IDs. Topic cards are exact UTF-8 YAML file bytes,
with review state in the description. Schemas are the committed JSON files, included in
wheel and source distributions. Schema resource names include `.schema.json`.

Saved calls use only the template `vulnwitness://investigations/{id}/calls/{n}`; individual
calls are not listed because each investigation can contain up to 100. Content is the same
JSON envelope as `read_call`, including call metadata and exact response text. Above 1 MiB,
the envelope retains metadata and the typed `response_too_large` failure, without response
text. Summaries match `get_investigation`; findings return the exact `findings.yaml` text.
Report resources exist only once rendered, and stale reports remain readable with a stale
description. MIME types are `text/yaml`, `application/json`, `text/html` and `text/markdown`.

Every resource description labels source text untrusted and states dataset identity.
Investigation descriptions use the saved record's identity, while packaged resources and
the call template state the served identity. Literal URI matching permits only fixed
artifacts and validated investigation IDs; no path, URI normalization or percent decoding
can grant filesystem authority. Investigation reads reuse the tools' workspace storage
checks and call limit. Resource failures use JSON-RPC invalid params or resource-not-found,
with the fixed typed `ToolFailure` JSON in the message for invalid IDs and unknown
investigations; no request data or exception text is included.

The three prompts are templates only: `triage_product(product, version?)`,
`investigate_topic(topic, scope)` and `deliver_report(session_id)`. Required arguments are
validated before rendering; fetching a prompt never executes tools. Each template directs
follow-up knowledge calls to pass `session_id`, records findings through `add_findings`,
runs `check_investigation`, renders through `render_report` and presents its path or resource.
They distinguish check layers, state what is not established and never call a passing
check a verified answer. In Claude Code, prompts appear as `/server:prompt` and resource
references use `@server:uri`. These are client presentation conventions, not workflow
execution inside the server. MCP descriptors use the SDK's protocol models; this project
does not snapshot descriptor schemas, so this surface adds no committed schema change.

### Claude Code plugin

`plugins/vulnwitness/` is self-contained: a manifest, MCP wrapper, canonical
investigation Skill, restricted analyst and POSIX shell hook entry point. Other
clients reference the same Skill source. Both wrappers discover `VULNWITNESS_BIN`
or `vulnwitness` on PATH. The MCP server serves a private workspace at
`~/.vulnwitness/workspace`, overridden with `VULNWITNESS_WORKSPACE`. Demo mode
unsets operator data, snapshot identities and planner settings and disables
inherited semantic enablement. `VULNWITNESS_PLUGIN_REAL_DATA=1` preserves them.
The MCP server name yields `mcp__plugin_vulnwitness_vulnwitness__*` tools; the
analyst is restricted to that pattern and uses no agent-local server or hooks.

PostToolUse collects validated returned investigation IDs from JSON envelopes,
MCP text content and structuredContent. Both hooks share atomic, locked state at
`${CLAUDE_PLUGIN_DATA}/conversations/<Claude-session-id>.json`. They never parse
transcripts or scan modification times. Stop hashes session metadata, findings,
calls and responses as checker inputs, independently of report freshness. Only a
changed input set runs the CLI's existing layered checker. `bin/vulnwitness-hook`
shares executable discovery and demo isolation with `bin/vulnwitness-mcp` and runs
`vulnwitness hook record-investigation` or `vulnwitness hook check-on-stop`.
Hook logic uses the installed package's Python environment; the Stop command runs
`session check` in a bounded subprocess through the chosen CLI without loading a
deployment corpus. Successful executions save the digest, including failed check
layers, before returning a block decision. Unchanged inputs
and `stop_hook_active` do not block. A concurrent input change is retried on the
next Stop. Per-command and total budgets fit within the explicit hook timeout.

A missing CLI exits 0 with one stderr line. Other hook errors fail open and log
only their exception type under plugin data. Lock contention can skip an event;
investigations not returned by tools are outside
coverage. Checks cover record consistency, citation resolution and structured
claims, never narrative, source support, source authenticity, real-world truth or
deployed applicability. Local plugin validation and subprocess tests do not prove
client acceptance: response shape, hook firing and prompt/resource availability
remain for C5. The runbook documents loading, opt-in real data and disabling hooks.

Acceptance uses an isolated Claude Code run on demo data, followed by a manual owner pass.
The evidence covers discovery, triage, report delivery, tool-authored wrong citations and
claims, disk tampering, caps and failure handling. The stage passes only after that manual
pass. Other clients are claimed only after testing.

## Out of scope

C1 implements workspace storage, service, tools, recording inputs, supersession, schemas
and documentation. C2 implements resource and prompt handlers and their transport tests.
Skill and README integration, plugin and Stop-hook packaging, and client acceptance belong
to C3–C5. A router, built-in agent loop,
local UI, triage resume, arbitrary-path access, REST investigation writes, narrative
verification and source-authenticity guarantees are outside this decision's implementation.
