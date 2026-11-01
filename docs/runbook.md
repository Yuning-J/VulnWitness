# Operator runbook

See [architecture](architecture.md), [evaluation](evaluation.md) and [contracts](../schemas/v2/manifest.json).

## Install

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/). From a checkout:

```sh
uv sync --locked
source .venv/bin/activate
vulnwitness demo
```

`uv` can install Python. The locked checkout includes development, MCP, API and migration
dependencies. Core wheels keep integrations optional: `mcp`, `api`, `migration`, `semantic`.
Install the semantic extra separately in a checkout.

## Command reference

```sh
vulnwitness lookup CVE-9999-0001
vulnwitness search "authentication bypass" --graph-expand
vulnwitness product --vendor democorp --version 2.0 --format text
vulnwitness topic 5G-AKA --scope mixed
vulnwitness investigate 5G-AKA --scope mixed --format text
vulnwitness capabilities
vulnwitness resolve 5G-AKA
vulnwitness affectedness CVE-9999-0003 --purl pkg:generic/open5gs@2.7.0
vulnwitness evidence ev:d8097ae9c31b754d26a1ef92
vulnwitness investigate 5G-AKA --scope mixed > /data/vulnwitness/evidence-set.json
vulnwitness verify /data/vulnwitness/evidence-set.json
```

Create output directories first. Commands print JSON; lookup/search/investigation/product
also support `--format text`. Investigation exits 0 only for `ok`, otherwise 1 with
evidence; affectedness exits 1 with `unknown` / `blocked_unverified`. Product exits 0 for
records, 1 for empty.
Verify sets with matching sources/settings; keep them/model text out of version control.
Use `<command> --help` for scope/budgets. Repeatable search filters: vendor, product, purl,
CWE, severity, year and origin, plus `--kev-only`.
NVD has no purls: check `capabilities.purl_filter_available`; unsupported purl filters
fail as `filter_unsupported` (CLI 2, REST 422, MCP failure).
For product pagination repeat vendor, product, version and limit with `--cursor
<next_cursor>` until null; keep the corpus fixed. Pages default to 10, maximum 20.
Invalid/mismatched cursors fail (CLI 2, REST 422, MCP failure).

Lookup text shows catalogue paths and limits; search text shows word-match ranks, channel
outcomes and warnings. `product --vendor democorp --all --limit 20` traverses one fixed corpus,
printing a JSON array of unchanged `ProductQueryResponse` pages, each with its cursors
and evidence. `--max-pages` defaults to 100; an unfinished traversal exits 2 without
printing pages or publishing an export. `--output FILE --export csv|jsonl` exports every
matching CVE even without `--all`;
CSV excludes descriptions, JSONL keeps them. Multi-valued CSV cells contain JSON arrays;
version-note outcomes appear with `--version`. Exports publish atomically as 0600 files;
overwriting requires `--force`. Full traversal rejects `--cursor`; `--format text` cannot
accompany `--all` or `--output`.

## Configuration

Settings are startup-only `VULNWITNESS_*` variables; invalid settings are usage errors
naming the variable. Keep secrets in the environment, never arguments.

- `VULNWITNESS_STORE_ROOT`: absolute store root; unset selects the synthetic fixture.
- `VULNWITNESS_FIGHT_SNAPSHOT_PATH`, optional `VULNWITNESS_FIGHT_SNAPSHOT_SHA256`:
  [FiGHT file and pin](#the-operator-fight-snapshot).
- `VULNWITNESS_MITRE_SNAPSHOT_PATH`, optional `VULNWITNESS_MITRE_SNAPSHOT_SHA256`:
  [weakness mapping and pin](#weakness-association-mapping).
- `VULNWITNESS_PLANNER_*`: opt-in CLI/evaluation model; see
  [configuration](evaluation.md#optional-live-model-checks).
- `VULNWITNESS_SEMANTIC_*`: optional Chroma channel, disabled by default; requires an
  operator-named directory in the supported collection format, which this repo does
  not build. Imported stores report `collection_not_bound` for `--semantic` with
  `VULNWITNESS_SEMANTIC_ENABLED`; without the request the channel is `not_configured`.

### REST and MCP

```sh
export VULNWITNESS_HTTP_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
vulnwitness api
# Separate process: vulnwitness mcp --http; or use vulnwitness mcp for stdio.
curl -H "Authorization: Bearer $VULNWITNESS_HTTP_TOKEN" \
  -H 'Content-Type: application/json' -d '{"vendor":"democorp","limit":10}' \
  http://127.0.0.1:8766/api/v2/product
```

Run curl after readiness. HTTP needs a token. `VULNWITNESS_HTTP_HOST` defaults to `127.0.0.1`
(also `::1`); `VULNWITNESS_API_PORT` is 8766, `VULNWITNESS_MCP_HTTP_PORT` 8765 (`POST /mcp`).
Host/Origin guards restrict access to the configured loopback endpoint.
REST: `POST /api/v2/search`, `/api/v2/product`, `/api/v2/investigate`, `/api/v2/verify`;
`GET /api/v2/evidence/{evidence_id}`, `/api/v2/capabilities`. Bodies follow `schemas/v2/`.
`GET /health` alone is unauthenticated (204); authenticated `/ready` returns 204 while
a toolbox worker is free, otherwise 503. Servers use deterministic policy and never
open Chroma or call models. See the [MCP tools](architecture.md#interfaces).

## The store root

The root holds stores and `ACTIVE`; it must be a directory, not a symlink (parent links
are allowed). Serving is read-only; activation/rollback need writes.
Names are 1–64 letters/digits/`.`/`_`/`-`, starting alphanumeric; `ACTIVE` is case-insensitively
reserved. Commands do not print the root path.
`ACTIVE` pins active/previous manifests; replacing a named store requires activation.
Manifest, import and corpus identities identify stores/provenance; corpus binds replay/capabilities.

## Refresh a store

Keep feeds, manifests, stores, snapshots and outputs outside repositories under their
[data terms](../THIRD_PARTY_DATA.md). Create the store root first, then:

```sh
export VULNWITNESS_STORE_ROOT=/srv/vulnwitness/stores
.venv/bin/python scripts/operator/refresh_store.py \
  --feeds-dir ~/data/vulnwitness/feeds/2026-10-31 --store nvd-2026-10-31 --activate
```

Fetch downloads NVD 2.0 year feeds from 2002 through the current year, `modified` and
CISA KEV, paces/retries requests and verifies decompressed NVD feeds against `.meta`.
The feed download is about 270 MB; retry interrupted fetches into a fresh directory.
Only a complete fetch publishes `provenance.tsv` and `inputs.yaml`. Import uses a
fresh store name; failures stop before activation. Activation verifies the store
and preserves the previous store. Restart API/MCP after activation: there is no hot reload.
Use `--inputs /data/feeds/inputs.yaml` instead of `--feeds-dir` to reuse local feeds
without fetching. Omit `--activate` to keep `ACTIVE`; the command prints activation steps.
For a hand-managed manifest, `vulnwitness migrate legacy --inputs /data/feeds/inputs.yaml
--target /srv/vulnwitness/stores/nvd-2026-10-31 --dry-run` checks before importing;
remove `--dry-run` to write. Manifests declare raw NVD 1.1/2.0 and KEV CSV with acquisition
times. Import never overwrites targets or writes beside inputs; derived exports are refused.

```sh
vulnwitness store validate nvd-2026-10-31
vulnwitness store activate nvd-2026-10-31
vulnwitness store status
vulnwitness store rollback
```

Validate is read-only. Status exits 0 for an `ok` active store even if the previous
store is bad; it can verify both stores. Re-activating the active store re-verifies
it and preserves the previous store. Rollback verifies the recorded previous store,
makes it active and clears the previous slot: only one level. Restart services.
Unset `VULNWITNESS_STORE_ROOT` to serve synthetic fixtures again.

## Recovery and resource needs

Store failures exit 1 with a reason code; usage errors exit 2. Fix unusable roots
(`store_root_unusable`); re-import or activate another store for missing, changed,
invalid or unsupported stores (`store_missing`, `store_changed`, `store_invalid`,
`store_format_unsupported`). For `store_lock_held`, wait for activation/rollback.
For `active_write_failed`, check write permissions/space; `ACTIVE` is unchanged.
For `active_write_unconfirmed`, run status: replacement occurred but sync failed.
`no_previous_store` needs explicit activation. For `active_unreadable`, inspect the
JSON and move it aside manually only if this program should own the root; activation
and rollback refuse to overwrite it. This reader accepts store format 1. Before downgrading,
activate a store the target program can read; keep that store/program.

Configured roots must serve their active store or startup fails (exit 2), including
`no_active_store`, `active_store_missing` or `active_store_changed`; use status to diagnose.
Resolve, affectedness, migrate, store and schema do not load a served store; demo and
fixture-format evaluation use fixtures. All other data commands load the whole store.
For a full NVD corpus, expect minutes per startup/one-shot query, several GB of disk for
stores, feeds and rollback, and see the README for the recommended memory.
Keep servers running for repeated queries.
HTTP loads before binding: probes see connection refused meanwhile. MCP stdio answers
initialize/tools-list during loading; calls immediately fail `data_loading`, without
queuing/retry. Wait for readiness on stderr; load failures exit nonzero. Ctrl+C/closed
stdin stops stdio even during loading. Stdout remains JSON/protocol. Tool deadlines
stop waiting but cannot kill Python workers; CPU, memory and in-flight slots remain
occupied until they return. Large graph expansions can exhaust a tool deadline;
one-shot CLI search runs without that tool limit.

## The operator FiGHT snapshot

Unset, FiGHT serves the six-technique excerpt. For full coverage, fetch the `coverage:
full` entry pinned in `src/vulnwitness/knowledge/fight_snapshots.yaml`:

```sh
curl -fsSLo /srv/vulnwitness/fight.yaml \
  https://raw.githubusercontent.com/mitre/FiGHT/097cd5f73811dc34916ef84d5acc3fe7aba70450/fight.yaml
export VULNWITNESS_FIGHT_SNAPSHOT_PATH=/srv/vulnwitness/fight.yaml
```

Every load checks the computed SHA-256 against the reviewed catalog before parsing;
an optional expected digest adds a pin. Missing/non-regular/unreadable, oversized
(over 4 MiB), mismatched, uncatalogued or invalid files fail startup with
`fight_snapshot_*` reasons, never excerpt fallback. Another file needs catalog review.
The computed identity binds capabilities, evidence, evaluation and replay. Restart services.

## Weakness association mapping

Build from local official CWE XML, CAPEC XML and Enterprise ATT&CK STIX JSON. Pin
release versions/input SHA-256 in an operator inventory and verify it before building.
The builder reads without modifying inputs and contacts no service:

```sh
vulnwitness mitre build --cwe /data/cwec_v5.0.xml --capec /data/capec_latest.xml \
  --attack /data/enterprise-attack.json --out /data/weakness-mapping.json
export VULNWITNESS_MITRE_SNAPSHOT_PATH=/data/weakness-mapping.json
vulnwitness capabilities
vulnwitness lookup CVE-2026-12345
```

Use a fresh output path; overwrites/input paths are refused. Build prints size, digest,
link/inheritance counts and deprecated/revoked skip counts. To reproduce the
excerpt, use its `sources`-pinned full inputs and repeat `--cwe-id` for CWE-20, CWE-79,
CWE-787, CWE-284, CWE-269, CWE-78 and CWE-120; inheritance uses the full inputs.
Serving requires mapping format 2 and an absolute path. Optional
`VULNWITNESS_MITRE_SNAPSHOT_SHA256` must be lowercase and needs a path. Without a pin,
capabilities say “File identity recorded; no expected SHA-256 supplied.” With one,
“Compared with expected SHA-256.” Identity alone proves neither unchanged bytes nor
authenticity; MITRE has no reviewed catalog. Unset uses the manifest-pinned excerpt.
Non-regular, unreadable, oversized (over 32 MiB), invalid or mismatched files fail with
`mitre_snapshot_*`, never fallback. Restart after changing files/settings. See
[association limits](architecture.md#weakness-associations) and [bounded answers](architecture.md#bounded-investigation).

## One-command product triage

```sh
vulnwitness triage --vendor democorp --product demo_gateway --version 2.0 \
  --session /data/vulnwitness/triage --max-pages 20 --lookups 5 --time-limit 120
```

Supply vendor, product or both. Version is optional and is passed unchanged on every page.
The workflow records capabilities, follows product cursors and looks up selected CVEs using
the existing services. It writes `findings.yaml` with deterministic, unconfirmed workflow
claims for every inventoried CVE, plus version notes and returned lookup associations or
record facts. It then runs the ordinary session checker. It writes no narrative findings.

Defaults are 20 pages, 5 lookups (maximum 10), 120 seconds and 20 CVEs per page (`--limit`,
maximum 20). Before recording any call, the workflow reserves the worst-case call count:
`1 + max-pages + lookups`, or the number of `--select` IDs instead of `lookups`. It refuses
with exit 2 if that count exceeds `--session-call-limit` (default 100), even if the actual
inventory might fit. Reduce the caps to use a smaller session limit. Time is checked between
synchronous calls: an admitted call finishes and is recorded before the next deadline check.

Selection takes the first N by the stated order across the pages actually read:
`product_field` before `description_mention`; with a version, `hit`, `unknown`, then `no_hit`;
newest published first, with missing dates last; then CVE ID ascending. This is a traversal
and selection rule, with no severity or danger judgement. Repeat `--select CVE-…` to override
it in your supplied order. IDs must be unique, be in the read inventory and fit `--lookups`.
An ID on an unread page cannot be selected. `--lookups 0` records only the inventory.

The stdout summary and `triage.json` separately report inventory scope (pages, items,
`total_available`, traversal completion) and deep-dive scope (selected and looked-up IDs).
The artifact contains bookkeeping facts, caps hit and remaining planned steps, with no
vulnerability conclusions. `--format json` prints its exact JSON document. The summary
also reports the layered session check; rerun `vulnwitness session check DIR` for details.
Finished traversal describes only the served inventory, without establishing corpus
completeness, source support or deployed applicability.

Triage exit codes are `0` when the planned scope is complete and checks pass (reaching
`--lookups` is complete), `1` for a complete query with no matches, `2` for argument,
call, recording or check failures, and `3` for a page cap with unfinished inventory or
a time limit before planned lookups finish, with results saved and checks passing.
Failures take precedence over `3`. Exit `3` is non-zero for shells; automation that
accepts partial results should handle `0` and `3` explicitly and inspect `triage.json`
for the stop reason and remaining steps. `--lookups 0` completes after the inventory.
A service failure preserves completed calls and lists unexecuted steps. If a lookup
returns no catalogue paths or claimable record fields, `lookup_claim_unavailable`
exits 2. Every invocation requires a new or empty session directory; a non-empty
directory is refused with exit 2 without modifying its contents.

## Record and check a session

To share any CLI, MCP or triage session, run `vulnwitness report DIR --format html
--output DIR/report.html`, or choose `--format md` (the default). Rendering always checks
the session, reads only recorded content, adds no calls, and uses session timestamps for
deterministic output. The report separates consistency, citations, structured claims and
unchecked narrative; it does not establish narrative support or deployment affectedness.
An optional `triage.json` supplies scope context only. Output files are private (0600)
and written atomically; existing files require `--force`. Inside a session only an explicit
`DIR/report.*` destination is allowed. Without `--output`, the report goes to stdout.
Exit 0 means all three checked layers hold, 1 means a report rendered with a layer failure,
and 2 means unreadable session metadata, invalid arguments or an output failure. See
[ADR 0012](rebuild/adr/0012-session-reports.md) for the rendering boundary.

Add `--session DIR` to `lookup`, `search`, `product`, `investigate`, `topic`, `evidence`,
`affectedness`, `capabilities`, `resolve` or `verify`. Use JSON output; `--session` with
`--format text` is refused with exit 2 on lookup, search, product and investigate. The first call
creates private metadata, call logs and exact response files. Later calls must serve the
same corpus store and FiGHT/MITRE snapshots. Recorded commands load that complete dataset;
a changed identity refuses the call without appending anything.

```sh
vulnwitness product --vendor democorp --limit 1 --session /data/vulnwitness/session \
  --session-call-limit 20 --session-goal 'Review the selected product'
vulnwitness lookup CVE-9999-0007 --session /data/vulnwitness/session
vulnwitness session check /data/vulnwitness/session
vulnwitness session check /data/vulnwitness/session --format text
```

Use an ID actually returned by your product call for the lookup. The default session call
limit is 100. Set a smaller limit at creation with `--session-call-limit`; it cannot change
later. A refusal at the limit does not execute the call. Optional `--session-goal` and
`--session-scope` also set creation metadata. Recording failures withhold the answer.
Keep the directory outside the corpus store root and do not use a symlink.

With `product --all --session DIR`, each page is a separate recorded call, including its
validated request and cursor. The CLI prints the usual JSON array only when traversal
finishes. `--output FILE --export csv|jsonl --session DIR` records those same page calls,
even without `--all`, then publishes the export. The export file is not part of the
session record; keep it outside `DIR`. Saved responses are the individual JSON pages,
not the combined array or exported rows.

The session call limit applies per page. If it is reached mid-traversal, the command
exits 2 without executing or recording the refused page. Completed page calls remain;
no partial call, combined stdout or new export is written. Reaching `--max-pages` also
retains completed page calls and exits 2 without publishing output. An existing export
stays unchanged on either limit, including with `--force`.

For agents, start `vulnwitness mcp --session DIR`, or add `--http` for the authenticated HTTP
transport. Every dispatched tool call, failures included, is recorded. There is no tool
that edits findings. REST recording is unavailable.

Author `DIR/findings.yaml` separately from recording. The recorder never edits it. Start with:

```yaml
findings: []
selections:
  cve_ids: []
  product_queries: []
open_questions: []
```

A finding contains `id`, `author`, `kind`, `status` and `citations`. Deterministic kinds
require `claim`; omit `statement` to use its canonical rendering. An explicit statement
must match that rendering exactly. For example, after replacing the claim values and
evidence ID with fields and a complete anchor returned by the cited product page:

```yaml
findings:
  - id: review-1
    author: user
    kind: product_field_match
    claim:
      kind: product_field_match
      call: 1
      cve_id: CVE-9999-0001
      vendor: democorp
      product: demo_gateway
    status: unconfirmed
    citations:
      - call: 1
        evidence_id: 'ev:000000000000000000000000'
selections:
  cve_ids: []
  product_queries: []
open_questions: []
```

For each product query, `selections.product_queries` can hold `vendor`, `product`, `version`,
`calls` (page-call sequence numbers), `next_cursor` and `complete`. Save progress as you
follow the returned cursor. These fields and finding statuses are your declarations.
See the [session findings schema](../schemas/v2/session_findings.schema.json) for all kinds
and fields.

The six deterministic kinds are `product_field_match`, `description_mention`,
`version_note`, `catalogue_association`, `need_status`, and `record_fact`. Copy exact fields
from the named response. Catalogue claims include inheritance and every hop; version
claims include the exact mention and leave applicability unknown. A record fact selects
`published`, `cwe_ids`, `kev` or `cvss.base_severity` in a typed `fact` object. Missing
source fields are unverifiable. See [ADR 0010](rebuild/adr/0010-investigation-sessions.md)
for the field contract and canonical statement rule.

Authors are `user`, `agent` or `workflow`. Workflow findings must be deterministic and
`unconfirmed`; a user or agent takes authorship to confirm one. `model_judgement` and
`analyst_note` require free-text `statement` and no claim. Put interpretation in those kinds.

The JSON report has separate `record`, `citations`, `claims`, and `not_checked` layers.
Claims are `verified`, `contradicted` with the differing field, or `unverifiable` when the
call failed or a field is absent. `not_checked` lists the count and IDs of model and analyst
findings. Text output explains each layer and repeats that free narrative is not checked.
Exit 0 requires record consistency, resolved citations and every deterministic claim
verified; otherwise exit 1. A confirmed status supplies no verification. Agreement with
saved fields does not establish source support or real-world truth. Treat session contents
and source text as untrusted input.

## Workspace mode for agents

Start `vulnwitness mcp --workspace ROOT` for stdio, or add `--http` and the usual HTTP token
configuration. The server creates ROOT privately (0700), refuses symlink roots and roots
inside the configured store, and cannot combine `--workspace` with `--session`.
`--workspace-limit` defaults to 200 investigations; `--session-call-limit` lowers the
per-investigation default of 100 calls. Prune old investigations when the workspace is full.

Use `triage_product` for bounded product triage or `start_investigation` for manual work.
Keep the returned opaque `session_id`. Pass a client-chosen `request_key` on creation when
you need safe retries: the same normalized arguments and served dataset return the same
investigation without rerunning; different arguments or dataset return a conflict.

Read `get_investigation` for workflow, record and report status. Triage outcomes are
`complete`, `stopped_at_cap`, `no_match` or `failed`; inspect remaining steps and check layers.
An interrupted triage cannot accept appends or resume. Start another investigation.
`investigation_busy` and `workspace_busy` mean another operation holds the relevant lock;
retry later. `list_investigations` includes unindexed creations as orphans.

Knowledge calls reach the record only when supplied with `session_id`. `read_call` returns
the exact saved JSON text and metadata; responses over 1 MiB return metadata and a size
failure. Source text is untrusted. No tool accepts a file path.

Submit findings through `add_findings`, with a client ID for each entry. The server fixes
the author to `agent`. Identical retries are no-ops; conflicting IDs and shape errors reject
the whole batch. Wrong citations and structured claims are written with failing checks:
`written: true` does not mean passed. Use a new ID with `supersedes` to revise an earlier
effective finding; the original stays in the file, and checks and reports count it as
superseded.

Run `check_investigation`, then `render_report` with `format: html` or `md`. The report tool
returns a local path, resource URI, byte size, digest and check layers; Markdown below
200 KiB is inline. Reports perform no retrieval. Later calls or findings make the report
`stale`; render again for a `current` report. Checks distinguish record consistency, citation resolution and structured field
agreement. Free narrative, real-world truth and deployment applicability are not checked.

Workspace mode also advertises resources and three prompt templates; read-only and recording
modes advertise tools only. List resources to discover topic cards, contract schemas and
this workspace's investigation summaries, findings and rendered reports:

| URI | MIME type |
|---|---|
| `vulnwitness://topics/{topic_id}` | `text/yaml` |
| `vulnwitness://schemas/{name}.schema.json` | `application/json` |
| `vulnwitness://investigations/{id}/summary` | `application/json` |
| `vulnwitness://investigations/{id}/findings` | `text/yaml` |
| `vulnwitness://investigations/{id}/report.html` | `text/html` |
| `vulnwitness://investigations/{id}/report.md` | `text/markdown` |

Topic cards preserve the packaged YAML bytes, and their descriptions state review status.
All descriptions state dataset identity and label source text untrusted. Investigation
resources use the same opaque ID and workspace path rules as tools; paths are never accepted.
Reports appear only after rendering. A stale report stays readable, with its description
marked stale; rendering one format does not refresh an older report in the other format.

Saved calls are available through the resource template
`vulnwitness://investigations/{id}/calls/{n}`, where `n` is 1 through 100. They are not listed
individually. The JSON content matches `read_call`, including metadata and exact saved
response text; above 1 MiB it contains metadata and `response_too_large`, without response
text. An unknown investigation returns a resource-not-found JSON-RPC error whose message
is typed `ToolFailure` JSON with `code: unknown_investigation`. Invalid IDs return invalid
params with `code: invalid_arguments`.

Choose `triage_product(product, version?)`, `investigate_topic(topic, scope)` or
`deliver_report(session_id)` from the client's MCP prompts. These render instructions;
the agent must execute the named tools. Required arguments cannot be omitted. Each prompt
calls for recorded follow-up knowledge calls, findings, layered checks, rendering and report
delivery, with explicit limits on what is established. A passing check is never a verified
answer. In Claude Code the interactive forms are `/server:prompt` and `@server:uri`;
use the actual server name shown by that client. Headless prompt and resource presentation
requires separate client acceptance testing.

## Claude Code plugin

Install VulnWitness from a checkout (`uv sync --locked`) and either put `vulnwitness` on
`PATH` or set `VULNWITNESS_BIN=<checkout>/.venv/bin/vulnwitness`. From the repository
root, test locally with:

```sh
claude --plugin-dir plugins/vulnwitness
```

Status: **acceptance in Claude Code pending**. This session-local command needs no
global settings changes. The self-contained plugin can also be installed through
Claude Code's plugin manager once distributed through a plugin marketplace.
The canonical Skill is `plugins/vulnwitness/skills/vulnwitness-investigation/`;
direct MCP clients use that same source and their adjacent `mcp-config/` snippets.
The plugin registers server `plugin:vulnwitness:vulnwitness` and tools prefixed
`mcp__plugin_vulnwitness_vulnwitness__`. Its analyst has access only to those tools.

The executable is `VULNWITNESS_BIN`, or `vulnwitness` on PATH. The workspace defaults
to `$HOME/.vulnwitness/workspace`; set `VULNWITNESS_WORKSPACE` to an absolute private
path outside any store root to override it. The wrapper unsets store and snapshot
paths, snapshot identities, planner variables and semantic enablement, serving
packaged synthetic demo data reproducibly. To use operator-configured real data,
set `VULNWITNESS_PLUGIN_REAL_DATA=1` before starting Claude Code; this preserves
those environment settings. The check command reads saved records without loading
the store, even in real-data mode.

PostToolUse extracts returned investigation IDs from this plugin's tool responses
into `${CLAUDE_PLUGIN_DATA}/conversations/<Claude-session-id>.json`. It accepts JSON
objects/strings, MCP text content and structuredContent defensively; live response
shape and hook firing still require C5 acceptance. Neither hook parses transcripts
or scans modification times. Stop checks only recorded IDs whose input digest
changed, binding session metadata, findings, calls and response bytes. Digests are
private hook freshness markers, separate from report freshness digests. It runs
`vulnwitness session check <workspace>/<id> --format json` using the same binary
discovery as the wrapper, reusing the package's checker without importing it into
the standard-library-only hooks. Each command has a 15-second limit, with a
45-second total check budget and a 60-second Claude hook timeout.

Failed layers block once per changed record, naming the investigation, layers
and up to five violations. The digest is saved before blocking; an unchanged Stop
cannot block again. `stop_hook_active` also prevents continuation loops. Missing
executables, malformed inputs, concurrent state locks and other hook errors fail
open and log their exception type to `${CLAUDE_PLUGIN_DATA}/hooks.log`; failed
executions do not advance the checked digest. State locks wait at most one second; a longer contention can skip an event.
The checker subprocess does not hold the conversation lock.
These checks cover the record, citations and structured claims; they do not verify narrative.
Passing checks do not establish source support, source authenticity, real-world
truth or deployed applicability. Unreturned investigation IDs are outside hook
coverage. Other clients have no hook and must explicitly check before delivery.

To disable both hooks, set `plugins/vulnwitness/hooks/hooks.json` to
`{"hooks": {}}` in a local plugin copy and restart Claude Code with that copy.
Loading the direct MCP snippet instead of the plugin also omits them.
