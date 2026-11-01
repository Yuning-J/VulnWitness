# Operator runbook

See [architecture](architecture.md), [evaluation](evaluation.md) and [contracts](../schemas/v2/manifest.json).

## Install

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/). From a checkout:

```sh
uv sync --locked
source .venv/bin/activate
cve-kgrag demo
```

`uv` can install Python. The locked checkout includes development, MCP, API and migration
dependencies. Core wheels keep integrations optional: `mcp`, `api`, `migration`, `semantic`.
Install the semantic extra separately in a checkout.

## Command reference

```sh
cve-kgrag lookup CVE-9999-0001
cve-kgrag search "authentication bypass" --graph-expand
cve-kgrag product --vendor democorp --version 2.0 --format text
cve-kgrag topic 5G-AKA --scope mixed
cve-kgrag investigate 5G-AKA --scope mixed --format text
cve-kgrag capabilities
cve-kgrag resolve 5G-AKA
cve-kgrag affectedness CVE-9999-0003 --purl pkg:generic/open5gs@2.7.0
cve-kgrag evidence ev:d8097ae9c31b754d26a1ef92
cve-kgrag investigate 5G-AKA --scope mixed > /data/cve-kgrag/evidence-set.json
cve-kgrag verify /data/cve-kgrag/evidence-set.json
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

Settings are startup-only `CVE_KGRAG_*` variables; invalid settings are usage errors
naming the variable. Keep secrets in the environment, never arguments.

- `CVE_KGRAG_STORE_ROOT`: absolute store root; unset selects the synthetic fixture.
- `CVE_KGRAG_FIGHT_SNAPSHOT_PATH`, optional `CVE_KGRAG_FIGHT_SNAPSHOT_SHA256`:
  [FiGHT file and pin](#the-operator-fight-snapshot).
- `CVE_KGRAG_MITRE_SNAPSHOT_PATH`, optional `CVE_KGRAG_MITRE_SNAPSHOT_SHA256`:
  [weakness mapping and pin](#weakness-association-mapping).
- `CVE_KGRAG_PLANNER_*`: opt-in CLI/evaluation model; see
  [configuration](evaluation.md#optional-live-model-checks).
- `CVE_KGRAG_SEMANTIC_*`: optional Chroma channel, disabled by default; requires an
  operator-named directory in the supported collection format, which this repo does
  not build. Imported stores report `collection_not_bound` for `--semantic` with
  `CVE_KGRAG_SEMANTIC_ENABLED`; without the request the channel is `not_configured`.

### REST and MCP

```sh
export CVE_KGRAG_HTTP_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
cve-kgrag api
# Separate process: cve-kgrag mcp --http; or use cve-kgrag mcp for stdio.
curl -H "Authorization: Bearer $CVE_KGRAG_HTTP_TOKEN" \
  -H 'Content-Type: application/json' -d '{"vendor":"democorp","limit":10}' \
  http://127.0.0.1:8766/api/v2/product
```

Run curl after readiness. HTTP needs a token. `CVE_KGRAG_HTTP_HOST` defaults to `127.0.0.1`
(also `::1`); `CVE_KGRAG_API_PORT` is 8766, `CVE_KGRAG_MCP_HTTP_PORT` 8765 (`POST /mcp`).
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
export CVE_KGRAG_STORE_ROOT=/srv/cve-kgrag/stores
.venv/bin/python scripts/operator/refresh_store.py \
  --feeds-dir ~/data/cve-kgrag/feeds/2026-10-31 --store nvd-2026-10-31 --activate
```

Fetch downloads NVD 2.0 year feeds from 2002 through the current year, `modified` and
CISA KEV, paces/retries requests and verifies decompressed NVD feeds against `.meta`.
The feed download is about 270 MB; retry interrupted fetches into a fresh directory.
Only a complete fetch publishes `provenance.tsv` and `inputs.yaml`. Import uses a
fresh store name; failures stop before activation. Activation verifies the store
and preserves the previous store. Restart API/MCP after activation: there is no hot reload.
Use `--inputs /data/feeds/inputs.yaml` instead of `--feeds-dir` to reuse local feeds
without fetching. Omit `--activate` to keep `ACTIVE`; the command prints activation steps.
For a hand-managed manifest, `cve-kgrag migrate legacy --inputs /data/feeds/inputs.yaml
--target /srv/cve-kgrag/stores/nvd-2026-10-31 --dry-run` checks before importing;
remove `--dry-run` to write. Manifests declare raw NVD 1.1/2.0 and KEV CSV with acquisition
times. Import never overwrites targets or writes beside inputs; derived exports are refused.

```sh
cve-kgrag store validate nvd-2026-10-31
cve-kgrag store activate nvd-2026-10-31
cve-kgrag store status
cve-kgrag store rollback
```

Validate is read-only. Status exits 0 for an `ok` active store even if the previous
store is bad; it can verify both stores. Re-activating the active store re-verifies
it and preserves the previous store. Rollback verifies the recorded previous store,
makes it active and clears the previous slot: only one level. Restart services.
Unset `CVE_KGRAG_STORE_ROOT` to serve synthetic fixtures again.

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
full` entry pinned in `src/cve_kgrag/knowledge/fight_snapshots.yaml`:

```sh
curl -fsSLo /srv/cve-kgrag/fight.yaml \
  https://raw.githubusercontent.com/mitre/FiGHT/097cd5f73811dc34916ef84d5acc3fe7aba70450/fight.yaml
export CVE_KGRAG_FIGHT_SNAPSHOT_PATH=/srv/cve-kgrag/fight.yaml
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
cve-kgrag mitre build --cwe /data/cwec_v5.0.xml --capec /data/capec_latest.xml \
  --attack /data/enterprise-attack.json --out /data/weakness-mapping.json
export CVE_KGRAG_MITRE_SNAPSHOT_PATH=/data/weakness-mapping.json
cve-kgrag capabilities
cve-kgrag lookup CVE-2026-12345
```

Use a fresh output path; overwrites/input paths are refused. Build prints size, digest,
link/inheritance counts and deprecated/revoked skip counts. To reproduce the
excerpt, use its `sources`-pinned full inputs and repeat `--cwe-id` for CWE-20, CWE-79,
CWE-787, CWE-284, CWE-269, CWE-78 and CWE-120; inheritance uses the full inputs.
Serving requires mapping format 2 and an absolute path. Optional
`CVE_KGRAG_MITRE_SNAPSHOT_SHA256` must be lowercase and needs a path. Without a pin,
capabilities say “File identity recorded; no expected SHA-256 supplied.” With one,
“Compared with expected SHA-256.” Identity alone proves neither unchanged bytes nor
authenticity; MITRE has no reviewed catalog. Unset uses the manifest-pinned excerpt.
Non-regular, unreadable, oversized (over 32 MiB), invalid or mismatched files fail with
`mitre_snapshot_*`, never fallback. Restart after changing files/settings. See
[association limits](architecture.md#weakness-associations) and [bounded answers](architecture.md#bounded-investigation).

## Record and check a session

Add `--session DIR` to `lookup`, `search`, `product`, `investigate`, `topic`, `evidence`,
`affectedness`, `capabilities`, `resolve` or `verify`. Use JSON output; `--session` with
`--format text` is refused with exit 2 on lookup, search, product and investigate. The first call
creates private metadata, call logs and exact response files. Later calls must serve the
same corpus store and FiGHT/MITRE snapshots. Recorded commands load that complete dataset;
a changed identity refuses the call without appending anything.

```sh
cve-kgrag product --vendor democorp --limit 1 --session /data/cve-kgrag/session \
  --session-call-limit 20 --session-goal 'Review the selected product'
cve-kgrag lookup CVE-9999-0007 --session /data/cve-kgrag/session
cve-kgrag session check /data/cve-kgrag/session
cve-kgrag session check /data/cve-kgrag/session --format text
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

For agents, start `cve-kgrag mcp --session DIR`, or add `--http` for the authenticated HTTP
transport. Every dispatched tool call, failures included, is recorded. There is no tool
that edits findings. REST recording is unavailable.

Author `DIR/findings.yaml` yourself. The server never creates or edits it. Start with:

```yaml
findings: []
selections:
  cve_ids: []
  product_queries: []
open_questions: []
```

A finding contains `id`, `statement`, `kind`, `status` and `citations`. For example, after
replacing the evidence ID with a complete anchor returned by the cited call:

```yaml
findings:
  - id: review-1
    statement: 'The selected product appears in the returned product fields.'
    kind: product_field_match
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

The checker validates files and resolves each citation only within its cited successful
call and dataset. It exits 0 on success and 1 with located violations otherwise. It does
not establish that a statement is supported by its evidence. Narrative support is never
established by IDs alone. Treat session contents and source text as untrusted input.
