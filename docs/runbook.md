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
vulnwitness lookup CNVD-2026-12345 --format text
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
outcomes and warnings. A CNVD ID resolves to its CVE record or pending entry when imported;
entries without a well-formed CVE ID are not retained ([ADR 0015](rebuild/adr/0015-cnvd-entries.md)).
Each authority's raw grade is shown with its scheme, assessing body and provenance. An NVD
record may carry a CNA score; only NVD's own CVSS v3.1, else v3.0, participates in
`cnvd_grade_vs_nvd_own_cvss3`. The neutral mark means CNVD grades higher under a named
VulnWitness mapping; same and lower grades stay plain text. Reports count distinct CVEs
from recorded lookups, naming the dataset and denominator: higher grades out of compared
CVEs, NVD record gaps (no servable record), score gaps (a record without an NVD-owned CVSS
v3 metric), and awaiting-analysis and deferred status separately. Status does not imply
a missing score. These signals change no triage order, selection or checker verdict.
CVSS measures severity, not risk. CNVD text stays in its original language; the core flow
does no translation, and clients and browsers can translate it.

Each CNVD entry's name check compares its extracted title name with NVD's CPE vendor and
product names. Overlap is evidence for review; no overlap asks for link review, and an
uncheckable label explains the missing input. The label never changes a grade or a link.
See [ADR 0017](rebuild/adr/0017-cnvd-name-check.md#context) for the measured shares and
sample findings; most differences are naming or scope differences, not wrong links.

`product --vendor democorp --all --limit 20` traverses one fixed corpus,
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
It also downloads both CIRCL CNVD Parquet files (about 25 MB) at the pinned revision
`986160c9b1c910049f64a166ab4056de191f6de7`, verifying each SHA-256 against
`src/vulnwitness/knowledge/cnvd_snapshots.yaml` ([ADR 0015](rebuild/adr/0015-cnvd-entries.md#8-fetching)).
The NVD/KEV download is about 270 MB; retry interrupted fetches into a fresh directory.
Only a complete fetch publishes `provenance.tsv` and `inputs.yaml`. Import uses a
fresh store name; failures stop before activation. Activation verifies the store
and preserves the previous store. Restart API/MCP after activation: there is no hot reload.
Use `--inputs /data/feeds/inputs.yaml` instead of `--feeds-dir` to reuse local feeds
without fetching. Omit `--activate` to keep `ACTIVE`; the command prints activation steps.
For a hand-managed manifest, `vulnwitness migrate legacy --inputs /data/feeds/inputs.yaml
--target /srv/vulnwitness/stores/nvd-2026-10-31 --dry-run` checks before importing;
remove `--dry-run` to write. Manifests declare raw NVD 1.1/2.0, KEV CSV and each CNVD
Parquet file with acquisition times. CNVD declarations must cover both files of one
catalogued revision. Import never overwrites targets or writes beside inputs; derived exports are refused.

The migration report counts each CNVD row under one of six join outcomes:

| Outcome | Meaning |
|---|---|
| `merged` | Attached to a servable NVD record |
| `cnvd_without_nvd_record` | No NVD candidate; kept pending |
| `cnvd_for_rejected_nvd_record` | NVD winner rejected; kept pending |
| `cnvd_for_excluded_nvd_record` | NVD CVE excluded by import; kept pending |
| `cnvd_without_cve_id` | Empty CVE ID; not stored |
| `cnvd_unrecognised_cve_id` | Other CVE ID text; not stored |

A pending entry has a well-formed CVE ID but no servable NVD record. Every import rebuilds
from all its inputs; the entry joins on a later import whose NVD input supplies a servable
record for that CVE. Refresh preserves each authority's grade and provenance; CNVD grading
higher under a named VulnWitness mapping and the separate record, score and status gaps
are descriptive signals, not a priority policy. CVSS measures severity, not risk. The core
flow does no translation; clients and browsers can translate the original CNVD text.

## Raw CNVD research input

Raw CNVD records from CIRCL Vulnerability-Lookup are an opt-in research input with an
unverified data licence ([ADR 0018](rebuild/adr/0018-cnvd-raw-research-input.md)). Keep
them outside repositories and build a store under a separate research root:

```sh
.venv/bin/python scripts/operator/fetch_raw_cnvd.py base ~/data/vulnwitness/feeds/cnvd-raw
.venv/bin/python scripts/operator/fetch_raw_cnvd.py increment ~/data/vulnwitness/feeds/cnvd-raw
.venv/bin/python scripts/operator/fetch_raw_cnvd.py manifest ~/data/vulnwitness/feeds/cnvd-raw \
  --inputs /data/feeds/nvd-kev-only.yaml --output ~/data/vulnwitness/feeds/cnvd-raw/inputs.yaml
mkdir -p ~/data/vulnwitness/stores-cnvd-raw
VULNWITNESS_STORE_ROOT=~/data/vulnwitness/stores-cnvd-raw \
  .venv/bin/python scripts/operator/refresh_store.py \
  --inputs ~/data/vulnwitness/feeds/cnvd-raw/inputs.yaml --store research-2026-11-09 --activate
```

`base` streams one dump into a temporary file, validates its NDJSON and renames it only
when complete. It refuses a directory that already holds a base. `increment` reads the
latest `openTime` recorded across the base and all earlier runs in `provenance.tsv`,
queries from that date minus one day, and requests pages of 100 in ascending updated
order until a short page. All attempts are spaced by at least one second. A 429 or 5xx
gets one retry, respecting `Retry-After` (seconds or HTTP date); other non-200 statuses,
invalid JSON and interruptions fail without a partial run file or provenance row.
SIGINT/SIGTERM are handled; an uncatchable kill or power loss may require removing a
stale `.fetch.lock` and temporary files after checking that no fetch process remains.

Each successful run adds a provenance row with retrieval time, SHA-256, byte and record
counts, high-water date, request/429 counts and elapsed seconds. Base rows also retain
the URL, Last-Modified and ETag; increment rows retain the query template, `since` and
page count. Nonempty increments use retrieval-time filenames. A zero-record run adds a
row with an empty filename, zero bytes and the empty-stream SHA-256, and writes no NDJSON.
The base is downloaded once; increments run only when an operator requests them.
Nothing is scheduled. CIRCL maps `openTime` to updated: increments cannot see CNVD edits
made after that date. A new base download needs the owner's decision.

`manifest --inputs EXISTING --output NEW` combines existing NVD/KEV entries with the
base and nonempty increments in retrieval order, each with its recorded `retrieved_at`.
It resolves all paths to absolute paths, so NEW can live in a different directory, and
refuses an existing output or any CNVD source already in EXISTING, including `circl-cnvd`.
For a manifest containing pinned CNVD, first write an NVD/KEV-only copy, preserving the
original file and resolving each retained path relative to its original manifest directory.

The raw source is `vulnerability-lookup-cnvd`, used instead of `circl-cnvd`; combining
them is refused. Import pins every file by SHA-256 and replaces the whole earlier record
when a later input has the same CNVD ID. Raw fields are untrusted source text; the name
check still uses the title. Full API records use the same retained-field object shape as
dump lines, with different optional metadata keys; increments serialize each record
directly as one NDJSON line, with no wrapper or light-mode query. Both outer `cves` and
inner `cve` values can be an object or list. Null `formalWay` means absent advice. Raw
records lacking both a CVE link and `serverity` count as `cnvd_without_cve_id` and are
never served; a linked record still requires a valid grade.
Use the research root for every activation and serving command; the command-scoped
environment assignment above leaves the default root untouched. For several checks
with one store load, use the documented MCP workspace process below.

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
HTTP loads before binding: probes see connection refused meanwhile, preserving its
ready-notice and authenticated readiness semantics. In all modes, MCP stdio answers
initialize/tools-list during loading; calls other than `wait_for_data` immediately fail
`data_loading`, without queuing or automatic retry. Use `wait_for_data` for readiness;
load failures exit nonzero. Ctrl+C/closed
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

Stdio recording answers initialization and tool discovery before loading the store.
Knowledge calls during loading return the typed, retryable `data_loading` failure immediately;
they are never recorded or queued. The recorder binds to the complete dataset identity
only when loading succeeds. Use `wait_for_data`, then retry calls once ready. Loading
failures report the reason and exit nonzero. HTTP recording loads before binding, so
its ready notice continues to mean the data plane is available.

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

## Prioritise a session

Record one capabilities call and exact CVE lookups, then supply an analyst-authored asset
register and an explicit reference date. The [example register](examples/priority-assets.yaml)
describes a fictional vehicle with synthetic CVEs; replace its assets and assessments for
your investigation. Every affected or not-affected assessment needs a concrete justification,
an assessor and an assessment date. Unknown applicability is never treated as not affected.

```sh
vulnwitness capabilities --session /data/vulnwitness/priority-session
vulnwitness lookup CVE-9999-0001 --session /data/vulnwitness/priority-session
vulnwitness lookup CVE-9999-0002 --session /data/vulnwitness/priority-session
vulnwitness lookup CVE-9999-0003 --session /data/vulnwitness/priority-session
vulnwitness prioritise /data/vulnwitness/priority-session \
  --assets docs/examples/priority-assets.yaml --policy cn-auto-demo --as-of 2026-11-09
vulnwitness report /data/vulnwitness/priority-session --format html \
  --output /data/vulnwitness/priority-report.html
```

Individual recording commands load the complete store each time. For several lookups on
a large store, use one `vulnwitness mcp --workspace ROOT` process, wait for readiness, call
`start_investigation`, then `get_knowledge_capabilities` and `lookup_cve` with its returned
`session_id`. That process reuses one loaded dataset. The session directory is
`ROOT/SESSION_ID`; run the same offline `prioritise` and `report` commands on it. Neither
command loads a store or calls a service. Keep real records and registers outside the repo.

The command atomically writes `SESSION/priority.json`; `--force` replaces an existing
artifact. It prints each (asset, CVE) recommendation, matched rule and separate compliance
status. The report and the investigation page's Records view show the policy name, format
version and digest, register digest, reference date and after-reference-date flag. Each
decision includes its reason, matched conditions, facts and evidence IDs, unknown facts,
notes, and every earlier unmatched rule's failed conditions under “What would change this”.
An invalid artifact appears as a check finding and is not displayed as decisions. Later
recordings do not recompute decisions; rerun `prioritise --force` when inputs change.

`act`, `attend`, `track` and `manual_triage_required` are VulnWitness policy recommendations,
not compliance conclusions. GB 44495 status stays `basis_insufficient` for in-scope assets
without authoritative-platform data: the platform record, grade, publication date,
reference date and handling evidence remain required basis. CNVD grades are triage reference
and do not substitute for that platform. KEV `not_listed_in_snapshot` means only that the CVE
was not listed in the imported snapshot, never “not exploited”. The reference date does not
reconstruct history; the artifact flags evidence retrieved after it. See
[ADR 0016](rebuild/adr/0016-priority-decisions.md) for rule order and limits.

## Workspace mode for agents

Start `vulnwitness mcp --workspace ROOT` for stdio, or add `--http` and the usual HTTP token
configuration. Once the dataset is ready, the server creates ROOT privately (0700).
Before loading, it refuses symlink roots and roots
inside the configured store, and cannot combine `--workspace` with `--session`.
`--workspace-limit` defaults to 200 investigations; `--session-call-limit` lowers the
per-investigation default of 100 calls. Prune old investigations when the workspace is full.

Stdio initializes and lists tools, resources, resource templates and prompts while the
store loads. Topic-card and schema resources are readable then. Every knowledge and
investigation tool, and every investigation-resource read, immediately returns the typed,
retryable `data_loading` failure until the stderr `ready after` notice. Nothing is queued,
no investigation or call is saved, and request keys are not consumed; retry the same key
once ready. Dataset identity binds when loading succeeds. HTTP workspace mode loads
before binding to preserve its readiness semantics.

After `data_loading`, call `wait_for_data(timeout_seconds?)` (default 20, range 1–60),
then retry the original request with its original `request_key` once ready; while loading,
do not spin on request retries or create an investigation with a new key. Expiry returns
`loading`, not failure, and waiting does not shorten loading; a client's own tool-call
timeout may be shorter than 60 seconds.

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

Status: tested with Claude Code 2.1.316 through `--plugin-dir`, including both hooks,
real-data loading with `wait_for_data`, and interactive prompts and resources. This session-local command needs no
global settings changes. The self-contained plugin can also be installed through
Claude Code's plugin manager once distributed through a plugin marketplace.
The canonical Skill is `plugins/vulnwitness/skills/vulnwitness-investigation/`;
direct MCP clients use that same source and their adjacent `mcp-config/` snippets.
The plugin registers server `plugin:vulnwitness:vulnwitness` and tools prefixed
`mcp__plugin_vulnwitness_vulnwitness__`. Its analyst has access only to those tools.

A real-data first start takes minutes. The stdio server answers initialization and
discovery immediately; knowledge and investigation tools answer `data_loading` until the
store is ready. Loading refusals create no investigation or
call and do not consume a request key. Topic cards, schemas and prompt templates remain
available during loading; investigation resources return `data_loading`.

After `data_loading`, call `wait_for_data` (default 20 seconds, range 1–60), then retry
the original request with its original `request_key` once ready; while loading, do not
spin on request retries or create an investigation with a new key. Expiry returns
`loading`, not failure, and waiting does not shorten loading; a client's own tool-call
timeout may be shorter than 60 seconds.

The executable is `VULNWITNESS_BIN`, or `vulnwitness` on PATH. The workspace defaults
to `$HOME/.vulnwitness/workspace`; set `VULNWITNESS_WORKSPACE` to an absolute private
path outside any store root to override it. Both shell wrappers unset store and
snapshot paths, snapshot identities, planner variables and semantic enablement, serving
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
private hook freshness markers, separate from report freshness digests. The POSIX
shell entry point `bin/vulnwitness-hook` uses the same executable discovery and demo
isolation as `bin/vulnwitness-mcp`, then runs `vulnwitness hook record-investigation`
or `vulnwitness hook check-on-stop` with JSON from stdin. Hook logic runs in the
installed package's Python environment. Stop runs
`vulnwitness session check <workspace>/<id> --format json` through that CLI.
Each checker command has a 15-second limit, with a 45-second total check budget
and a 60-second Claude hook timeout.

Failed layers block once per changed record, naming the investigation, layers
and up to five violations. The digest is saved before blocking; an unchanged Stop
cannot block again. `stop_hook_active` also prevents continuation loops. Missing
executables fail open with one stderr line and exit 0. Malformed inputs, concurrent
state locks and other hook errors fail open and log their exception type to
`${CLAUDE_PLUGIN_DATA}/hooks.log`; failed executions do not advance the checked
digest. State locks wait at most one second; a longer contention can skip an event.
The checker subprocess does not hold the conversation lock.
These checks cover the record, citations and structured claims; they do not verify narrative.
Passing checks do not establish source support, source authenticity, real-world
truth or deployed applicability. Unreturned investigation IDs are outside hook
coverage. Other clients have no hook and must explicitly check before delivery.

To disable both hooks, set `plugins/vulnwitness/hooks/hooks.json` to
`{"hooks": {}}` in a local plugin copy and restart Claude Code with that copy.
Loading the direct MCP snippet instead of the plugin also omits them.

## Local browser UI

Install from a checkout with `uv sync --locked` ([Install](#install)), then run:

```sh
vulnwitness ui --workspace ~/.vulnwitness/workspace --port 8767
```

Both flags are optional with the defaults above. Open the printed URL, including its
fragment token. The UI binds to 127.0.0.1 only. Each launch generates a different token;
keep the printed URL private. The page removes the fragment after saving it in tab
session storage and sends Authorization headers for all data requests and mutations.
Host and Origin allowlists refuse other origins; no cookie or CORS access is enabled.
Do not put this server behind a public proxy.

The page and list answer immediately while data loads. Controls enable after the
readiness wait completes. Loading uses the same settings and data plane as
`vulnwitness mcp --workspace`: packaged synthetic demo data unless store variables
are configured. No model or semantic channel is served. Loading failure stops the
process with exit 1; retry after correcting the deployment settings.

Choose Product (required product, optional vendor/version), CVE, or Topic with an
explicit implementation/protocol/mixed scope. Product submissions run recorded,
bounded triage. Refreshes and retries reuse a saved submission key; choose **New
submission** for another investigation with identical values. CVE/topic submissions
start a manual investigation and record its initial lookup/investigate call. Saved
investigations appear with workflow/report status and dataset identity. The browser
shows escaped source text and the report's existing evidence and uncertainty wording.

Open an investigation to inspect records, saved call JSON, inventory/deep-dive scope,
follow-up CVE lookups and check layers. Busy or interrupted investigations return the
backend's typed message. **Render HTML report** renders and opens the saved report
at an ID-addressed URL. **Open HTML report / export** opens it again if needed. Use the browser's **Save Page As** to export its
self-contained HTML. Report navigation uses a read-only form POST with the launch
token in its bounded body, because browser navigation cannot set Authorization;
it still passes the Host/Origin guard and requires the token before reading a file.
The server reads only that investigation's fixed report file. A later recorded call
makes the HTML report stale; re-render to refresh it. Rendering Markdown in another client does
not refresh this HTML report. Checks cover record consistency, citation resolution
and structured field agreement. Free narrative is never checked; passing checks do
not establish source support, source authenticity, real-world truth or applicability.
