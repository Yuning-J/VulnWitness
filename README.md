# telecom-cve-kgrag

A telecom-focused, evidence-bound CVE and threat-context investigation system: a bounded,
auditable investigation agent whose evidence authority stays deterministic. A model planner
may propose the next tool calls; whether the evidence answers a question, when to stop and
what an answer may claim are decided by deterministic code. Topics come from an
extensible, review-governed topic registry. The first topic card is 5G-AKA. It is marked
`pending_review` while the design is experimental: it was checked against 3GPP TS 33.501
V19.7.0 but has no named reviewer, so every answer that uses it says so.

Every answer cites evidence: a claim that no served record supports is not returned. CVE
evidence and protocol threat context (MITRE FiGHT, topic cards) stay separate,
so CVE evidence cannot be relabelled to support a protocol-context claim.

Status: pre-release. The contracts are at `2.0.0-dev.45` and may change between versions
without a deprecation window. The roadmap is in [`docs/rebuild/PLAN.md`](docs/rebuild/PLAN.md).

Known limit: the current version does not judge free-text results sufficient
automatically. A free-text investigation (one that names no CVE ID and resolves no reviewed
topic) lists the CVEs and techniques that match the question's words and ends
`needs_unmet` / `partial`, each such need `matches_unassessed`: matches were found and
their relevance was not assessed, which does not mean no relevant evidence exists. Read the
candidates and the terms each matched before relying on them. An investigation ends
`sufficient` only through an exact lookup of a named CVE or a reviewed topic's mapping, and
a topic run can still stop `sufficient` on CVEs that do not answer the question.

When `interpretation.affectedness_mentions` names a product and version, each CVE
candidate carries `nvd_version_notes`: `hit`, `no_hit` or `unknown` against its retained
NVD CPE version conditions for a matching vendor or product. Dotted numeric segments
compare numerically (5.10 > 5.9), with missing trailing segments equal to zero
(2.7 == 2.7.0); any non-digit segment is uncomparable, except an exact condition may
match by trimmed string equality. A hit records the matching entry and condition;
no hit does not show the version is unaffected. The full configuration and environment
conditions were not evaluated: non-vulnerable CPE conditions and the configuration
tree are not retained. These annotations do not change retrieval, needs or stop rules.

## What it does

- **Search** CVE records by exact ID, lexical match, structured filters, a graph channel
  and an optional semantic channel, with typed per-channel outcomes.
- **Topic context**: resolve a protocol topic (for example 5G-AKA) and gather its scoped
  context, keeping protocol context and implementation vulnerabilities apart.
- **Bounded investigation**: a state machine with budgets, a hard wall time and a
  replayable trajectory, planned by a deterministic policy or by an optional model planner
  behind a plan gate that falls back to the policy. With the planner enabled, the model
  plans questions that name a CVE ID or resolve a reviewed topic. For free-text CVE
  questions it labels admitted candidates and may propose one sourced refined search;
  relevance labels group the final answer without meeting evidence needs. Round 1 is
  planned by the policy.
- **Evidence sets** that can be verified and replayed offline (`cve-kgrag verify`).
- **A read-only MCP server** with nine bounded tools, over stdio or over Streamable
  HTTP on a loopback address behind a bearer token.
- **A v2 REST API** on a loopback address behind the same token: search, investigate,
  evidence, capabilities and evidence-set verification.

The package runs offline on a bundled synthetic fixture (`CVE-9999-*` records), or on a
corpus store an operator imports from raw NVD feeds and the CISA KEV catalog and
activates. It commits no NVD, CVE Program or CISA KEV feeds. MITRE catalogue
excerpts carry notices; see
[`THIRD_PARTY_DATA.md`](THIRD_PARTY_DATA.md).

## Install

Requires [uv](https://docs.astral.sh/uv/). The package needs Python 3.11 or later; when
none is installed, `uv sync` downloads one, so the system `python3` (3.9 on stock macOS)
does not matter.

```bash
uv sync --locked
uv run cve-kgrag demo
```

Optional extras: `mcp` (the MCP server, on stdio and over Streamable HTTP), `api` (the
REST API), `migration` (the legacy-data importer's streaming JSON parser) and `semantic`
(Chroma and sentence-transformers). `uv sync --locked` also installs the development
group, which brings in the `mcp` and `migration` extras and the packages the `api` server
runs on, so a checkout can run every command but the semantic channel without naming an
extra.

## Commands

```bash
uv run cve-kgrag demo                                   # sample queries on the fixture
uv run cve-kgrag lookup CVE-9999-0001                   # exact CVE-ID lookup
uv run cve-kgrag product --vendor democorp --version 2.0 --format text
uv run cve-kgrag search "authentication bypass"         # ranked search
uv run cve-kgrag search gateway --vendor democorp --severity critical --graph-expand
uv run cve-kgrag topic 5G-AKA --scope mixed             # scoped topic context
uv run cve-kgrag investigate 5G-AKA --scope mixed       # bounded investigation
uv run cve-kgrag investigate 5G-AKA --scope mixed --format text
uv run cve-kgrag investigate 5G-AKA --scope mixed --max-rounds 1
uv run cve-kgrag capabilities                           # the sources and what each serves
uv run cve-kgrag resolve 5G-AKA                         # the reviewed topics a query names
uv run cve-kgrag affectedness CVE-9999-0003 --purl pkg:generic/open5gs@2.7.0  # exits 1
uv run cve-kgrag evidence ev:d8097ae9c31b754d26a1ef92   # one served evidence anchor
uv run cve-kgrag investigate 5G-AKA --scope mixed > evidence-set.json
uv run cve-kgrag verify evidence-set.json               # validate, audit and replay that set
uv run cve-kgrag mcp                                    # MCP server on stdio (mcp extra)
uv run cve-kgrag mcp --http                             # MCP over HTTP on 127.0.0.1:8765
uv run cve-kgrag api                                    # REST API on 127.0.0.1:8766 (api extra)
uv run cve-kgrag schema check                           # compare schemas with the snapshots
uv run cve-kgrag eval planner --gold eval/gold/m4_trajectories.yaml --out eval-results
uv run cve-kgrag migrate legacy --inputs inputs.yaml --target /data/stores/nvd-2026-10 --dry-run
uv run cve-kgrag store activate nvd-2026-10             # serve that store (store root set)
uv run cve-kgrag store status                           # the active and previous stores
uv run cve-kgrag store rollback                         # back to the store active before
```

`investigate --format text` shows needs, CVE severity and KEV status, protocol context,
uncertainties, warnings and where to find the evidence.

Every command but `mcp`, `api` and `schema` prints JSON by default. `--scope` is one of
`protocol_context_only`, `implementation_only` or `mixed`. `search` filters by
`--vendor`, `--product`, `--purl`, `--cwe`, `--severity`, `--year`, `--origin` (each
repeatable) and `--kev-only`; `investigate` takes the product options and the budget
options `--max-rounds`, `--max-tool-calls`, `--max-sources`, `--max-results-per-call`,
`--max-wall-time-seconds` and `--max-context-bytes`. `cve-kgrag <command> --help` lists
each command's options.

`affectedness` is unavailable in this release: no affectedness source is verified, so it
always answers `unknown` with the failure `blocked_unverified` and exits 1, by design.
`verify` takes an evidence set, which is what `investigate` prints, the REST
`/api/v2/investigate` route answers and the MCP `investigate_telecom_topic` tool returns.

A `--purl` filter (`filters.purls` over REST and MCP) needs a dataset whose records name
package URLs. The packaged fixture names some; an NVD import names none, because NVD
records identify products by CPE. Over a dataset that names none, a request with a purl
filter is refused instead of being answered as if nothing matched: the CLI exits 2 with
`filters.purls: filter_unsupported`, REST answers 422 and MCP a `filter_unsupported` tool
failure, each naming the filter and never its value. `capabilities` reports
`purl_filter_available`.

These warnings explain an answer without reading its trajectory:

- `result_limit_reached` names the limit when a search may have cut its matches at it
  (`--limit` for `search`, `--max-results-per-call` for each search of an investigation):
  it found more matches than it lists, or one of its lexical, semantic or graph channels
  returned as many as the limit. More matches may exist; nothing counts them, and it does
  not say that relevant ones were left out. An investigation raises it only for searches
  whose CVEs can be in its answer, so never under `protocol_context_only`.
  `answer_truncated` counts results the admitted steps knew that answer assembly left out.
- `evidence_prefix_omitted` names a step and the number of returned results its context
  budget omitted. An oversized step admits the longest prefix of whole results and all
  their anchors that fits the remaining 200,000-byte cap, as `admitted_prefix`. If the
  first result cannot fit, the whole step is discarded with `evidence_discarded`.
  Topic calls interleave implementation CVEs, techniques and excluded CVEs by rank,
  stopping at the first result that does not fit. Prefix admission is not a budget breach.
  The step carries the original response's digest, per-list counts, admitted bytes and
  first-omitted-result byte increment; the original response body stays out of the set.
- `term_not_indexed`, at the top of an investigation, names once each search word an
  adopted step reported that no CVE record (or, for a direct FiGHT search, no technique)
  holds. Such a word matched nothing, which is often why a need stays unmet.

Search matches individual words, so a lexical hit is not evidence that a record is about
the question: read each candidate's matched terms.

`max_context_bytes` measures the tool results admitted into the investigation's context.
The evidence set the user receives is larger because it also carries claims, evidence
entries and the trajectory: a real-store example charges 199,477 bytes in a
339,057-byte answer. There is no separate cap on answer size.

`migrate legacy` imports raw NVD 1.1 and 2.0 feeds and the CISA KEV catalog CSV that an
operator-written input manifest declares, each with the time it was obtained, into a
new, verified corpus store; it prints a migration report and never writes beside an
input or over an existing store ([ADR 0008](docs/rebuild/adr/0008-legacy-data-importer.md)).
Legacy derived exports are never imported. The store holds operator-supplied data under
NVD's and CISA's terms ([`THIRD_PARTY_DATA.md`](THIRD_PARTY_DATA.md)); keep it out of
version control.

With `CVE_KGRAG_STORE_ROOT` set, `store validate`, `store activate`, `store rollback` and
`store status` manage the stores under it, and every surface that serves CVE records
serves the store `ACTIVE` names, or refuses to start; it never falls back to the
fixture. `demo` always uses the fixture; `eval planner` uses it for an M7a gold file, and
the active store with the operator FiGHT snapshot for an M7b gold file
([`m7b-planner-evaluation.md`](docs/rebuild/m7b-planner-evaluation.md)). The
[operator runbook](docs/runbook.md) covers importing, activating, serving, rolling back
and the full FiGHT snapshot
([ADR 0009](docs/rebuild/adr/0009-store-activation-and-serving.md)).

`eval planner` is a local reviewer and operator tool, served by no API: it runs each gold
case with the deterministic policy and, with `--model-runs N` (0 to 20, default 0), N times
with the model planner the settings enable, then prints a report of counts, codes and
hashes ([`m7a-planner-baseline.md`](docs/rebuild/m7a-planner-baseline.md)). Without
`--model-runs` it calls no endpoint. It writes every evidence set to a new owner-only
directory under `--out`; those sets hold the queries and the model's plan text, so keep
them out of version control (`eval-results/` is ignored).

## Product vulnerabilities

Use explicit product and/or vendor fields for inventory queries:

```bash
uv run cve-kgrag product --product oai-cn5g-amf --vendor openairinterface --version 2.0 --format text
uv run cve-kgrag product --vendor openairinterface --limit 20
```

The same service is `POST /api/v2/product` and MCP `query_product_vulnerabilities`,
listed by `capabilities.tools`. At least one of `vendor` or `product` is required;
`version`, `limit` and `cursor` are optional. Names compare exactly after Unicode `casefold()`,
like the structured filters. Use stored CPE component names (unescaped on import),
preserving underscores, punctuation and whitespace. Vendor and product must match
the same implicated entry (`status != unaffected`); there is no recognition from prose.

Each item's `basis.kind` is `product_field` with matched vendor:product pairs, or
`description_mention` with a matched phrase. Only records with no implicated products
can match descriptions, using consecutive project-tokenizer tokens: `oai-cn5g-amf`
reads as `oai cn5g amf`. With both vendor and product, each must occur separately as
a whole-token phrase; without a product, the phrase is the vendor.
`description_mentions_vendor_unconfirmed` counts product mentions left out because
the vendor was not named, across all pages (zero unless both fields are supplied).
Mention-only evidence cannot establish vendor ownership. CVEs appear once, with field
evidence taking precedence. The response's `matched_products` shows all matched pairs across
all pages; shared product names include every vendor, so narrow with `vendor`.

With `version`, each item carries `nvd_version_note`: `hit` means it
matches a listed NVD CPE version condition; `no_hit` means none of the listed conditions
matched and **does not show the version is unaffected**; `unknown` gives a reason,
such as missing version conditions, an uncomparable version or a description mention
only. Version never becomes search text or removes CVEs. Full configuration and
environment conditions are not evaluated, and `applicability` remains `unknown`.

This is deterministic grouping, not ranking: with a version, `hit`, `unknown`, then
`no_hit`; then product-field before mention-only evidence, newest publication first
(missing dates last), then CVE ID ascending. Each `items` page holds up to `limit` (default 10,
maximum 20); `total_available` counts matching stored CVEs across all pages. Repeat the same
request with `cursor` set to `next_cursor` (CLI `--cursor`) until `next_cursor` is null.
The response echoes the request, including its cursor. Continue against the same served
corpus: cursors are stateless offsets over that corpus's deterministic order. Invalid or
mismatched cursors return `invalid_cursor` (REST 422, MCP tool failure, CLI exit 2).
The service builds vendor, product and eligible description-token indexes once on load;
queries verify exact matching rules on the indexed candidates. JSON retains
severity metrics, KEV entries and evidence anchors; text summarizes them. CLI exit 0
means CVEs were returned, 1 means empty. NVD's enrichment backlog can lack product/version
data; mention-only evidence and absent matches cannot establish affectedness or safety.
This view makes no completeness or sufficiency claim. Protocol/technology investigations
remain a separate entry.

## Configuration

Settings come from `CVE_KGRAG_*` environment variables, read once at startup; an invalid
setting is a usage error that names the variable and never echoes its value. Both
optional capabilities are off by default:

- the model planner (an OpenAI-compatible endpoint), `CVE_KGRAG_PLANNER_*`
  ([ADR 0004](docs/rebuild/adr/0004-settings-and-secrets.md),
  [ADR 0005](docs/rebuild/adr/0005-model-planner-adapter.md)). It plans only questions
  that name a CVE ID or resolve a reviewed topic. For free-text CVE questions the policy
  retrieves round 1, then the model labels candidates and may name a question component
  whose coverage is unclear and propose one refined search. Every term must come from
  the question or an admitted candidate's vendor, product or parsed CPE product name.
  The gate enforces the sources and existing budgets; new candidates get one more
  assessment. The answer groups relevant, cannot tell, not relevant and unassessed
  candidates before applying the cap of 20. Labels change no evidence need or stop;
  failures retain round 1's evidence. Both assessor calls and retrieval share the
  existing deadline, with at most two rounds. Only the CLI's `investigate` and
  `eval planner` use it; the REST API and MCP servers plan with the deterministic policy
  ([ADR 0007](docs/rebuild/adr/0007-http-surfaces.md));
- the semantic channel, `CVE_KGRAG_SEMANTIC_*`. It reads a Chroma store in the format
  CVE-KGRAG's pipeline writes, from a directory the operator names; this repository does
  not build that store ([ADR 0006](docs/rebuild/adr/0006-repository-split.md)).

`cve-kgrag mcp --http` and `cve-kgrag api` read `CVE_KGRAG_HTTP_HOST` (`127.0.0.1`, the
default, or `::1`), their ports `CVE_KGRAG_MCP_HTTP_PORT` (default 8765) and
`CVE_KGRAG_API_PORT` (default 8766), and `CVE_KGRAG_HTTP_TOKEN`, the bearer token every
route but `/health` requires, without which they refuse to start
([ADR 0007](docs/rebuild/adr/0007-http-surfaces.md)). Generate the token, for example
with `uv run python -c "import secrets; print(secrets.token_urlsafe(32))"` (or `python3`;
stock macOS has no `python`). The MCP endpoint is `POST /mcp`. The REST API serves
`POST /api/v2/search`, `POST /api/v2/product`, `POST /api/v2/investigate`,
`GET /api/v2/evidence/{evidence_id}`,
`GET /api/v2/capabilities` and `POST /api/v2/verify`; the request bodies are the
`*_request` schemas under [`schemas/v2/`](schemas/v2/). On both servers `/health`
answers 204 without the token; `/ready` needs the bearer token like every other route,
and answers 204 while a toolbox worker is free and 503 otherwise, so a readiness probe
must send the token.

The served data has no switch: `CVE_KGRAG_STORE_ROOT`, an absolute directory, serves the
store its `ACTIVE` names in place of the fixture. `CVE_KGRAG_FIGHT_SNAPSHOT_PATH` serves
a reviewed FiGHT snapshot in place of the packaged excerpt; its digest is computed at
load and must be in the reviewed catalog. `CVE_KGRAG_FIGHT_SNAPSHOT_SHA256` is an optional
expected value, strictly compared when supplied ([`docs/runbook.md`](docs/runbook.md)).

Keep keys and tokens in the environment, never on a command line or in a committed file.

## Running on real data

Without `CVE_KGRAG_STORE_ROOT` every command serves the synthetic fixture. To serve real
NVD and CISA KEV data, an operator sets `CVE_KGRAG_STORE_ROOT` to an absolute directory
outside the repository and builds a store under it once, following the
[operator runbook](docs/runbook.md):

1. Fetch, import and explicitly activate a fresh store in one command:
   `.venv/bin/python scripts/operator/refresh_store.py --feeds-dir ~/data/cve-kgrag/feeds/<date> --store nvd-<date> --activate`.
   Fetching downloads about 270 MB. The command checks NVD metadata digests,
   imports, then verifies and activates the store, printing the import report and status.
   Use `--inputs <feeds>/inputs.yaml` instead of `--feeds-dir` to reuse local feeds;
   omit `--activate` to import without changing the active store.
2. Restart API and MCP services to serve the activated store. To undo activation, run
   `cve-kgrag store rollback` and restart the services again.

Optionally serve the full MITRE FiGHT snapshot by fetching `fight.yaml` at the reviewed
catalog's commit and setting `CVE_KGRAG_FIGHT_SNAPSHOT_PATH`
([runbook](docs/runbook.md#the-operator-fight-snapshot)). The server computes the file's
digest and enforces the catalog; an expected SHA-256 is optional.

Commands load the whole store before answering data queries. MCP stdio completes
`initialize` and lists its static tools while the store loads in the background. A tool
call during loading immediately returns a `data_loading` tool error: “The data is still
loading; retry later.” Calls are neither queued nor retried automatically.

Progress goes to standard error: `loading store <name>`, then `<dataset version> data
loaded after <N> s`. Stdio prints `<dataset version> ready after <N> s` only when its
complete toolbox is usable. `api` and `mcp --http` load before binding and print
`ready on http://<host>:<port>` only once they are serving; a bind failure prints no ready
line. Standard output carries only the command's JSON or the MCP protocol. Measurements use
the store of 2026-10-27 (396,211 records):

| What | Measured |
|---|---|
| store on disk | — |
| one CLI command (`lookup`, `search`, `capabilities`, ...) | — |
| `api` ready (`/health` answers) | — |
| `mcp --http` ready | — |
| MCP stdio, store loading | — |
| peak memory while loading | — |

Once loaded, queries reuse the store. For more than one query, run
the REST API (`cve-kgrag api`) or the MCP HTTP server (`cve-kgrag mcp --http`) and keep it
running, rather than a one-shot command per query. A client that starts `cve-kgrag mcp`
over stdio can connect immediately and make data calls after the ready notice. A store
load failure prints its reason on standard error and exits non-zero; closing stdin or
pressing Ctrl+C stops the process promptly even during loading. The fixture is loaded
before use.

## Development

```bash
uv run pytest -q
uv run ruff check
uv run ruff format --check
uv run mypy
uv run cve-kgrag schema check
uv lock --check
```

The default lane is offline. Live model tests are opt-in (`tests/live`; see `PLAN.md`).
Design records are under [`docs/rebuild/`](docs/rebuild/): one document per milestone and
the ADRs in `docs/rebuild/adr/`.

## Origin

This repository holds the evidence-bound CVE and telecom knowledge service (Python
package `cve_kgrag`, distribution and command `cve-kgrag`). It was split from
[CVE-KGRAG](https://github.com/Yuning-J/CVE-KGRAG) at commit `53d75e3`;
[`PROVENANCE.md`](PROVENANCE.md) lists what was carried and under which licences. The
package, command, MCP server name and `CVE_KGRAG_*` settings keep the original name; only
the repository is named differently.

CVE-KGRAG keeps the legacy RAG pipeline, the FastAPI `/api/v1` service, the Gradio UI
and the Neo4j knowledge-graph tooling, and receives their security fixes. This repository
does not provide or emulate any of them and makes no compatibility promise with them.

## Licence

Code: MIT ([`LICENSE`](LICENSE)). Third-party data carries its own terms; see
[`THIRD_PARTY_DATA.md`](THIRD_PARTY_DATA.md) and [`PROVENANCE.md`](PROVENANCE.md).

## Weakness associations

Single-CVE `lookup` answers carry full `weakness_associations`. Search, topic and
investigation candidates, including excluded candidates, omit the field entirely
so associations cannot displace retrieval results from the context-byte budget.
Use `cve-kgrag lookup <CVE-ID>` or MCP `lookup_cve` for
catalogue-derived CVE → CWE → CAPEC → ATT&CK paths or paths ending at CAPEC, the source of
every hop, technique names and tactics when mapped, the snapshot digest, missing
links and an omitted count. Paths ending at CAPEC have `terminal_reason` set to
`"no_attack_mapping"`, with `technique` and `technique_source` set to null. CAPEC mappings
inherited through `ChildOf` include their parent chain and `inherited_from`.
When a CWE has no direct `Related_Attack_Patterns`, the builder follows CWE
`ChildOf` relations in view 1000 (Complete Weakness Hierarchy), preferring relations
marked `Ordinal="Primary"` within that view, or all its `ChildOf` relations if none
is marked. It takes all linked ancestors at the nearest depth and retains each
`cwe_child_of` hop with `inherited_from_cwe`. This is an inference along the CWE
hierarchy, not a catalogue link from the original CWE to CAPEC. Direct CWE links
always prevent CWE inheritance, including links to deprecated CAPECs. CWE-787
inherits CWE-119's 12 CAPEC links in CWE 5.0.

This association is derived from official catalogues. It is not evidence that the
CVE was used with that technique. It is not an attack path.
No ATT&CK mapping describes only the loaded catalogue snapshot; it does not mean
the weakness has no attack technique or no way to be exploited.

Full paths and paths ending at CAPEC share a cap of 20 per CVE, with the exact
omitted count. Direct mappings precede CAPEC-inherited mappings, then CWE-inherited
full paths, then all paths ending at CAPEC, then lexicographic CWE, CAPEC, technique
and inheritance IDs. This order is not an importance ranking.
CWE inference uses only the selected catalogue hierarchy;
no model or keyword inference fills a missing link.
`missing_links` reports unavailable links without repeating CAPEC terminal reasons.
Text investigations point to `lookup` for the full paths, sources and omitted counts.
NVD placeholders are normalized to no specific CWE. FiGHT `protocol_context`, needs,
ranking, affectedness and NVD version notes retain their own meanings.

Build from local official files, without a corpus store or network:

```sh
cve-kgrag mitre build --cwe /data/cwec_v5.0.xml --capec /data/capec_latest.xml \
  --attack /data/enterprise-attack.json --out /data/weakness-mapping.json
```

Set `CVE_KGRAG_MITRE_SNAPSHOT_PATH` to the built file. The server computes its digest
at load and records it as data identity. Optionally set `CVE_KGRAG_MITRE_SNAPSHOT_SHA256`
to an expected digest; a mismatch refuses serving. MITRE has no reviewed snapshot
catalog: without an expected digest the file identity is recorded, without verifying
that it is unchanged. `capabilities.weakness_associations.integrity` says whether the
digest was compared, alongside coverage, digest and catalogue versions. An unset path
serves the manifest-pinned packaged excerpt. Restart services after replacing a file
or changing its settings.
See [the runbook](docs/runbook.md#weakness-association-mapping) for serving and rebuilding.
