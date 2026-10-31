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

Status: pre-release. The contracts are at `2.0.0-dev.34` and may change between versions
without a deprecation window. The roadmap is in [`docs/rebuild/PLAN.md`](docs/rebuild/PLAN.md).

Known limit: the current version does not judge free-text results sufficient
automatically. A free-text investigation (one that names no CVE ID and resolves no reviewed
topic) lists the CVEs and techniques that match the question's words and ends
`needs_unmet` / `partial`, each such need `matches_unassessed`: matches were found and
their relevance was not assessed, which does not mean no relevant evidence exists. Read the
candidates and the terms each matched before relying on them. An investigation ends
`sufficient` only through an exact lookup of a named CVE or a reviewed topic's mapping, and
a topic run can still stop `sufficient` on CVEs that do not answer the question.

## What it does

- **Search** CVE records by exact ID, lexical match, structured filters, a graph channel
  and an optional semantic channel, with typed per-channel outcomes.
- **Topic context**: resolve a protocol topic (for example 5G-AKA) and gather its scoped
  context, keeping protocol context and implementation vulnerabilities apart.
- **Bounded investigation**: a state machine with budgets, a hard wall time and a
  replayable trajectory, planned by a deterministic policy or by an optional model planner
  behind a plan gate that falls back to the policy. With the planner enabled, the model
  plans only questions that name a CVE ID or resolve a reviewed topic; free text is
  planned by the policy.
- **Evidence sets** that can be verified and replayed offline (`cve-kgrag verify`).
- **A read-only MCP server** with eight bounded tools, over stdio or over Streamable
  HTTP on a loopback address behind a bearer token.
- **A v2 REST API** on a loopback address behind the same token: search, investigate,
  evidence, capabilities and evidence-set verification.

The package runs offline on a bundled synthetic fixture (`CVE-9999-*` records), or on a
corpus store an operator imports from raw NVD feeds and the CISA KEV catalog and
activates. It commits no NVD, CVE Program, CISA KEV, CWE or CAPEC data; see
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

Two warnings explain an answer without reading its trajectory:

- `result_limit_reached` names the limit when a search may have cut its matches at it
  (`--limit` for `search`, `--max-results-per-call` for each search of an investigation):
  it found more matches than it lists, or one of its lexical, semantic or graph channels
  returned as many as the limit. More matches may exist; nothing counts them, and it does
  not say that relevant ones were left out. An investigation raises it only for searches
  whose CVEs can be in its answer, so never under `protocol_context_only`.
  `answer_truncated`, by contrast, counts results the answer is known to have left out.
- `term_not_indexed`, at the top of an investigation, names once each search word an
  adopted step reported that no CVE record (or, for a direct FiGHT search, no technique)
  holds. Such a word matched nothing, which is often why a need stays unmet.

Search matches individual words, so a lexical hit is not evidence that a record is about
the question: read each candidate's matched terms.

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

## Configuration

Settings come from `CVE_KGRAG_*` environment variables, read once at startup; an invalid
setting is a usage error that names the variable and never echoes its value. Both
optional capabilities are off by default:

- the model planner (an OpenAI-compatible endpoint), `CVE_KGRAG_PLANNER_*`
  ([ADR 0004](docs/rebuild/adr/0004-settings-and-secrets.md),
  [ADR 0005](docs/rebuild/adr/0005-model-planner-adapter.md)). It plans only questions
  that name a CVE ID or resolve a reviewed topic; free text is planned by the policy, and
  its rounds record `model_not_consulted` (`model_skipped_at_deadline` when the deadline
  passed before planning). Only the CLI's `investigate` and `eval planner` use it; the
  REST API and MCP servers plan with the deterministic policy
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
`POST /api/v2/search`, `POST /api/v2/investigate`, `GET /api/v2/evidence/{evidence_id}`,
`GET /api/v2/capabilities` and `POST /api/v2/verify`; the request bodies are the
`*_request` schemas under [`schemas/v2/`](schemas/v2/). On both servers `/health`
answers 204 without the token; `/ready` needs the bearer token like every other route,
and answers 204 while a toolbox worker is free and 503 otherwise, so a readiness probe
must send the token.

The served data has no switch: `CVE_KGRAG_STORE_ROOT`, an absolute directory, serves the
store its `ACTIVE` names in place of the fixture, and `CVE_KGRAG_FIGHT_SNAPSHOT_PATH` with
`CVE_KGRAG_FIGHT_SNAPSHOT_SHA256`, set together, serve a reviewed full FiGHT snapshot in
place of the packaged excerpt ([`docs/runbook.md`](docs/runbook.md)).

Keep keys and tokens in the environment, never on a command line or in a committed file.

## Running on real data

Without `CVE_KGRAG_STORE_ROOT` every command serves the synthetic fixture. To serve real
NVD and CISA KEV data, an operator sets `CVE_KGRAG_STORE_ROOT` to an absolute directory
outside the repository and builds a store under it once, following the
[operator runbook](docs/runbook.md):

1. Fetch the feeds into a directory outside the repository:
   `scripts/operator/fetch_feeds.sh ~/data/cve-kgrag/feeds/<date>`. It downloads
   about 270 MB, and writes the `inputs.yaml` manifest the import reads.
2. Import them into a new store under the root:
   `uv run cve-kgrag migrate legacy --inputs <feeds>/inputs.yaml --target "$CVE_KGRAG_STORE_ROOT/nvd-<date>"`.
3. Check and activate it: `uv run cve-kgrag store validate nvd-<date>`, then
   `uv run cve-kgrag store activate nvd-<date>`.
4. Optionally serve the full MITRE FiGHT snapshot: fetch `fight.yaml` at the catalogued
   commit, check that its SHA-256 is
   `59a9addbd75d8680091797d66d5b237d9d026512990c61a6f51692ca94d2a7a8` (`shasum -a 256` on
   macOS), and set `CVE_KGRAG_FIGHT_SNAPSHOT_PATH` and `CVE_KGRAG_FIGHT_SNAPSHOT_SHA256`
   ([runbook](docs/runbook.md#the-operator-fight-snapshot)).

Every command and server that serves records loads the whole store before it answers.
It says so on standard error (`loading store <name>`, then `<dataset version> ready after
<N> s`); standard output carries only the command's JSON or the MCP protocol. Measurements use
the store of 2026-10-27 (396,211 records):

| What | Measured |
|---|---|
| store on disk | — |
| one CLI command (`lookup`, `search`, `capabilities`, ...) | — |
| `api` ready (`/health` answers) | — |
| `mcp --http` ready | — |
| MCP stdio, the answer to `initialize` | — |
| peak memory while loading | — |

Once loaded, queries reuse the store. For more than one query, run
the REST API (`cve-kgrag api`) or the MCP HTTP server (`cve-kgrag mcp --http`) and keep it
running, rather than a one-shot command per query. An MCP client that starts
`cve-kgrag mcp` over stdio waits for the whole load before `initialize` is answered, which
can exceed the client's initialize timeout; the progress lines on standard error do not
change that. Use `mcp --http` for such a client, or raise its timeout. The fixture is loaded
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
