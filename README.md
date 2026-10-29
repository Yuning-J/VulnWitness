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

Status: pre-release. The contracts are at `2.0.0-dev.26` and may change between versions
without a deprecation window. The roadmap is in [`docs/rebuild/PLAN.md`](docs/rebuild/PLAN.md).

## What it does

- **Search** CVE records by exact ID, lexical match, structured filters, a graph channel
  and an optional semantic channel, with typed per-channel outcomes.
- **Topic context**: resolve a protocol topic (for example 5G-AKA) and gather its scoped
  context, keeping protocol context and implementation vulnerabilities apart.
- **Bounded investigation**: a state machine with budgets, a hard wall time and a
  replayable trajectory, planned by a deterministic policy or by an optional model planner
  behind a plan gate that falls back to the policy.
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

Requires Python 3.11 or later and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --locked
uv run cve-kgrag demo
```

Optional extras: `mcp` (the MCP server, on stdio and over Streamable HTTP), `api` (the
REST API), `migration` (the legacy-data importer's streaming JSON parser) and `semantic`
(Chroma and sentence-transformers).

## Commands

```bash
uv run cve-kgrag demo                                   # sample queries on the fixture
uv run cve-kgrag lookup CVE-9999-0001                   # exact CVE-ID lookup
uv run cve-kgrag search "authentication bypass"         # ranked search
uv run cve-kgrag search gateway --vendor democorp --severity critical --graph-expand
uv run cve-kgrag topic 5G-AKA --scope mixed             # scoped topic context
uv run cve-kgrag investigate 5G-AKA --scope mixed       # bounded investigation
uv run cve-kgrag investigate 5G-AKA --scope mixed --max-rounds 1
uv run cve-kgrag capabilities                           # the sources and what each serves
uv run cve-kgrag resolve 5G-AKA                         # the reviewed topics a query names
uv run cve-kgrag affectedness CVE-9999-0003 --purl pkg:generic/open5gs@2.7.0
uv run cve-kgrag evidence ev:d8097ae9c31b754d26a1ef92   # one served evidence anchor
uv run cve-kgrag verify evidence-set.json               # validate, audit and replay a set
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

Every command but `mcp`, `api` and `schema` prints JSON. `--scope` is one of
`protocol_context_only`, `implementation_only` or `mixed`. `search` filters by
`--vendor`, `--product`, `--purl`, `--cwe`, `--severity`, `--year`, `--origin` (each
repeatable) and `--kev-only`; `investigate` takes the product options and the budget
options `--max-rounds`, `--max-tool-calls`, `--max-sources`, `--max-results-per-call`,
`--max-wall-time-seconds` and `--max-context-bytes`. `cve-kgrag <command> --help` lists
each command's options.

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
  [ADR 0005](docs/rebuild/adr/0005-model-planner-adapter.md));
- the semantic channel, `CVE_KGRAG_SEMANTIC_*`. It reads a Chroma store in the format
  CVE-KGRAG's pipeline writes, from a directory the operator names; this repository does
  not build that store ([ADR 0006](docs/rebuild/adr/0006-repository-split.md)).

`cve-kgrag mcp --http` and `cve-kgrag api` read `CVE_KGRAG_HTTP_HOST` (`127.0.0.1`, the
default, or `::1`), their ports `CVE_KGRAG_MCP_HTTP_PORT` (default 8765) and
`CVE_KGRAG_API_PORT` (default 8766), and `CVE_KGRAG_HTTP_TOKEN`, the bearer token every
route but `/health` requires, without which they refuse to start
([ADR 0007](docs/rebuild/adr/0007-http-surfaces.md)). Generate the token, for example
with `python -c "import secrets; print(secrets.token_urlsafe(32))"`. The MCP endpoint is
`POST /mcp`. The REST API serves `POST /api/v2/search`, `POST /api/v2/investigate`,
`GET /api/v2/evidence/{evidence_id}`, `GET /api/v2/capabilities` and
`POST /api/v2/verify`. On both, `/health` answers 204, and `/ready` answers 204 while a
toolbox worker is free and 503 otherwise.

The served data has no switch: `CVE_KGRAG_STORE_ROOT`, an absolute directory, serves the
store its `ACTIVE` names in place of the fixture, and `CVE_KGRAG_FIGHT_SNAPSHOT_PATH` with
`CVE_KGRAG_FIGHT_SNAPSHOT_SHA256`, set together, serve a reviewed full FiGHT snapshot in
place of the packaged excerpt ([`docs/runbook.md`](docs/runbook.md)).

Keep keys and tokens in the environment, never on a command line or in a committed file.

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
