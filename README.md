# telecom-cve-kgrag

A telecom-focused, evidence-bound CVE and threat-context investigation system, with an
extensible, review-governed topic registry. The first topic card is 5G-AKA. It is marked
`pending_review` while the design is experimental: it was checked against 3GPP TS 33.501
V19.7.0 but has no named reviewer, so every answer that uses it says so.

Every answer cites evidence: a claim that no served record supports is not returned. CVE
evidence and protocol threat context (MITRE FiGHT, reviewed topic cards) stay separate,
so CVE evidence cannot be relabelled to support a protocol-context claim.

Status: pre-release. The contracts are at `2.0.0-dev.20` and may change between versions
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
- **A read-only MCP server** over stdio with eight bounded tools.

The package runs offline on a bundled synthetic fixture (`CVE-9999-*` records). It
commits no NVD, CVE Program, CISA KEV, CWE or CAPEC data; see
[`THIRD_PARTY_DATA.md`](THIRD_PARTY_DATA.md).

## Install

Requires Python 3.11 or later and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --locked
uv run cve-kgrag demo
```

Optional extras: `mcp` (the MCP server) and `semantic` (Chroma and sentence-transformers).

## Commands

```bash
uv run cve-kgrag demo                                   # sample queries on the fixture
uv run cve-kgrag lookup CVE-9999-0001                   # exact CVE-ID lookup
uv run cve-kgrag search "authentication bypass"         # ranked search
uv run cve-kgrag topic 5G-AKA --scope mixed             # scoped topic context
uv run cve-kgrag investigate 5G-AKA --scope mixed       # bounded investigation
uv run cve-kgrag verify evidence-set.json               # validate, audit and replay a set
uv run cve-kgrag mcp                                    # MCP server on stdio (mcp extra)
uv run cve-kgrag schema check                           # compare schemas with the snapshots
```

The query commands and `verify` print JSON. `--scope` is one of `protocol_context_only`,
`implementation_only` or `mixed`.

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

Keep keys in the environment, never on a command line or in a committed file.

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
and the Neo4j knowledge-graph tooling; security fixes for that code are made there. This
repository does not provide or emulate any of them and makes no compatibility promise
with them.

## Licence

Code: MIT ([`LICENSE`](LICENSE)). Third-party data carries its own terms; see
[`THIRD_PARTY_DATA.md`](THIRD_PARTY_DATA.md) and [`PROVENANCE.md`](PROVENANCE.md).
