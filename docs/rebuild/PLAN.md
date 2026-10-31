# Rebuild plan (live)

Split from CVE-KGRAG at commit `53d75e3` ([`PROVENANCE.md`](../../PROVENANCE.md),
ADR 0006); M0 to M5 and the first M6 packages were built there. One atomic commit per
milestone once its exit criterion is met and the offline lane is green.

| Milestone | Scope | Status |
|---|---|---|
| M0 | Baseline, v1 consumer check, characterization tests, packaging/migration ADR (the baseline and the characterization tests live in CVE-KGRAG: `docs/rebuild/baseline.md`, `tests/characterization/`) | done |
| M1 | `pyproject`, `cve_kgrag` core: canonical contracts + JSON Schemas, synthetic fixture + manifest, in-memory repository, exact-ID and lexical search, claim/evidence validator, minimal CLI | done |
| M2 | Structured filters, graph channel, typed backend outcomes, legacy ports, optional semantic adapter, NVD normalizer; review fixes (filter semantics, CVE-anchor scope rule, legacy wrapper, NVD boundary validation); the legacy wrapper is not part of this repository (ADR 0006) | done |
| M3 | Topic registry + 5G-AKA card (`pending_review` by owner decision while the design is experimental: technically checked against TS 33.501 V19.7.0, no named reviewer, every answer that uses it carries `topic_pending_review`), pinned FiGHT YAML source + licensed excerpt, relevance tiers, scoped topic-context service, gold queries, source registry and THIRD_PARTY_DATA.md | done |
| M4 | Bounded investigation state machine, deterministic policy m4.1, model-planner port with plan gate and deterministic fallback, budgets, replayable trajectory, gold trajectories, hard wall time via abandoning call runner, per-request result cap, catalog re-check of served content, trajectory cross-validation (network LLM adapter follows separately) | done |
| M5 | Trustify port + disabled adapter (real adapter BLOCKED_UNVERIFIED, ADR 0003), read-only stdio MCP server with eight bounded tools, evidence-set verification (`cve-kgrag verify`), server-owned text at the MCP boundary (typed affectedness and backend failures, vouched match explanations), search-tool boundary below; contracts `2.0.0-dev.16` | done |
| M6 | v2 API, full CLI, read-only legacy-data importer, dependency split, offline CI; Streamable HTTP (opt-in, loopback, auth, health/readiness), typed settings boundary, semantic load-failure capability, set verification over HTTP; no v1 compatibility (ADR 0006); work packages in [`m6-api-cli-and-migration.md`](m6-api-cli-and-migration.md) (done: WP1 settings and secrets, ADR 0004; the model planner adapter, ADR 0005; WP2 semantic settings; WP-S repository split, ADR 0006; WP3′ HTTP surfaces, ADR 0007; WP4 offline CI; WP5 full CLI and the verification report contract, with bounded violations in the server's own words; WP6 HTTP guard, HTTP settings and MCP over Streamable HTTP; WP7 v2 REST API with set verification over HTTP; WP9 read-only legacy-data importer, ADR 0008; WP10 store activation and serving, the operator FiGHT snapshot, visible truncation and the M6 exit audit, ADR 0009; contracts `2.0.0-dev.26`); exit audit in [`m6-exit-audit.md`](m6-exit-audit.md) | done |
| M7a | Planner behaviour baseline before WP9: `cve-kgrag eval planner`, a pure analyzer over the evidence sets' trajectories (outcomes, fallbacks, divergence from the policy's plans, run stability), the deterministic baseline on the M4 gold file; no agent, vocabulary, round or contract change; [`m7a-planner-baseline.md`](m7a-planner-baseline.md) | done offline; live model runs are started by hand, outside CI |
| M7 | M7b after WP10: the same evaluation on imported data with hand-labelled sufficiency, then the decision on evidence gaps, controlled term expansion and more rounds; review packet | in progress: gold cases and the M7b evaluation done; the first model run, its causes and the planned work order in [`m7b-results-2026-10-28.md`](m7b-results-2026-10-28.md); A1 and A2 done, A2 as the `term_not_indexed` warning without the measured admission rule ([`m7b-work-packages.md`](m7b-work-packages.md)); B, evidence needs deciding stop and refinement ([`m7b-b-evidence-needs.md`](m7b-b-evidence-needs.md)); C, FiGHT protocol threat context from the question's own words with one shared phrase-BM25 FiGHT order ([`m7b-c-fight-direct-search.md`](m7b-c-fight-direct-search.md), contracts `2.0.0-dev.30`, policy `m7b.2`), implemented and awaiting owner review; C follow-up, mixed-script words read as the CVE side reads them ([`m7b-work-packages.md`](m7b-work-packages.md#c-follow-up--mixed-script-words), contracts `2.0.0-dev.31`, policy `m7b.3`), implemented and awaiting owner review; free text planned by the policy, the model planning only questions that name a CVE ID or resolve a reviewed topic (ADR 0005 §3, contracts `2.0.0-dev.32`, policy `m7b.3`, report format 5), implemented and awaiting owner review; real-use acceptance package 1: a purls filter refused (`filter_unsupported`) on a dataset that names no package URL, `result_limit_reached` without a count, `term_not_indexed` at the top of an investigation, store loading reported on stderr and a real-data README section (contracts `2.0.0-dev.33`, policy `m7b.3`), implemented and awaiting owner review; real-use acceptance package 2: a resolved topic explored first in every scope, and a need `found` only through an exact lookup of a named CVE or a reviewed topic's mapping, so free-text answers end `partial` with their matches `matches_unassessed` ([`m7b-work-packages.md`](m7b-work-packages.md#package-2--topic-first-and-unassessed-matches), contracts `2.0.0-dev.34`, policy `m7b.4`), implemented and awaiting owner review |

## M5 acceptance: the search-tool boundary

The MCP search tool (`search_vulnerabilities`) opens `SearchService` directly and
returns its ordinary ranked candidate list; bounded investigation stays its own tool,
so a retrieval tool and an investigating agent keep separate contracts. Searched as a
word, a bare `cve` matches whichever description mentions CVEs, so one shared query
rule (`extract_search_text` and `list_query_terms` in `domain/text.py`) leaves the
low-signal words `cve` and `cves` out of every search. The rule changes accepted M4
behaviour (schema `2.0.0-dev.13`); the shared-core change is recorded in
[`m5-mcp-and-sources.md`](m5-mcp-and-sources.md#compatibility-change-low-signal-query-terms).

## Follow-up: model planner adapter

Built after M6 WP1 (ADR 0004 fixed its settings, entry point, factory contract, guard and
identity): the OpenAI-compatible adapter in `adapters/planner/` with loopback offline
tests and opt-in live tests (ADR 0005, m6 doc). Done. The owner ran the live tests on
2026-10-21 against `https://api.deepseek.com` with `deepseek-flash` and reasoning effort
`none`: 2 passed.

A configured model plans only questions that name a CVE ID or resolve a reviewed topic.
It is not consulted in three cases, each decided by one rule the controller and the audit
share (`is_model_consultable`, or the refinement table for round 2):
- free text (no kept CVE ID, no resolved topic), in every scope: the policy plans it, with
  the question's search terms as its baseline. That is product policy, not a completeness
  or sufficiency guarantee; query rewriting by a model may be reopened by evaluation.
- round 1 when the policy's own plan is over the source budget (`5G-AKA` under
  `max_sources: 1`), since a round-1 model plan must consult the same sources.
- round 2 when the policy has no refinement for an open need
  ([`m7b-b-evidence-needs.md`](m7b-b-evidence-needs.md)), so `CVE-9999-4242` under
  `implementation_only` makes one planner call.

In every other round it is consulted, whether or not some plan could pass the gate; over
the tool-call budget alone, a search may reach a topic call's sources with fewer calls.
A round 1 not given to the model records `model_not_consulted`: no reply and no planner
call; it runs the policy's plan, or records the gate's rejections of it and runs nothing.
Contracts `2.0.0-dev.34`; `evaluation_format_version` 5, whose round outcome counts include
`model_not_consulted` and whose model rates leave those rounds out.

## Live lane (opt-in)

The key comes from a variable already in the shell, so it never appears in a command
line or its history:

```bash
CVE_KGRAG_LIVE_TESTS=1 CVE_KGRAG_PLANNER_ENABLED=true \
CVE_KGRAG_PLANNER_BASE_URL=https://api.deepseek.com CVE_KGRAG_PLANNER_MODEL_NAME=deepseek-flash \
CVE_KGRAG_PLANNER_REASONING_EFFORT=none CVE_KGRAG_PLANNER_API_KEY="$DEEPSEEK_API_KEY" \
uv run pytest tests/live -m live
```

The planner evaluation's model runs use the same variables, and only the report is meant
to be shared ([`m7a-planner-baseline.md`](m7a-planner-baseline.md#live-runs)):

```bash
CVE_KGRAG_PLANNER_ENABLED=true \
CVE_KGRAG_PLANNER_BASE_URL=https://api.deepseek.com CVE_KGRAG_PLANNER_MODEL_NAME=deepseek-flash \
CVE_KGRAG_PLANNER_REASONING_EFFORT=none CVE_KGRAG_PLANNER_API_KEY="$DEEPSEEK_API_KEY" \
uv run cve-kgrag eval planner --gold eval/gold/m4_trajectories.yaml --out eval-results \
  --model-runs 5
```

## Follow-up: verified Trustify adapter

A separate task after M5 writes the Trustify adapter that M5 ships only as
`DisabledTrustifyAdapter` (BLOCKED_UNVERIFIED, ADR 0003 §1). It starts only once one
of these is available:

- (a) a deployed Trustify version, its OpenAPI document and a test instance, or
- (b) a trustify-mcp release that states the Trustify versions it supports.

Its scope:

- the adapter behind `TrustifyPort`, the `trustify` extra and its `cve_kgrag.adapters`
  entry point; typed settings for the endpoint (from configuration and an allowlist,
  never from a caller) and for the OIDC secret; finite retry for the read tools only;
  detection of tool-schema drift against the pinned trustify-mcp snapshot; live tests
  behind a marker and an environment opt-in; the whole purl percent-encoded as one
  path segment (ADR 0003 §1); the port answers typed failures only, and the server
  owns every published sentence (ADR 0003 §2);
- one contract change adding the verdict statuses and the Trustify evidence anchors
  together, with the status mapping fixed in ADR 0003 §2, and an `available`
  affectedness state;
- whether the investigation calls the port, together with an auditable
  product-to-purl mapping; until both exist, named products stay `unknown`
  (ADR 0003 §4).

An adapter for Trustify v0.4.x is out of scope.

## Follow-ups from the legacy migration map

The migration map lives with the legacy modules it describes, in CVE-KGRAG
(`docs/rebuild/migration-map.md`). Its rows not yet covered here:

- CSAF import and the legacy pipeline commands (collect, process, export) have no v2
  counterpart; M6 WP9 records them, and CSAF is an M6 follow-up below.
- `export_kg_for_rag` output is detected by the M6 WP9 importer and reported as derived
  data, never imported as a source of record.
- The CVE→CWE→CAPEC→ATT&CK mapper becomes a derived mapping with its method, inputs,
  confidence and asserted or inferred status; FiGHT threat context stays matched by
  reviewed topic terms, or by the question's own words without a card, and is never
  derived from CVEs.
- There is no v2 Neo4j adapter; whether one is built is open.

## Follow-ups from M6 (ADR 0009)

Recorded when M6 closed; none blocks M7b unless it says so.

- CSAF import; an allowlisted refresh command; the Trustify adapter (above).
- The semantic index build from a store: a collection built from a store records its
  `corpus_content_sha256`, and the semantic channel serves a store only when that
  digest equals the served one; it also settles legacy `KEV-` chunk IDs.
- The `search_cves` filtered seam; hot reload of an activated store; removing old
  stores; a matched count for `search` responses; revisiting the 20-technique cap on
  topic context, whose cuts are now reported.
- The importer accepts at most 1 GiB decompressed per file. Measured on 2026-10-31 with
  `/usr/bin/time -l`, the peak of the target, staging and partial
  directories sampled every 2 s:

  | Input | Decompressed | Records imported | Wall time | Peak RSS | Peak disk |
  |---|---|---|---|---|---|
  | The 2026-10-27 NVD and KEV feeds (largest file 493,417,964 bytes) | 3,073,040,466 bytes | 396,211 | — | — | — |
  | One plain synthetic NVD 2.0 file | 736,352,257 bytes | 935,000 | — | — | — |

  A 1,073,741,825-byte file is refused as `decompressed_file_too_large` before it is
  parsed. Memory grows with the largest file and stays far below serving's; the peak disk
  is bounded by the 16 GiB staging cap. The other caps are unchanged.
- Serving cost on real data. The 2026-10-27 store (396,211 records)
  takes time and memory to load (`load_served_corpus`), and uses
  memory for the API's two deployments over one data plane, measured with
  `scripts/operator/measure_serving.py` ; loading differs from the
  250,000-record synthetic store, as does the API. M7b loads once per evaluation and does not wait on
  it. Lexical search is an inverted index that builds a match object only for the
  results it returns. Over that store it builds, and 1,056 searches (the M7b
  run's queries and 300 sampled ones, at three limits and filters each) completed
  without collection stalls, so the stalls in
  [`m7b-results-2026-10-28.md`](m7b-results-2026-10-28.md#causes) do not recur and
  `gc.freeze()` is not needed.
- 18 NVD records are excluded at import because a vulnerable CPE names no concrete
  vendor or product (`cpe:2.3:h:qualcomm:-:-:…`, `cpe:2.3:o:-:-:-:…`). An alternative
  is keeping the record and dropping only that CPE match; decide it if a gold case turns
  out to need one of them.
- `graph_expand` passed the bounded real-store release check on 2026-10-31, using
  `scripts/operator/measure_graph_expand.py` with one store load and no model or network.
  The 396,211-record store's `corpus_content_sha256` is
  `0dc90836bb0f02f748ef0bd758909711557cb85413110c58a14d5a4d55c15f3a`.
  Relation degrees count the CVEs sharing each distinct relation value; p99 is nearest
  rank, and the store holds no purls:

  | Relation | Values | Median degree | p99 degree | Max degree |
  |---|---:|---:|---:|---:|
  | CWE | 811 | 14 | 10,463 | 48,754 |
  | Vendor | 36,595 | 1 | 78 | 17,280 |
  | Product | 121,689 | 1 | 85 | 15,187 |
  | CPE | 374,206 | 1 | 90 | 14,191 |
  | purl | 0 | — | — | — |

  Ten typical seeds (two lexical matches each for Open5GS, free5GC, Kamailio, OpenSIPS
  and OpenAirInterface, named by the M7b baseline or relevance gold cases) ran
  synchronous searches. Ten high-degree seeds (four leading CWEs,
  three vendors and three products, with degrees 8,366–48,754) completed.
  Every search finished inside the 10 s tool limit, with an `ok` graph outcome and
  10 returned candidates at limit 10, each warning `result_limit_reached`; the warning
  does not count visited or omitted nodes. The process peak RSS, read with Python's
  `resource`, was recorded, unchanged from its serving startup
  peak and below the recorded API serving baseline plus the fixed
  1 GiB allowance. All fixed criteria passed. Graph expansion remains available,
  with no tuning or contract change. The operator output contains the degree figures,
  per-seed timings and peak RSS in `measurement.json` and `summary.md` under
  `~/data/cve-kgrag/runs/graph-expand/`. This check covers these twenty single-CVE
  queries, not arbitrary multi-seed searches.

## Offline lane

The lanes live in `scripts/ci/`; the CI workflow (`.github/workflows/offline.yml`) runs
the same scripts, with no service, no secret and no live test.

```bash
scripts/ci/offline_lane.sh            # tests, ruff, format, mypy, schema check, lock
scripts/ci/core_only_lane.sh 3.12     # the wheel in a fresh venv, no dev group, no extra
```

A network guard (`tests/conftest.py`) refuses connects outside loopback from before
collection to the end of the run, so module-level test code is covered too. Only an
explicitly enabled live run (`CVE_KGRAG_LIVE_TESTS=1`, the live lane above) goes without
it.
