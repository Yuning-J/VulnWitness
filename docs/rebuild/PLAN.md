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
| M7 | M7b after WP10: the same evaluation on imported data with hand-labelled sufficiency, then the decision on evidence gaps, controlled term expansion and more rounds; review packet | in progress: gold cases and the M7b evaluation done; the first model run, its causes and the planned work order in [`m7b-results-2026-10-28.md`](m7b-results-2026-10-28.md) |

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

Follow-up: round 2 consults a configured model even when no call can pass the gate.
Reproduction: query `CVE-9999-4242`, scope `implementation_only`; round 1 looks the ID up,
and round 2's planning input offers only that lookup (now repeated) and a search with no
allowed terms, so every reply is rejected and the set carries `model_plan_rejected`.
The same holds in round 1 when the policy's own plan is over the source budget (query
`5G-AKA`, budget `max_sources: 1`). Proposed fix: consult no model in a round where no
offered call can pass the gate, with the controller and the audit deciding that by one
shared rule, and record the round as the policy's.

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
  reviewed topic terms, not derived from CVEs.
- There is no v2 Neo4j adapter; whether one is built is open.

## Follow-ups from M6 (ADR 0009)

Recorded when M6 closed; none blocks M7b unless it says so.

- CSAF import; an allowlisted refresh command; the Trustify adapter (above); the planner
  round-2 fix (above).
- The semantic index build from a store: a collection built from a store records its
  `corpus_content_sha256`, and the semantic channel serves a store only when that
  digest equals the served one; it also settles legacy `KEV-` chunk IDs.
- The `search_cves` filtered seam; hot reload of an activated store; removing old
  stores; a matched count for `search` responses; revisiting the 20-technique cap on
  topic context, whose cuts are now reported.
- The importer's 512 MiB per-file cap against the current year's feed. On 2026-10-27 the
  2026 feed decompressed to 493,417,964 bytes (92% of the cap) and grows until the year
  ends, so a full import will fail once it passes the cap; raise the cap, measured
  against staging and import memory, before then.
- Serving cost on real data. The 2026-10-27 store (396,211 records)
  takes time and memory to load (`load_served_corpus`), and uses
  memory for the API's two deployments over one data plane, measured with
  `scripts/operator/measure_serving.py` ; both differ from the
  250,000-record synthetic figures. M7b loads once per evaluation and does not wait on
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
- `graph_expand` at scale, acceptance work on a real NVD store: record the relation
  degree distribution (CWE, vendor, product, CPE, purl) and, for typical and
  high-degree seeds, latency, peak memory and candidate count, each with the store's
  `corpus_content_sha256`; try exact optimizations first (build paths only for the
  final top-k, no full path set per candidate); only if those are not enough, design
  pruning of high-degree relations with its own warning (such as
  `graph_expansion_truncated`) and an omitted count. If ordinary graph queries often time
  out on real data, fix it or disable `graph_expand` over a corpus store before the
  public release.

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
