# M6 exit audit

The repository's requirement baseline for M6 (ADR 0009 §17). The rebuild brief and the
requirements inventory are not committed, so every requirement ID the M6 plan used, A1
to H, has a self-contained entry here: its source, the text it rests on, the reading
adopted, where it is implemented and tested, and its status.

## Sources and conventions

- **Brief**: "Owner-provided rebuild brief, 2026-10-13, §N". Quotes join the brief's
  hard line wraps with a space.
- **Inventory**: "M6 requirements inventory, reconstructed 2026-10-21 and
  owner-approved", which listed A1 to H. The inventory was compiled from an earlier draft
  of the brief; where the two differ (the v1 wording of §14, §18, §19 and the definition
  of done), this audit quotes the brief as provided on 2026-10-13 and says so.
- **M6 plan**: the M6 work-package plan of 2026-10-21, which assigned each ID to a work
  package and split E4 into E4a and E4b.
- **Source type** is one of: a sentence of the brief; an item derived by the inventory
  (a gap it found, not a sentence of the brief); or a split made by the M6 plan.
- Work-package records are in [`m6-api-cli-and-migration.md`](m6-api-cli-and-migration.md);
  test paths are relative to the repository root.

## The M6 exit criterion

Brief §18, M6: "implement v2 API/CLI over the same application layer; apply the v1
decision from section 2 with matching tests; implement legacy migration dry-run/new-target
behavior; split dependencies and remove unsafe defaults; add offline CI. Exit criterion:
default CI requires no external service; migration cannot overwrite legacy data; v1 (if
retained) and v2 contract tests pass."

| Exit clause | Met by |
|---|---|
| default CI requires no external service | WP4: `scripts/ci/offline_lane.sh`, `core_only_lane.sh`, `.github/workflows/offline.yml`; the test-time network guard (`tests/conftest.py`, `tests/unit/test_network_guard.py`); `tests/contract/test_ci_workflow.py` |
| migration cannot overwrite legacy data | WP9 (ADR 0008 §9): a new target only, never an existing store or an input; `tests/integration/adapters/migration/test_legacy_migration.py` |
| v1 (if retained) and v2 contract tests pass | v1 is not retained here (ADR 0006 decision 3; its characterization tests run in CVE-KGRAG). v2: `tests/contract/test_request_schema_agreement.py`, `test_response_schema_agreement.py`, `test_schema_snapshots.py`, `tests/integration/interfaces/rest/test_rest_api.py` |

## Owner decisions 15 to 17

These are the M6 plan's recommendations as written on 2026-10-21. The owner accepted the
plan's recommendations without objection that day, the WP10 scope was confirmed against
them on 2026-10-25, and the owner's review of ADR 0009 on 2026-10-26 applied them: it
called the in-memory indexes startup builds, with nothing written to disk, an
owner-approved refinement (D9), and required a configured FiGHT snapshot that cannot be
served to stop the command with exit 2, with no fallback to the excerpt.

- **15. Index scope.** "In M6 the index is the validated corpus store. It is produced by
  `migrate`, activated explicitly by `store activate`, and the lexical and graph
  structures are built in memory at startup. A Chroma or semantic index build from a
  migrated store is a follow-up." Why: "this meets 'explicit build/import' and 'active
  only through an operator action' without the semantic extra in CI. The ADR records
  that building in memory is not a migration or a rebuild on disk."
- **16. A configured store that is missing or invalid.** "Every surface refuses to
  start; there is no fixture fallback." Why: "silently serving synthetic data to an
  operator who configured real data would mislead them."
- **17. Operator FiGHT snapshot.** "In M6 (WP10)." Why: "it uses the same
  pin-and-validate pattern, and m3 deferred it to M6."

## A. v2 HTTP API

**A1. `api` extra.** Source: brief §15, "Replace the monolithic install story with
pyproject.toml and optional extras." with the item "- api: FastAPI/uvicorn;". Inventory:
add an `api` extra. Reading: the extra holds the ASGI stack the REST API runs on;
ADR 0007 decision 1 chose Starlette and uvicorn, and FastAPI is in no dependency group.
Implemented: `pyproject.toml` (`api` extra), `interfaces/rest/` (WP7). Tests:
`scripts/ci/core_only_lane.sh` (the API refuses to start without the extra). Status: met,
with the framework deviation ADR 0007 records.

**A2. v2 API over the same services.** Source: brief §14, "Create versioned v2 APIs over
the same application services used by MCP. Do not duplicate query logic in HTTP routes."
and the suggested surface `POST /api/v2/search`, `POST /api/v2/investigate`,
`GET /api/v2/evidence/{evidence_id}`, `GET /api/v2/capabilities`, `GET /health`,
`GET /ready`. Reading: the routes hand each request to the same `KnowledgeToolbox` the
MCP server uses. Implemented: `interfaces/rest/tool_routes.py`, `api_runner.py` (WP7).
Tests: `tests/integration/interfaces/rest/test_rest_api.py`. Status: met.

**A3. App factory, no module-global state.** Source: brief §14, "Use dependency
injection/application factories rather than a module-global mutable dictionary.", and
§22, "leave module-global application state as the dependency mechanism;" (under "Do
not:"). Implemented: `build_api_app` builds the app from an injected toolbox and check;
composition builds both (WP7). Tests: `test_rest_api.py` builds a fresh app per test.
Status: met.

**A4. Health and readiness kept separate.** Source: brief §14, "Separate liveness from
readiness and report optional source capabilities without making the whole service
unhealthy.", and §20, "Separate health and readiness." Implemented:
`interfaces/http/status_routes.py` (WP6): `/health` 204 always, `/ready` 204 while a
worker is free; unavailable sources show in `capabilities`. Tests:
`tests/integration/interfaces/http/test_http_guard.py`, `test_rest_api.py`. Status: met.

**A5. No wildcard credentialed CORS.** Source: brief §14, "Default CORS must be disabled
or restricted to configured local origins. Never combine wildcard origins with
credentials.", and §22, "retain a wildcard credentialed CORS configuration;". Reading:
no CORS layer at all: the servers send no CORS headers, and the guard refuses a request
whose `Origin` is not a served loopback origin (403 `origin_not_allowed`, ADR 0007
decision 7). Tests: `test_http_guard.py`. Status: met.

**A6. Loopback bind and the MCP bounds over HTTP.** Source: brief §20, "Bind network
interfaces locally by default.", "Prevent SSRF, path traversal, query injection, and
oversized payloads.", "Do not expose arbitrary Cypher, SQL, shell, Python, filesystem, or
model operations through HTTP or MCP.", "Apply strict timeouts and bounded retries.",
"Ensure error messages do not leak credentials or local paths."; §13, "every tool has
strict typed input, length/page/result limits, timeout, and bounded response size;",
"callers cannot pass filesystem paths, source endpoints, raw SQL/Cypher, executable code,
shell commands, arbitrary URLs, model download names, or index-rebuild requests;",
"errors are typed and sanitized;". Implemented: loopback-only host setting, wire body
caps, the request deadline and fixed rejection envelopes in `interfaces/http/guard.py`
(WP6, ADR 0007). Tests: `test_http_guard.py`, `test_rest_api.py`,
`tests/contract/test_knowledge_tools.py`. Status: met.

**A7. v2 contract tests over real HTTP.** Source: brief §19, "API v1 compatibility (if
retained) and v2 contracts;" (the inventory's draft read "API v1 compatibility and v2
contracts"). Inventory: tests through the in-process client; new HTTP envelopes get
schema snapshots. Implemented: `http_rejection.schema.json`, `verification_report.schema.json`
(WP5–WP7). Tests: `test_rest_api.py` (every route over the ASGI client),
`tests/contract/test_response_schema_agreement.py`. Status: met for v2; v1 see B1.

**A8. Whole-set verification over HTTP.** Source: derived by the inventory from ADR 0003
§10 ("M6 decides whether the v2 API exposes it") and the M6 scope in `PLAN.md`; no
sentence of the brief. Description: if the API exposes verification, its verdict
becomes a published contract. Implemented: `POST /api/v2/verify` and
`verification_report.schema.json` (WP5, WP7); WP10 shares the read-only data plane with
the tool deployment (ADR 0009 §12). Tests: `test_rest_api.py`,
`tests/integration/interfaces/rest/test_shared_data_plane.py`. Status: met.

## B. v1 compatibility

**B1. The v1 decision.** Source: brief §14, "If section 2 established /api/v1 as a
public contract, then before replacing v1: … preserve a compatibility facade with an
explicit deprecation header/window; … If it did not, replace v1 directly and record the
decision in the migration map."; §2, reconciliation item 1, "If no external consumer is
verifiable, record that finding and treat v1 as internal: do not build a deprecation
window; plan its replacement in the migration map instead."; §18 M6, "apply the v1
decision from section 2 with matching tests;". (The inventory's draft required "tested v1
compatibility" unconditionally.) Reading: the owner split the repository on 2026-10-21;
`/api/v1` and its characterization tests stay in CVE-KGRAG, and this repository provides
no v1 surface (ADR 0006 decision 3). Status: decided; out of this repository's scope.

**B2. v1 incompatibilities listed.** Source: brief §14, "write characterization/contract
tests for the documented /api/v1/search, /query, /summary, and /health behavior;" and
"document unavoidable incompatibilities." Status: not provided here (ADR 0006,
deviations); optional in CVE-KGRAG.

**B3. Legacy wildcard CORS and 0.0.0.0 bind.** Source: brief §22, "retain a wildcard
credentialed CORS configuration;" and §20, "Bind network interfaces locally by default."
Status: out of this repository's scope; fixed in CVE-KGRAG (ADR 0006, deviations).

## C. CLI

The C items rest on brief §14, "Provide a small CLI using the package entry point for:
offline fixture demo; exact/search/investigate; schema export/check; legacy migration
dry-run; explicit index build/import; MCP server startup; API startup."

**C1. Migration with `--dry-run`.** Source: brief §14, "legacy migration dry-run;", and
§17, "Implement a read-only legacy importer and a migration command with: … --dry-run;".
Implemented: `cve-kgrag migrate legacy --dry-run` (WP9, ADR 0008). Tests:
`tests/integration/adapters/migration/test_legacy_migration.py`,
`tests/integration/test_cli.py`. Status: met.

**C2. Explicit index build/import.** Source: brief §14, "explicit index build/import;".
Reading (owner decision 15): the index is the validated corpus store, imported by
`migrate legacy` and activated by `store activate`; startup builds the lexical and graph
structures in memory and writes nothing. Implemented: WP9 and WP10 (ADR 0009 §7–§9).
Tests: `tests/integration/adapters/store/test_store_activation.py`, `test_active_store.py`,
`tests/integration/test_cli_store_root.py`. Status: met; a semantic index build is a
follow-up.

**C3. API startup.** Source: brief §14, "API startup.". Implemented: `cve-kgrag api`
(WP7). Tests: `test_rest_api.py` (the command served on a free port). Status: met.

**C4. MCP Streamable HTTP startup.** Source: brief §14, "MCP server startup;", and §13,
"Streamable HTTP is optional, must be explicitly enabled, bind to 127.0.0.1 by default,
and must not expose an unauthenticated 0.0.0.0 listener;". Implemented:
`cve-kgrag mcp --http` (WP6). Tests: `tests/integration/interfaces/mcp/`. Status: met.

**C5. Search filter and graph options.** Source: derived by the inventory from the M2
deferral of the filter options to the full M6 CLI; related brief text, §9, "structured
filtering over vendor/product/severity/year/CWE and available package identifiers;" and
"deterministic graph expansion over validated canonical relations;". Implemented:
`search --vendor --product --purl --cwe --severity --year --origin --kev-only
--graph-expand` (WP5). Tests: `test_cli.py`. Status: met.

**C6. Importing a module has no side effects.** Source: brief §14, "No import may start a
server, connect to a database, load a model, write an index, or create persistent
directories." Tests: `tests/contract/test_import_side_effects.py`,
`tests/contract/test_core_isolation.py`. Status: met.

## D. Migration tooling

The D items rest on brief §17, "Implement a read-only legacy importer and a migration
command with: schema/version detection; --dry-run; input checksum; validation/error
statistics; an explicit new target directory; no in-place overwrite; idempotency; a
manifest of produced artifacts; rollback instructions.", on §23, "Legacy migration is
dry-run-first, non-overwriting, and reversible.", and on §18 M6, "implement legacy
migration dry-run/new-target behavior;". D1 to D8 and D10 are WP9 (ADR 0008); their tests
are under `tests/integration/adapters/migration/` and
`tests/integration/adapters/store/test_corpus_store.py`.

**D1. A read-only legacy importer.** Source: brief §17 (above) and §9, "Add a read-only
legacy importer; never rewrite source files in place." Reading (M6 plan decision 11,
ADR 0008): the importer reads the raw NVD feeds and the CISA KEV catalog the legacy
pipeline downloaded; its derived exports are detected and refused as sources. Status:
met.

**D2. Schema and version detection.** Source: brief §17, "schema/version detection;".
Implemented: feed format and artifact detection; derived-file fingerprinting (ADR 0008
§2, §3). Status: met.

**D3. Input checksum.** Source: brief §17, "input checksum;". Implemented: every input's
SHA-256, and the payload's for NVD, in the store manifest (ADR 0008 §3). Status: met.

**D4. Validation and error statistics.** Source: brief §17, "validation/error
statistics;". Implemented: the migration report's counts by reason code (ADR 0008 §7).
Status: met.

**D5. A new target only.** Source: brief §17, "an explicit new target directory;" and
"no in-place overwrite;"; §18 M6 exit, "migration cannot overwrite legacy data".
Implemented: ADR 0008 §9; with a store root set, a target in it must be a validly named
store directly under it (ADR 0009 §4). Status: met.

**D6. Idempotency.** Source: brief §17, "idempotency;". Implemented: the import identity;
a run whose target holds the same import reports `already_imported` (ADR 0008 §4).
Status: met.

**D7. A manifest of produced artifacts.** Source: brief §17, "a manifest of produced
artifacts;". Implemented: `manifest.json` pinning every store file
(`corpus_store_manifest.schema.json`). Status: met.

**D8. Rollback metadata and instructions.** Source: brief §17, "rollback
instructions.", and §19, "migration dry-run, idempotency, checksum, new target, and
rollback metadata;". Implemented: the fixed rollback kind, scope and instruction in the
manifest and the report (ADR 0008 §9); after activation, `cve-kgrag store rollback`
(ADR 0009 §7). Status: met.

**D9. Explicit activation; startup never migrates.** Source: brief §17, "Index builds
must write to a new versioned directory. They may be activated only after validation by
an explicit operator action. Application startup must not hide migrations or index
rebuilds." Reading (owner, 2026-10-26): the "versioned directory" is a new directory the
importer never overwrites, identified by its manifest digest and import identity; the
indexes startup builds in memory, with nothing written to disk, are the owner-approved
refinement of owner decision 15; a persisted semantic index must follow D9.
Implemented: `store validate | activate | rollback | status` and startup loading
(ADR 0009 §5–§9, WP10). Tests: `test_store_activation.py`, `test_active_store.py`
(a read-only root serves and startup writes nothing), `test_cli_store_root.py`. Status:
met.

**D10. Migration tests.** Source: brief §19, "migration dry-run, idempotency, checksum,
new target, and rollback metadata;". Tests: `tests/integration/adapters/migration/`,
`tests/unit/domain/test_migration_report.py`. Status: met.

**D11. Serving a migrated store.** Source: derived by the inventory, not a sentence of
the brief: "Serving a migrated store. Today every composition path serves only the
packaged synthetic fixture, and no setting points at a corpus or index." Reading
(ADR 0009 §10): every surface that serves CVE records, search or evidence serves the
active store; `eval planner` and `demo`, fixed to the fixture, and the commands that use
no corpus are outside it. Implemented: `load_served_corpus`, the `ServedCorpus` seam and
the store root setting (WP10). Tests: `test_cli_store_root.py`, `test_active_store.py`,
`tests/contract/test_store_format_compatibility.py`. Status: met.

**D12. CSAF and the pipeline commands.** Source: derived by the inventory from the
migration map and the M2 deferral; related brief text, §9, "Reuse verified parsing
knowledge from the legacy NVD/CPE/KEV/CSAF code, but normalize it into the canonical
models." Status: deferred; recorded in `PLAN.md` (follow-ups from M6).

**D13. The `search_cves` seam.** Source: brief §17, "The first migration seam should
preserve the useful logical operation: search_cves(query, n_results, severity_filter,
vendor_filter) -> results … Define a port and initially support it with a legacy adapter
while replacing the internals incrementally." Status: the legacy wrapper was dropped with
the repository split (ADR 0006, deviations); the filtered seam is a follow-up in
`PLAN.md`.

## E. Dependencies, settings and unsafe defaults

**E1. Dependency split.** Source: brief §15, "Replace the monolithic install story with
pyproject.toml and optional extras.", "The default core install must not pull Torch,
CUDA packages, transformers, Gradio, Neo4j, or Chroma.", "Pin or lock reproducible
dependency versions using the repository's chosen tool."; §18 M6, "split dependencies
and remove unsafe defaults;". Implemented: core depends on pydantic and pyyaml only;
extras `semantic`, `mcp`, `api`, `migration`; `uv.lock` committed. No `neo4j` extra: no
v2 Neo4j adapter exists, and whether one is built is open (`PLAN.md`); no `trustify`
extra until a verified adapter exists (ADR 0003). Tests:
`tests/contract/test_core_isolation.py`, `scripts/ci/core_only_lane.sh`. Status: met.

**E2. Hard-coded production passwords.** Source: brief §22, "retain hard-coded
production passwords;", and §15, "There must be no default production password." Status:
out of this repository's scope (it holds no Neo4j code); fixed in CVE-KGRAG (ADR 0006,
deviations). This repository has no default secret (ADR 0004).

**E3. `requirements.txt` and docker-compose review.** Source: derived by the inventory
from the migration map; related brief text, §15 and §18 M6 (above). Status: out of this
repository's scope; reviewed in CVE-KGRAG (ADR 0006, deviations).

**E4. One typed settings boundary.** Source: brief §15, "Consolidate configuration into
one typed settings boundary. There must be no default production password. Missing
credentials disable the corresponding adapter with a typed capability status."
Inventory: settings covered only the planner and the semantic channel; still unsettled
were the operator FiGHT snapshot path and pin, the corpus or index location, the HTTP
bind address, auth token, CORS origins and allowed hosts. Implemented: `settings.py`
(WP1, WP2, and E4a and E4b below). Status: met through E4a and E4b.

**E4a. HTTP settings.** Source: brief §15 (above); a split by the M6 plan, which divided
E4 into "E4a HTTP settings (host, ports, token, origins, limits)" (WP6) and E4b (WP10).
Implemented: `CVE_KGRAG_HTTP_HOST` (loopback only), `CVE_KGRAG_MCP_HTTP_PORT`,
`CVE_KGRAG_API_PORT`, `CVE_KGRAG_HTTP_TOKEN` (ADR 0004, ADR 0007); origins are fixed to
the served loopback origins rather than configured. Tests: `tests/unit/test_settings.py`,
`test_http_guard.py`. Status: met.

**E4b. Store root and FiGHT snapshot settings.** Source: brief §15 (above); a split by
the M6 plan, "E4b store root and FiGHT snapshot settings" (WP10). Implemented:
`CVE_KGRAG_STORE_ROOT` and the pair `CVE_KGRAG_FIGHT_SNAPSHOT_PATH` and
`CVE_KGRAG_FIGHT_SNAPSHOT_SHA256` (ADR 0009 §3, ADR 0004 §1); the snapshot is checked
against the reviewed catalog when it is loaded (ADR 0009 §11). Tests:
`tests/unit/test_settings.py`, `tests/integration/adapters/fight/test_operator_snapshot.py`,
`test_cli_store_root.py`. Status: met.

**E5. Provenance of the legacy model.** Source: brief §16, "The repository's MIT
software license does not automatically cover collected data, models, or weights." and
"Treat FiGHT, ATT&CK, NVD/CVE data, CISA KEV, CWE, CAPEC, Trustify software, data
returned by Trustify, and any model artifacts as separate provenance/license subjects.";
§23, "Third-party data/model provenance is documented." Status: the model is not in
this repository; its provenance is recorded in CVE-KGRAG (ADR 0006 decision 6). This
repository's data provenance is `THIRD_PARTY_DATA.md`.

## F. Offline CI

**F1. Offline CI.** Source: brief §18 M6, "add offline CI." and its exit, "default CI
requires no external service"; §19, "Default tests must be offline and require no GPU,
network, Docker, Neo4j, Chroma, Ollama, Trustify, or full data files." and "core-only
import with no optional extras installed;"; §24's checks (format, lint, types, offline
tests, package build, clean-environment core install). Implemented: WP4,
`scripts/ci/offline_lane.sh`, `core_only_lane.sh`, `.github/workflows/offline.yml`.
Tests: `tests/contract/test_ci_workflow.py`. Status: met.

**F2. Live tests opt-in.** Source: brief §19, "Live tests must use explicit markers and
environment opt-in." Implemented: `tests/live` behind the `live` marker and
`CVE_KGRAG_LIVE_TESTS=1`; the network guard refuses non-loopback connects otherwise.
Tests: `tests/unit/test_network_guard.py`. Status: met.

## G. Streamable HTTP for MCP

**G1. Opt-in, loopback.** Source: brief §13, "Streamable HTTP is optional, must be
explicitly enabled, bind to 127.0.0.1 by default, and must not expose an unauthenticated
0.0.0.0 listener;". Implemented: `mcp --http` only, host setting loopback-only (WP6,
ADR 0007 decision 3). Tests: `tests/unit/test_settings.py`, `test_http_guard.py`.
Status: met.

**G2. Bearer authentication.** Source: brief §13, "must not expose an unauthenticated
0.0.0.0 listener;" and "authorization headers, tokens, passwords, and source excerpts
disallowed by terms are never logged."; §20, "Redact secrets, API keys, and
authentication headers."; §15, one typed settings boundary. Reading: a bearer token from
settings only, never a flag, required even on loopback (ADR 0007 decision 4). Tests:
`test_http_guard.py`, `tests/unit/test_settings.py`. Status: met.

**G3. DNS-rebinding protection.** Source: derived by the inventory from ADR 0003 §12 and
an inspection of the MCP SDK, whose own protection is off unless configured; no sentence
of the brief (nearest, §20, "Bind network interfaces locally by default."). Implemented:
the guard checks `Host` and `Origin` on every route (ADR 0007 decision 7, WP6); a request
without `Origin` passes, as a non-browser client sends none. Tests: `test_http_guard.py`.
Status: met.

**G4. Health and readiness.** Source: brief §20, "Separate health and readiness.", and
§14 (see A4). Status: met (A4).

**G5. Per-call bounds and a body cap.** Source: brief §13, "every tool has strict typed
input, length/page/result limits, timeout, and bounded response size;", and §20,
"Prevent SSRF, path traversal, query injection, and oversized payloads." Implemented:
the toolbox's bounds and the guard's wire body caps (ADR 0007 decision 11). Tests:
`test_http_guard.py`, `tests/integration/interfaces/test_knowledge_toolbox.py`. Status:
met.

**G6. Offline HTTP transport tests.** Source: brief §13, "Test the MCP handlers without
network and, if supported by the SDK, through an in-memory MCP client/server integration
test.", and §19, "MCP input/output limits and read-only surface;". Tests:
`tests/integration/interfaces/mcp/`, `test_http_guard.py`. Status: met.

## H. Required tests

**H. §19 tests owed by M6.** Source: brief §19, "At minimum cover (each in the
milestone that introduces the behavior):" with "API v1 compatibility (if retained) and v2
contracts;", "rejection of arbitrary URL/path/SQL/Cypher/shell fields;", "migration
dry-run, idempotency, checksum, new target, and rollback metadata;", "idempotent
fixture/legacy normalization;". Implemented: v2 contracts (A7); field rejection,
`tests/contract/test_knowledge_tools.py` (no input field names a URL, path, endpoint,
query language, command, code, model or index) and the contracts' closed models, which
refuse unknown fields over HTTP (`test_rest_api.py`); migration tests (D10), import
idempotency included; normalizer idempotency,
`tests/unit/adapters/test_nvd_normalizer.py`. v1 tests are not retained here (B1).
Status: met for this repository.

## WP10 additions recorded at the M6 exit

Beyond the IDs above, WP10 made truncation visible (ADR 0009 §11a), shared the API's
read-only data plane (§12), kept the semantic channel unbound over a store (§14), and
added the two format-1 guards (§15). Follow-ups are listed in `PLAN.md`, "Follow-ups from
M6".
