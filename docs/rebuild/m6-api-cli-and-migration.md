# M6 — API, CLI and migration

Schema version `2.0.0-dev.20`. M6 is built in work packages; this document records each
one as it lands.

## Work packages

| Package | Scope | Status |
|---|---|---|
| WP1 | Typed settings boundary and secret handling, model planner discovery and its `unavailable` capability (ADR 0004) | done |
| — | Model planner adapter (OpenAI-compatible, off by default, opt-in live test; ADR 0005); a separate task between WP1 and WP2 | done; live tests passed against DeepSeek `deepseek-flash` on 2026-10-21 |
| WP2 | Semantic settings from the environment, with `semantic_channel` reporting a failed load as unavailable and every command that can run the channel wired to the same settings | done |
| WP-S | Repository split bootstrap: this repository's first commit (ADR 0006) | done |
| WP3′ | ADR 0007, HTTP surfaces (documentation only) | done |
| WP4 | Offline CI: lane scripts, GitHub workflow, test-time network guard | done |
| WP5 | Full CLI, verification report contract, served-bundle seam | not started |
| WP6 | HTTP guard, HTTP settings, health and readiness, opt-in Streamable HTTP for MCP | not started |
| WP7 | v2 REST API, set verification over HTTP, `api` extra | not started |
| WP9 | Read-only legacy-data importer (ADR 0008) | not started |
| WP10 | Store activation and serving, operator FiGHT snapshot, M6 exit audit | not started |

v1 compatibility is not an M6 package here: it stays in CVE-KGRAG (ADR 0006).

## WP1 — settings and secrets

Decisions: ADR 0004.

- `settings.py` reads five `CVE_KGRAG_PLANNER_*` variables, once, at the CLI entry
  point. The planner is off unless `CVE_KGRAG_PLANNER_ENABLED` is on. Invalid settings
  are a usage error naming the variables, never their values.
- An enabled planner without a key, or without a usable `model_planner` adapter, leaves
  the deterministic policy planning and reports `model_planner: unavailable` with a
  server sentence. The OpenAI-compatible adapter (ADR 0005) is the registered
  `model_planner` entry point.
- `cve-kgrag investigate` plans with the discovered planner. `cve-kgrag verify` accepts
  the planner capabilities the settings allow, without the key and without loading the
  adapter; a model-planned set verifies only where the same adapter is installed.
  `cve-kgrag mcp` keeps the deterministic planner.
- A discovered adapter is guarded: anything it raises, and an answer that is not a valid
  reply, is logged by type only and recorded as a fixed failed reply. A failed reply
  carries one of the server's sentences, never adapter text.
- The server builds the planner's identity from the settings and the installed entry
  point: model, adapter, adapter version and endpoint fingerprint. The same model behind
  another endpoint is another planner, and its sets do not verify here. The settings
  reject port 0 and remove exactly one trailing `/` from the endpoint; the fingerprint
  keeps an explicit port and the path as configured, so `/v1//` is another endpoint.
- Listing the adapter registry is guarded on every discovery path.

### Contracts at `2.0.0-dev.18` (WP1)

- `SourceCapability.detail` gains `ModelPlannerUnavailableDetail`:
  - `the model planner is enabled but no API key is configured`
  - `the model planner adapter is not installed or could not be used`
- `model_planner` may be `unavailable`. The validator allows `not_configured` or
  `unavailable` for the deterministic policy, and `available` with the planner's version
  (`format_planner_version`: model name and identity hash) for a model.
- `ModelPlannerIdentity` gains `adapter`, `adapter_version` and `endpoint_sha256`.
- `ModelReply.detail` is a `ModelReplyFailureDetail` sentence; `plan_text` is described
  as untrusted model output, as are the investigate tool and the server instructions.

## Model planner adapter

Decisions: ADR 0005.

- `cve_kgrag.adapters.planner.openai_compatible:build_model_port` is the core
  `model_planner` entry point: one chat-completions request per round on `http.client`,
  its reads ended by a watchdog at the deadline, with no redirect, no environment proxy,
  no error body read and no reply text logged.
- A planner call gets at most a third of the run's budget (`PLANNER_SHARE_OF_WALL_TIME`,
  10 s of 30 s), enforced by the controller: a planner still running then, or whose reply
  lands at or after it, is recorded as a `TIMED_OUT` reply and the round falls back to the
  policy.
- `PlanningInput.required_tools` tells the model which tools a round-1 plan includes.
- A reply whose content holds the key, as written or JSON-escaped, is refused as
  malformed.
- The planner is offered only tools the source budget leaves room for.

### Contracts at `2.0.0-dev.19`

- `ModelPlannerIdentity` gains `reasoning_effort` (null when none is sent), set from
  `CVE_KGRAG_PLANNER_REASONING_EFFORT`.
- `PlanningInput` gains `required_tools` (not part of any published response).
- The settings refuse a key that is not printable ASCII without whitespace and an endpoint
  that is not ASCII.

### Running with a planner configured

```bash
export CVE_KGRAG_PLANNER_ENABLED=true
export CVE_KGRAG_PLANNER_BASE_URL=https://api.deepseek.com
export CVE_KGRAG_PLANNER_MODEL_NAME=deepseek-flash
export CVE_KGRAG_PLANNER_REASONING_EFFORT=none   # DeepSeek reasons by default
export CVE_KGRAG_PLANNER_API_KEY="$DEEPSEEK_API_KEY"   # or source an untracked .env:
                                                       # set -a; . ./.env; set +a
cve-kgrag investigate "5G-AKA" --scope implementation_only
```

Never pass the key on the command line. The live tests read the same variables:

```bash
CVE_KGRAG_LIVE_TESTS=1 uv run pytest tests/live -m live
```

### Known limits

- The endpoint fingerprint does not name the host, but a guessable host can be confirmed
  by hashing it.
- The in-core adapter's `adapter_version` is the package version, `2.0.0.dev0` during
  development, so a change to its instructions does not change the planner identity
  until the version moves.
- https is not exercised by the offline tests; the live tests exercise it.
- Connecting runs under the socket timeout for each address tried, so a slow connect and
  a slow TLS handshake can take the timeout each; the core stops waiting at the run's
  deadline regardless.
- Round 2 consults a configured model even when no call can pass the gate (PLAN.md
  follow-up).

## WP2 — semantic settings

Decisions: ADR 0004 §1.

- `CVE_KGRAG_SEMANTIC_ENABLED` turns the semantic channel on; its collection and model
  have the CVE-KGRAG pipeline's defaults, its directory is required, and each has its
  own variable.
- `search`, `topic` and `investigate` load the semantic adapter only when run with
  `--semantic`; without it, and for `lookup` and `demo`, no adapter is loaded. Every
  command still validates the settings at startup, so an invalid one is a usage error.
- `mcp` and `verify` never load it, whatever the settings, and log one line saying so:
  Chroma has no read-only client, so opening its store may write to it, and both
  surfaces promise not to change local state. Their `semantic_channel` is
  `not_configured`.
- The adapter loads its model from disk only (`local_files_only`), so it never reaches the
  model hub or writes the model cache.
- The Chroma adapter opens only a directory that already holds a Chroma database, so a
  mistyped directory is reported unusable rather than created.
- The validator requires a semantic failure's reason to match the capability:
  `NOT_CONFIGURED` when not configured, `ADAPTER_UNUSABLE` when unavailable.
- An enabled channel whose adapter is not installed or fails to load reports
  `semantic_channel: unavailable` with `the semantic adapter is not installed or could not
  be loaded`, and each of its searches reports the channel unavailable. Discovery logs the
  failure by type only.
- `SearchService` takes a retriever or the reason the channel cannot search, and the
  composition root reads the capability from it (`describe_semantic_capability`).

### Contracts at `2.0.0-dev.20`

- `semantic_channel` may be `unavailable`; `SourceCapability.detail` gains
  `SemanticUnavailableDetail`.

### Known limits

- A set sealed with `--semantic` while the semantic channel was enabled does not verify:
  `verify` serves no semantic channel, so the set reports a capability it does not serve.
  A read-only semantic store would lift this.
- An operator running `--semantic` accepts that Chroma may write to its own store
  (journal, migrations) while opening it; loading runs before the run's clock starts, so
  a slow store or model load is not bounded by the run's wall time.
- The Chroma adapter's directory check runs only with the `semantic` extra, which the
  offline lane does not install, so no offline test exercises it.

## WP-S — repository split

Decisions: ADR 0006.

- This repository starts from CVE-KGRAG commit `53d75e3` without its history
  (`PROVENANCE.md`). Its first commit carries the package, `schemas/v2`, `eval/gold`, the
  tests and the rebuild docs, already adapted here.
- The legacy RAG wrapper, its unit test and its test double are not carried. Three
  `SearchService` tests that ran through it run through `VectorSemanticRetriever` with
  the shared `FakeCollection` and `FixedEncoder` (`tests/support/vector_store.py`), so
  chunk collapse, machine-independent failure details and over-long CVE IDs stay tested
  through the service. Filtered semantic search stays tested on that adapter.
- `CVE_KGRAG_SEMANTIC_PERSIST_DIRECTORY` has no default: an enabled semantic channel
  without it is a usage error naming the variable.
- The legacy fine-tuned model's registry entry and `LocalStoragePolicy.COMMITTED_ARTIFACT`
  are not carried; no schema changes, and the contracts stay at `2.0.0-dev.20`.
- The dev group does not list FastAPI or httpx2 (httpx2 still arrives through the `mcp`
  extra), and `testpaths` lists
  `tests/unit`, `tests/contract` and `tests/integration`.

## WP3′ — HTTP surfaces (ADR 0007)

Documentation only; no listener, setting or contract changes. ADR 0007 fixes what WP6
and WP7 build: Starlette and uvicorn; REST and MCP over HTTP as separate processes,
with the `mcp` extra owning MCP over HTTP and a new `api` extra; loopback hosts only; a
bearer token on both servers, with `/health` the only open route; the deterministic
planner and no semantic channel on HTTP; stateless MCP sessions; an `HttpRejection`
envelope for rejections before any tool runs and for the request deadline; the
`ToolFailureCode` to HTTP status table; the REST endpoints, verification included;
ports 8765 and 8766 from settings only. ADR 0001 §2 and ADR 0003 §10 and §12 are
amended to match.

## WP4 — offline CI

- `scripts/ci/offline_lane.sh` runs `uv sync --locked`, pytest, `ruff check`,
  `ruff format --check`, mypy, `cve-kgrag schema check` and `uv lock --check`.
  `scripts/ci/core_only_lane.sh [python]` builds the wheel, installs it alone in a fresh
  venv, runs `cve-kgrag demo`, expects `cve-kgrag mcp` to exit 1 with the missing-extra
  refusal, and runs the unit, contract and integration tests outside the MCP interface. PLAN.md
  calls these scripts.
- `.github/workflows/offline.yml` runs the offline lane on Python 3.11 and 3.12 and the
  core-only lane on 3.12, on pushes to `main` and on pull requests. It starts no service,
  reads no secret, sets no live-test variable, gives its token read access only (no job
  widens it), pins each action to a commit, installs uv 0.12.17, passes each matrix
  Python to setup-uv and keeps no checkout credentials; `tests/contract/test_ci_workflow.py`
  checks all of these.
- A `pytest_runtest_protocol` hook in `tests/conftest.py` refuses every connect outside
  loopback (`tests/support/network_guard.py`) while each test is set up, run and torn
  down, so fixtures of every scope are covered, except in the opt-in live tests under
  `tests/live`. `tests/unit/test_network_guard.py` checks that a documentation address is
  refused and loopback is allowed.
- The first run on GitHub Actions passed: the offline lane gave 2407 passed on Python
  3.11 and on 3.12, the core-only lane 2349 passed. With the review fixes the local
  offline lane (3.12) gives 2409 passed and the core-only lane 2351 passed.
