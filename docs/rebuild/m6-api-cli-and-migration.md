# M6 — API, CLI and migration

Schema version `2.0.0-dev.25`. M6 is built in work packages; this document records each
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
| WP5 | Full CLI, verification report contract, served-bundle seam | done |
| WP6 | HTTP guard, HTTP settings, health and readiness, opt-in Streamable HTTP for MCP | done |
| WP7 | v2 REST API, set verification over HTTP, `api` extra | done |
| WP9 | Read-only legacy-data importer (ADR 0008) | done |
| WP10 | Store activation and serving, operator FiGHT snapshot, visible truncation, M6 exit audit (ADR 0009) | done |

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
- A configured model plans only questions that name a CVE ID or resolve a reviewed
  topic. Free text is planned by the policy, and so is a round 1 whose policy plan is over
  the source budget, which no round-1 model plan can meet; both record
  `model_not_consulted` (ADR 0005 §3).

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
- The dev group lists no FastAPI, and `testpaths` lists `tests/unit`, `tests/contract` and
  `tests/integration`.

## WP3′ — HTTP surfaces (ADR 0007)

Documentation only; no listener, setting or contract changes. ADR 0007 fixes what WP6
and WP7 build: Starlette and uvicorn; REST and MCP over HTTP as separate processes,
with the `mcp` extra owning MCP over HTTP and a new `api` extra; loopback hosts only; a
bearer token on both servers, with `/health` the only open route; the deterministic
planner and no semantic channel on HTTP; stateless MCP sessions; an `HttpRejection`
envelope for rejections before any tool runs and for the request deadline; the
REST API's `ToolFailureCode` to HTTP status table; the REST endpoints, verification included;
ports 8765 and 8766 from settings only; body caps counted on the wire before any
parsing (4 MiB for verification, 256 KiB for every other route). ADR 0001 §2 and ADR 0003 §10 and §12 are
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
- `pytest_configure` in `tests/conftest.py` installs a guard that refuses every connect
  outside loopback (`tests/support/network_guard.py`) before collection, so test modules
  are guarded while they are imported, and keeps it to the end of the run. Only an
  explicitly enabled live run (`CVE_KGRAG_LIVE_TESTS=1`) goes without it.
  `tests/unit/test_network_guard.py` checks that a documentation address is refused,
  loopback is allowed, and a test module that connects at import fails collection with
  the guard's refusal.
- The first run on GitHub Actions passed: the offline lane gave 2407 passed on Python
  3.11 and on 3.12, the core-only lane 2349 passed. With the review fixes the local
  offline lane (3.12) gives 2409 passed and the core-only lane 2351 passed.

## WP5 — full CLI, verification report, served bundle

Decisions: the CLI calls the application services directly rather than going through the
toolbox, whose limits exist for remote callers; ADR 0003 §10.

- **Verification report.** `VerificationReport` (`domain/evidence_set_verification_report.py`)
  is the verdict, at most `MAX_REPORTED_VIOLATIONS` (100) violations of 1 to
  `MAX_VIOLATION_CHARS` (1024) characters each, and each replay difference as
  `step_index` (null for a set-level part) and `part`; a validator ties the
  findings to the verdict (violations only for `malformed` and `invalid`, differences only
  for `replay_differs`), and the published schema states the same rule.
  `application/evidence_set_verification.check_evidence_set` parses the bytes and
  verifies them into a report, so the CLI, and later the API, share one path. It passes
  every violation list through `bound_violations`, which keeps the first 100 and cuts a
  longer violation to 1024 characters ending in `...`. `cve-kgrag verify` prints the keys
  in declaration order (`verdict`, `violations`, `differences`) with non-ASCII text
  escaped, and exits 0 only for `verified`; tests pin the exact text of a `verified` and a
  `malformed` report and the escaping.
- **Violations in the server's own words.** No violation repeats text the checked set
  chose. A violation names a value from the set only when the value's pattern leaves no
  room for words: CVE, CWE, evidence, investigation and technique IDs, hashes, enum values
  and integers. Any other value, a free string (a warning subject, a policy version) or one
  whose pattern fixes only its start or its alphabet (a topic ID, a package URL), is named
  by its position or not at all.
  - `list_validation_problems` (`domain/contract_model.py`) reports unexpected fields as a
    count at the location holding them (`claims.0: 2 unexpected fields`), never their
    names, and rebuilds the message for an unknown union tag from the tags the contract
    expects.
  - The validator and the citation audit name a claim by its position (`claims[3]`), not
    by its `claim_id`, `subject_id` or the record its evidence is about; a step's answer
    ID (`step 1 answer_ids[0]`), a step's search warning (`step 1 search_warnings[0]`)
    and a product applicability (`product_applicability[0]`) likewise.
  - The decision-path audit compares the run's warnings in full but describes them
    without their subjects, since a recorded subject is the set's text and a derived one
    can repeat the request's query: when the codes differ it lists both sides' codes, and
    when only subjects differ it names each such warning by its number among the decision
    warnings (`the run's decision warning 1 (excluded_term) has another subject than its
    interpretation and decisions give`). It says that a step explores a topic the registry
    lacks without naming the topic, and that the planner names a policy other than the
    one the audit re-derives without naming the planner's.
  - The longest violation a contract gives, one listing every allowed value, is 676
    characters.
  - `tests/support/marker_sweep.py` plants a marker in each text location of a genuine
    set: alone, appended plainly and after a dash (so it survives a slug or prefix
    pattern), inside each string of a text that is itself JSON (a model's plan), and once
    renaming every copy of the text in the trajectory. It then recomputes the
    investigation ID, the call keys and the reply hashes from the fields they hash,
    reseals the set and checks it. `test_check_repeats_no_text_a_forger_plants_in_the_set`
    runs it over eleven genuine runs, each of which first gets the verdict its run expects,
    and expects no report to repeat the marker. Between them the runs hold every text
    field any genuine run in the suite carries, and two seal the marker into the request,
    so text the audit derives from the query or the product filters is swept too. Fields
    no genuine run carries, such as graph paths, a version range's `start_excluding`,
    contextual-alias terms, an anchor's `inference_method`, a candidate's `missing_fields`,
    a reference's `source` and a model's reasoning effort, are covered by reading every
    violation formatter instead.
- **Served bundle.** `composition.load_served_bundle()` returns the CVE records and
  evidence anchors every surface serves, the packaged fixture until WP10; the CLI and `mcp`
  both use it. The topic registry and the pinned FiGHT snapshot are assembled separately.
  It takes no settings yet: none names a store before WP10.
- **Search options.** `search` takes `--vendor`, `--product`, `--purl`, `--cwe`,
  `--severity`, `--year`, `--origin` (each repeatable; `--cwe` and `--severity` are read
  case-insensitively), `--kev-only` and `--graph-expand`, mapped onto `SearchFilters` and
  `SearchRequest`.
- **Investigation budget.** `investigate` takes `--max-rounds`, `--max-tool-calls`,
  `--max-sources`, `--max-results-per-call`, `--max-wall-time-seconds` and
  `--max-context-bytes`; a budget option left out keeps the contract's default, the cap.
- **Topic.** `topic` takes `--max-results-per-search`.
- **New commands**, each printing its tool contract:
  - `capabilities [--semantic]`: the source capabilities `investigate` would report, with
    the planner the settings configure; always exits 0.
  - `resolve QUERY`: the `ConceptResolution`; exits 0 when the query names a topic, 1
    otherwise.
  - `affectedness CVE_ID... --purl PURL`: a JSON list of `AffectednessCheck`, one per CVE
    (at most 20); exits 0 only when every answer establishes applicability, so 1 while no
    verified affectedness source exists.
  - `evidence EVIDENCE_ID`: the `EvidenceLookup`; exits 1 with one stderr line when no
    anchor is served under the ID or the catalogued one fails the anchor rules.
  FiGHT has no command of its own: `topic` reaches it (`--scope protocol_context_only` for
  FiGHT context alone), and so does `investigate`.
- **Usage errors.** Every request the CLI builds goes through its contract (`lookup`'s
  `CveLookupRequest` included), and an argument the contract rejects is a usage error
  (exit 2) naming the problem without the input.
- **Shared lookups.** `application/knowledge_lookup.py` holds `lookup_cve`, used by the CLI's
  `lookup` and the toolbox's `lookup_cve`, and `find_served_evidence`, used by the CLI's
  `evidence` and the toolbox's `get_evidence`.
- **Import side effects.** `tests/contract/test_import_side_effects.py` imports every core
  module in a fresh interpreter under an audit hook, from an empty working directory with
  empty home, cache, data and temporary directories, and expects no file written, no
  directory created, no network use (name lookups included) and no process started.
  The module walk (`tests/support/module_walk.py`) fails on a package that cannot be
  imported rather than skipping it.

### Contracts at `2.0.0-dev.21`

- New snapshot `verification_report.schema.json` (`VerificationReport`), stating the
  verdict-to-findings rule as `if`/`then`; step indices start at 1.
- Every versioned schema moves to `2.0.0-dev.21`; no other contract changes.
- `test_schema_snapshots.py` also checks that no snapshot states a bound under a pydantic
  name (`ge`, `le`, `gt`, `lt`), which a JSON Schema validator ignores.

### Contracts at `2.0.0-dev.22`

- `verification_report.schema.json`: each violation has `minLength` 1 and `maxLength`
  1024.
- Every versioned schema moves to `2.0.0-dev.22`; no other contract changes.
- Tests: the marker sweep above; an unexpected field's name, an unknown planner kind, and
  a claim's forged `claim_id` and `subject_id` are not repeated in a report; a set whose
  only field name is 200,000 emoji gives a report under 4 KiB; an empty or overlong
  violation is rejected by the model and by the published schema; more than 100
  violations are cut to 100.

## WP6 — HTTP guard, HTTP settings, MCP over Streamable HTTP

Decisions: ADR 0007.

- **Settings.** `HttpSettings` (`settings.py`) reads `CVE_KGRAG_HTTP_HOST` (`127.0.0.1`,
  the default, or `::1`; any other value, `localhost`, other 127/8 addresses and mapped
  forms included, is invalid), `CVE_KGRAG_MCP_HTTP_PORT` (1 to 65535, default 8765) and
  `CVE_KGRAG_HTTP_TOKEN`: 32 to 512 characters of RFC 6750's `b64token` alphabet, held as
  a `SecretStr`. The section has no switch: every command reads and validates it, and
  only `mcp --http` and `api` (WP7, on `CVE_KGRAG_API_PORT`) serve.
- **Command.** `cve-kgrag mcp --http` serves the packaged fixture's toolbox, with the
  deterministic planner and no semantic channel, until it is interrupted (SIGINT), then
  exits 0 with nothing on stdout or stderr; on SIGTERM it shuts down the same way and
  ends by that signal, as uvicorn re-raises it. Without a token it is a usage error naming
  `CVE_KGRAG_HTTP_TOKEN` (exit 2), checked before the runner is looked up. The runner
  loads through the `mcp_http_server` entry point (`interfaces/mcp/http_runner.py`);
  without the `mcp` extra the command exits 1 with the missing-extra line, which the
  core-only lane checks. A port that cannot be bound exits 1 after uvicorn logs why.
- **Guard.** `interfaces/http/guard.py` is the ASGI app uvicorn runs, ready for WP7's
  routes as well. In order, it refuses with an `HttpRejection`:
  - a missing, repeated or unserved `Host` (421): only `127.0.0.1:PORT` or
    `localhost:PORT` for `127.0.0.1`, `[::1]:PORT` or `localhost:PORT` for `::1`, in any
    case, without the port only on port 80;
  - a repeated `Origin`, or one other than `http://` and a served host (403); a request
    without `Origin` passes;
  - a request without exactly one `Authorization: Bearer TOKEN` header, the scheme in any
    case and the token compared as bytes in constant time (401, `WWW-Authenticate:
    Bearer`), on every route but `/health`, unknown routes included;
  - a target that is not a route byte for byte with an empty query (404): no
    normalization, so `/mcp/`, `//mcp`, `/mc%70`, dot segments, absolute-form and `*`
    name no route;
  - a method the route does not take (405, `Allow`);
  - a `Content-Length` other than one decimal number (400), or over the route's cap
    (413) before any body is read.
  It then reads the body under the request deadline, counting it and refusing 413 as soon
  as the count passes the cap (256 KiB), and hands the route the body in one message.
  The route's answer is recorded and sent once complete, so when the deadline passes the
  guard answers 504 `deadline_exceeded` first and only then cancels the route, whatever
  the route waits on. A route that raises or answers nothing is answered 500
  `internal_error`; a client that disconnects during the body gets nothing. Every answer
  carries `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`, and no
  rejection carries `Connection: close`, so a client still sending a refused body reads
  the answer instead of a reset.
- **Routes.** `POST /mcp` is the MCP endpoint: the SDK's `StreamableHTTPSessionManager`,
  stateless with JSON answers, its own DNS-rebinding check off (the guard's applies) and
  its body cap at 256 KiB. `GET /health` answers 204 without the token; `GET /ready`
  answers 204 while the toolbox has a free worker (`KnowledgeToolbox.has_free_worker`)
  and 503 `not_ready` otherwise. A tool that fails answers as on stdio: HTTP 200 with a
  JSON-RPC result whose `isError` is true and whose text block holds the `ToolFailure`;
  ADR 0007's status table is the REST API's (WP7). The request deadline is the
  toolbox's longest call (`ToolLimits.find_longest_call_seconds`: 30 s of investigation
  wall time plus the 10 s seal margin) plus 10 s, 50 s in all, so a tool call that runs
  out of time answers its own `timed_out` first.
- **The SDK's answers in the server's words.** `interfaces/mcp/sdk_answers.py` restates
  every answer the SDK's transport makes itself: a JSON-RPC error keeps its status, code
  and `id`, loses `data`, and keeps its message only when it is a fixed sentence
  (`unknown tool`, `Method not found`, `Invalid request parameters`), any other becoming
  its code's fixed sentence; any other answer with status 400 or above becomes
  `invalid_request` (4xx) or `internal_error` (5xx). The SDK otherwise repeats a value
  sent in a validation error, and the method name in `data`. On stdio as well, the
  server's middleware (`withhold_error_data`) drops `data` from every JSON-RPC error
  raised while handling a request, and answers parameters that fail the SDK's request
  model with its fixed `Invalid request parameters` and no `data`.
- **uvicorn** (`interfaces/http/serving.py`) runs h11 without WebSocket support, with
  proxy headers ignored, no `Server` header, no access log (it would record request
  targets) and a 5 s keep-alive. A stop waits for the requests in flight up to one second
  past the request deadline (51 s), so each ends with its route's answer or the guard's
  504 rather than being cut off; a second interrupt stops at once. A request arriving
  while 32 connections (its own included) or 32 requests are open gets uvicorn's own
  503. uvicorn logs through the command's handlers at error level only, so its
  per-request warnings (an upgrade it does not serve, a request it cannot parse, the
  503) are not logged and no caller can fill the log with them; a port it cannot bind
  and an app that raised are errors, and are logged.
- **Packaging.** The `mcp` extra declares Starlette and uvicorn, and `MCP_EXTRA`
  (`adapter_discovery.OptionalExtra`) names them, so a core install missing either reports the missing extra. The dev group
  declares `httpx2`, which the HTTP tests import. `interfaces/http/` imports the ASGI
  stack and stays out of the core module walk, as `interfaces/mcp/` does; the core-only
  lane leaves out `tests/integration/interfaces/http` as well.
- **Tests.**
  - `tests/integration/interfaces/http/test_http_guard.py` drives the guard in-process
    with any target bytes and header list (`tests/support/asgi.py`): tables of hosts,
    origins, authorizations, targets and methods, each checking the route was not
    reached; length declarations; caps counted across messages; the deadline over a
    stalled body, a route that never returns and a route blocked on a worker thread
    (answered while the thread still blocks); a route that raises, answers nothing or
    answers only in part; each code's status against the published table; and no
    rejection repeating a marker sent in the target, a header or the body.
  - `tests/integration/interfaces/mcp/test_mcp_http.py` runs the SDK client in both
    modes over the guarded app, checks the unknown-tool error, that a tool failure
    (`invalid_arguments`, `unknown_evidence_id`, `arguments_too_large`, `timed_out`) is
    HTTP 200 with an `isError` result holding the `ToolFailure` and no structured
    content, in both client modes as well, the 405 on `GET /mcp`,
    `/ready` answering 503 while the toolbox's only worker holds a call, the 50 s
    deadline and the stop waiting past it, and the exact status and body of eight
    requests the SDK answers itself, none repeating the marker it carries (a plain-text
    server error becomes `internal_error`); and starts `cve-kgrag mcp --http` on a free
    port of `127.0.0.1` and of `::1`: the client lists the tools, `/ready` without the
    token is 401 without a `Server` header, a 1 MiB body is 413 over a real socket, an
    upgrade request and an unparsable one log nothing, and an interrupt exits 0 with
    empty stdout and stderr; on a port in use it exits 1 and says why.
  - `test_mcp_stdio.py` checks that an unknown method's error and an invalid-params error
    carry no `data` and repeat nothing sent.

### Known limits

- uvicorn refuses no connection and reads request headers with no timeout of its own: a
  local process can open any number of connections and leave their headers unfinished,
  each holding up to h11's partial-header limit (16 KiB) until the client closes it, and
  while 32 are open every other request gets uvicorn's 503. Anything on the machine can
  already exhaust a loopback service this way.
- uvicorn's own refusals (a malformed request line or headers: 400; the 503 above) are
  its plain-text sentences, not `HttpRejection`: they happen before the guard runs. They
  repeat nothing the request sent.
- JSON-RPC requires a reply to repeat the request's `id`, so a JSON-RPC error carries the
  `id` the client chose.
- On stdio, the server stops at the end of its input, and a reply still being worked out
  then is not written; a client reads its replies before closing stdin.

### Contracts at `2.0.0-dev.23`

- New snapshot `http_rejection.schema.json` (`HttpRejection`): `schema_version`, `code`
  and `message`, the code's fixed sentence, stated as `if`/`then` per code.

  | Code | Status |
  |---|---|
  | `invalid_request` | 400 |
  | `unauthorized` | 401 |
  | `origin_not_allowed` | 403 |
  | `not_found` | 404 |
  | `method_not_allowed` | 405 |
  | `body_too_large` | 413 |
  | `host_not_allowed` | 421 |
  | `internal_error` | 500 |
  | `not_ready` | 503 |
  | `deadline_exceeded` | 504 |

- Every versioned schema moves to `2.0.0-dev.23`; no other contract changes.
- Tests: a genuine rejection and every code's fixed sentence validate under the published
  schema; a rejection quoting the request, carrying another code's sentence or a
  `status` field is rejected by the model and by the schema.

## WP7 — v2 REST API

Decisions: ADR 0007, decisions 8 and 9.

- **Command.** `cve-kgrag api` serves the packaged fixture's toolbox, with the
  deterministic planner and no semantic channel, on `CVE_KGRAG_HTTP_HOST` and
  `CVE_KGRAG_API_PORT` (default 8766) behind `CVE_KGRAG_HTTP_TOKEN`, until it is
  interrupted, as `mcp --http` does: exit 0 on SIGINT with nothing on stdout or stderr,
  exit 1 on a port it cannot bind, exit 2 without a token. The runner loads through the
  `api_server` entry point (`interfaces/rest/api_runner.py`); without the `api` extra
  the command exits 1 with `the 'api' extra is not installed: pip install
  'cve-kgrag[api]'`, which the core-only lane checks.
- **Routes**, all behind the WP6 guard and its 50 s request deadline:

  | Route | Tool or check | Arguments |
  |---|---|---|
  | `POST /api/v2/search` | `search_vulnerabilities` | the JSON body |
  | `POST /api/v2/investigate` | `investigate_telecom_topic` | the JSON body |
  | `GET /api/v2/evidence/{evidence_id}` | `get_evidence` | the path's last segment, exactly as written |
  | `GET /api/v2/capabilities` | `get_knowledge_capabilities` | none |
  | `POST /api/v2/verify` | `check_evidence_set` | the body, up to 4 MiB |
  | `GET /health`, `GET /ready` | as in WP6 | none |

  A tool route hands its arguments to `KnowledgeToolbox.call` on a worker thread and
  answers the tool's JSON with 200, or the bare `ToolFailure` with its status
  (`TOOL_FAILURE_STATUSES`: 422, 413, 404, 503, 504, or 500 for `response_too_large`,
  `integrity_check_failed` and `internal_error`). A body that is not a JSON object, and
  an evidence ID segment that is not ASCII, are the tool's `invalid_arguments`; the
  toolbox parses everything else with the tool's request contract, so no answer repeats
  what the request sent. A percent-encoded evidence ID is not decoded, so
  `ev%3A...` is not an evidence ID. The guard routes a path ending in one segment after
  `/api/v2/evidence/` and nothing else there (`GuardedRoute.takes_path_segment`).
- **Verification.** `POST /api/v2/verify` checks the body as `cve-kgrag verify` checks
  a file: against the packaged fixture and the planners the settings configure
  (`list_accepted_planner_capabilities`), and answers the `VerificationReport` with 200
  for every verdict. It checks one set at a time: a request arriving while a check runs,
  one abandoned at its deadline included, is answered 503 `route_busy` without waiting.
  The check takes the route on its worker thread, so a request cancelled before its
  check starts holds nothing. Its body cap is `MAX_EVIDENCE_SET_BYTES` (4 MiB), the size
  `cve-kgrag verify` reads, defined once in `application/evidence_set_verification.py`;
  every other route keeps 256 KiB. `cve-kgrag verify` and the route build their check
  the same way (`build_evidence_set_check`).
- **Packaging.** The `api` extra declares anyio, Starlette and uvicorn and no MCP SDK;
  discovery reports it missing when one of those three modules is (`API_EXTRA`), while a
  REST runner failing on the MCP SDK is a broken runner, logged with its traceback.
  `interfaces/rest/` stays out of the core module walk, and the core-only lane leaves
  out `tests/integration/interfaces/rest`.
- **Tests.**
  - `tests/integration/interfaces/rest/test_rest_api.py`: each route's contract; a set
    investigated over the API verifying over the API; the REST status of every
    `ToolFailureCode` against the published table, and real failures over HTTP (bodies
    of the wrong type, with an unexpected field, not JSON, not an object, an array of
    pairs, `null`, nested 100,000 deep, or too large; an unknown, invalid,
    percent-encoded or non-ASCII evidence ID; a raising backend; a call out of time;
    every worker busy), none repeating the marker sent; the `malformed` and
    `replay_differs` verdicts answered 200; the 50 s deadline; the 4 MiB cap on
    verification and 256 KiB on the search and investigate routes; a second
    verification answered `route_busy` and a later one 200; a check abandoned at its
    deadline answered 504 and keeping the route until it returns; a verification
    cancelled before its check starts leaving the route free; 405 for each route's other
    method; 401 on every route but `/health`; and `cve-kgrag api` as a process:
    investigate, verify, an interrupt with empty output, and a port in use exiting 1
    without the token in its output.
  - `test_cli.py` checks that the API's verification accepts the planners the settings
    configure, as `verify` does.
  - `test_http_guard.py` checks a route taking a path segment gets it as written, and
    that no segment, two segments, an empty one or a query names no route.
  - `tests/support/process_servers.py` starts either HTTP command as a process.

### Contracts at `2.0.0-dev.24`

- `http_rejection.schema.json`: a new code `route_busy` (503), "The route is serving as
  many requests as it takes; retry later.", for the verification route's one-at-a-time
  bound.
- Every versioned schema moves to `2.0.0-dev.24`; no other contract changes.

## WP9 — read-only legacy-data importer

Decisions: ADR 0008.

- **Command.** `cve-kgrag migrate legacy --inputs FILE --target DIR [--legacy-root DIR]
  [--dry-run]` imports the raw NVD 1.1 and 2.0 feeds and the CISA KEV catalog CSV the
  input manifest declares into a new corpus store at `--target`, and prints the
  `MigrationReport`. Exit 0 for `imported`, `already_imported` and `dry_run`; 1 for
  `failed`, which the report explains, and without the `migration` extra (`the
  'migration' extra is not installed: pip install 'cve-kgrag[migration]'`, checked by
  the core-only lane); 2 for an input manifest that is not valid, reported without
  quoting it. The parsers load through the `migration_parsers` entry point
  (`adapters/migration/nvd_feed_reader.py`, `build_migration_parsers`); every importer
  module except `nvd_feed_reader`, `json_fingerprint` and `ijson_events`, which import
  ijson, is core.
- **Input manifest** (`domain/migration_inputs.py`, `adapters/migration/inputs_manifest.py`).
  Opened like every importer file (a regular file, no link followed, no FIFO waited on)
  and read with the declaration loader: the strict loader with aliases forbidden and
  timestamps kept as text (`load_declaration_yaml`), so `retrieved_at` is validated as
  written, RFC 3339 with an offset, and refused when UTC cannot express it. At most
  1 MiB, 128 inputs and one `cisa-kev` input; no path holds a NUL. Paths resolve against
  the manifest's directory; an input must be a regular file, and two declarations naming
  one file, or two files with the same bytes, are refused.
- **Provenance and identity** (`adapters/migration/input_resolution.py`). A standard
  feed name gives the artifact (a year before 2002 is no standard name); another name
  declares it; both must agree. `source_uri` is the registry's template filled for the
  artifact (`artifact_uri_template` in `knowledge/sources.yaml`), whatever the container;
  `source_version` is `sha256:` of the decompressed payload for NVD and of the file for
  KEV, which `StoreInput` enforces. `retrieved_at` is normalized to UTC, so two offsets
  naming one instant give one evidence ID. The normalizer keeps no terms constant of its
  own: it cites the registry's terms, which composition injects (`build_nvd_normalizer`),
  and its errors carry a `NormalizationFailureCode`. `import_identity_sha256` hashes the inputs
  sorted by source, artifact and file hash, the cited registry entries, the importer,
  store format and contract versions; the raw manifest's hash is recorded for audit
  only.
- **NVD entries** (`adapters/migration/nvd_entry_stager.py`, `candidate_staging.py`).
  Every entry with a readable CVE ID is staged in SQLite with its modification time
  (exact microseconds, a time UTC cannot express counting as none), format, state,
  semantic hash and raw entry; one without is counted with its locator, a withdrawn one
  included. A database or disk error is `staging_failed`. `resolve_cve` applies ADR 0008
  §5: the latest candidates win; equal ones collapse to one chosen by the tie-break;
  across formats 2.0 decides; unequal ones are a `conflicting_duplicate`; a rejected
  winner withdraws the CVE; a malformed latest or an unorderable group excludes it. The
  winner is normalized again with its final snapshot (the payload hash is known only
  once its feed is read whole) and its KEV entry.
- **KEV** (`adapters/migration/kev_csv_reader.py`). All or nothing: a fixed column set in
  any order (`notes`, `knownRansomwareCampaignUse` and `cwes` may be absent), `cveID` (a
  CVE ID of at most 32 characters) and `dateAdded` required, dates `YYYY-MM-DD`, UTF-8
  with one optional BOM, the strict `excel` dialect, no blank line, at most 16 MiB and
  50,000 rows; unequal repeated rows fail the run. Rows merge onto final records only,
  superseding NVD's mirrored CISA fields; the others are counted as
  `kev_without_nvd_record`, `kev_for_rejected_nvd_record` or `kev_for_excluded_nvd_record`,
  and the first brings the fixed `kev_advice` to add the covering year feed.
- **Reading** (`adapters/migration/input_files.py`, `nvd_feed_reader.py`,
  `entry_assembler.py`, `surrogate_guard.py`, `adapters/regular_files.py`). Every file
  is opened without following a link and without blocking, so a FIFO is refused at once.
  Each input is copied into the staging directory before it is read, hashed as it is
  copied (`input_changed` unless the copy holds the resolved bytes), and only the copy
  is read, so rewriting the operator's file in place during the run cannot pair one
  file's hash with another payload. The copy counts against the 16 GiB staging cap:
  there must be room for its inspected size before it is made, it never grows past that
  size, and the directory is measured again before the copy is removed and once the last
  anchor is staged, which a dry run stages too. An NVD input must be a whole feed: 2.0
  from `startIndex` 0 with `totalResults` entries, 1.1 with `CVE_data_numberOfCVEs`
  entries; a page of a larger API result fails as `incomplete_feed`. Containers are told
  by their first bytes; a gzip or zip file is capped at 256 MiB, a plain one by the 512
  MiB decompressed cap. A zip's end record must declare one member and a one-member
  directory before `zipfile` reads it, and any damage, CRC included, is
  `bad_compression`. Feeds stream through ijson's `yajl2_c` backend with 64 KiB reads;
  entries are assembled from events, with the cap checked on the stream and on the
  assembled keys and values; top-level keys and values count against the same cap, and a
  feed has at most 32 top-level members. A high surrogate escape without its low escape
  is refused before the parser could turn it into `?`. The reading, staging, KEV and
  walk bounds are `MigrationLimits`, whose defaults are the ADR's constants; tests pass
  smaller ones. The manifest caps, the top-level member caps and the 100-locator report
  bound are module constants.
- **Legacy root** (`adapters/migration/legacy_root_scan.py`, `json_fingerprint.py`). A
  bounded, read-only walk that counts derived files by structure and files never
  deserialized by magic bytes or suffix; the report cites the formats' commit
  (`legacy_formats_commit`, `b64eef3`). A missing root is `legacy_root_unreadable`.
  Every input's first decompressed bytes are fingerprinted before it is read, so a
  derived file declared as an input, under either source, fails the run as
  `derived_file_declared_as_source`.
- **Store** (`adapters/store/corpus_store.py`, `domain/corpus_store_manifest.py`).
  `manifest.json` plus `records.jsonl` and `anchors.jsonl`, canonical JSON lines in CVE
  ID and evidence ID order. The target's parent must be a writable directory, in a dry
  run too (`target_unusable`); target and protected paths are compared by file identity,
  so another case of a name on a case-insensitive file system does not slip past, and a
  dangling link at the target is refused. The run writes the store in a sibling partial
  directory, deletes its sibling staging directory, verifies the partial store
  (`verify_corpus_store`, which keeps only an anchor index) and renames it into place
  with mode 0755, its files 0644, both set explicitly whatever the umask.
  `load_corpus_store` runs the same checks and keeps the records and anchors, for
  WP10; both read the manifest and every line within a cap and check a file's size
  before its lines. The report and the store manifest carry the fixed
  rollback (`rollback_kind` `delete_unactivated_target`, `rollback_scope`
  `before_activation_only` and the instruction); WP9 never deletes anything itself.
- **Scale.** `scripts/operator/migration_scale.sh` (an operator lane, not CI) imports
  synthetic gzipped 2.0 feeds. The lane imported 250,000 records,
  using resident memory, temporary disk and a
  store (one run; the disk figures are sampled once a second).
- **Packaging.** The `migration` extra declares `ijson` only (`ijson` 3.6.0 in
  `uv.lock`, no transitive dependency); the dev group installs it, so the default lane
  runs the importer's tests. `ijson_events`, `json_fingerprint` and `nvd_feed_reader`
  stay out of the core module walk, and the core-only lane ignores the tests that run
  the importer.

### Known limits

- Real feeds were not available offline: the importer is proven on authored synthetic
  inputs, and the first real run checks the 512 MiB per-file cap against a current 2.0
  year feed.
- An integer of magnitude 2^63 or more, which `json.loads` would read, is refused
  as `invalid_json`: the `yajl2_c` backend reads no wider integer.
- An entry's memory is a bounded multiple of its encoded bytes
  for an entry of many empty containers.
- The rename into place is atomic only on one file system, which the sibling partial
  directory guarantees. A target another process creates between the last check and
  the rename is replaced if it is an empty directory and otherwise fails the run as
  `store_write_failed`; the window is not closed.
- The legacy-root walk lists directories by path, so a directory replaced by a link
  while the walk runs is not detected.
- A whole API 2.0 result has a feed's shape, so a query narrower than the artifact it is
  named or declared as (a date or keyword filter) is imported as that artifact; only a
  page of a larger result is caught.

### Contracts at `2.0.0-dev.25`

- `corpus_store_manifest.schema.json` and `migration_report.schema.json` are new.
- Every versioned schema moves to `2.0.0-dev.25`; no other contract changes.

## WP10 — store activation and serving

Decisions: ADR 0009, which amends ADR 0003, 0004, 0006 and 0008. Operator steps:
[`docs/runbook.md`](../runbook.md).

- **Settings.** `CVE_KGRAG_STORE_ROOT`, an absolute directory, and the pair
  `CVE_KGRAG_FIGHT_SNAPSHOT_PATH` and `CVE_KGRAG_FIGHT_SNAPSHOT_SHA256`, set together, are
  always read and open nothing; errors name the variable, never its value.
- **The seam.** Every composition function takes a `ServedCorpus` (`ports/served_corpus.py`):
  the packaged `FixtureBundle` or a `CorpusStore`. Its `ServedDataset` names the kind and
  the `cve_search` capability version: the fixture's `fixture_id@version+sha256:<manifest
  hash>`, a store's `corpus-store-v1@sha256:<corpus_content_sha256>`. The content digest
  is taken over the records' and anchors' pins only, once both files match them, so
  stores with byte-for-byte equal records and anchors serve one dataset whatever their
  manifests say. MCP instructions are one of two fixed texts by kind; the store's carry
  the NVD notice.
- **Store commands** (`adapters/store/`). `store validate | activate | rollback | status`.
  `ACTIVE` is canonical JSON with its own format version, read within 4 KiB and never
  through a link; changes hold a non-blocking `flock` on `.lock` and go through an
  injected file seam (check sync, temporary file, `os.replace`, confirming sync), so a
  failure is either `active_write_failed` (unchanged) or `active_write_unconfirmed`. An
  unreadable `ACTIVE` is refused and left as it is. A store is checked in a fixed order:
  present as a directory, manifest digest as recorded (on the raw bytes), format version,
  then full verification. `store_status.schema.json` is published.
- **Startup.** `load_served_corpus` serves the fixture without a root and the active
  store with one; a root that cannot be served stops the command, exit 2, with a closed
  reason and no fallback. The order is settings, the HTTP token, the extra and runner,
  the store, the FiGHT snapshot. A command loads only what its row of ADR 0009 §10 names:
  `resolve`, `affectedness`, `migrate`, `store` and `schema` load no served corpus;
  `demo` and `eval planner` always use the fixture and say so on stderr; `eval planner`
  refuses an `--out` inside the root. `migrate legacy` refuses a target in the root that
  is not a validly named store directly under it.
- **Data plane** (`application/serving_data_plane.py`). Every deployment is built over a
  `ServingDataPlane`: the topic cards, the search service and its indexes, the FiGHT
  source and pin, and the evidence catalog, each built once. The `api` process's tool
  deployment and verification route share one, with separate call runners and admission.
- **Semantic channel.** Over a store, a requested channel is unavailable
  (`COLLECTION_NOT_BOUND`, failure `collection_not_bound`) and no adapter is looked up;
  ADR 0004 §1 holds the four-row table.
- **FiGHT snapshot** (`adapters/fight/operator_snapshot.py`). One open; a 4 MiB cap
  while reading, the pin, the catalog, then the strict parse, on those bytes; seven
  fixed reason codes; never the excerpt instead. The full catalogued 3.1.0 file (183
  techniques) loads through it.
- **Truncation.** The FiGHT source reports its matched count (internal);
  `protocol_context_truncated` and `candidates_truncated` say what a topic response's
  bounds left out, without changing its status; an investigation's `answer_truncated`
  counts |K| − |L| + F (ADR 0009 §11a). Both validators check the warnings' structure and
  relations; replay re-derives the counts.
- **Format guards.** The format-1 compatibility store, written by the importer at
  `28e5b4d`, is committed with every file's SHA-256 pinned outside it
  (`tests/contract/data/corpus_store_format1_28e5b4d/`); a pinned digest of the
  manifest, record and anchor schemas raises the alarm on any change to them.
- **Scale** (`scripts/operator/serving_scale.sh`, an operator lane). On 250,000
  synthetic records: loading the store; `api` startup with the
  shared data plane, compared with two separate
  data planes (one run; the peak is reached while the store loads).

### Known limits

- Every figure is from synthetic records; real NVD records need more time and memory.
- `graph_expand` over a large store can reach the tool time limit; the follow-up in
  `PLAN.md` settles it before the public release.
- A server serves the store active when it started; activation takes effect on restart.
- The semantic channel is unavailable over a store until a collection records the
  dataset it was built from.

### Contracts at `2.0.0-dev.26`

- `store_status.schema.json` is new.
- `corpus_store_manifest.schema.json`: `schema_version` and the rollback instruction are
  bounded provenance with no default, so the schema no longer moves with the contract
  version; a `2.0.0-dev.25` manifest is valid under it.
- `migration_report.schema.json`: `corpus_content_sha256`, the instruction naming
  `cve-kgrag store rollback`, and the failure codes `target_in_store_root` and
  `store_root_unusable`.
- `knowledge_capabilities`, `search_response`, `topic_context_response` and
  `knowledge_evidence_set`: `collection_not_bound`; the topic and evidence-set schemas
  also gain the two truncation codes, the coverage description and the meaning of
  `answer_truncated`'s count.
- `search_request`, `topic_context_request` and `fight_search_request`: the limit
  descriptions say what is and is not counted.
- Every versioned schema moves to `2.0.0-dev.26`.
