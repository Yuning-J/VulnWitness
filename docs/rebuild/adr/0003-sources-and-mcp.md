# ADR 0003 — Sources and the MCP server

Status: accepted (M5). Applies to `ports/affectedness.py`, `adapters/trustify/`,
`domain/affectedness.py`, `domain/tool_contracts.py`, the capability contract in
`domain/investigation.py`, `application/affectedness.py`,
`application/evidence_set_verification.py`, `interfaces/` and the `mcp` and
`verify` CLI commands. §10 and §12 are amended by ADR 0007 (HTTP surfaces).

## Context

The brief (§12, §13) asks for a Trustify affectedness source behind a port, with
capability discovery and typed failures, and for a read-only MCP facade with eight
tools over the application services: strict typed input, limits, timeouts, bounded
and sanitized output, stdio required, Streamable HTTP optional. M5's exit criterion
is that the deterministic tools and the bounded investigation work against fixtures,
that Trustify's absence is explicit and nonfatal, and that no unsafe generic tool is
exposed.

The official Trustify MCP server, guacsec/trustify-mcp, was read from source at
`ac8955f768a5bfef6f1c9a5c1d02ec5b5cf9bf5e`, the head of `main` on 2026-10-17
(Apache-2.0). It has no release and no tag. Its tool surface is pinned by its own CI
test (`tests/integration_test.rs:29-276`, twelve tools). Its behaviour against a
server cannot be verified:

- It builds against Trustify crates at `v0.5.0` but calls `/api/v2` routes that
  Trustify removed in v0.5.0. Read from the tags' OpenAPI files, 8 of its 11
  Trustify-calling tools have no route on v0.5.0, v0.6.3 (`e399b16`) or v0.7.0
  (`9c54e1d`). Both affectedness tools are among them: `trustify_purl_vulnerabilities`
  calls `/api/v2/purl/{key}` and `trustify_vulnerability_details` calls
  `/api/v2/vulnerability/{id}`. The deployment baseline is Trustify 0.6.2 stable, with
  0.7 nightly unsupported. No release from v0.5.0 to v0.7.0 serves those routes.
- `trustify_sbom_list_packages` advertises only `sbom_uri` while its handler needs
  `query` and `limit`, so it cannot succeed on any version.
  `trustify_vulnerabilities_for_multiple_purls` expects a response shape that Trustify
  replaced in v0.4.0.
- Outbound auth is OIDC client credentials only. A failed discovery or token request
  panics inside a detached task (`trustify.rs:61-80`) and no reply is ever sent. A
  missing environment variable panics at start-up.
- Every failure is JSON-RPC `-32603`, carrying the Trustify status text or `reqwest`
  error text, which includes the request URL. Auth, not-found and server errors can be
  told apart only by parsing that text.
- Affectedness can be asked only by purl or by CVE ID. No tool resolves a vendor or
  product name to a package.

The official MCP Python SDK is `mcp` 2.3.0, and every CVE-KGRAG service is
synchronous. `MCPServer` (2.x's FastMCP) ignores unknown arguments, coerces values
leniently, echoes rejected input values in its errors, and generates output schemas
in validation mode, which differ from the committed serialization-mode snapshots. The
low-level `Server` validates nothing. It returns `str(exc)` for a handler exception
to clients that negotiated an older protocol (`code=0`).

`anyio.fail_after` around a synchronous call on a worker thread returns only when
the call does.

Two designs were compared. One is deletion-first. The other adds an affectedness
verdict path, a concurrency runner and typed unavailable reasons. The design taken is
the first, with the second's in-flight limit, failure contract, composition guard,
labelling of untrusted text and gold file.

## Decisions

### 1. Trustify sits behind `TrustifyPort`; the only shipped adapter is disabled

`ports/affectedness.py` defines `TrustifyPort`:

- `describe() -> AffectednessFailure` gives the reason affectedness is unavailable
  from the source. The composition root reads it once, when it builds a deployment,
  as it reads the model port.
- `check_affectedness(request: AffectednessRequest, timeout_seconds: float) ->
  AffectednessFailure` gives the reason the check established nothing. It never
  raises and honours `timeout_seconds`.

A port answers with a typed reason only. It authors no text: every sentence the server
publishes about affectedness is the server's own (decision 2).

`DisabledTrustifyAdapter` (`adapters/trustify/disabled_trustify_adapter.py`) is the
only production implementation:

- It gives `blocked_unverified` as the reason affectedness is unavailable.
- It answers every check with `blocked_unverified`.

It has no dependency, so it is part of the core and loads without an entry point. The
in-memory fake lives in `tests/support/fakes.py` and is not in the wheel, so no
deployment can be wired with it outside tests.

No `TrustifyMcpAdapter` exists, and none is marked as integrated. Writing one is a
separate task. It starts only after one of these is available:

- (a) a deployed Trustify version, its OpenAPI document and a test instance, or
- (b) a trustify-mcp release that states the Trustify versions it supports.

That task adds:

- the `trustify` extra and the `cve_kgrag.adapters` entry point;
- typed settings for the endpoint, from configuration and an allowlist and never from
  a caller, and for the OIDC secret;
- finite retry for the read tools only;
- detection of tool-schema drift against the pinned snapshot (decision 5);
- live tests behind a marker and an environment opt-in;
- percent-encoding of the whole purl as one path segment before it reaches a route.
  `VersionedPackageUrl` refuses empty, `.` and `..` segments, but a percent-encoded
  `%2e%2e` passes it, and is harmless only when the purl never becomes more than one
  segment of a request path.

An adapter for Trustify v0.4.x is out of scope.

### 2. An affectedness answer carries no verdict in this contract version

`domain/affectedness.py` holds the affectedness contract:

- **`AffectednessRequest{cve_id: CveId, purl: VersionedPackageUrl}`.** It takes no
  product name, because no Trustify tool maps a name to a package.
- **`AffectednessFailure`**, the port's answer, and **`AffectednessDetail`**, the
  server's sentence for each failure (`AFFECTEDNESS_DETAILS`).
- **`AffectednessCheck{schema_version, request, applicability, failure, detail}`**,
  the published response.

Field rules:

- `applicability` is `ApplicabilityStatus`, whose only member is `unknown`.
- `failure` is required. It is an `AffectednessFailure`, one of `blocked_unverified`,
  `source_unavailable`, `timeout`, `auth_failed`, `tool_mismatch`.
- `detail` is an `AffectednessDetail`: a closed set of five server-owned sentences,
  one per failure, which the published schema lists as an `enum`. The sentence for
  `blocked_unverified` begins `BLOCKED_UNVERIFIED:`; every other ends "Affectedness is
  not established." `check_affectedness` builds `detail` from the port's failure, and
  refuses (`ValueError`) a port answer that is neither an `AffectednessFailure` nor
  the value of one, so a port
  answering "CONFIRMED: affected" makes the tool fail `internal_error`, and the text
  reaches no client.

An investigation's `product_applicability` entry pairs `unknown` with the one
`ApplicabilityBasis` sentence, so its basis is no free text either.

No field of the affectedness or investigation contracts can say "affected", "fixed"
or "not affected": `applicability` admits only `unknown`, `failure` names only
failures, and the investigation's basis and every affectedness detail are fixed
sentences the server owns; an investigation's affectedness outcome carries the
capability's sentence, which its schema states too. No affectedness adapter's text is
published, so neither a check nor an investigation presents affectedness as
established while no verified source exists, whatever the port returns. Retrieval
channels and the FiGHT source follow the same rule (§3).

A CVE record's `affected[].status` is a different thing: the record publisher's
statement about its own record, which `lookup_cve` and `search_vulnerabilities` serve as
source text. It is never an affectedness check, and the server's instructions and the
description of every tool whose answer can carry a record say so (§6).

The failures are their own enum rather than new `BackendStatus` members.
`BackendStatus` is shared by every retrieval outcome and feeds several status tables,
while auth and tool-mismatch failures arise only at this boundary.

A verdict needs evidence. Every factual claim cites an anchor, and Trustify responses
carry no record URL, retrieval time or terms. Designing that anchor, a `SourceType`
value and a URI scheme without a live response to check them against would invent a
response contract (brief §12).

The adapter that can return a verdict adds the verdict statuses and the Trustify
anchors together, as one contract change. It maps statuses like this:

- `affected`, `not_affected`, `fixed` and `under_investigation` map to statuses of the
  same names.
- `recommended` and any other string map to `unknown`.
- A purl or CVE that the response does not mention maps to `unknown`, never to
  `not_affected`.

### 3. Capabilities say why a source is unavailable; affectedness is always unavailable

`SourceCapability` gains `detail`, the server's sentence for why a source is
unavailable. It is set exactly when the state is `unavailable`, and it is one of the
sentences of the capability's subject (`UNAVAILABLE_DETAILS_BY_SUBJECT`): an
`AffectednessDetail` for `affectedness`, `FightUnavailableDetail.NOT_PINNED` ("no
pinned FiGHT snapshot is served") for `mitre_fight`, and none for any other subject.
The validator and the published shape both state these rules, so a set or capability
list carrying any other text fails to parse or validate.

`CAPABILITY_STATES_BY_SUBJECT[AFFECTEDNESS]` is `{unavailable}`: no deployment can
serve affectedness.

`describe_affectedness(trustify_port)` in the composition root reads the port's
reason once and builds the `affectedness` capability from it: `unavailable`, with
the `AffectednessDetail` for that reason. It raises `AffectednessConfigurationError`
for a port that gives anything but an `AffectednessFailure`, so no service is built
to serve it. The model planner differs: the server builds its identity (ADR 0004 §5),
and an unusable adapter is reported `ADAPTER_UNUSABLE` (ADR 0004 §4), since the planner
has a deterministic fallback.

The investigation's affectedness coverage outcome carries the capability's detail.
The validator requires the two to be equal, so the outcome's detail is one of the
server's sentences too. A run that needs affectedness stops on the
decision basis `affectedness_unavailable`.

Every published contract states its draft:
`"$schema": "https://json-schema.org/draft/2020-12/schema"`. The evidence-set schema
relies on `prefixItems`, which earlier drafts read differently.

**Backend failures are typed reasons too.** A retrieval channel or the FiGHT source
that gives no answer names a `BackendFailure` (`not_configured`, `adapter_unusable`,
`unreachable`, `search_failed`, `index_incomplete`, `filters_unsupported`,
`no_answer`) in `RetrievalOutcome.failure` or `ThreatContextOutcome.failure`, and
writes no text. The server publishes its own `BackendFailureDetail` sentence for it:

- a search response's `channel_outcomes[].detail` is that sentence, set exactly when
  the channel failed;
- a FiGHT source outcome's `detail` is that sentence, set exactly when the source did
  not answer;
- a CVE search source outcome carries no `detail`: it lists each distinct
  failure of its channels once in `channel_failures`, a list of those channel
  outcomes;
- an affectedness source outcome's `detail` is an `AffectednessDetail`, set exactly
  when the source did not answer, which is always.

Each rule is stated by the model, the validator and the published schema, so a set or
response carrying any other text fails to parse. An adapter that skips validation
(`model_construct`) to put text in its failure makes the server fail the call
`internal_error`: the published outcomes are built with validation, so the text
reaches no client.

**A successful answer carries no adapter text either.** A match's fields are closed
sets (`MatchedField` for the CVE channels, `TechniqueField` for FiGHT). Its matched
terms are checked against what the server sent: the search service accepts only the
caller's query terms from the lexical channel, the caller's filter values from the
structured channel (`SearchFilters.list_match_terms`), no term from the semantic
channel, and from the graph channel only relation values that both the seed and the
hit record assert (`record_relations`), each graph path checked the same way. The
topic-context service accepts only the topic terms it sent the FiGHT source. A
violation raises `EvidenceValidationError`, so the call fails `integrity_check_failed`
and an investigation step is `rejected_invalid_evidence`; the violation names the
record or technique, never the adapter's text. A FiGHT claim names the technique by ID
and status only. A FiGHT anchor's source name must be `mitre-fight` and its locator the
one its technique ID derives (`format_fight_locator`), beside the pinned version, URI,
retrieval time and terms (`has_pinned_provenance`), so the excerpt is the only text of
a FiGHT anchor the source chooses; a CVE anchor comes from the bundle the server
loads.

Every other text field a response carries is the server's (claims, scope bases,
warnings, failure sentences), the packaged topic cards', the caller's own query and
filters, or source text: a CVE record's descriptions, CVSS, affected products and
references, the record values a graph match repeats, a FiGHT technique's name, status
and tactics, and an evidence excerpt. Every tool description names the source-text
fields its answer can carry as untrusted.

These are contract changes; the schema version is `2.0.0-dev.16`.

### 4. The investigation reports affectedness from the capability and never calls the port

`ToolName`, `BackendRequest`, the plan gate, the validator's step rules, the audit and
replay are unchanged. A product question still ends `source_unavailable`, with
`partial` or a failure status. Each named product is `applicability: unknown`, with a
basis that says no verified affectedness source is available. That is the answer
brief §10 case 3 allows ("verified applicability or unknown").

Wiring affectedness into the trajectory would add all of the following, every one
exercised only by a fake: a tool name, a backend request, gate rules, validation,
audit and replay paths. Production could still answer only `unknown`. The gold product
questions also name products (`open5gs`, `f5gc`), which no Trustify tool accepts, so
even a verified adapter would not change those rows without an auditable
product-to-purl mapping. The verified-adapter task decides both.

Only `check_affectedness` calls the port. That tool is an explicit caller request with
no investigation scope. Brief §12's "skip Trustify when the policy excludes
implementation lookup" holds because the investigation never calls the port.

### 5. The trustify-mcp tool surface is pinned as test data

`tests/contract/data/trustify_mcp_ac8955f/tools.json` is the unmodified content of
`EXPECTED_TOOLS_LIST_RESPONSE` at the pinned commit. Beside it is a copy of the
commit's Apache-2.0 `LICENSE` (sha256 `c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4`;
the commit has no `NOTICE` file). Only tests read them, so they stay outside the
package. The facts about the server live in this ADR, not in the excerpt.

A contract test pins:

- the excerpt's hash;
- the twelve tool names;
- the inputs of the two affectedness tools (`package_uri_or_purl`; `cve_id`);
- that no tool takes a product name;
- that the source registry names the same commit.

The registry entry `trustify-mcp` and `THIRD_PARTY_DATA.md` record the licence,
verified from the `LICENSE` file at that commit.

### 6. The MCP server is the SDK's low-level `Server`; its schemas are the committed contracts

The server uses `mcp.server.Server` (`mcp>=2.3,<3`). `build_knowledge_mcp_server`
builds it, registering only `on_list_tools` and `on_call_tool`. It therefore
advertises tools and nothing else: no resources, prompts, completion or logging
control. No module holds a server, a client or a service.

Each tool's input and output is a contract registered in `schema_snapshots.py`.
`tools/list` publishes exactly what `render_schema` commits under `schemas/v2/`, so
the listing and the snapshots cannot drift. The listing is about 160 KB of compact
JSON, of which about 63 KB is the evidence-set schema. It is computed once when the
server is built. A slimmer evidence-set schema was rejected: it would be a second,
unpinned contract for the same payload.

| Tool | Input contract | Output contract | Service |
|---|---|---|---|
| `get_knowledge_capabilities` | `capabilities_request` (no fields) | `knowledge_capabilities` | the investigation service's capabilities, read at composition |
| `resolve_telecom_concept` | `concept_resolution_request` | `concept_resolution` | `TopicRegistry.resolve` |
| `lookup_cve` | `cve_lookup_request` | `search_response` | `SearchService.search`, query = the ID, limit 1 |
| `search_vulnerabilities` | `search_request` | `search_response` | `SearchService.search`, directly |
| `search_fight` | `fight_search_request` | `topic_context_response` | `TopicContextService.explore`, scope `protocol_context_only` |
| `check_affectedness` | `affectedness_request` | `affectedness_check` | `check_affectedness` over `TrustifyPort` |
| `get_evidence` | `evidence_lookup_request` | `evidence_lookup` | `EvidenceCatalog.get_evidence`, then `validate_served_anchor` |
| `investigate_telecom_topic` | `investigation_request` | `knowledge_evidence_set` | `InvestigationService.investigate` |

`concept_resolution` and `evidence_lookup` wrap the existing `TopicResolution` and
`EvidenceAnchor` with a `schema_version`, so every tool output names its contract
version.

`search_fight` reaches FiGHT only through a reviewed topic. A bare `aka` resolves to
no topic and searches nothing. The response lists CVE candidates only as excluded
implementation evidence.

Every tool is annotated read-only, non-destructive, idempotent and closed-world.

Source text is untrusted. A CVE record's descriptions, CVSS metrics, affected products
and references, a FiGHT technique's names, status and tactics, and evidence excerpts
are data. The server's `instructions` and each tool's description say so, and name the
fields that carry such text.

A record's `affected` entries, `status: affected` included, are its publisher's
statement, not an affectedness check. The `instructions` and the description of every
tool whose answer can carry a CVE record (`lookup_cve`, `search_vulnerabilities`,
`search_fight` and `investigate_telecom_topic`) say so, and that only
`check_affectedness` checks applicability, which answers `unknown`.

### 7. Input is parsed by the contract; failures are one sanitized contract

Arguments are first serialized with `json.dumps`. If the serialization exceeds 64
KiB, the call fails `arguments_too_large`. This is defence in depth against work in
our own validation; the SDK has already decoded the frame.

A frame the SDK cannot decode gets no answer at all: malformed or truncated JSON, a
lone surrogate escape, or JSON nested about 200 levels deep or more. The SDK's stdio
transport drops it without a JSON-RPC error and writes nothing to stderr, so the client
waits for its own timeout; the server keeps answering later frames.

Free-text request fields refuse what a reader cannot see: a query (1–512 characters)
holds no control character other than tab, line feed and carriage return, which a
pasted query holds and normalization folds into spaces, no U+007F and no bidirectional
override or isolate (U+202A–U+202E, U+2066–U+2069). A query of whitespace only is still
accepted and answered `no_match` with `no_searchable_terms`. A vendor or product filter
is a single line with a visible character, no control character and no override or
isolate. A purl filter is a package URL without version,
qualifiers or subpath, from the character set of the versioned purl: a type, then
segments none of which is empty, `.` or `..`; its type may be in any case, since purl
filters match case-insensitively.

They are then parsed with the request contract's `model_validate_json`, the parse
the request schema-agreement tests prove. The contracts reject unknown fields,
numbers sent as strings and booleans sent as anything else.

A failure is an `is_error` result with one text block holding a `ToolFailure`, and
no `structured_content`. The SDK client validates output schemas only on success
results.

`ToolFailure` (published) has these fields:

- `schema_version`.
- `code`, one of the codes in the table below.
- `message`, the fixed sentence for that code.
- `invalid_fields`: at most 20 entries. Each is `{location, error_type}`, with a
  declared field path and a pydantic error type, never an input value.
- `unexpected_field_count`: the number of keys the contract does not declare. Their
  names are never echoed.

| Code | When |
|---|---|
| `invalid_arguments` | the arguments do not parse as the request contract |
| `arguments_too_large` | the serialized arguments exceed 64 KiB |
| `unknown_evidence_id` | `get_evidence` names an ID the catalog does not hold |
| `server_busy` | every worker holds a live call, or, for an investigation, the deployment's runner has 4 live calls |
| `timed_out` | the call runner abandoned the call at the tool's bound |
| `response_too_large` | the serialized output exceeds the response cap |
| `integrity_check_failed` | the service rejected its own result, or `get_evidence` an anchor breaking an anchor rule (`EvidenceValidationError`) |
| `internal_error` | any other exception |

An unknown tool name is a JSON-RPC `-32602` error with the fixed message
`unknown tool`.

Every exception is caught in the handler, which closes the low-level server's
`code=0` leak in both protocol modes. An internal error is logged to stderr with its
traceback; the client sees the fixed message only.

No tool accepts any of the following:

- a path, URL or endpoint;
- SQL or Cypher;
- a shell command or code;
- a model name;
- an index operation.

A contract test scans every published input schema for such field names. The same
test checks that no input schema admits free-form keys.

### 8. Every call is bounded in time, concurrency and size

The async handler awaits `anyio.to_thread.run_sync(toolbox.call, …)`, so the event
loop never blocks. `KnowledgeToolbox.call` enforces three bounds.

**Concurrency.** The toolbox runs every tool body on its own `ThreadedCallRunner`,
built with `max_live_calls=4`. The runner counts a call as live until the call
returns, whether its caller still waits or abandoned it, and starts no call beyond the
cap: it raises `NoFreeWorker` at once, which the toolbox answers `server_busy`. A body
abandoned at its time limit therefore keeps its place under the cap until its backend
returns, and a backend that never returns leaves at most four tool bodies behind,
however many calls arrive.

An investigation runs its planner and tool calls on its deployment's own runner and
abandons a blocked one at its own deadline, then seals and returns, so its tool body
finishes while the abandoned call is still live. The toolbox therefore also answers
`investigate_telecom_topic` with `server_busy` while the deployment's runner has 4
live calls. The toolbox runner asks that question under its own lock, just before it
counts the investigation's body live (`run(..., admits=...)`), so investigations are
admitted one at a time. The toolbox's investigations plan with the deterministic policy,
so each consults no planner and abandons at most one call, a tool call at its deadline. Of
the
investigations whose abandoned calls are live together, the last admitted saw fewer
than 4 live deployment calls and at most 3 other bodies in flight, so these calls
never exceed 7. A backend that never returns therefore holds at most 4 tool bodies
and 7 abandoned investigation calls.

**Time.** It runs the tool body under `ThreadedCallRunner`, the abandoning runner the
investigation uses, with a deadline read from the toolbox's own injected monotonic
clock:

- 10 seconds for every tool except `investigate_telecom_topic`;
- for `investigate_telecom_topic`, the request's `max_wall_time_seconds` plus 10
  seconds for sealing.

The runner returns at the deadline at the latest. An abandoned call keeps its daemon
thread, and its place under the cap, until it returns.

**Size.** It serializes the response once, as compact JSON. A response over 1 MiB per
copy is refused with `response_too_large`. A result carries the text copy and the
structured copy, so the wire size is at most about 2 MiB. A response is never
truncated, because truncation would break its `result_sha256` and its validation; the
caller lowers `limit` instead.

There are two kinds of timeout:

- A port that honours its own timeout answers `timeout`, and the tool returns a typed
  `AffectednessCheck` with failure
  `timeout`. `check_affectedness` gives the port 8 seconds.
- A body that overruns the tool bound is abandoned and answers `timed_out`.

The services mutate nothing after construction and keep per-request state local, so
concurrent calls share them safely.

### 9. `search_vulnerabilities` is a direct ranked search

The tool returns `SearchService`'s ordinary ranked candidates, not an investigation,
so a retrieval tool and an investigating agent keep separate contracts. It inherits
the shared low-signal rule ("Compatibility change: low-signal query terms" in
`m5-mcp-and-sources.md`). Under that rule, `cve` and `cves` leave the search text after
full CVE IDs are taken out. A query with nothing left answers `no_match` with
`no_searchable_terms`; it calls no channel, or only the structured channel when a
filter is active, which never creates a candidate. Filters only narrow a result.

### 10. A set handed back is verified by `verify_evidence_set` and `cve-kgrag verify`

`verify_evidence_set(evidence_set, deployment, accepted_planner_capabilities)`
(`application/evidence_set_verification.py`) runs three checks in order:

1. `validate_knowledge_evidence_set`, against the deployment's capabilities followed by
   a `model_planner` capability the verifying settings accept
   (`list_accepted_planner_capabilities`, ADR 0004 §7), never one the set alone
   vouches for, so a set naming a planner those settings do not run reports
   capabilities they do not serve and is rejected;
2. `audit_decision_path`;
3. `replay_evidence_set`.

It raises `EvidenceValidationError` when validation or the audit rejects the set, or
when the replayed set fails the checks the controller runs at seal, and returns the
replay outcome otherwise.

`cve-kgrag verify FILE` checks against the packaged fixture and the planners its
settings configure (ADR 0004 §7); with no planner configured, a model-planned set is
`invalid` there.
It reads at most 4 MiB and prints one of these verdicts:
`verified`, `malformed`, `invalid`, `replay_differs`, `replay_timed_out`. It exits 0
only for `verified`.

The MCP surface stays at the brief's eight tools. A whole-set check is not a lookup:
its input is the size of the largest output, and it runs for up to the run's wall
time. The v2 API exposes it as `POST /api/v2/verify` (ADR 0007, decision 9).
`get_evidence` serves the anchor the catalog holds under one evidence ID, the catalog
every served anchor is checked
against; a consumer compares it with the anchor it holds. It serves the anchor only
when it passes `validate_served_anchor`, the anchor rules every response applies: the
evidence ID derives from the anchor's fields, the scope fits the source (CVE evidence
is `implementation_vulnerability`, FiGHT evidence `protocol_threat_context`, and no
anchor is `formal_protocol_finding`), and FiGHT evidence carries the provenance of the
snapshot the deployment pinned. Any violation answers `integrity_check_failed`, so a
catalogued anchor relabelled as a formal finding is never served, even resealed under
a re-derived ID.

### 11. Packaging, layers and start-up

**Packaging.**

- The `mcp` extra holds `mcp>=2.3,<3` and `anyio>=4.9,<5`. The server imports `anyio`
  directly.
- The `dev` group includes `cve-kgrag[mcp]`, so the default lane, strict mypy and the
  MCP tests run with the SDK.
- There is no `trustify` extra, because no code needs it (ADR 0001 §2).

**Layers.** `interfaces/` is the outermost layer:

- `interfaces/knowledge_tools.py` (tool table and limits) and
  `interfaces/knowledge_toolbox.py` (dispatch, parsing, bounds) import no SDK, so the
  core lane tests them.
- `interfaces/mcp/` is the only package that imports `mcp` or `anyio`. Its
  `__init__.py` stays empty, because importing every core module walks into the
  package.
- Domain, ports, topics and application never import `interfaces`.
- `interfaces` never imports adapters, discovery, the composition root or the CLI.

**Start-up.**

- `cve-kgrag mcp` starts the stdio server over the packaged synthetic fixture, the
  deterministic planner, the disabled Trustify adapter and no semantic channel.
- The CLI loads the runner through `discover_mcp_server_runner`, from the entry
  point `mcp_server = "cve_kgrag.interfaces.mcp.stdio_runner:serve_stdio"` in the
  `cve_kgrag.adapters` group, and hands it the SDK-free toolbox the composition root
  builds (`build_knowledge_toolbox`). The runner is looked up first, so an install
  that cannot serve the command never loads the fixture.
- That group stays the single dynamic-loading point (ADR 0001 §3). An optional
  interface loads through it the way an optional adapter does.
- Without the extra, the command exits 1 and its stderr is one fixed line naming the
  extra. A core install registers the entry point without the SDK, so there the load
  always fails on a module the extra installs (`mcp` or `anyio`); that failure is
  expected, so it logs nothing and prints no traceback.
- Any other unusable runner also exits 1, with one line on stderr naming the reason:
  no entry point, more than one, or a load that failed with the SDK installed. Such a
  load, for example after an SDK release renamed an import, first logs its traceback
  at warning, because there the traceback is the diagnosis.
- Nothing writes to stdout before the protocol starts.

### 12. Deferred, and where each item is recorded

| Item | Deferred to | Recorded in |
|---|---|---|
| Streamable HTTP: opt-in, 127.0.0.1, bearer auth, separate health and readiness; DNS-rebinding settings for other hosts stay a later decision | M6 WP6, owned by the `mcp` extra | ADR 0007 |
| Typed settings boundary: no M5 path has an endpoint, a credential or an optional adapter to enable | M6 (planner settings: ADR 0004) | PLAN.md M6 row |
| `semantic_channel` reporting a failed adapter load | M6 WP2: `unavailable` with a server sentence (ADR 0004 §1) | m6 doc |
| Real Trustify adapter, verdicts and Trustify anchors, drift detection against the pinned snapshot, retries, product-to-purl mapping, investigation wiring, `live` marker | Verified-adapter task | PLAN.md "Follow-up: verified Trustify adapter" |
| Whole-set verification over HTTP | M6 WP7: `POST /api/v2/verify` | ADR 0007 |

## Consequences

- Trustify's absence is explicit on every surface:
  - `get_knowledge_capabilities` reports `affectedness: unavailable` with a
    `BLOCKED_UNVERIFIED` detail.
  - `check_affectedness` answers `applicability: unknown` with failure
    `blocked_unverified`.
  - Investigations keep `source_unavailable` and `unknown` for products.
  None of these is fatal.
- No field of `2.0.0-dev.16`'s affectedness and investigation contracts states that a
  product is or is not affected; every affectedness `detail` is one of the server's
  fixed sentences, and an adapter can return nothing but a typed failure. A CVE
  record's `affected[].status` is its publisher's statement, never an affectedness
  check. Adding a
  verdict, a Trustify anchor or an `available` affectedness state is a contract change,
  made with the adapter that needs it.
- The M5 server serves the packaged synthetic fixture only. Its `cve_search`
  capability names the fixture.
- `tools/list` carries the full committed schemas, about 160 KB. Clients that
  validate structured output validate against the files the repository commits.
- An abandoned call keeps its daemon thread, and its place under the toolbox's cap,
  until it returns. A backend that never returns therefore makes the server answer
  `server_busy` once 4 such calls are live, instead of accumulating threads. Every M5
  backend is in memory, so none outlives its call for long; a network adapter must
  still honour its timeout, or it degrades the server to `server_busy`.
- The stdio peer is the local process that launched the server. Frames are read by
  the SDK before any of our caps apply, so the 64 KiB argument cap applies only after
  the SDK has decoded the whole frame, and a frame it cannot decode gets no reply
  (§7).
- The core-only install lacks the SDK:
  - its import-every-module check skips `cve_kgrag.interfaces.mcp.*`;
  - its test run excludes the MCP test directory by an explicit `--ignore`;
  - `cve-kgrag mcp` exits 1.
- A consumer checks one anchor by comparing it with what `get_evidence` serves under
  its ID, and a whole set through `cve-kgrag verify`.
- A set is verified against the planners the verifying settings configure, not the
  planner it records (ADR 0004 §7). With no planner configured, `cve-kgrag verify`
  reports a model-planned set `invalid`, even one a deployment running that model
  sealed.
