# M5 MCP server and sources

Schema version `2.0.0-dev.16`. M5 adds the Trustify port with a disabled adapter (the
real adapter is BLOCKED_UNVERIFIED) and the CVE-KGRAG MCP server. Design rationale:
ADR 0003. The compatibility change below landed at `2.0.0-dev.13` and is reviewed on its
own.

## Compatibility change: low-signal query terms

The MCP search tool (`search_vulnerabilities`) opens `SearchService` directly and
returns its ordinary ranked candidate list; bounded investigation stays a separate
tool. Searched as a word, a bare `cve` matches whichever description mentions CVEs
(CVE-9999-0007 in the synthetic fixture), so a search for `cve` alone answers `ok`
with an unrelated record. The change below removes that match from the shared core,
which every search goes through.

**Rule.** `cve` and `cves` are low-signal query words (`LOW_SIGNAL_QUERY_TERMS` in
`domain/text.py`, compared after NFKC normalization and case folding): every record
is a CVE, so they discriminate none. A query's search text, `extract_search_text(query)`,
is built in this order:

1. remove its CVE-ID tokens, malformed ones included (`remove_cve_id_tokens`), so the
   `CVE` of `CVE-2024-1234` is never read as a word and the ID's exact lookup is
   untouched;
2. normalize (`normalize_query`);
3. remove the unsearchable words (`find_unsearchable_word_spans`): every word of an
   ID likeness the words form once stopwords and punctuation are left out, read with
   `cve` and `cves` still in place (`CVE of 2021-44228` reads as `cve 2021 44228`),
   and each whole word that reads as `cve` or `cves` (`list_query_words`): a
   possessive with any apostrophe (`CVE's`, `CVE’s`) and a word with invisible or
   control characters inside it (`c`+ZWSP+`ve`, `cv`+U+FE0F+`e`, `C`+soft
   hyphen+`VEs`) read as the plain word, while visible separators keep words apart
   (`c ve` is the two words `c` and `ve`); `nvdcve` and `cvelist` stay;
4. repeat step 3, and the removal of any CVE-ID token, until the text holds none:
   dropping a word can bring others together into a likeness (`nvdcve cves 2021
   44228` reads as `nvdcve 2021 44228`).

The query's search terms, `list_query_terms(query)`, are the tokens of that text. The
rule applies to queries only: `tokenize` builds the lexical index from every
description word, `cve` included. `vulnerability`, `vulnerabilities` and `vuln` stay
search words; whether they join the set is decided on the M5 and M7 gold queries and
evaluation data. Over the 2026-10-27 NVD store `vulnerability` occurs in 193,984 of the
396,211 records, `vulnerabilities` in 12,185 and `vuln` in 245.

**Readers.** No component keeps its own word list; each calls one of the two functions.

| Reader | Where | Calls |
|---|---|---|
| Search service: the text the lexical and semantic channels read, and whether they run | `SearchService.search` (`application/search.py`) | `extract_search_text`, and `tokenize` over its text (what `list_query_terms` returns) |
| Investigation policy: the interpretation's search terms, hence every search it plans | `list_search_terms` (`application/investigation_policy.py`) | `list_query_terms` |
| Plan gate: the vocabulary and empty-search check, and the canonical call the repeat check keys | `find_call_rejection`, `canonicalize_call` (`application/plan_gate.py`) | `list_query_terms`, and `list_search_terms` |
| Call key: the set of search terms a search's key hashes | `compute_call_key` (`domain/planning.py`) | `list_query_terms` |
| Validator: whether a step's CVE search sends searchable text, which a semantic request needs | `sends_searchable_text` (`domain/investigation_validation.py`) | `list_query_terms` |
| Topic registry: every query template holds a search term | `find_card_violations` (`topics/registry.py`) | `list_query_terms` |
| Decision-path audit and replay | `application/decision_path_audit.py`, `application/trajectory_replay.py` | re-derive through `interpret_request`, the gate and `SearchService` |

**Behaviour.** Observed over the synthetic fixture. Search-service requests set
`semantic` and `graph_expand`; graph expansion seeds from the exact lookup's hits and
the text channels' hits.

| Query | Search service | Investigation (`implementation_only` and `mixed`) |
|---|---|---|
| `cve`, `CVE`, `CVEs` | no lexical, semantic or graph call; `no_match` with `no_searchable_terms` | intent `unsearchable`, no call, `no_evidence` (`no_searchable_terms`) |
| `cve ausf crash` | lexical and semantic read `ausf crash` | `cve_search("ausf crash")`, answer CVE-9999-0003 |
| `CVE 2022 log4j` | lexical and semantic read `2022 log4j`; `term_not_indexed` for `2022` and `log4j` | `cve_search("2022 log4j")`, `no_evidence` |
| `CVE-9999-0003 cve` | exact lookup, and graph expansion from its hit; no lexical or semantic call | exact lookup only, no search terms |
| `cves of ausf` | lexical and semantic read `of ausf` | `cve_search("ausf")` |
| `CVE of 2021-44228`, `nvdcve in 2021 and 2022`, `nvdcve cves 2021 44228` | no lexical, semantic or graph call; `no_match` with `no_searchable_terms` | intent `unsearchable`, no call, `no_evidence` (`no_searchable_terms`) |
| `ausf crash cve in 2021 and 2022` | lexical and semantic read `ausf crash in and` | `cve_search("ausf crash")`, answer CVE-9999-0003 |

A model plan whose search holds only low-signal words and stopwords (`cve`), or only
those and the words of an ID likeness (`cve of 2021 44228`), is rejected
`term_outside_vocabulary` as a search with no term, and the round falls back to the
policy's plan. A model search that also holds valid terms passes, and its canonical
call drops the low-signal words: `cve ausf` runs, is keyed and is recorded as `ausf`,
so after an issued `ausf` it is a `repeated_call`. The call key of a search hashes its
search terms, so `cve ausf` and `ausf` share a key even where a call is keyed without
being canonicalized first.

Filters only narrow what a query finds. A query with neither a search term nor a CVE
ID runs the structured channel when a filter is active, and the structured channel
never creates a candidate (`application/fusion.py`), so the query answers `no_match`
with no candidate whatever its filters. M4 behaved the same; tests pin it for `cve`
and for a stopword-only query.

Possessives and invisible characters do not hide a low-signal word: `CVE's`, `CVE’s`
and `c`+ZWSP+`ve` search nothing, and `CVE’s ausf` searches `ausf`, in the search
service, the investigation and a model plan's canonical call alike. A visible mark
inside the word is not read past (`c`+U+0306+`ve` searches `c` and `ve`), as no
visible separator joins words.

**What changes relative to M4 acceptance** (schema `2.0.0-dev.11`):

- `cve` and `CVE` were searched as words: the search service answered `ok` with
  CVE-9999-0007, and an investigation ran `cve_search("cve")` and stopped
  `sufficient` with it. `CVEs` ran one search that found nothing. All three stop
  before any call.
- `cve ausf crash` and `CVE 2022 log4j` searched `cve` too, so CVE-9999-0007 joined
  the answer (`CVE 2022 log4j` stopped `sufficient` on it alone). They search
  `ausf crash` (CVE-9999-0003) and `2022 log4j` (`no_evidence`).
- `CVE-9999-0003 cve` ran the lexical and semantic channels on `cve` beside the
  exact lookup; it runs the lookup, and any requested graph expansion, without the
  text channels.
- The search service read a query's words once, so an ID likeness its words formed
  only once stopwords and punctuation were left out reached the text channels:
  `CVE of 2021-44228` searched `cve of 2021-44228`, and `nvdcve in 2021 and 2022`
  all three words, where the investigation searched none of them. Both answer
  `no_match` with `no_searchable_terms`, as the investigation's search terms already
  did; M4's known limit on that split no longer applies.
- `CVE's` and `CVE’s` searched `cve` and `s`, and `c`+ZWSP+`ve` searched `c` and
  `ve`; with a semantic channel wired, any hit it returned could seal a run
  `sufficient`. Each reads as the plain low-signal word and searches nothing.
- `nvdcve cves 2021 44228` was searched whole, by the search service and the
  investigation alike; dropping `cves` makes its words a likeness, so it searches
  nothing.
- A model search holding `cve` passed the vocabulary check only when the query held
  `cve`, and then ran with it; `cve ausf` and `ausf` were two calls with two keys.
  A model search of only `cve` is rejected whatever the query, and `cve ausf`
  repeats `ausf`.
- `compute_call_key` hashes a search's `list_query_terms` rather than its tokens. A
  canonical search holds no stopword, low-signal word or ID likeness, so for every
  call M4 recorded the two agree and no recorded key changes; a run whose query or
  model plan holds a low-signal word records its search without the word, so that
  search's call key differs from the one M4 recorded.
- A topic card whose query template holds only low-signal words fails registry
  validation. The packaged 5G-AKA card's templates hold none.
- The published descriptions of `SearchRequest` and `Interpretation.search_terms`
  state the rule, and the schema version is `2.0.0-dev.13`, so a set sealed under
  `2.0.0-dev.11` no longer validates.
- `eval/gold/m4_trajectories.yaml` gains `low_signal_only`,
  `near_id_after_low_signal_word` and `low_signal_beside_terms`; no existing row
  changes.

## Contracts at `2.0.0-dev.16`

A set sealed under an earlier contract version does not validate (ADR 0003 §2, §3).

- **Capability detail.** `SourceCapability.detail` is the server's sentence for why a
  source is unavailable. It is set exactly when the state is `unavailable`, and it is
  one of its subject's sentences: an unavailable `mitre_fight` carries `no pinned FiGHT
  snapshot is served`, an `affectedness` capability one of the five
  `AffectednessDetail` sentences, and no other subject has any. The validator and the
  published shape both state these rules.
- **Affectedness is `unavailable`.** It is the only state the `affectedness` subject
  admits. A Trustify port gives only a typed reason (`AffectednessFailure`); the server
  publishes its own sentence for it, so no affectedness adapter's text reaches a
  capability, a check or an investigation; the investigation's affectedness outcome
  detail is one of those sentences in the schema too. The shipped `DisabledTrustifyAdapter` gives
  `blocked_unverified`, whose sentence begins `BLOCKED_UNVERIFIED:`. The investigation's
  affectedness coverage outcome carries the capability's detail, and the validator
  requires the two to be equal.
- **Backend failures are typed.** A retrieval channel or the FiGHT source that gives no
  answer names a `BackendFailure` reason and writes no text; the server publishes its
  own `BackendFailureDetail` sentence for it. A search response's channel outcome
  carries that sentence exactly when the channel failed; a FiGHT source outcome carries
  it as `detail` exactly when the source did not answer; a CVE search source outcome carries no `detail` and lists each
  distinct failure of its channels once in `channel_failures` (ADR 0003 §3).
- **Match explanations are checked.** A match's `matched_fields` is a closed set
  (`MatchedField`, and `TechniqueField` for FiGHT). Its `matched_terms` must be terms
  the server sent: the caller's query terms (lexical), its filter values (structured),
  none (semantic), relation values both records assert (graph, whose `graph_paths` are
  checked the same way), or the terms sent to FiGHT: the resolved topic's terms, or,
  with no topic, the interpretation's `fight_terms` an investigation's direct FiGHT
  search sends. Anything else fails the call
  `integrity_check_failed`, or rejects the investigation step, without echoing the text.
  A FiGHT claim names the technique by ID and status only, and a FiGHT anchor's
  source name and locator are fixed by the pin and its technique ID (ADR 0003 §3).
- **Basis rename.** The decision basis `affectedness_not_configured` is
  `affectedness_unavailable`. Each named product's `product_applicability` entry pairs
  `unknown` with one fixed basis sentence: no verified affectedness source is
  available.
- **Eleven new contracts**, one input and one output per tool where no contract served
  it yet, and the failure every tool shares: `capabilities_request`,
  `concept_resolution_request`, `cve_lookup_request`, `fight_search_request`,
  `evidence_lookup_request`, `affectedness_request`, `knowledge_capabilities`,
  `concept_resolution`, `evidence_lookup`, `affectedness_check` and `tool_failure`.
  `schemas/v2/` holds 21 contracts plus the manifest. An affectedness request takes a
  CVE ID and a versioned package URL (`VersionedPackageUrl`: no whitespace, control
  character, `?` qualifier or `#` subpath, and a required version), never a product
  name.
- **Request text.** Every query (`search_request`, `topic_context_request`,
  `investigation_request`, `concept_resolution_request`, `fight_search_request`) holds
  no control character other than tab, line feed and carriage return (a query pasted
  from a document holds them, and normalization folds them into spaces), no U+007F and
  no bidirectional override or isolate (U+202A–U+202E, U+2066–U+2069); a query of
  whitespace only is still answered `no_match` with `no_searchable_terms`. A vendor or
  product filter is single-line text with a visible character, no control character and
  no override or isolate. A purl filter has the versioned purl's
  character set without the version: a type in any case, then segments none of which is
  empty, `.` or `..`.
- **`$schema`.** Every published contract states
  `"$schema": "https://json-schema.org/draft/2020-12/schema"`; the evidence-set schema
  relies on `prefixItems`, which earlier drafts read differently.

## MCP tools

`vulnwitness mcp` serves eight read-only tools over stdio (ADR 0003 §6). Each tool's
listed input and output schema is the committed snapshot of its contract, and every
tool is annotated read-only, non-destructive, idempotent and closed-world. The server
advertises tools only: no resources, prompts, completion or logging control.

| Tool | Input | Output | Answered by |
|---|---|---|---|
| `get_knowledge_capabilities` | `capabilities_request` | `knowledge_capabilities` | the investigation service's capabilities |
| `resolve_telecom_concept` | `concept_resolution_request` | `concept_resolution` | `TopicRegistry.resolve` |
| `lookup_cve` | `cve_lookup_request` | `search_response` | `SearchService.search`, query = the ID, limit 1 |
| `search_vulnerabilities` | `search_request` | `search_response` | `SearchService.search` |
| `search_fight` | `fight_search_request` | `topic_context_response` | `TopicContextService.explore`, scope `protocol_context_only` |
| `check_affectedness` | `affectedness_request` | `affectedness_check` | the Trustify port |
| `get_evidence` | `evidence_lookup_request` | `evidence_lookup` | `EvidenceCatalog.get_evidence`, served only when the anchor passes the anchor rules |
| `investigate_telecom_topic` | `investigation_request` | `knowledge_evidence_set` | `InvestigationService.investigate` |

**Limits** (`ToolLimits`, ADR 0003 §7, §8):

- arguments: at most 64 KiB serialized, parsed by the request contract, which rejects
  unknown keys, numbers sent as strings and booleans sent as anything else;
- time: 10 seconds per call; an investigation gets its request's
  `max_wall_time_seconds` plus 10 seconds to seal;
- concurrency: 4 live tool bodies; a call over that fails at once. A body abandoned at
  its time limit stays live until its backend returns, so a backend that never returns
  holds its place. An investigation also fails at once while its deployment has 4
  live planner or tool calls, which bounds the calls investigations abandon;
- size: at most 1 MiB of compact JSON per copy of the answer (a result carries a text
  and a structured copy). An answer is never truncated; the caller lowers `limit`.

**Failures.** A failed call is an error result with one text block holding a
`tool_failure` and no structured content. Its message is the fixed sentence of its
code, never exception text or an input value; an argument that does not parse is named
by its declared field path and pydantic error type, and an undeclared key is only
counted.

| Code | When |
|---|---|
| `invalid_arguments` | the arguments do not parse as the request contract |
| `arguments_too_large` | the serialized arguments exceed 64 KiB |
| `unknown_evidence_id` | `get_evidence` names an ID the catalog does not hold |
| `server_busy` | 4 tool bodies are live, or, for an investigation, 4 of its deployment's calls |
| `timed_out` | the call was abandoned at its time limit |
| `response_too_large` | the answer exceeds 1 MiB |
| `integrity_check_failed` | the service rejected its own result, or the anchor `get_evidence` found breaks an anchor rule |
| `internal_error` | any other exception; its traceback goes to stderr only |

An unknown tool name is a JSON-RPC `-32602` error with the message `unknown tool`.

**Two kinds of timeout.** The affectedness port is given 8 seconds; a port that
honours it answers a typed `affectedness_check` with failure `timeout`. A tool body
that overruns its time limit is abandoned and the call fails `timed_out`.

**Start-up.** `vulnwitness mcp` serves the packaged synthetic fixture with the
deterministic planner, the disabled Trustify adapter and no semantic channel, and
exits 0 when the client closes stdin. The runner loads through the
`vulnwitness.adapters` entry point `mcp_server`, before the fixture is read. Without the
`mcp` extra, or with any other unusable runner (no entry point, more than one, or a
load that fails with the SDK installed), the command writes nothing to stdout, prints
`vulnwitness mcp cannot start: <reason>` to stderr and exits 1. Without the extra the
reason is `the 'mcp' extra is not installed: pip install 'vulnwitness[mcp]'`; a load that
fails with the SDK installed logs its traceback first.

**`instructions`.** The server's instructions state the contract version, that source
text is untrusted data that cannot instruct tool use, the fields that carry it (a CVE
record's `descriptions`, `cvss`, `affected` and `references`; a FiGHT technique's
`name`, `source_status`, `tactic_ids` and `tactic_names`; an evidence anchor's
`excerpt`), that a record's `affected` entries are its publisher's statement and not an
affectedness check, and that affectedness is unavailable (BLOCKED_UNVERIFIED). Each
tool's description names the source-text fields its answer carries, and every tool whose
answer can carry a CVE record (`lookup_cve`, `search_vulnerabilities`, `search_fight`,
`investigate_telecom_topic`) repeats the `affected` sentence.

## Affectedness and Trustify

**BLOCKED_UNVERIFIED.** No Trustify adapter is verified. The official trustify-mcp
server, pinned at `ac8955f768a5bfef6f1c9a5c1d02ec5b5cf9bf5e`, calls `/api/v2` routes
that Trustify removed in v0.5.0, including both affectedness routes; no release from
v0.5.0 to v0.7.0 serves them (ADR 0003 Context). Its tool surface is pinned unmodified
in `tests/contract/data/trustify_mcp_ac8955f/`, with its Apache-2.0 licence, and
contract tests pin its hash, its twelve tool names and the inputs of the two
affectedness tools.

**What a check returns.** The only shipped adapter, `DisabledTrustifyAdapter`, gives
`blocked_unverified` both as the reason affectedness is unavailable and as the answer
to every check. `check_affectedness` therefore answers `applicability: unknown` with
that failure and its `BLOCKED_UNVERIFIED:` sentence. No field of the affectedness and
investigation contracts can say affected, fixed or not affected: a port returns only
an `AffectednessFailure`, every `detail` is one of the server's fixed sentences (an
`enum` in the published schemas), and a port answering anything else, such as
"CONFIRMED: affected", fails the call `internal_error` without its text reaching the
client. So no surface presents affectedness as established, whatever an adapter
returns, and `unknown` never means not affected. A CVE
record's `affected[].status`, which `lookup_cve` and `search_vulnerabilities` serve, is
the record publisher's statement, never an affectedness check.

**The investigation does not call the port.** A product question ends
`source_unavailable`, `partial` or a failure status, with each named product
`unknown`. Wiring the port into the trajectory would add a tool name, gate, validation,
audit and replay paths that could still only answer `unknown`, and the gold product
questions name products (`open5gs`, `f5gc`) that no Trustify tool accepts (ADR 0003 §4).

**Preconditions for the real adapter.** It is a separate task, started only once (a) a
deployed Trustify version, its OpenAPI document and a test instance, or (b) a
trustify-mcp release stating the Trustify versions it supports is available. Its scope
is in `PLAN.md`, "Follow-up: verified Trustify adapter".

## Verifying a set

`vulnwitness verify FILE` checks an evidence set handed back
(`verify_evidence_set`, ADR 0003 §10): the validator, the decision-path audit and
replay, in that order, against the packaged fixture. It reads at most 4 MiB (a larger
file exits 2) and prints JSON with the verdict, at most 100 violations and the replay
differences. It exits 0 only for `verified`.

| Verdict | Meaning |
|---|---|
| `verified` | the set validates, passes the audit and replays to itself |
| `malformed` | the file does not parse as a `knowledge_evidence_set` of this version |
| `invalid` | the validator or the audit rejects the set, or its replay fails the checks run at seal |
| `replay_differs` | replay gives back a different set; each difference names its step and part |
| `replay_timed_out` | replay ran into its own wall-time deadline before the point where the recorded run found one, so nothing was compared |

The set is checked against the capabilities of the verifying deployment and the
planners its settings configure, never the planner the set alone records (ADR 0004 §7).
With no planner configured, `vulnwitness verify` reports a model-planned set `invalid`.

One anchor is checked through the `get_evidence` tool: it serves the anchor the catalog
holds under an evidence ID, the catalog every served anchor is checked against, and a
consumer compares it with the anchor it holds. The anchor is served only when it passes
the anchor rules every response applies (`validate_served_anchor`): its ID derives from
its fields, its scope fits its source, it is never `formal_protocol_finding`, and FiGHT
evidence carries the pinned snapshot's provenance. Otherwise the call fails
`integrity_check_failed`, so no catalogued CVE anchor is served as a formal or
protocol finding, even resealed under a re-derived ID. Whole-set verification is not an MCP
tool; the v2 API exposes it as `POST /api/v2/verify` (ADR 0007, decision 9).

## Gold queries

`eval/gold/m5_tool_queries.yaml` holds hand-labelled answers of the eight tools over the
synthetic fixture, the 5G-AKA card, the FiGHT excerpt, the disabled adapter and the
deterministic planner. Tests run each row through the toolbox and compare; they never
regenerate the file.

- `search_vulnerabilities` rows pin the low-signal rule: `cve` and `CVEs` answer
  `no_match` with `no_searchable_terms`, a severity filter creates no candidate,
  `cve ausf crash` finds CVE-9999-0003, `CVE 2022 log4j` finds nothing and warns
  `term_not_indexed` for `2022` and `log4j`, and `CVE-9999-0003 cve` runs the exact
  lookup only.
- The measurement rows record how the fixture answers `vulnerability`,
  `vulnerabilities`, `vuln` and `ausf vulnerability` without changing the rule;
  `vulnerability` finds CVE-9999-0008, and `vulnerabilities` and `vuln` find nothing,
  each warned `term_not_indexed`.
  They feed the M7 decision on whether these words join the low-signal set.
- The other rows cover a known and an unknown CVE ID, `5gaka` and a bare `aka` for
  concept resolution and FiGHT search, the free text `SUCI threats` for FiGHT search
  (no topic resolves, so nothing is searched), the affectedness check, an unknown evidence ID,
  the capabilities, and the two product investigations, which end `partial` with the
  product `unknown`.

The MCP tests also run every M4 gold investigation request that runs on the packaged
FiGHT excerpt, the one the server serves, through an in-process client and compare the
answer with the investigation service's.

## Deliberate deferrals

| Item | Deferred to | Recorded in |
|---|---|---|
| Streamable HTTP: opt-in, loopback, bearer auth, separate health and readiness; DNS-rebinding settings for other hosts stay a later decision | M6 WP6, owned by the `mcp` extra | ADR 0007 |
| Typed settings boundary: no M5 path has an endpoint, a credential or an optional adapter to enable | M6 | PLAN.md M6 row |
| `semantic_channel` reporting a failed adapter load | M6 WP2: `unavailable` with a server sentence | m6 doc, ADR 0004 §1 |
| Real Trustify adapter, verdicts and Trustify anchors, drift detection against the pinned snapshot, retries, product-to-purl mapping, investigation wiring, `live` marker | Verified-adapter task | PLAN.md "Follow-up: verified Trustify adapter" |
| Whole-set verification over HTTP | M6 WP7 (done): `POST /api/v2/verify` | ADR 0007, m6 doc WP7 |

## Known limits

- **`tools/list` size.** The listing carries the full committed schemas, about 160 KB
  of compact JSON, of which the evidence-set schema is about 63 KB.
- **Abandoned threads.** A call abandoned at its time limit keeps its daemon thread
  until the body returns, and its place under the cap of 4 live tool bodies, so a
  backend that never returns holds at most 4 tool bodies, plus at most 7 calls that
  investigations abandoned (ADR 0003 §8), and the server answers `server_busy` while
  they are live. Every M5 backend is in memory; a network adapter must honour its
  timeout, or it degrades the server to `server_busy`.
- **A model planner's reply is model text.** M4's trajectory records each model reply
  (`ModelReply`: its plan text, or its failure `detail`, one of the server's
  `ModelReplyFailureDetail` sentences) so that replay can re-read it.
  No M5 deployment runs a model planner, so no M5 response carries one, and, with no
  planner configured, `vulnwitness verify` reports a model-planned set `invalid`
  (ADR 0004 §7). Its plan text is untrusted model output, and the tool descriptions
  say so (ADR 0004 §5).
- **No product-to-purl mapping.** Affectedness is asked by versioned purl only, and no
  source maps a vendor or product name to a package.
- **Undecodable frames get no reply.** The SDK's stdio transport drops a frame it
  cannot decode (malformed or truncated JSON, a lone surrogate escape, JSON nested
  about 200 levels deep or more) without a JSON-RPC error and with nothing on stderr,
  so the client waits for its own timeout; the server keeps answering later frames.
  The 64 KiB argument cap applies only after the SDK has decoded the whole frame. A
  frame-size cap would need a wrapped read stream, which a local stdio peer does not
  warrant.
- **Synthetic fixture only.** The server serves the packaged synthetic fixture; its
  `cve_search` capability names it.
