# Architecture and behaviour

This service is a read-only vulnerability and telecom threat-context input layer.
It retrieves records and preserves their provenance; it does not execute attacks,
simulate networks, or turn catalogue associations into attack paths.

Start with the [README](../README.md) for commands and the [runbook](runbook.md)
for real data. [Evaluation](evaluation.md) explains reproducibility and quality limits.
The full [decision records](rebuild/adr/0001-packaging-and-migration.md)
remain available for implementation detail. Current pre-release contracts are named by
the [schema manifest](../schemas/v2/manifest.json).

## Components

| Layer | Responsibility |
|---|---|
| CLI, REST, MCP | Validate requests and present typed answers |
| Application services | Search, product queries, topic context, bounded investigation, verification |
| Domain and ports | Records, provenance, needs, budgets, plan gate and source interfaces |
| Adapters | NVD/KEV import, corpus stores, lexical/graph/optional semantic retrieval, FiGHT, MITRE mappings, model transport |
| Packaged knowledge | Source metadata, draft topic cards and notice-bearing offline fixtures |

Dependencies point inward: interfaces and adapters depend on domain/ports; domain
and application code do not import transport SDKs or storage implementations.
The core requires only Pydantic and PyYAML. Heavy integrations use optional extras
and entry points, not import-time downloads.

## Data and retrieval

Without a store root, the service uses synthetic CVE records and packaged MITRE
excerpts. With a configured root, it serves the immutable store named by `ACTIVE`,
or refuses to serve; it never silently substitutes sample data.

File digests are computed when operator snapshots load. Optional expected SHA settings
enforce an operator pin when supplied. FiGHT always requires its reviewed catalog;
MITRE has no such catalog, so automatic identity alone does not verify an unchanged
or authentic upstream file.

NVD supplies CVE descriptions, weaknesses, affected-product entries and retained CPE
conditions. CISA KEV is joined by CVE ID with separate evidence. Imports preserve
source URLs, acquisition times and input identity. They do not infer absent product
information. The [runbook](runbook.md) covers import and activation.

The retrieval paths are distinct:

- Exact lookup answers a named CVE ID.
- Lexical search uses an inverted BM25 index, with deterministic tie-breaking and
  per-channel outcomes. It indexes descriptions, implicated vendors/products and CWE
  IDs once at load, with CVE-ID tie-breaking. Query normalization removes stopwords
  and low-signal `cve`/`cves` terms. A match of individual words is not a relevance
  assessment. Search fuses channels by reciprocal rank: exact IDs first, direct
  lexical/semantic hits next, graph-only neighbours last; structured filters annotate
  admitted records without adding relevance scores.
- Product queries use explicit vendor/product fields, with description-phrase
  supplementation only for records without implicated products. When both fields
  are supplied, both must occur; product-only mentions with unconfirmed vendor
  ownership are counted separately, not returned as vendor-confirmed matches.
- Graph expansion follows shared record attributes such as CWE, vendor, product,
  CPE and purl. It is association expansion, not an exploit graph.
- The optional semantic adapter is not bound to imported corpus stores:
  requesting it there reports `collection_not_bound`. A full store-index build
  and refresh workflow is not implemented.

NVD imports have no purls. An unsupported purl filter is rejected explicitly,
not interpreted as a successful search with no vulnerabilities.

### Product vulnerabilities

The CLI `product`, authenticated `POST /api/v2/product` and MCP
`query_product_vulnerabilities` share one service. Supply at least one of `vendor`
or `product`; `version`, `limit` and `cursor` are optional. Names compare exactly
with Unicode `casefold()`. Use stored CPE component names, unescaped on import,
preserving underscores, punctuation and whitespace. Both names must match the same
implicated entry (`status != unaffected`), without recognizing names from prose.
A product-only query includes all vendors sharing that product name.

Only records with no implicated products can supplement field matches through
consecutive description tokens. For example, `oai-cn5g-amf` becomes `oai cn5g amf`.
With both fields, the vendor and product must each occur as whole-token phrases;
without product, the phrase is the vendor. Product mentions without the requested
vendor are excluded and counted in `description_mentions_vendor_unconfirmed`
across all pages (zero unless both fields are supplied). Even a returned description
mention cannot establish ownership. Each CVE appears once; field evidence wins.
`basis.kind` distinguishes `product_field` and `description_mention`.

Vendor, product and eligible description-token postings are built once at load.
Queries intersect postings, then verify same-entry names and consecutive phrases
on candidates. `matched_products` lists all matched vendor:product pairs, and
`total_available` counts stored matching CVEs across all pages. Neither asserts
coverage beyond the loaded corpus. Each page carries only its returned records'
anchors; JSON retains severity metrics and KEV entries, while text summarizes them.

This is grouping, without a relevance score: with version, `hit`, `unknown`, then
`no_hit`; within each, field evidence before mentions, newest publication first
(missing dates last), then ascending CVE ID. Pages default to 10, maximum 20.
Repeat vendor, product, version and limit with `cursor=next_cursor` (CLI `--cursor`)
until `next_cursor` is null. Requests are echoed, including the cursor. Cursors are
opaque stateless offsets over this order, requiring the same served corpus throughout
traversal. Invalid, mismatched or out-of-range cursors give `invalid_cursor`:
CLI exit 2, REST 422, MCP tool failure. Wrong types fail request validation.
CLI exit 0 means records returned; exit 1 means empty. This inventory view makes
no sufficiency claim; protocol/technology investigations are a separate entry.

### NVD version facts and affectedness

Product items with `version` carry `nvd_version_note`; investigation candidates
carry `nvd_version_notes` for recognized affectedness mentions. `hit` records the
matching implicated NVD entry and retained condition. `no_hit` means no retained
condition matched, never that a version is unaffected. `unknown` explains missing
conditions, uncomparable versions or description-only evidence. Version never
filters CVEs or becomes lexical search text for a recognized product version.

Dotted numeric segments compare numerically (5.10 > 5.9), ignoring trailing zero
segments (2.7 == 2.7.0). Non-digit segments are uncomparable except that an exact
condition may match by trimmed string equality. Full configuration/environment
conditions are not evaluated: non-vulnerable CPE conditions and the configuration
tree are not retained. NVD enrichment can omit product and version data entirely.
Annotations do not change evidence needs, stop decisions or unknown applicability.
The `affectedness` command always returns `unknown` / `blocked_unverified`, exit 1.

## Topics and protocol context

A topic card contributes reviewed terminology, retrieval templates, relevance
rules, exclusions and references. The bundled GTP-family and 5G-AKA cards are
`pending_review`; using them emits a warning. They participate in retrieval but
cannot establish `found` or `sufficient`. In an otherwise completed run with
pending-card matches, the stop reason is `needs_unmet` and status is `partial`;
budget or source failures can take precedence.

Aliases identify a topic, not every record's relevance. Network functions and
product names can provide context without being protocol-equivalent aliases.
Shared authentication operations alone do not identify the 5G-AKA method.
The GTP card retrieves the family broadly: a GTP-U question can also return
GTP-C records and receives a family-scope notice. Its six retrieval templates each
consume a backend call. The 5G-AKA card cites 3GPP TS 33.501 V19.7.0 and has no named
reviewer; pending status is disclosed in answers.

FiGHT techniques remain in `protocol_context`, separate from implementation CVEs.
A topic call searches FiGHT only when the scope allows it. Without a resolved topic,
`fight_direct_search` searches the original permitted terms. CVE IDs, reported
exclusions or terms individually resolving as topics block that direct path.
The public MCP `search_fight` tool is a separate interface, not that internal call.
FiGHT uses phrase BM25 with technique-ID tie-breaking.

Only exclusions the registry reports are stripped or block retrieval. Unicode
format characters are hard boundaries: inserting one can change exclusion coverage.
Registry and CVE normalization also differ for certain case-fold/combining-character
sequences. These are known limits, not an end-to-end exclusion guarantee;
[ADR 0002 §8](rebuild/adr/0002-bounded-investigation.md#8-excluded-term-tokens-are-stripped-from-free-text)
records the boundary.

## Bounded investigation

The controller follows:
`interpret → plan → retrieve → assess → [refine → retrieve → assess] → validate`.
There is at most one refinement and no unbounded agent loop. The policy looks up
named CVE IDs first, explores a resolved topic through its card, or searches the
question's permitted words. Mixed free text also searches FiGHT when allowed;
protocol-only free text uses FiGHT alone. Refinement can explore an untried topic
or send still-unsearched permitted terms for an open need; it cannot invent IDs.

### Named-product step and merge order

For free-text implementation or mixed questions, the interpreter can recognize one
whole served vendor/product phrase. A vendor may name a family; a product name must
identify one vendor. Vendor phrases take precedence, contained shorter names defer
to longer ones, and ambiguous or excluded collision names stay lexical. Recognition
uses served identities, without an external entity resolver. A recognized dotted
version is kept out of lexical terms; unrelated numbers stay. Affectedness-language
extraction can also provide the recognized name/version.

Round 1 keeps its lexical search and adds one bounded `product_query` only when the
base plan leaves room in the call budget, reserving a mixed-scope FiGHT call where
needed. Protocol-only, exact-ID and topic plans do not gain this step. It charges
one backend call and uses the existing source, result, context and wall-time budgets.
It reads the first product page only; investigation filters apply after that cap,
so later matching records can be missed. This step performs no lexical search,
assigns zero relevance score and grants no evidence need. Product facts and
recognized versions remain structured evidence, not an affectedness verdict.

The answer deduplicates CVEs across admitted steps, retaining every sighting.
Base merge order is named exact lookups, then relevance tier, product-name support
when a product step was admitted, non-product retrieval before product-only
candidates, first step, tool rank and CVE ID. Product-name support means an exact
implicated vendor/product or a whole description phrase; unlike inventory admission,
it does not require CPE-less records or confirm ownership. Matching lexical candidates
keep their relative order. The named-product signal does not establish component
relevance. Optional model labels stably group this order before the answer cap.

Default server ceilings are two rounds, eight backend calls, four sources,
20 results per call, 30 seconds and 200,000 admitted context bytes. A caller may
lower, not raise, them. A topic step charges its template fan-out plus a FiGHT
query when applicable. Charges are not refunded on failure.

An oversized response admits the longest ranked prefix of whole results with
their anchors that fits. Topic results are interleaved across sections by rank.
The step records `admitted_prefix`, omitted counts, charged bytes and the next
result's size; the answer warns about omissions. This is not a promise that the
first result fits, or that the context limit caps the final answer size.

Calls are abandoned at deadlines and late results are not admitted. Python cannot
kill their worker threads; they may continue until returning. A thread holding the
interpreter lock can delay deadline handling. See
[ADR 0002](rebuild/adr/0002-bounded-investigation.md) for the execution boundary.

### Needs and stopping

Needs derive from the request and interpretation, never from evaluation labels:

- Each retained named CVE gets a named-CVE need.
- A text target adds implementation and/or protocol needs according to scope.
  With a named ID, ordinary surrounding prose alone is not a second target;
  a resolved topic can be.
- Explicit product context and recognized product-version mentions add affectedness
  needs outside protocol-only scope. Natural-language recognition is deliberately
  limited; explicit product queries are preferable for inventories.

A need can be `found`, `matches_unassessed`, `not_found`, `not_evaluated`,
`source_unavailable` or `unsupported`. No adopted serving step means
`not_evaluated`, not “searched and found nothing”. Matching words or a pending
card can produce candidates without evaluating whether they answer the question.
Unexplained terms absent from the index can leave a need `not_found` while
preserving all returned candidates.

Only exact ID correspondence or a reviewed topic mapping can establish `found`.
All needs must be found to support the `sufficient` stop; other execution,
budget and source conditions still apply. Even a reviewed mapping is not proof
that the answer covers every relevant record. Review of card content and authority
to declare sufficiency must not be conflated.

Free-text results do not automatically reach sufficient. A budget failure in a
redundant later step can still change the run's outcome despite earlier useful
evidence. That precedence is not fixed by prefix admission.

### Where the model participates

REST and both MCP transports use the deterministic policy, without the semantic
adapter. CLI `investigate` and `eval planner` can use a configured model.

For named-ID and topic questions, the model proposes allowlisted tool plans;
the gate checks vocabulary, scope, IDs, repetition, baseline sources and budgets.
Rejected or unavailable proposals fall back to the policy when the fallback fits.
Free-text round 1 uses the policy and records `model_not_consulted` for planning.
That label does **not** mean a configured relevance assessor was never called.

For free-text CVE questions, a configured model can label admitted candidates
`relevant`, `not_relevant` or `cannot_tell`, and propose one gap and follow-up
search. New terms must come from the question or admitted candidates' vendor,
product or CPE product names. Store-wide names are not an allowed source.
The gate checks these sources and the shared budget.

Labels stably group relevant, cannot tell, not relevant and unassessed candidates
before the answer cut (at most 20, or a lower requested limit). They do not delete
records by label, change need outcomes or grant sufficiency. New candidates can
receive one more assessment; assessor calls and retrieval share the run deadline,
with at most two rounds. Failures preserve round 1's evidence. Candidate text and
model replies are untrusted data, never instructions or evidence authority.

## Weakness associations

Single-CVE lookup can attach CVE → CWE → CAPEC → ATT&CK associations from an
offline-built mapping. Each hop retains its catalogue version/input digest and the
NVD record's evidence IDs. Direct catalogue links, CAPEC-parent inheritance
(`inherited_from`) and CWE-parent inference (`inherited_from_cwe`) stay distinct.
Both parent traversals are labelled inferences, without inventing a direct link.
CAPEC inheritance follows explicit `ChildOf` hops; deprecated CAPECs cannot bridge
chains. Deprecated/revoked ATT&CK objects cannot provide techniques. Technique IDs
retain sub-techniques; tactics come from ATT&CK phases, not truncated IDs.

For a CWE without direct `Related_Attack_Patterns`, the builder searches breadth
first for all linked ancestors at the nearest depth in CWE view 1000 (Complete
Weakness Hierarchy). Only `ChildOf` relations in that view count; use relations
marked `Ordinal="Primary"` if present, otherwise all its parents. Ordinal is a
relation property within a view, not a primary view. Other views/relation types
and reverse CAPEC-to-CWE references do not count. Any direct link prevents CWE
inheritance, even to a deprecated CAPEC. Each branch stops at its first directly
linked ancestor. Missing parents cannot bridge chains; encountered cycles refuse
the build. CWE-787 inherits CWE-119's 12 CAPEC links in CWE 5.0: an inference along
the hierarchy, not a direct catalogue link from the original CWE. Such paths retain
every source-labelled `cwe_child_of` hop and may also inherit through CAPEC parents.

With no usable direct/inherited ATT&CK mapping, a path ends at CAPEC with
`terminal_reason: "no_attack_mapping"`, null `technique` and `technique_source`.
These terminal reasons are not repeated in `missing_links`; unavailable techniques,
parents and missing CWE-to-CAPEC links remain there. Absence from an excerpt means
absence from that snapshot, not from the full catalogue. NVD noinfo/Other
placeholders normalize to no specific CWE.

All paths share a 20-path cap per CVE with an exact omitted count. Order is direct
full paths, CAPEC-inherited full paths, CWE-inherited full paths, then all CAPEC
terminals, followed by lexicographic IDs/parent chains. It is not an importance
ranking. No model or keyword inference fills a missing link. Every served path
is validated against the loaded snapshot; a forged path or changed identity fails.

Search, topic and investigation candidates, including excluded candidates, omit
associations entirely. They consume no investigation context bytes and affect no
retrieval, ranking, planner input, need, FiGHT context or affectedness decision.
Text investigations point to `lookup` for full paths, sources and omitted counts.
These are derived associations, not evidence of exploitation, an attack path or
FiGHT protocol evidence. No ATT&CK mapping means only that this snapshot has no
mapping; it does not mean there is no attack technique or exploitation route.
See the [runbook](runbook.md#weakness-association-mapping) for offline building,
source pinning, digest integrity statements and serving.

## Verification and compatibility

Evidence IDs, source content identities and result digests support source binding,
validation and replay. The verifier checks served records against its source catalog,
re-derives decisions and replays the controller using recorded replies. A recomputed
hash alone does not prove authenticity; neither do recorded timings attest real time.

API/schema, store-format, policy and evaluation-report versions serve different
compatibility purposes. The current contracts are pre-release; matching a version
string alone does not guarantee that an older evidence set replays after a policy
change. Keep the original program, settings, snapshots and evidence sets when replay
is required. Existing store-format compatibility is specified in
[ADR 0008 §9](rebuild/adr/0008-legacy-data-importer.md#9-the-store-and-the-write-protocol).

This repository supplies data and evidence to downstream learning or simulation
projects. Those consumers own their simulation, execution permissions and safety
boundaries; this service does not provide an execution engine.

## Repository boundary and origin

The service (package `cve_kgrag`, distribution/command `cve-kgrag`) originated in
[CVE-KGRAG](https://github.com/Yuning-J/CVE-KGRAG) at revision `53d75e3`.
The repository name does not rename the command, MCP server or `CVE_KGRAG_*`
settings. [PROVENANCE](../PROVENANCE.md) records the carried material and licences.
CVE-KGRAG contains the legacy RAG pipeline, FastAPI `/api/v1`, Gradio UI and Neo4j
tooling and receives their security fixes. This service supplies none of those
interfaces and promises no compatibility with their modules, files or model artifacts.
Code is [MIT](../LICENSE); data retains its [own terms](../THIRD_PARTY_DATA.md).

## Interfaces

CLI, REST and MCP share validated services. The REST API provides search, product,
investigation, evidence, capabilities and verification; the [runbook](runbook.md#rest-and-mcp)
lists routes, authentication and startup behaviour. MCP exposes nine read-only tools:

| Tool | Example input |
|---|---|
| `get_knowledge_capabilities` | `{}` |
| `resolve_telecom_concept` | `{"query":"5G-AKA"}` |
| `lookup_cve` | `{"cve_id":"CVE-9999-0001"}` |
| `search_vulnerabilities` | `{"query":"authentication bypass"}` |
| `query_product_vulnerabilities` | `{"vendor":"democorp","limit":10}` |
| `search_fight` | `{"query":"5G-AKA"}` |
| `check_affectedness` | `{"cve_id":"CVE-9999-0003","purl":"pkg:generic/open5gs@2.7.0"}` |
| `get_evidence` | `{"evidence_id":"ev:d8097ae9c31b754d26a1ef92"}` |
| `investigate_telecom_topic` | `{"query":"5G-AKA","scope":"mixed"}` |

`verify_evidence_set` is a toolbox operation exposed by CLI/REST, not a tenth MCP tool.
Source descriptions, references, excerpts, model replies and candidate text are
untrusted input. They cannot authorize actions or override fixed claims, gates,
source validation and budgets.
