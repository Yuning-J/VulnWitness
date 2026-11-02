# Architecture and behaviour

A read-only vulnerability and telecom threat-context layer retrieves cited records,
without attack execution or simulation. Associations are not attack paths. Read the
[README](../README.md), [runbook](runbook.md), [evaluation](evaluation.md) and [contracts](../schemas/v2/manifest.json).

## Components

| Component | Responsibility |
|---|---|
| CLI, REST, MCP | Validate requests and present typed answers |
| Application services | Search, inventory, topic context, bounded investigation, verification |
| Domain and ports | Records, provenance, evidence needs, budgets, plan gate and source boundaries |
| Adapters | Feed import, stores, lexical/graph/optional semantic retrieval, FiGHT, MITRE mappings, model calls |
| Packaged knowledge | Source metadata, topic cards and notice-bearing synthetic/MITRE fixtures |

## Sources, snapshots and trust

Without a store root, CVEs are synthetic and MITRE data is excerpted. A configured
root serves the immutable store pinned by `ACTIVE` or refuses startup, without
fixture fallback. NVD supplies descriptions, weaknesses, product entries and retained
CPE conditions; CISA KEV joins by CVE ID with separate evidence. Imports retain
source URLs, acquisition times and input identity, without inferring absent products.
Store activation and snapshot changes require service restart.
FiGHT files must match a reviewed catalog; optional expected SHA-256 adds a pin.
MITRE mapping files have no reviewed catalog: their computed identity alone proves
neither authenticity nor unchanged bytes. A configured invalid snapshot fails startup,
without excerpt fallback. See [snapshot operations](runbook.md#the-operator-fight-snapshot).
Source descriptions, references, excerpts, candidates and model replies are untrusted
data; they cannot override validation, claims, gates, budgets or authorize actions.

## Search

Exact lookup answers a named CVE. BM25 searches descriptions, vendors/products and CWE IDs;
normalization removes stopwords and `cve`/`cves`. Individual word matches do not assess relevance. Reciprocal-rank fusion
puts exact IDs first, direct lexical/semantic hits next, graph-only neighbours last,
with deterministic CVE-ID tie-breaking. Filters add no relevance score.
Graph expansion follows shared CWE, vendor, product, CPE or purl attributes; it is
association expansion. Imported stores have no bound semantic collection: requests
report `collection_not_bound`. This repository builds no semantic collection.
NVD imports contain no purls; unsupported purl filters fail explicitly, never as empty success.

### Product vulnerabilities

CLI `product`, REST `POST /api/v2/product` and MCP `query_product_vulnerabilities`
require vendor or product; version, limit and cursor are optional. Names compare
exactly by Unicode casefold, using unescaped stored CPE component names, preserving
underscores, punctuation and whitespace. Both supplied names must match the same
implicated entry (`status != unaffected`); product-only queries include all vendors.
Only records without implicated products supplement field matches using consecutive
description-token phrases (`oai-cn5g-amf` becomes `oai cn5g amf`). Both names must occur
when supplied. Product mentions lacking the requested vendor are excluded and counted
in `description_mentions_vendor_unconfirmed`; returned mentions still cannot confirm
ownership. Each CVE appears once; `basis.kind` distinguishes field evidence and mentions.
`matched_products` and `total_available` cover all matching stored CVEs across pages,
without asserting corpus completeness. Each page carries its own records' anchors.

With a version, grouping is `hit`, `unknown`, `no_hit`; within groups, field evidence
precedes mentions, newest publication first (missing dates last), then ascending CVE ID.
Pages default to 10, maximum 20; repeat vendor, product, version and limit with
`next_cursor` until null. There is no relevance score. Keep the corpus fixed during
traversal. Invalid/mismatched/out-of-range cursors fail (CLI 2, REST 422, MCP failure);
wrong types fail validation. CLI exits 0 for records, 1 for empty, without a sufficiency claim.

### NVD version facts and affectedness

Product version notes and recognized investigation versions annotate retained NVD
conditions: `hit` means a condition matched, `no_hit` never means unaffected, and
`unknown` covers missing conditions, uncomparable versions or description-only evidence.
Version does not filter CVEs or become lexical text for a recognized product version.
Dotted numeric segments compare numerically, ignoring trailing zeroes; non-digit
segments are uncomparable except trimmed exact-condition string equality.
Full configuration/environment trees and non-vulnerable CPE conditions are not retained
or evaluated. NVD may omit product/version information. Notes never change evidence
needs, stopping or applicability. Affectedness always returns `unknown` /
`blocked_unverified` (CLI 1); a missing match never establishes safety.

## Topics and protocol context

Cards supply terminology, templates, relevance rules, exclusions and references.
Bundled GTP-family and 5G-AKA cards are `pending_review`, emit warnings and cannot
establish `found` or `sufficient`. Otherwise-completed runs with their matches are
`partial` / `needs_unmet`; budget/source failures can take precedence. Aliases identify
a topic, without establishing every record's relevance; shared authentication or
network-function names alone do not establish protocol equivalence. GTP is family-wide:
a GTP-U question can return GTP-C records. Its six templates each consume a backend call.
FiGHT techniques stay in `protocol_context`, separate from implementation CVEs.
Topic calls search FiGHT only within scope. Unresolved free text can search permitted
original terms directly; named CVEs, reported exclusions or individually resolved
topic terms block that path. Public MCP `search_fight` is a separate tool.
FiGHT uses phrase BM25/technique-ID ties; `protocol_context_truncated` counts omitted matches.
Only registry-reported exclusions are stripped or block retrieval. Unicode format
characters can change exclusion coverage; registry and CVE normalization can differ
on casefold/combining sequences. Exclusion coverage is not an end-to-end guarantee.

## Bounded investigation

The controller interprets, plans, retrieves, assesses, optionally refines once, then
validates. It looks up named IDs, uses resolved topic cards or searches permitted
question words. Mixed free text also searches FiGHT where allowed; protocol-only
free text uses FiGHT alone. Refinement cannot invent IDs and uses untried topics or
still-unsearched permitted terms for open needs.
Ceilings are two rounds, eight backend calls, four sources, 20 results per call,
30 seconds and 200,000 admitted context bytes. Callers can lower them. Template fan-out
and FiGHT calls are charged; failures receive no refund.
Oversized responses admit the longest ranked prefix of whole results and anchors
that fits, interleaving topic sections by rank. `evidence_prefix_omitted` counts
omissions; if no first result fits, `evidence_discarded` marks the discarded step.
Prefix admission alone is not a budget breach. Context bytes do not cap the serialized
answer; claims, anchors and trajectory add size, and transport response limits apply.
`result_limit_reached` means more matches or a full channel limit, without an exact
remaining count or a claim of lost relevance. `answer_truncated` counts known adopted
results omitted from assembly. `term_not_indexed` identifies unmatched search terms;
other terms can still return candidates without satisfying the need.
Deadlines abandon late results, without killing Python workers; they retain resources
and in-flight slots until returning. Interpreter-lock contention can delay deadline handling.

### Named-product step and merge order

Implementation/mixed free text can recognize one whole served vendor/product phrase.
Vendor phrases win, longer contained names win, ambiguous/excluded collisions remain
lexical, and product names must identify one vendor. Recognized dotted versions leave
lexical text; unrelated numbers remain. No external resolver supplies identities.
Round 1 adds one first-page product query only if the base call budget leaves room,
reserving mixed-scope FiGHT where needed. Exact-ID, topic and protocol-only plans do
not gain it. All budgets apply; investigation filters run after the page cap, so
later matches can be missed. This step grants no need or affectedness verdict.
CVEs deduplicate while retaining sightings. Base order: named exact lookups, relevance
tier, product-name support when a product step was admitted, non-product before
product-only retrieval, first step, tool rank, CVE ID. Product-name support accepts
exact implicated names or whole description phrases without requiring CPE-less records
or confirming ownership. Component relevance is unassessed; matching lexical candidates
retain order. Optional model labels group this order before the cap.

### Needs and stopping

Named IDs each create a named-CVE need. Text adds implementation/protocol needs by
scope; ordinary prose around a named ID is not another target, but a resolved topic
can be. Explicit product context/recognized versions add affectedness needs outside
protocol-only scope; natural-language recognition is limited.
Needs can be `found`, `matches_unassessed`, `not_found`, `not_evaluated`,
`source_unavailable` or `unsupported`. No adopted step means `not_evaluated`.
Words and pending cards can return candidates without assessing the question; absent
terms can leave `not_found` alongside candidates. Only exact-ID correspondence or a
reviewed topic mapping can establish `found`. All needs must be found for `sufficient`,
and execution/budget/source conditions still apply. A later redundant step's budget
failure can determine the outcome despite earlier evidence. Review authority and
card-content review are separate; even reviewed mappings do not prove completeness.

### Where the model participates

REST/MCP use deterministic policy without semantic retrieval. CLI investigation and
evaluation can opt into a model. Named-ID/topic plans are gated for allowed vocabulary,
scope, IDs, repetition, baseline sources and budgets; rejected/unavailable proposals
fall back to policy only when it fits. Free-text round 1 is policy-planned:
`model_not_consulted` describes planning, without ruling out an assessor call.
A configured assessor labels free-text CVEs `relevant`, `not_relevant` or `cannot_tell`
and may propose one gap/follow-up. Terms must come from the question or admitted
candidates' vendor/product/CPE names, never store-wide names. Shared budgets and gates
apply. Labels group relevant, cannot tell, not relevant, unassessed before the answer
cap (20 or lower); they never delete by label, change needs or grant sufficiency.
New candidates can receive one further assessment within two rounds and the shared
deadline; failures preserve first-round evidence.

## Weakness associations

Single-CVE lookup attaches derived CVE → CWE → CAPEC → ATT&CK paths with source
versions/input identities and NVD evidence. Direct links, CAPEC-parent inheritance
and CWE-parent inference are labelled separately. CWE inheritance uses nearest linked
ancestors in view 1000 through `ChildOf`, preferring Primary parents; any direct
CWE link prevents it. CAPEC inheritance follows explicit `ChildOf`; missing/deprecated
CAPECs do not bridge chains and deprecated/revoked ATT&CK objects supply no techniques.
Missing parents cannot bridge CWE chains; encountered cycles refuse builds.
Paths without a usable ATT&CK mapping end at CAPEC with `no_attack_mapping`; missing
links remain explicit. Absence means absent from this snapshot, without establishing
absence from the full catalogue, exploitation or possible techniques. NVD noinfo/Other
means no specific CWE. No keyword or model inference fills missing links.
The shared cap is 20 paths per CVE with exact omitted count. Order is direct full,
CAPEC-inherited full, CWE-inherited full, then CAPEC terminals, then lexicographic
IDs/chains; it is not importance ranking. Every served path validates against its snapshot.
Search, topic and investigation omit paths, including excluded candidates: they affect
no retrieval, ranking, context budget, model input, needs, FiGHT context or affectedness.
Use lookup for paths. These associations are neither exploitation evidence nor attack
paths. See [mapping operations](runbook.md#weakness-association-mapping).

## Verification and compatibility

Verification binds source content, validates records, re-derives decisions and replays
the controller with recorded replies. Recomputed digests alone prove no authenticity;
recorded timings attest no real time. API/schema, store, policy and evaluation formats
have separate compatibility purposes. Pre-release version strings alone do not ensure
replay: keep the original program, settings, snapshots and evidence sets.

## Interfaces

CLI, REST and MCP share services; [REST setup](runbook.md#rest-and-mcp) covers routes/authentication.
By default MCP has ten bounded read-only tools: `get_knowledge_capabilities`,
`resolve_telecom_concept`, `lookup_cve`, `search_vulnerabilities`,
`query_product_vulnerabilities`, `search_fight`, `check_affectedness`, `get_evidence`,
`investigate_telecom_topic` and `wait_for_data`. `verify_evidence_set` is available through
CLI/REST only.
With `--workspace`, MCP has 18 tools and writes to the workspace. It adds
`start_investigation`, `triage_product`, `get_investigation`, `read_call`, `add_findings`,
`check_investigation`, `render_report` and `list_investigations`. The nine knowledge tools
take an optional `session_id` that records the call in that investigation;
`start_investigation` and `triage_product` create investigations, `add_findings` writes
findings and `render_report` writes report files.
