# M4 bounded investigation

Schema version `2.0.0-dev.11`. Adds an investigation service that interprets a
question, chooses allowlisted tools, observes what they return, refines at most
once, and returns a validated `KnowledgeEvidenceSet` with a replayable
trajectory. The deterministic policy `m7b.4` is the production planner; a model
planner is optional and untrusted. Design rationale: ADR 0002.

## Contracts

| Contract | Module | Schema |
|---|---|---|
| `InvestigationRequest(query, scope, filters, semantic, budget)` | `domain/investigation.py` | `investigation_request.schema.json` |
| `InvestigationBudget`, `BudgetUsage`, `BudgetBreach` | `domain/budget.py` | inside the request and the evidence set |
| `QueryPlan(steps: ToolCall[1..8])`, the only shape a model may emit | `domain/planning.py` | `query_plan.schema.json` |
| `KnowledgeEvidenceSet` | `domain/investigation.py` | `knowledge_evidence_set.schema.json` |
| `ModelPort.propose_plan(planning_input, timeout_seconds)` | `ports/planning.py` | none until a network adapter exists |

- The scope has no default and no alias: `protocol_context_only`,
  `implementation_only` or `mixed`.
- `filters` is a `SearchFilters` that constrains every CVE tool call, including
  each template search a `topic_context` call fans out to (FiGHT is never
  filtered). Its vendors, products and purls are the product context, with each
  product version the query asks affectedness of.
- A tool call is one of `cve_exact_lookup(cve_ids)`, `cve_search(query)`,
  `topic_context(topic_id)` or `fight_direct_search()`, which takes no arguments:
  it searches MITRE FiGHT with the interpretation's `fight_terms`, so no planner
  chooses its words. Scope, filters, limits, the semantic flag, URLs,
  claims and evidence are not part of a call, so a closed model rejects a plan
  that tries to carry them.
- The evidence set keeps implementation candidates (CVEs), excluded candidates
  (CVEs kept out of a `protocol_context_only` answer, with the reason) and
  protocol threat context (FiGHT) in separate sections. Each answer item has
  exactly one templated claim: `cve:<id>` ("… is a CVE record of an implementation
  vulnerability; it does not establish a protocol-design flaw.") or
  `fight:<technique>` ("MITRE FiGHT lists … as … protocol threat context; it is
  not formal proof."). Claims carry no source prose and no planner text.
- `product_applicability` has one entry per named vendor, product and purl, then one
  `product_version` entry per product version the query asks affectedness of, always
  `unknown`: no verified affectedness source is available (ADR 0003), and neither a
  CVE match nor threat context establishes affectedness. Its `basis` is the one
  sentence `ApplicabilityBasis` holds, which says exactly that.
- `investigation_id` is `inv:` plus 24 hex characters of the hash of the schema
  version and the request, so equal requests share an ID. `result_sha256` covers
  everything except itself and `timings`, so the start time and the speed of a run
  never change it.
- `source_capabilities` describes each source and optional component of the
  deployment, once each and in this order: `cve_search` (`available`, with the
  fixture manifest hash as its version), `mitre_fight` (`available` with the
  pinned snapshot version and coverage, or `unavailable`), `affectedness`
  (`unavailable`; ADR 0003), `semantic_channel` (`available` once its adapter loads,
  `unavailable` with `SemanticUnavailableDetail` when an enabled adapter cannot load, else
  `not_configured`; never a version; ADR 0004 §1) and `model_planner`
  (`available` with `format_planner_version(identity)`, the model's name and the
  identity's hash, as its version; for the deterministic policy
  `not_configured`, or `unavailable` when a configured model planner cannot plan,
  ADR 0004 §6). An
  `unavailable` capability carries a `detail` saying why, and no other does. The
  composition root computes the four source entries once when it builds the
  deployment, reading `affectedness` from the Trustify port (ADR 0003); the service
  appends the `model_planner` entry from the planner it is built with, so the two can
  never disagree. Every set reports exactly those (see
  Validation).
- The published schemas (ADR 0002, 14) state these rules, so a payload that breaks
  one fails both the schema and the server:
  - `schema_version` is a `const` in the evidence-set, search-response and
    topic-context-response schemas, and parsing and each response's validator
    reject any other version;
  - the planner identity is `DeterministicPlannerIdentity` or
    `ModelPlannerIdentity`, discriminated by `kind`;
  - the cross-field rules of `ModelReply`, `ToolStep`, `EvidenceAnchor`,
    `VersionRange`, `SourceOutcome` and `TopicReview`;
  - every timestamp and date has a `pattern` admitting only values the server parses
    (real calendar dates from year 0001, times to 23:59:59, offsets to 23:59),
    because Draft 2020-12 treats `format` as an annotation;
  - every published pattern ends exactly (`$(?!\n)`), so a Python validator, whose
    `$` also matches before a final newline, refuses `CVE-2024-0001\n` as the server
    does;
  - the evidence-set validator's single-payload rules: the capability shape
    (`prefixItems` in `CAPABILITY_SUBJECTS` order, each subject's states, version,
    coverage and an `unavailable` capability's detail); the planner kind fixing each round's outcomes and which planner
    may plan a step; each round recording a reply and its hash exactly when the
    model replied, a rejected reply's rejections with the outcome's fixed code
    first, and no rejection or only policy codes elsewhere; the statuses each stop
    reason allows (`STATUSES_BY_STOP_REASON`); and the requested and applied scope
    equal to the request's.

  `ToolStep`, `VersionRange`, `SourceOutcome`, `SourceCapability`, `RoundRecord`,
  `Trajectory` and `KnowledgeEvidenceSet` generate their clauses from the
  constants the code checks; `ModelReply`, `EvidenceAnchor` and `TopicReview` state
  their two-way rule by hand beside the validator. Every other validator rule
  compares more than one part of the set with another, or the set with something
  outside it, and stays server-side, named in its field's description where a
  field carries it: recomputed hashes and IDs, the evidence catalog, the
  deployment's capabilities, the counts, transitions and coverage the steps imply,
  and the trajectory's re-derivation. `tests/contract/test_response_schema_agreement.py`
  validates genuine payloads against the exported schemas, and requires each
  payload that breaks one of the listed rules to fail both the schema and the
  server.

## Interpretation

`interpret_request` normalizes the query, extracts every CVE ID it names (an ID's
parts may be joined by any dash, and the ID ends at a visible character that cannot
continue it, so one written against CJK or Thai text, as in `CVE-2021-44228漏洞`, is
found, while one run together with another digit or Latin letter, as in
`CVE-2021-44228٤`, `CVE-2021-44228²` or `xCVE-2021-44228`, or with an invisible
character inside it, as in `CVE-2021-4422`+ZWSP+`8`, is a malformed token that is
neither looked up nor searched; so is text read as an ID but not written as one, such
as `CVE 2021 44228`, `CVE.2021.44228`, `CVE ID 2021-44228`, `CVE-2021-4422 8`,
Arabic-Indic digits or a Cyrillic Es for the C), resolves the topic and computes the
search terms: the query's search terms (`list_query_terms` in `domain/text.py`: its
tokens once its CVE-ID tokens are removed, without stopwords, without the words of
any ID likeness they form once stopwords and punctuation are left out, and without
the low-signal words `cve` and `cves`, repeated until none is left) without the tokens
of any excluded term, each once, read again for CVE-ID tokens once joined until none
is left. So `CVE of 2021-44228` searches nothing, `ausf crash cve in 2021 and 2022`
and `ausf crash nvdcve cves 2021 2022` search `ausf crash`, and `crash nvdcve EPS AKA
2021 2022` searches `crash`. The low-signal words name the kind of record every result
is, so `cve ausf crash` searches `ausf crash`, `CVE 2022 log4j` searches `2022 log4j`,
`CVE-9999-0003 cve` looks the ID up and searches nothing, and `cve` or `CVEs` alone is
`unsearchable`; `nvdcve` and other words that merely contain `cve` stay. Stripping
excluded tokens keeps an ambiguous alias out of free text: `EPS AKA crash` searches
`crash`, `aka bug in amf` searches `bug amf`, and `aka` searches nothing.
An ID longer than 32 characters is one the CVE program never assigns: it is neither
looked up nor searched.

`fight_block` says why the query's words may not go to FiGHT without a reviewed
topic (`find_fight_block` in `application/investigation_policy.py`), checked in
order: `topic_resolved` (the card's terms reach FiGHT through `topic_context`),
`excluded_term` (an excluded term is named; its words are never stripped and sent
around it), `cve_id_named` (a CVE ID the interpretation keeps is named), and
`term_reads_as_topic` (one search term the registry reads alone as a topic or an
excluded term). An ASCII run is a registry word of its own beside a non-ASCII letter
(`topics/normalization.py`), so `5Géaka threats` names the excluded `aka`, searches
`5g threats` and is blocked `excluded_term`; `term_reads_as_topic` catches a search term
that is not a registry word, which double normalization can produce
(`na\u00df\u0301 threats` searches `nas`; ADR 0002 §8), and guards FiGHT only. Its `subject` is the first matched topic
ID, excluded term or CVE ID, or that term.
`fight_terms` are every search term when there is no block and none otherwise, never
a subset (`list_fight_terms`, the one source of the words a direct FiGHT search
sends).

Intent, first match wins: `exact_id` (a CVE ID), `topic` (a topic resolved),
`free_text` (search terms remain), `excluded_terms_only`, `unsearchable`.

Some requests stop before any call. One exact lookup carries every named ID, and its
backend limit is the request's `max_results_per_call`, so a query naming more IDs
than one lookup can return is blocked rather than cut short:

| Condition | Stop | Basis |
|---|---|---|
| `protocol_context_only` with a CVE ID | `policy_blocked` | `cve_ids_outside_scope` |
| `protocol_context_only` with any active filter | `policy_blocked` | `filters_outside_scope` |
| more CVE IDs than `max_results_per_call` (at most 20) | `policy_blocked` | `cve_ids_over_lookup_cap` |
| intent `excluded_terms_only` | `no_evidence` | `excluded_terms_only` |
| intent `unsearchable` | `no_evidence` | `no_searchable_terms` |
| `protocol_context_only` with intent `free_text` and no `fight_terms` | `no_evidence` | `protocol_scope_needs_topic` |

## Policy m7b.4

Round 1 plans one call, or two for `mixed` free text whose words may go to FiGHT:

| Intent | `implementation_only` | `mixed` | `protocol_context_only` |
|---|---|---|---|
| `exact_id` | `cve_exact_lookup(ids)` | `cve_exact_lookup(ids)` | stopped |
| `topic` | `topic_context(topic)`, CVE searches only | `topic_context(topic)` | `topic_context(topic)` |
| `free_text` with `fight_terms` | `cve_search(terms)` | `cve_search(terms)`, then `fight_direct_search` | `fight_direct_search` |
| `free_text` without `fight_terms` | `cve_search(terms)` | `cve_search(terms)` | stopped |

An exact ID is never expanded into a topic or a semantic search. A resolved topic is
explored with its reviewed card in every scope: the card's mapping is what can meet the
need (see Evidence needs below), and a search of the question's own words cannot. Under
`implementation_only` the topic call fans out to the card's CVE searches only, never to
FiGHT, so it costs 4 tool calls for 5G-AKA against 1 for a literal search; a spelled-out
search of a common phrase can also return a response over the byte cap, which the topic's
capped template searches avoid. A direct FiGHT search has reason `query_terms_fight`. Both needs of a `mixed` question are known before planning and
neither search depends on the other's results, so both run in round 1 under one
budget pre-check. The policy plans free text without a configured model (see Model
planner). Under `max_sources: 1` that plan consults 2 sources, and under
`max_tool_calls: 1` it costs 2: the gate rejects it (`over_source_budget` or
`over_tool_call_budget`) and the run stops `budget_exhausted` (`plan_over_budget`) with
no answer. A `mixed` topic query, whose `topic_context` consults both sources, stops the
same way under `max_sources: 1`, where no model is consulted either; under
`max_tool_calls: 1` its model is consulted, but any round-1 plan it proposes must reach
both sources, so the gate rejects it too. An `implementation_only` topic query under a
`max_tool_calls` below its card's template count (1 to 3 for 5G-AKA) has a policy plan
over budget: without a model it stops `budget_exhausted` (`plan_over_budget`) with no
answer, and no literal search stands in. A configured model is still consulted, since a
tool-call overage does not stop that; a literal search it plans runs, but its matches
leave the need open (`matches_unassessed`), so the run ends on the round cap or the
budget, never `sufficient`.

Refinement, at most one rule, for a need round 1 left open (evidence needs:
[`m7b-b-evidence-needs.md`](m7b-b-evidence-needs.md)):

- **R1, unknown IDs.** Round 1 was an exact lookup, every requested ID drew an
  `unknown_cve_id` warning (an ID excluded by the filters is known, so it never
  counts), and a resolved topic leaves an implementation or protocol need open.
  Explore the topic (`topic_after_unknown_ids`). An unknown ID beside plain text
  needs only that CVE, which no search can meet, so nothing is refined.
- **R2, topic not explored.** A topic resolved, its call has not run, and the
  implementation or protocol need is open. Explore the topic
  (`topic_after_literal_miss` when the intent is `topic` and round 1's literal search did
  not meet the need, `topic_for_open_need` otherwise). The policy's own round 1 explores
  a resolved topic, so a literal search of a topic question is always a model's plan;
  its matches leave the need `matches_unassessed`, so R2 follows it whether or not it
  found anything. R2 is the policy's refinement: with a model configured, round 2
  consults the model, whose plan may replace the topic call. The run still cannot end
  `sufficient` on word matches.
- **R3, terms not searched.** The implementation need is open, round 1's admitted
  searches did not send every search term, and no unexplained term is unindexed.
  Search all of them (`query_terms_for_open_need`).

No rule plans `fight_direct_search`: round 1 plans it wherever it may run, and a
run holds at most one. No other call serves a protocol need it left open, so unless
R3 serves an open implementation need, the run stops `no_refinement_available`.

**Evidence needs.** A need is `found` only through an exact correspondence or a reviewed
mapping: an exact lookup that returned the named CVE, or the topic call of a resolved,
reviewed topic that returned evidence. Matches of a search on the question's own words
(`cve_search`, `fight_direct_search`) leave it `matches_unassessed`: matches were found
and their relevance was not assessed, which says nothing about whether relevant evidence
exists. The current version does not judge such matches sufficient automatically. The
outcome is open, so R2 still explores a resolved topic after it; for free text no rule
applies (R3 needs an unsent term, and no rule plans FiGHT), so the run lists its matches
and stops `needs_unmet` (`partial`, basis `no_refinement_available`) without a second
search. A topic's `found` is no proof of sufficiency either: the card's mapping can list
CVEs that do not answer the question, so a topic run can still stop `sufficient` wrongly
([`m7b-b-evidence-needs.md`](m7b-b-evidence-needs.md)).

The policy never invents an ID or a term, and `plan_refinement` drops a
refinement whose call round 1 already ran (a model's round-1 plan may have run it).

When a topic resolved, every CVE a free-text search step returns is kept only if
`assess_relevance` relates its record to the topic; the rest are dropped and
counted in an `unrelated_candidates_dropped` warning. A CVE the caller named by ID
is never dropped: an exact-lookup candidate keeps its relevance when it relates to
the topic and is kept with `relevance: null` otherwise, so `CVE-9999-0007 5gaka`
answers CVE-9999-0007. An unassessed candidate sorts with the first relevance tier.
The merge (`named_then_tier_then_step_then_tool_rank`) puts every candidate an exact
lookup found ahead of the rest before it cuts the answer to `max_results_per_call`.
A run names at most that many IDs, so the cut never reaches a named CVE, whatever
order a model's plan lists its steps in.

## State machine

`application/investigate.py` runs `interpret → plan → retrieve → assess →
(refine → retrieve → assess) → validate → return`. There is no loop over rounds:
round 2 is reachable only through the single `assess → refine` edge. Each stop below
is decided by a pure function of the recorded observations in
`application/investigation_decisions.py` (`decide_assessment`,
`decide_refinement_stop`, `decide_rejected_plan_stop`, `decide_open_stop`) over
the needs `judge_needs` gives, and the gate's context for a plan is built from the
steps issued before it (`build_plan_context` in `application/plan_gate.py`); the
decision-path audit (below) calls the same functions.

| From | Observation | To | Basis | Stop |
|---|---|---|---|---|
| interpret | an interpretation stop | validate | per the table above | per the table above |
| interpret | otherwise | plan | `query_interpreted` | – |
| plan | the policy's plan is over budget | validate | `plan_over_budget` | `budget_exhausted` |
| plan | the deadline passed before planning, the model had not replied by it, or the model replied after it | validate | `budget_breached` | `budget_exhausted` |
| plan | the policy's own plan fails another gate check (a defect guard) | validate | `plan_rejected_by_policy` | `policy_blocked` |
| plan | a plan was accepted | retrieve | `plan_accepted` | – |
| retrieve | the steps ran, or one stopped the round (failed, timed out, late or unable to fit its first result) | assess | `steps_finished` | – |
| assess | 1. a step's evidence failed integrity | validate | `evidence_invalid` | `invalid_evidence` |
| assess | 2. a cap was breached | validate | `budget_breached` | `budget_exhausted` |
| assess | 3. an answer source returned neither `ok` nor `no_match` | validate | `answer_source_failed` | `source_unavailable` |
| assess | 4. every need found | validate | `answer_found` | `sufficient` |
| assess | 5. an answer whose only unmet needs are affectedness | validate | `affectedness_unavailable` | `source_unavailable` |
| assess | 6. a need open after round 1 | refine | `needs_open` | – |
| assess | 7. a need open after round 2 | validate | `needs_open_after_refinement` | `needs_unmet` with an answer; else `no_evidence`, or `source_unavailable` when affectedness is needed |
| refine | no refinement plan | validate | `no_refinement_available` | as rule 7 |
| refine | `max_rounds` is 1 and the policy would refine | validate | `round_cap_reached` | `budget_exhausted` |
| refine | the deadline passed before planning the refinement | validate | `budget_breached` | `budget_exhausted` |
| refine | the plan is over budget | validate | `plan_over_budget` | `budget_exhausted` |
| refine | a plan was accepted | retrieve | `plan_accepted` | – |
| validate | the sealed set passed validation and the decision-path audit | return | `answer_validated` | – |

Affectedness is needed when the request names a product, by filter or as a product
version the query asks affectedness of, outside `protocol_context_only`. Round 2 is
planned, and a configured model consulted for it, only when the policy has a
refinement. Rule 3 makes an unavailable source an honest typed stop
without retrying it: a failed call's key is already issued and is never reissued.

## Model planner

Optional and off by default: `build_investigation_service(..., planner_setup=...)`
defaults to `DeterministicPlanning()`, and `discover_planner_setup` builds the planner
the settings configure (ADR 0004).
A configured model plans only a question that names a CVE ID the policy keeps or
resolves a reviewed topic (`is_model_consultable` in
`application/investigation_decisions.py`). Free text (intent `free_text`: no kept CVE ID,
no resolved topic) is planned by the policy in every scope, with the question's search
terms as its baseline; that is product policy, not a completeness or sufficiency
guarantee and not a safety rule. A round 1 whose policy plan is over the source budget
is not given to the model either (see the table below).
For each round the model plans, the core builds a `PlanningInput`: the caller's query as a quoted
JSON string, the scope, intent, CVE IDs, topic ID, version and review status, the
allowed tools with their costs (never `fight_direct_search`: only free text has
`fight_terms`), the sorted search
vocabulary (the query's terms
plus the resolved card's terms), the remaining tool calls and sources, the issued
calls, and per executed step only its tool, status, answer count and warning
codes. It never contains source records or their text.

The port returns `ModelReply`: raw plan text, or a typed failure. The core parses
the text into a `QueryPlan` and passes it through `application/plan_gate.py`, the
same gate as the policy's plan. Per call, in order: `tool_not_permitted_by_scope`,
`invented_cve_id`, `cve_id_in_search_text`, `term_outside_vocabulary`,
`topic_not_resolved` or `fight_direct_search_blocked` (a direct FiGHT search the
interpretation gives no `fight_terms`; `fight_block` says why), `repeated_call`.
A direct FiGHT search is not permitted under `implementation_only`, and its call key
is constant, so a run holds at most one. Over the whole plan: `missing_baseline_source`
(a round-1 plan skipping a source the policy's round-1 plan consults),
`missing_named_cve_id`, `over_tool_call_budget`, `over_source_budget`. Any rejection
rejects the whole plan.

`missing_named_cve_id` rejects a plan when a CVE ID the caller named is carried
neither by an exact lookup the run already issued nor by one of the plan's exact
lookups that passed the per-call checks. A search never stands in for the lookup
(`CVE-9999-0003 zzqx` answered by `cve_search("zzqx")` is rejected), and the plan
may split the IDs over several lookups as long as their union covers every named
one. Every named ID is therefore looked up in round 1: a model plan that omits one
falls back to the policy's plan, which looks every named ID up in one call that
fits any budget (one tool call, one source, and no more IDs than
`max_results_per_call`, or the run was stopped at interpretation), so a plan that covers the IDs only by
overrunning the budget is rejected as `over_tool_call_budget` and falls back the
same way. Round 2 runs only after round 1 issued its whole plan, so a round-2 plan
owes no lookup and only adds calls. A round 1 stopped before its lookup ran ends
`budget_exhausted` or `invalid_evidence`, never with an answer or `no_evidence`. The
policy's plan never fails this check, so a round that records it under a
`deterministic` outcome fails validation. Under `protocol_context_only` a named ID
stops the run at interpretation (`policy_blocked`), before any planner is consulted.

The vocabulary check reads search terms (`list_query_terms`), so an accepted call
runs and is recorded in its canonical form: a search keeps only its search terms,
each once and in order (text in another script, punctuation, stopwords and the
low-signal words `cve` and `cves` never reach a channel or the trajectory), and an
exact lookup each ID once. A search with no search term, such as `cve` alone or
`cve of 2021 44228`, is rejected `term_outside_vocabulary`; `cve ausf` passes and runs
as `ausf`. A call key (`compute_call_key` in `domain/planning.py`) hashes what the
backend query depends on, the set of IDs or the set of search terms
(`list_query_terms`), so a call that only reorders or repeats terms or IDs, or adds a
stopword or low-signal word, is a `repeated_call`. The repeat check keys the canonical
call, the one that would run: NFKC can lengthen a search past `MAX_QUERY_CHARS` (`ﬃ`
becomes `ffi`), and the canonical search drops a token that would push it over, so
two searches that differ only in such a token run as one query and the second is a
`repeated_call`.

| Reply | Round outcome | What runs |
|---|---|---|
| a plan passing the gate | `model_accepted` | the model's calls, reason `model_proposal` |
| a malformed or rejected plan | `model_rejected`, with a `model_plan_rejected` warning | the policy's plan; the round records the model plan's rejections, then any of the policy's plan |
| a failed reply | `model_unavailable` | the policy's plan |
| no reply, or a reply landing, when the planner's third of the run ends, the run still in time | `model_unavailable`, with the recorded reply `PLANNER_CAP_REPLY` (`TIMED_OUT`) | the policy's plan |
| no reply by the deadline | `model_timed_out`, rejection `planner_timed_out`, no reply | nothing; `budget_exhausted` |
| any reply finishing after the deadline | `model_reply_after_deadline`, rejection `reply_after_deadline`; the reply is recorded but never parsed | nothing; `budget_exhausted` |
| not called: the deadline had passed before the round was planned | `model_skipped_at_deadline`, no rejection, no reply | nothing; `budget_exhausted` |
| not called: the question is free text, and the policy plans it | `model_not_consulted`, no reply | the policy's plan, reasons `query_terms` and `query_terms_fight`; or, when the gate rejects that plan (`mixed` free text under `max_tool_calls: 1`), its rejections and nothing (`budget_exhausted`, `plan_over_budget`) |
| not called: the policy's own round-1 plan is over the source budget, and a round-1 model plan must consult the policy's sources, so none could pass the gate | `model_not_consulted`, the policy plan's rejections, no reply | nothing; `budget_exhausted` (`plan_over_budget`) |

Without a model planner every round's outcome is `deterministic`, including a round
the deadline stopped before planning; with one, no round is `deterministic`. Once
the deadline has passed the planner is not called, and the round stops with
`budget_breached`; the deadline is checked first, so a free-text round whose deadline
passed before planning records `model_skipped_at_deadline`, not `model_not_consulted`.
A `model_not_consulted` round is always round 1: after a free-text round 1 the policy
planned, no refinement rule fires (R1 and R2 need a topic, and R3 needs a term the
admitted searches left unsent). The planner call runs under the call runner (see Budgets), so a
planner that never replies is abandoned at the deadline. The planner's identity is
built once, by discovery from the settings and the installed entry point, before the
service is built (ADR 0004 §5); it gives both the `model_planner` capability's version
and every trajectory's planner, and the port has no method but `propose_plan`. A model
planner's identity (`ModelPlannerIdentity`) names its model, adapter, adapter version
and endpoint fingerprint and no policy version, and a
deterministic planner's (`DeterministicPlannerIdentity`) names the policy version,
`m7b.4`, and no model; neither shape has the other's field, so a set handed back with
one fails to parse. The service has a model to consult exactly when a port is
configured, so `ModelPlanning` pairs the port with a `ModelPlannerIdentity` and
never with the policy's. The planner chooses
which allowlisted calls run; the records, claims, evidence and applicability are
always the tools' and the templates' output.

Each round records the model's reply as the port returned it (`RoundRecord.model_reply`:
status, plan text within `ModelReply`'s cap of 16,384 characters, or a
`ModelReplyFailureDetail` sentence) beside `model_reply_sha256`, its hash from
`compute_model_reply_sha256`. Every outcome with a reply records it, a typed
failure (`model_unavailable`) and a late reply (`model_reply_after_deadline`)
included; only `deterministic`, `model_timed_out`, `model_skipped_at_deadline` and
`model_not_consulted` have none. The reply is data: it is never logged, never quoted in a warning or a
violation, and its text reaches the set only in that field, while the steps and the
accepted plan carry the canonical calls. The decision-path audit parses and gates
the recorded reply again (see Decision-path audit). The controller and the audit
choose a round's plan with the same function, `choose_round_plan` in
`application/investigation_decisions.py`, and stop a round at the deadline with
`plan_deadline_round`.

## Budgets

| Cap | Server maximum | Enforcement |
|---|---|---|
| `max_rounds` | 2 | Code shape plus the refine edge; at 1, a justified refinement ends `budget_exhausted` (breach `rounds`). |
| `max_tool_calls` | 8 | Backend queries. A CVE tool and `fight_direct_search` cost 1; `topic_context` costs one per query template plus one FiGHT search unless the scope is `implementation_only` (5G-AKA: 5, or 4 under `implementation_only`). The gate checks the cost before the plan runs; each call is charged before it runs and never refunded, and each step records the backend requests its charge counts. Planner calls are counted separately (`planner_calls`). |
| `max_sources` | 4 | The union of consulted sources, checked by the gate. |
| `max_results_per_call` | 20 | The `limit` of every backend request: each CVE tool's search, each template search a `topic_context` call fans out to (`TopicContextRequest.max_results_per_search`), and its FiGHT search, or the one FiGHT search of `fight_direct_search`. Also the cut of each answer section. |
| `max_wall_time_seconds` | 30 | A ceiling on the run, measured on an injected monotonic clock. It is checked before every planner and tool call, and every such call runs under the call runner, which gives control back when the remaining time reaches zero whether or not the call has returned; see the limits below. |
| `max_context_bytes` | 200 000 | The canonical JSON size of each admitted tool response, including metadata and anchors. An oversized response admits its longest whole-result prefix; if the first result cannot fit, it is discarded and the run stops. |

A caller may lower each cap and never raise it; a value above a cap is rejected,
not clamped. An oversized response is admitted as `admitted_prefix` when at least its
first whole result fits. CVE searches and lookups take candidates in their ranked order;
direct FiGHT searches take techniques in their ranked order. Topic calls interleave the
heads of `implementation_candidates`, `protocol_context` and
`excluded_implementation_candidates`, then their second entries, and so on, stopping
at the first entry that does not fit. This gives both answer sections a head before
either receives a tail, with excluded context last at each rank. Every retained entry
keeps its complete record and all referenced anchors. The step charges the canonical
JSON size of this retained response, including metadata. Its compact `prefix_admission`
records `original_result_sha256` (the complete response's sealed digest), per-list kept
and omitted counts, `charged_bytes`, and `next_result_bytes`. The next-result figure is
the canonical size of the prefix extended by the first omitted entry minus the admitted
size, including any added anchors and changed warnings. The set carries no original
response body; its size depends on admitted content and the existing envelope overhead,
not the size of omitted records. A prefix is not a breach. Its `evidence_prefix_omitted` warning names the step and
the exact number of omitted entries. Topic truncation warnings include the entries
omitted by admission; search-limit warnings still describe the original retrieval. `answer_truncated` describes cuts made by answer
assembly and retrieval limits, independently of the context-budget cut.

A late result, or one whose first whole result cannot fit, is recorded with its hash
and admission (`discarded_after_deadline`, `discarded_over_context_budget`), never
admitted, and adds an `evidence_discarded` warning. A call that has not returned when the
remaining time reaches zero is abandoned: its step is recorded as `timed_out`,
charged, with no status, hash, results or bytes, the breach is `wall_time`, the
run stops `budget_exhausted` and the warning is `evidence_discarded`. A response
whose evidence fails validation is recorded as `rejected_invalid_evidence` with
no status or hash, and the run returns no answer at all.

`application/threaded_call_runner.py` (`ThreadedCallRunner`, built per deployment by
the composition root) runs each planner and tool call on a fresh daemon thread and
waits on a queue for at most the remaining seconds, read from the ledger's
injected clock. It reads that clock once before the call starts and again only
when a wait runs out, so the call is reported timed out only when the injected
clock says the deadline has come; a call that returns in time is unaffected, and
an exception it raises is re-raised to the service. A request calls no adapter
method outside the runner: the planner's identity, the FiGHT snapshot pin, the
evidence catalog (built from the FiGHT source's evidence and techniques), the topic
registry and the source capabilities are all read when the service is built, and
interpreting, planning, gating, assessing and sealing work only on those and on the
steps' results. Just before each read of the clock at a deadline check, the service
tells its injected `reach_checkpoint` which point it reached
(`application/deadline_checkpoint.py`: a round's planner or a step, before it starts,
while its call runs, or at its finish). A measured run ignores it
(`ignore_checkpoint`); replay uses it to put a recorded deadline back where it fell.

## Stop reasons and statuses

| Stop reason | Status |
|---|---|
| `sufficient` | `ok` |
| `no_evidence` | `no_match` |
| `source_unavailable` | `partial`, `source_unavailable`, `backend_error` or `incomplete_index`, summarized over the answer sources' outcomes |
| `budget_exhausted` | `partial`, even when no call ran |
| `policy_blocked` | `policy_blocked` |
| `invalid_evidence` | `backend_error` |
| `needs_unmet` | `partial` |

`coverage.source_outcomes` holds one outcome per answer source a step consulted,
plus `affectedness: source_unavailable`, with the `affectedness` capability's detail,
once any step ran when affectedness is required. Once a call has run, a product question therefore never ends `sufficient`
or `no_match`.

## Validation

`domain/investigation_validation.py` runs on every sealed set; a violation is a
controller defect and raises instead of returning. It checks:

- anchors, records, threat context and claims: each claim cites only anchors about
  its own subject, and every anchor's ID derives from all of its other fields, so
  it changes when any provenance field changes;
- every anchor, CVE record and FiGHT technique the set serves against the
  service's evidence catalog (below);
- `schema_version` is the `SCHEMA_VERSION` this code serves; the identity of the
  ID, normalized query and scopes; scope separation and ranks;
- one claim per answer item, equal to its template (subject, scope, assertion
  kind, statement and cited anchors), and evidence exactly as cited;
- every answer ID, and every anchor of the answer, returned by an admitted step;
  every evidence ID a step records held by the catalog, and every answer ID it
  records the subject of one of those anchors;
- each step's observations against its call: a step that got a response records
  one source outcome per source it consulted, in order (a `timed_out` or
  `rejected_invalid_evidence` step records none); once a lookup's exact-ID channel
  ran, it warns `unknown_cve_id` for exactly the IDs it looked up that the catalog
  lacks, in lookup order, and `excluded_by_filters` only for an ID it looked up
  that the catalog holds and it did not return; a `cve_search` step warns
  `term_not_indexed` only for a search term its lexical channel was sent, and a
  `fight_direct_search` step warns `term_not_indexed` (a topic warning) only beside a
  served FiGHT outcome, each term once, for a term of its own FiGHT search that no
  technique the answer lists from it matched (a `topic_context` step never raises
  it); and the
  semantic channel runs in a
  `cve_search` step under a semantic request beside the lexical channel, and in no
  other step;
- relevance assessed for every candidate once a topic resolved, except a CVE
  named by ID; one `unknown` applicability entry and warning per named product;
- the status against the stop reason, a `sufficient` run with every need found and
  a `needs_unmet` run with an answer and an unmet need other than affectedness, and
  `coverage.refinement_applied` true exactly when a round-2 step ran;
- a legal walk of the state machine with at most one refinement, and no step after
  one that was not admitted; each step's call key recomputed from its call with
  the controller's `compute_call_key`, and unique;
- rounds tied to the state machine: round 1 recorded exactly when the run moved
  interpret -> plan, and round 2 only after assess -> refine;
- rounds and steps as one run: rounds numbered 1..n; each round's
  `executed_step_indices` exactly its steps in order; those steps' calls the
  leading entries of its `accepted_plan`, and calls left unrun only when the last
  step was not admitted or the deadline was reached; no call accepted twice across
  the run's plans, no CVE tool accepted under `protocol_context_only` and no
  direct FiGHT search under `implementation_only` (`is_tool_permitted`, the gate's
  own rule); a round with steps has an accepted
  plan; every step's `planned_by` is `model` exactly when its round is
  `model_accepted`, its reason is `model_proposal` exactly when the model planned
  it, and any other reason names the tool and round the policy gives it
  (`POLICY_STEP_TOOL_AND_ROUND`: `query_cve_ids` an exact lookup, `query_terms` a
  search, `reviewed_topic` a topic and `query_terms_fight` a direct FiGHT search in
  round 1; `query_terms_for_open_need` a
  search and `topic_after_unknown_ids`, `topic_after_literal_miss` or
  `topic_for_open_need` a topic in round 2);
- every round outcome one the trajectory's planner kind records; rejections
  exactly when the outcome says a plan was rejected: a `model_unavailable`,
  `model_timed_out` or `model_reply_after_deadline` round records its own code
  first, a `model_rejected` round never starts with one of those codes, a
  `model_accepted` or `model_skipped_at_deadline` round records none, a
  `model_not_consulted` round is round 1, and a `deterministic` or `model_not_consulted`
  round records the policy plan's rejections only when that plan was rejected, nothing
  ran and the run stopped `policy_blocked` or `budget_exhausted`; model-reply codes (`malformed_plan`, the
  three fixed first codes, `missing_baseline_source`, `missing_named_cve_id`) only
  under a rejected model outcome; a `deterministic` round that runs no plan and records
  no rejection reached the deadline, and a `model_not_consulted` round runs the policy's
  plan unless the gate rejected it (a deadline before planning records
  `model_skipped_at_deadline`);
- the model's reply exactly when the model replied (every model outcome but
  `model_timed_out`, `model_skipped_at_deadline` and `model_not_consulted`), with `model_reply_sha256`
  recomputed from it, never trusted, and `budget_used.rounds`,
  `planner_calls`, the number of planner durations in the timings and the number
  of `plan_accepted` transitions counted from the rounds;
- the budget usage against the steps and caps, including each step's finish time
  against the deadline (a `timed_out` or `discarded_after_deadline` step finished
  at or after it, a `discarded_over_context_budget` step before it), the byte cap
  replayed over the steps in order (a step is `discarded_over_context_budget`
  when its response exceeds the remaining `max_context_bytes` and its first whole
  result cannot fit; an `admitted_prefix` step has whole visible records, consistent
  ranks, per-list counts and omission warning, `charged_bytes == context_bytes`, and
  `charged_bytes <= remaining < charged_bytes + next_result_bytes`), one charged tool call per recorded backend request, every
  request's limit within `max_results_per_call`, the requests' sources equal to
  the step's, the step's sources those its call consults under the scope, and a
  CVE tool's one request its call's query text (`format_cve_tool_query`, the same
  function the executor sends) at `max_results_per_call`, and a
  `fight_direct_search` step's one request a FiGHT search of the interpretation's
  `fight_terms` at `max_results_per_call`. A topic step's template
  searches depend on its card, which the set does not carry, so the validator
  checks their count, sources and limits, and the decision-path audit and replay
  re-derive the rest;
- the interpretation's `fight_terms` none or every search term, and `fight_block`
  the first reason the interpretation shows (a match, an excluded term, a CVE ID),
  or a search term (`term_reads_as_topic`, which the audit re-checks against the
  registry); at most one step consults FiGHT, a `fight_direct_search` only with no
  topic resolved and some `fight_terms`, a `topic_context` only with one resolved;
  and every threat-context item returned by an admitted step of that kind and
  matched only by terms that step sent;
- a step or planner round that ran into the deadline, or a
  `model_skipped_at_deadline` round, names `wall_time` as the breach, and such a
  round runs no plan; a run whose breach is `wall_time` records a wall time at or
  past the cap, since the seal reads the elapsed time after the deadline was found;
- FiGHT evidence, and every served FiGHT outcome of the coverage and the steps,
  against the deployment's pin;
- `source_capabilities` equal to the capabilities the service reports: the
  deployment's four source entries and its planner's `model_planner` entry
  (`validate_knowledge_evidence_set` takes them beside the pin and the catalog), in
  the fixed shape above (`CAPABILITY_SUBJECTS`,
  `CAPABILITY_STATES_BY_SUBJECT`, and a version and coverage exactly where the
  state names one), and agreeing with the run: `model_planner` is `available` with
  the trajectory planner's model name, or `not_configured` or `unavailable` (with a
  `ModelPlannerUnavailableDetail`) under the deterministic policy; an `available` `mitre_fight` names the pinned snapshot's version and
  coverage, and an `unavailable` one served no FiGHT outcome or threat context (so,
  with one outcome per consulted source, every step that consulted FiGHT records
  its failure); a `semantic_channel` that cannot search (not configured or
  unavailable) leaves no semantic hit on any candidate, every search step that ran the
  channel records its `backend_unavailable` warning and a semantic failure whose reason
  matches the capability (`NOT_CONFIGURED` or `ADAPTER_UNUSABLE`), and under a semantic request every step whose CVE
  searches carry a search term (`list_query_terms`: a word beyond CVE IDs, stopwords
  and the low-signal words; a `cve_search`, or a topic's template
  searches) reports its `cve_search` outcome unserved; and the coverage holds a
  `source_unavailable` affectedness outcome exactly when affectedness is an answer
  source and a step ran, with the `affectedness` capability's detail;
- `result_sha256`.

Tests forge sets, reseal them, and expect rejection.

`result_sha256` and evidence IDs are integrity, not authenticity. A holder can
point a real anchor at another URI and excerpt, or rewrite a record's description
or a technique's observation status behind its genuine anchors, recompute what
hashes it must and reseal the set, and every hash still matches. The final
validation therefore re-checks served content against the service's own
`EvidenceCatalog` (`domain/evidence_catalog.py`): every anchor must equal, field
for field, the anchor it holds under that evidence ID; every CVE record, the
record it holds under that CVE ID; and every FiGHT technique, the technique it
holds under that ID apart from `matched_fields` and `matched_terms`, which come
from the search that found it. The composition root builds the catalog
(`InMemoryEvidenceCatalog`) from the CVE bundle's records and anchors and the
FiGHT source's techniques and anchors (`FightSource.list_techniques` and
`list_evidence`), and passes the same catalog to the topic-context service inside
the tool executor and to the investigation service, so content no configured
source holds, or content altered after it left its source, is rejected. The
service also holds the source capabilities the composition root computed, so a
set resealed with an emptied, reordered or rewritten capability list is rejected,
and the cross-checks against the run catch a composition root that describes its
deployment wrongly. The rest
of the trajectory is checked by re-deriving it from its own parts, by the
decision-path audit, and by replay. `cve-kgrag verify` (`verify_evidence_set`) runs
the validator, the audit and replay on a set handed back, against the deployment's
sources; the `get_evidence` knowledge tool serves the catalog's anchor under an
evidence ID, which a consumer compares with the anchor it holds. A set
alone proves its internal consistency, not its origin.

## Decision-path audit

The validator checks that a set's parts agree with one another. A holder who
rewrites a decision everywhere it shows, such as an interpretation, or a policy call
together with its call key, accepted plan and backend request, and reseals the set,
still passes it. `application/decision_path_audit.py` (`audit_decision_path`) runs
on every sealed set right after the validator, raises the same
`EvidenceValidationError`, and takes only the set, the topic registry and the
evidence catalog, so `verify_evidence_set` runs it on a set handed back. It
re-derives each decision from the request, the registry, the catalog and the set's
recorded observations, with the controller's own functions, and requires the record
to say exactly that:

- the interpretation equals `interpret_request(request, registry, catalog)`: intent,
  normalized query, CVE IDs, search terms, `fight_terms` and `fight_block`, the
  resolution, including every match's
  topic ID, version, content hash and review status and every excluded term, and the
  product versions the query asks affectedness of. Every later check derives from it,
  so a differing interpretation ends the audit;
- the run stops at interpretation exactly when `find_interpretation_stop` says so,
  with its reason and basis;
- every round planned before the deadline is the one `choose_round_plan` gives
  over the model reply the round records, the policy's plan for that round
  (`plan_first_round`, or `plan_refinement` over round 1's recorded steps) and the
  gate's context rebuilt from the steps issued before the round
  (`build_plan_context`: the issued call keys, the remaining tool calls, the sources
  consulted and the named CVE IDs no issued lookup carried). The recorded reply is
  parsed with `parse_plan_text` and gated with `find_plan_rejections` again, with
  round 1's baseline sources, so the planner outcome, the rejection codes and positions in order (the reply's, then
  the policy plan's), the accepted plan in canonical form, each step's
  `planned_by` and reason, and the round's stop and breach must equal the
  re-derived ones. A failed reply re-derives `model_unavailable` and a reply the
  gate rejects `model_rejected`, so neither can be relabelled `model_accepted`, and
  an accepted plan cannot be swapped for another plan the gate would also accept. A
  model's accepted lookup of one ID resealed as the run for a query naming two
  re-derives `model_rejected` (`missing_named_cve_id`). Whether a configured model was
  to be called (`is_model_consultable`) is re-derived too, so a topic or exact-ID round
  relabelled `model_not_consulted` re-derives `deterministic`, and a free-text round
  recorded as `model_accepted` re-derives `model_not_consulted`;
- a round the deadline stopped records exactly the rejection its outcome fixes
  (`plan_deadline_round`: `planner_timed_out`, `reply_after_deadline`, or none) and
  runs nothing;
- every assess and refine decision is the one `decide_assessment` and
  `decide_refinement_stop` give over the recorded steps and the needs `judge_needs`
  gives after each round: whether round 1 breached a cap is read from its steps'
  admissions and unrun calls, and whether it found an answer, and the needs it met,
  from the answer items its admitted steps found. The transitions, the
  number of rounds and the stop reason must equal the re-derived ones;
- the breach is the cap the decisions name: `wall_time` for the deadline (before
  planning, in the planner, or in or before a step), `tool_calls` or `sources` for
  a policy plan the gate rejected as over budget (`decide_over_budget_breach`, tool
  calls first), `rounds` for the round cap, and `context_bytes` for a step
  discarded over the byte cap;
- every step's backend requests are the ones its call sends under the request and
  the registry's card (`list_backend_requests` in
  `application/investigation_tools.py`, the function the controller records them
  with), so a topic step's template searches and its charge, from which the gate's
  remaining budget is rebuilt, are bound to the card, and a direct FiGHT search's
  terms to the interpretation; a `fight_direct_search` step of a query whose words
  may not go to FiGHT is reported rather than rebuilt;
- the warnings other than `unrelated_candidates_dropped`, `answer_truncated` and
  `applicability_unknown` (which follow from the responses, so replay checks them) are exactly,
  and in order, the ones
  `application/investigation_warnings.py` gives: `excluded_term`,
  `topic_not_resolved`, `no_searchable_terms` and `topic_pending_review` from the
  interpretation and the card, then per round one `model_plan_rejected` for a
  model reply the gate rejects (naming its re-derived codes, never its text) and
  one `evidence_discarded` per step a cap kept out of the answer, and one
  `evidence_prefix_omitted` naming each prefix-admitted step and its omitted count;
- each compact prefix witness agrees with visible whole records, ranks, per-list counts,
  anchors and omission warning; its charged bytes equal the step's charge and satisfy
  `charged <= remaining < charged + next` over the running budget;
- the coverage's source outcomes are `aggregate_source_outcomes` over the admitted
  steps' outcomes (none in an `invalid_evidence` run) and the answer, and its needs
  are `judge_needs` over the same steps and the answer;
- the trajectory's ranking is `describe_ranking()` (`application/investigation_answer.py`,
  the RRF constant, tier order and merge rule the controller records and the answer
  is ranked with), and a deterministic planner is `describe_deterministic_planner()`,
  whose policy version is the one these decisions are re-derived with.

It relies on what the validator established (rounds numbered from 1, each step in
its round running the leading calls of the round's accepted plan, a reply recorded
exactly when the model replied and matching its hash, one outcome per
consulted source on each step that got a response, byte admissions that follow the
cap, one charged tool call per backend request, every answer item returned by an
admitted step). Tests forge each re-derived element consistently, reseal, and
expect the audit to reject what the validator accepts.

## Replay

Each step records its call, reason, planner, call key, backend requests, charge,
sources, admission, status, channels, source outcomes, warnings, answer IDs,
evidence IDs, the tool response's own `result_sha256` and its byte size (a
`timed_out` or `rejected_invalid_evidence` step has no response, so no status,
hash, results or bytes). A backend request is one search the call sends: a CVE
search with its query text (the joined IDs of a lookup, the search text, or a
card's query template) and limit, or a FiGHT search with the topic's terms, or the
interpretation's `fight_terms` for `fight_direct_search`, and limit, in the order the
tool sends them. The controller records them with
`list_backend_requests`, which builds them from the same request builders the
executor runs the call with. The trajectory also records the planner identity, the
ranking configuration (RRF k, tier order, merge rule), `randomness: none`, the
transitions, the rounds and the budget used.

`replay_evidence_set(evidence_set, deployment)` (`application/trajectory_replay.py`)
takes a sealed set and the deployment it is checked against
(`InvestigationDeployment`: the topic registry, tool executor, source capabilities,
FiGHT pin, evidence catalog, call runner and clocks, as
`build_investigation_deployment` wires them). It runs the controller itself,
`InvestigationService`, again for the recorded request, and compares the set it
seals with the recorded one over every part except `timings` (measured) and
`result_sha256` (a hash over the compared parts). It returns `ReplayCompleted` with
a `ReplayDifference` for every part that differs: a step field (`step_index`,
`part`; `part` is `step` when only one of the two runs issued that step), or a
set-level part (`step_index` `None`, `part` such as `stop_reason`,
`trajectory.rounds` or `coverage.basis`). Never any response or reply text.

Since the controller produces the replayed set, there is one implementation of
planning, the gate, admission, assessment, refinement, the stop and breach, answer
assembly, coverage and warnings, and replay cannot drift from it. The replayed run
plans from what the sources return now: a response that shrank under the byte cap
is admitted and the run stops `sufficient` / `ok`, so replay names the step's
admission and bytes, `status`, `stop_reason`, `warnings`, `coverage.basis`,
`trajectory.budget_used.breach` and `trajectory.transitions`; a round 1 that now
meets the need ends the run there, so the recorded round 2 is not run, and replay names the
step only the record holds, `trajectory.rounds`, `trajectory.transitions` and
`coverage.refinement_applied`.

A run has two external inputs besides its sources, and replay puts both back:

- **Model replies.** A model-planned set is replayed with `RecordedModelPort`,
  which describes the recorded planner and answers each round with the reply that
  round records, so the controller parses and gates exactly those replies again. A
  round the record holds no reply for is answered with a typed `unavailable` reply,
  and a recorded reply the replayed run never asks for is left out of its round;
  either way the replayed round differs, and replay names `trajectory.rounds`. The
  replay's service is built with the recorded planner, so the replayed set's
  `model_planner` capability describes that planner; the deployment's capabilities
  describe its sources only.
- **The deadline.** Running into it is measured, not decided, so it cannot be
  re-derived. `find_deadline_checkpoint` reads from the record where the run found
  it: a run finds the deadline exactly when `wall_time` is its breach, at the last
  checkpoint it reached (a round's planner skipped, timed out or answering late; a
  deterministic round planned past it; a step timed out or finishing late; or the
  start of the step after the last). `ReplayClock` reads the deployment's clock and,
  when the controller reaches that checkpoint, moves it on by the whole wall-time
  cap, so the controller's own check there finds the deadline as the recorded run
  did. A `timed_out` call is therefore never re-issued. The controller announces a
  call's finish only for a call that returned: a call its own runner abandoned
  found the deadline during the call, so a replay whose call never returns cannot
  pass for a recorded late result. If the replayed run stops
  before that point, the deadline is never put back, and replay names the stop,
  breach and rounds that differ.

Replay is bounded by the recorded request's own `max_wall_time_seconds`, measured
on the deployment's monotonic clock (`time.monotonic` in production): the replayed
run's tool calls run under the deployment's call runner, which gives control back
when that time is up, and the replay planner never blocks. A replay that finds the
deadline anywhere but at the recorded point ran out of its own time: it compared
nothing and returns `ReplayTimedOut`, never a list of differences. Against a
backend that never returns, a one-second set's replay returns `ReplayTimedOut` in
about one second, whether the recorded run found the deadline nowhere, during a
call or at a late result's finish.

A response's hash carries no timestamp, so the same calls over the same data
reproduce the set exactly. Replay relies on the validator and the audit having
passed, and raises `EvidenceValidationError` when the replayed set fails the checks
the controller runs at seal, as the controller does.

### What each check proves

- **Validator** (`validate_knowledge_evidence_set`): the set's parts agree with one
  another and with the deployment's evidence catalog, FiGHT pin and source
  capabilities. For prefix admissions it checks whole visible records and anchors against
  the catalog, visible search ranks, the deterministic per-list cut order, counts,
  omission and topic warnings, charge agreement and the remaining-budget inequality.
  When every search candidate survives with its per-call metadata, it reconstructs the
  admitted response and checks its exact canonical charge and retained-prefix hash.
- **Decision-path audit** (`audit_decision_path`): every decision the set records
  (interpretation, round plans over the recorded model replies, assess, refine,
  stop, breach, backend requests, decision warnings and coverage outcomes) is the
  one the controller's functions give over the observations the set records, and
  the ranking and deterministic policy version it names are this code's.
- **Replay** (`replay_evidence_set`): the whole set but its timings is what the
  controller produces now from the sources, given the recorded model replies and
  the recorded deadline point: every step summary and admission, the stop, status,
  breach, rounds, transitions, warnings, coverage, answer, claims and evidence. It
  recomputes prefix admissions from complete source responses, checking the original
  digest, exact maximal prefix, canonical admitted byte charge and next-result increment.
  It says `ReplayTimedOut` instead when it runs out of its own time.

Run together, the three tie a set's decisions to the sources' responses. The
service runs the validator and the audit on every set it seals. Replay needs the
sources, so a caller holding a set runs it: `cve-kgrag verify`
(`verify_evidence_set`) runs the validator, the audit and replay on a set handed back.

Validator and audit cannot catch a step summary rewritten over a real hash. Two
such forgeries pass both checks, and replay names them:
a FiGHT topic step whose failed response's hash is kept while its summary and the
answer are rewritten to the five catalog techniques; and a 2,513-byte admitted
response recorded as 200,001 bytes discarded over the byte cap, with the
`budget_exhausted` stop that follows. A response's size is the length of its
canonical JSON. A set does not carry complete response bodies, and answer assembly can
merge or drop admitted candidates, so the compact witness alone cannot establish the exact
canonical charge after per-call metadata is lost, or the omitted count or next-result
increment, if a holder rewrites consistent figures together. Replay proves those figures against complete source responses.

For prefix forgeries, the checks have these boundaries:

| Forgery | Validator and decision-path audit | Replay |
|---|---|---|
| Too short | Rejects inconsistent counts, content or a next entry that still fits according to the witness | Recomputes the maximal prefix, including a consistently rewritten witness |
| Too long | Rejects a charge over the remaining cap or an improper/full cut | Recomputes the maximal prefix |
| Partial record or anchor | Rejects a mismatch with the catalog | Compares the complete returned content |
| Wrong counts | Rejects counts inconsistent with IDs, list order, or warnings | Recomputes kept and omitted counts, including a coordinated count/warning forgery |
| Missing warning | Rejects the absent or incorrect step omission warning | Reproduces warnings |
| Wrong charged bytes | Rejects charge disagreement, broken fit/budget arithmetic, or a canonical size mismatch for a reconstructible search | Recomputes canonical prefix bytes even when merging or filtering removed per-call metadata |
| Wrong next-result bytes | Rejects a figure that breaks the fit inequality | Recomputes the exact increment, including a different figure that still satisfies the inequality |
| Wrong original digest | Checks digest format at parsing | Compares the complete response's sealed digest |

## Golden trajectories

`eval/gold/m4_trajectories.yaml` holds hand-labelled trajectories over the
packaged card, FiGHT excerpt and synthetic CVEs; `tests/integration/
test_investigation_gold.py` compares every row and never regenerates the file.

| Row | Request | Calls | Stop / status | Answer |
|---|---|---|---|---|
| `exact_id` | `CVE-9999-0003`, implementation_only | exact lookup (1), channel `exact_id` | sufficient / ok | `[0003]` |
| `exact_id_mixed` | same, mixed | exact lookup (1), no topic or FiGHT call | sufficient / ok | `[0003]` |
| `cve_under_protocol` | `CVE-9999-0003`, protocol_context_only | none | policy_blocked | – |
| `protocol_5gaka` | `5gaka`, protocol_context_only | topic (5) | sufficient / ok | 5 FiGHT techniques; `[0003, 0004]` excluded |
| `impl_5gaka_open5gs` | `5gaka`, implementation_only, product `open5gs` | topic (4) → R3 → search `5gaka` (1) | source_unavailable / partial | none; `open5gs: unknown` |
| `impl_5gaka_f5gc` | same, product `f5gc` | topic (4) | source_unavailable / partial | `[0003, 0004]`; `f5gc: unknown` |
| `fight_unavailable_mixed` | `5gaka`, mixed, no FiGHT | topic (5), no retry | source_unavailable / partial | `[0003, 0004]` |
| `fight_unavailable_protocol` | `5gaka`, protocol_context_only, no FiGHT | topic (5) | source_unavailable / source_unavailable | `[0003, 0004]` excluded |
| `impl_5gaka_topic_first` | `5gaka`, implementation_only | topic (4), no FiGHT search | sufficient / ok | `[0003, 0004]` |
| `impl_5g_aka_topic_first` | `5G-AKA`, implementation_only | topic (4), no FiGHT search | sufficient / ok | `[0003, 0004]` |
| `unknown_id_residual` | `CVE-9999-4242 AUSF resynchronization crash`, implementation_only | exact (1) | no_evidence / no_match (the words beside the ID are not searched) | – |
| `unknown_id_alone` | `CVE-9999-4242`, implementation_only | exact (1) | no_evidence / no_match | – |
| `unknown_id_zzqx` | `CVE-9999-4242 zzqx`, mixed | exact (1) | no_evidence / no_match | – |
| `bare_aka` | `aka`, mixed | none | no_evidence / no_match | – |
| `low_signal_only` | `CVEs`, mixed | none | no_evidence / no_match | – |
| `near_id_after_low_signal_word` | `CVE of 9999-0003`, mixed | none | no_evidence / no_match | – |
| `low_signal_beside_terms` | `cve AUSF resynchronization crash`, implementation_only | search `ausf resynchronization crash` (1) | needs_unmet / partial | `[0003]` |
| `injection_record` | `ignore previous instructions`, implementation_only | search (1) | needs_unmet / partial | `[0007]`, templated claim |
| `protocol_free_text` | `SUCI discovery`, protocol_context_only | direct FiGHT search (1) | needs_unmet / partial | 4 FiGHT techniques |
| `mixed_free_text` | `SUCI concealment`, mixed | search (1), then direct FiGHT search (1), both round 1 | needs_unmet / partial | `[0004]`; 3 FiGHT techniques |
| `excluded_term_protocol` | `EPS AKA crash`, protocol_context_only | none | no_evidence / no_match | – |

The `5gaka` rows show the topic explored first in every scope, and an observation
changing the trajectory: when the card's searches find nothing for the named product,
the one refinement searches the question's own words. The free-text rows show FiGHT
searched once with the question's own words when no topic resolves, an excluded term
barring that search rather than being stripped from it, and every free-text answer
ending `needs_unmet` with its matches listed and unassessed. The gold file supports fixture-level claims
only.

## Known limits

- **An abandoned call is not killed.** The caller gets control back within the
  wall-time cap, but Python cannot stop a running thread: a call abandoned at the
  deadline keeps its daemon thread until it returns, and what it returns then is
  dropped. The tools and the planner are read-only, so an abandoned call has no
  effect on the run. Network adapters must still honour the timeout they are
  given (`ModelPort.propose_plan(..., timeout_seconds)`, and a network adapter, the
  Trustify adapter included once it exists (ADR 0003)), or each abandoned call holds
  a thread and a connection until the remote side gives up. The runner waits in real
  seconds, so the injected clock must be a real monotonic clock in production
  (`time.monotonic`).
- **No affectedness source.** Every product question ends `source_unavailable`
  with `partial` or a failure status, and applicability is `unknown`, while no
  verified affectedness source exists (ADR 0003).
- **Truncation counts what the adopted steps knew, not what backends left unseen.**
  `answer_truncated` counts, each once, the items the adopted steps knew and the answer
  does not list: the CVEs they kept, those the topic step kept and left out at its limit
  included, less the CVEs the answer lists, plus the techniques the step that searched
  FiGHT (a topic step or a direct FiGHT search) matched and did not list (ADR 0009
  §11a). A CVE tool's own top-k and each retrieval channel's
  cut are never counted, so more matches may exist unseen. The topic step's cuts are
  also its own `candidates_truncated` and `protocol_context_truncated` warnings, and a
  direct FiGHT search's cut its `protocol_context_truncated`; the
  validator checks the relations a set carries, and replay re-derives every count from
  the sources.
- **The pending 5G-AKA card drives retrieval.** Its `pending_review` status is
  reported with a `topic_pending_review` warning; gating retrieval on review is a
  human decision.
- **No network model adapter.** The port, the `QueryPlan` schema, the gate and a
  scripted test planner ship now; a provider adapter follows in a separate M4
  change. There is no schema snapshot of `PlanningInput` until then.
- **Consistency, not authenticity.** The validator, the audit and replay prove a
  set consistent with itself, with this deployment's catalog, registry and pin, and
  with what its sources return for its calls; they cannot prove the model sent the
  reply a round records. Whoever reseals a set can rewrite the reply, its hash, the
  accepted plan and the steps together (re-running the rewritten calls), and the
  rewrite is consistent; only an authenticated seal can detect it. If response
  authenticity is required, it needs a separate seal over the whole response,
  designed in its own ADR: a keyed hash over the planner's reply alone would leave
  every other recorded decision rewritable, so it is not the right boundary.
- **The deadline is measured, not decided.** The audit reads a round recording a
  deadline outcome (`model_timed_out`, `model_reply_after_deadline`,
  `model_skipped_at_deadline`, or a `deterministic` round that records neither a
  plan nor a rejection) as one the deadline stopped. Replay puts the deadline back
  at the checkpoint where the record says the run found it, and does not re-issue a
  `timed_out` call. The validator ties each deadline outcome to a `wall_time` breach;
  a `wall_time` breach to a run wall time at or past the cap; and a timed-out or
  late step to a finish at or past the deadline. A planner deadline outcome and a
  step that never started carry no timing of their own beyond the run's wall time.
  Timings are outside the hash, so a holder who rewrites a run to end at an earlier
  checkpoint, with timings to match, produces a set that replays without a
  difference: replay proves what follows from the deadline point, not that the
  deadline fell there.
- **Replay's budget is the request's.** A replay gets the recorded request's
  wall-time cap, so a deployment whose sources are slower now than when the set was
  sealed can make an honest set's replay return `ReplayTimedOut`; that proves
  nothing about the set either way.
- **Replay is not run at seal.** The service validates and audits every set it
  returns. Replay re-executes every call, so it is run by a caller that holds a set
  and the deployment's sources: `cve-kgrag verify` (`verify_evidence_set`). A step
  summary rewritten over a real hash is caught only when someone verifies the set.
- **Round 1's answer is read from the final answer.** The audit decides whether
  round 1 alone found an answer from the final answer. Each item is kept or dropped
  on its own, so round 1's items stay in it unless the result cap cut them for
  higher-tier round-2 items.
- **A likeness stops at a Latin letter.** Latin letters, and characters that fold
  into them (`™`, `№`), are never gaps between an ID's parts, so `CVE 2022 log4j` is
  not an ID and searches `2022 log4j`; the cost is that `CVE-99a99-0003`,
  `CVE™9999™0003` and wording outside the ID-word list (`CVE called 9999-0003`) are
  searched as words (`99a99 0003`, `cvetm9999tm0003`, `called 9999 0003`), which can
  match an unrelated description. The words `cve` and `cves` are never searched
  (`extract_search_text`), while `tokenize` keeps them in the lexical index; a
  likeness its words form is read with them in place, so `CVE of 2021-44228` and
  `nvdcve in 2021 and 2022` search nothing, in the search service and the policy
  alike.
- **Visible separators keep a low-signal word apart.** A possessive (`CVE's`,
  `CVE’s`) and invisible or control characters inside the word (`c`+ZWSP+`ve`) are
  read past, but a visible character is not: `CVE-s` searches `s`, and `c`+U+0306+`ve`
  searches `c` and `ve`. Joining words across visible characters would read ordinary
  text as a disguised `cve`; whether the set or its spellings widen is decided on the
  M5 and M7 gold queries.
- **The claim-subject rule** requires every cited anchor to be about the claim's
  subject; derived CVE→CWE→FiGHT mappings will need a relaxed rule.
- **No planner flags on the CLI.** The planner comes from the settings (ADR 0004).
  `cve-kgrag investigate QUERY --scope SCOPE [--vendor V]... [--product P]... [--purl U]...`
  and the budget options of M6 WP5 print the evidence set and exit 0 only when the
  status is `ok`.
