# C: FiGHT protocol threat context from the question's own words

Status: settled by the owner on 2026-10-29 (§10); implementation follows it.
Baseline: commit c1b5b8a, contracts `2.0.0-dev.29`, policy `m7b.1`.

## 1. Problem

Under dev.29, FiGHT is reached only through a reviewed topic card, and the only card is 5G-AKA. That causes three observed gaps:

1. **Protocol-only free text stops before planning.** `find_interpretation_stop` (`application/investigation_policy.py`) returns `no_evidence` / `protocol_scope_needs_topic` for every `protocol_context_only` + `free_text` query. Example: sip-ims-threats.
2. **Mixed free text gets no FiGHT step.** A `mixed` free-text query without a card plans only `cve_search`, and B judges its protocol need `unsupported` (`domain/evidence_needs.py:149-168`). Example: gtp-mobile-core has protocol coverage 0.0.
3. **FiGHT ranks by count, then ID.** `PinnedFightYamlSource.search` sorts by number of matched terms, then technique ID (`adapters/fight/pinned_yaml.py:279`). On the gtp words, the dev.29 order puts only 3 of 8 required techniques in the top 20.

The 5G-AKA card has its own gap. FGT5044 ranks 30th of 30 and is cut at 20, and FGT1036.501 is not matched at all. The cause is the card's terms, not the order (§4).

## 2. The action and when it is planned

### 2.1 Which words may go to FiGHT

There is one pure rule, in `application/investigation_policy.py` beside `list_search_terms`. It decides whether the query's words as a whole may enter a FiGHT search; it never removes a word and sends the rest:

```python
def find_fight_block(query: str, topic_registry: TopicRegistry) -> FightBlock | None:
    """Why the query's search terms may not be sent to FiGHT without a reviewed topic, or
    None when they may: all of them are sent, or none."""
```

It returns a block, checked in this order, when:

- **A topic resolved** (`topic_resolved`, subject: the first matched topic ID). `resolution.matches` is non-empty; the card's terms reach FiGHT through `topic_context`.
- **An excluded term is named** (`excluded_term`, subject: the first excluded term). `resolution.excluded_terms` is non-empty. This blocks `aka attacks`, `EPS AKA crash`, `EAP-AKA' threats` and `5G, aka NR GTP threats`.
- **A CVE ID is named** (`cve_id_named`, subject: the first ID). The query names an ID that `interpret_request` keeps: one of `find_cve_ids(query)` no longer than `MAX_CVE_ID_CHARS`, by the same filter (`list_kept_cve_ids`, which both call). With IDs only a topic is a text target (B). This also closes the path by which a model could add FiGHT to an `exact_id` run under `mixed`.
- **A single word reads as a topic or excluded term** (`term_reads_as_topic`, subject: the word). Any term of `list_search_terms(query, set())` that `topic_registry.resolve(term)` reads as a match or an excluded term blocks the search. This closes the verified `5Géaka threats` leak, where the ASCII tokenizer yields `aka` but the Unicode matcher reports nothing. Dropping the word instead would send the fragments `5g` and `threats`, whose generic matches could meet the need.

The rule invents no word list and no threshold. It reuses the registry's own resolution and exclusions, and the existing stopword and `cve`/`cves` rules.

`interpret_request` records two fields after `search_terms` in `domain/investigation.py`:

- **`Interpretation.fight_block: FightBlock | None`**, a `FightBlock(reason: FightBlockReason, subject: str)` with the four reasons above;
- **`Interpretation.fight_terms`**: `search_terms` when there is no block, else `()`.

They are recorded so that:

- the domain validator and the needs judge read them without importing `topics/`;
- the decision-path audit recomputes and compares them like every other interpretation field (`decision_path_audit.py:588`).

Invariant, checked in the domain: `fight_terms` is either `()` or exactly `search_terms`, never a subset. It is non-empty exactly when `fight_block` is None and `search_terms` is non-empty, and then the intent is `free_text` and the resolution has no match and no excluded term.

**One rule everywhere.** `list_fight_terms(query, topic_registry)` returns `search_terms` when `find_fight_block` gives None, else `()`. It is the only source of FiGHT words:

- `interpret_request` records its result, so the planner offer (§2.5), the round-1 plan (§2.3) and the gate (§7) read `fight_terms` and `fight_block` from the interpretation;
- the executor (§2.4) and `list_backend_requests` call it on the same request and registry, as they already call the shared request builders for the other tools;
- the evidence-set validator checks that every `fight_direct_search` step's request terms equal the recorded `fight_terms`, and the decision-path audit recomputes the interpretation, the plans, the gate decisions and each step's requests, so a divergence anywhere is caught.

The executor raises on empty `fight_terms`, a state the gate never admits.

### 2.2 The tool

Changes in `domain/planning.py`:

- `ToolName.FIGHT_DIRECT_SEARCH = "fight_direct_search"`.
- `FightDirectSearchCall(ContractModel)` with only `tool: Literal[ToolName.FIGHT_DIRECT_SEARCH]`. It takes no arguments, so neither planner chooses words. It joins the `ToolCall` union.
- `compute_call_key` returns the constant `canonical_sha256({"tool": "fight_direct_search"})`. `repeated_call` therefore allows one per run.
- `is_tool_permitted` rejects the tool under `implementation_only`.
- `list_tool_name_sources` gives `(MITRE_FIGHT,)`.
- `PlanRejectionCode.FIGHT_DIRECT_SEARCH_BLOCKED = "fight_direct_search_blocked"`: the interpretation does not allow a direct FiGHT search; `interpretation.fight_block` gives the reason (decision 6).
- `StepReason.QUERY_TERMS_FIGHT = "query_terms_fight"`, mapped to `(FIGHT_DIRECT_SEARCH, 1)` in `POLICY_STEP_TOOL_AND_ROUND`.

Every "not a topic, so CVE" fall-through becomes an explicit `isinstance` branch, because a missed branch would silently run a CVE search:

- `compute_call_key`, `is_tool_permitted`, `list_tool_name_sources` (planning.py);
- `count_tool_calls` (investigation_policy.py), with a new `FIGHT_DIRECT_SEARCH_COST = 1` beside `CVE_TOOL_COST`;
- `find_call_rejection` (plan_gate.py);
- `ToolExecutor.execute` and `list_backend_requests` (investigation_tools.py).

Mutual exclusion holds by construction. `topic_context` is admitted only when a topic resolved, and `fight_direct_search` only when none did. Together with the constant key, a run has **at most one step that searches FiGHT**. `collect_protocol_context` and `count_topic_cuts` already rely on that, so their arithmetic is unchanged and only their docstrings change.

### 2.3 Policy m7b.2: when it is planned

- **Stop table.** The row becomes `protocol_context_only` + `free_text` + empty `fight_terms` → `no_evidence` / `protocol_scope_needs_topic`. The enum value is kept. Its meaning narrows to "protocol-only free text whose words may not be sent to FiGHT without a reviewed topic". `EPS AKA crash`, `aka attacks` and `5Géaka threats` still stop as they do under dev.29.
- **Round 1** (`plan_first_round`), for `free_text`:

| Scope | Round-1 plan |
|---|---|
| implementation_only | `[cve_search]` (unchanged) |
| protocol_context_only | `[fight_direct_search]` |
| mixed, `fight_terms` non-empty | `[cve_search, fight_direct_search]` |
| mixed, `fight_terms` empty | `[cve_search]` (unchanged) |

  Both needs of a `mixed` question are known before planning, and the FiGHT search does not depend on what the CVE search returns, so nothing is gained by waiting for round 2. `cve_search` stays step 1. The plan is one complete round-1 plan under the existing budget pre-check: when it is over the source budget, dev.29's rule applies (no model is consulted); over the tool-call budget alone a configured model is consulted, but any round-1 plan it can pass must include both required tools. A `mixed` topic query, whose `topic_context` consults both sources in round 1, behaves the same, as a consequence. A round-2 rule was rejected because:
  - it would always fire, since the protocol need is always open after a CVE-only round;
  - it adds a reason;
  - under `max_rounds` 1 the round-2 FiGHT search cannot run.

  **Behaviour change under `max_sources: 1`.** A `mixed` free-text query whose `fight_terms` are non-empty has a round-1 plan of 2 sources, so the pre-check fails: no model is consulted, nothing runs, and the run stops `budget_exhausted` with no answer. Under dev.29 it ran `cve_search` and stopped `needs_unmet` with its CVEs. A regression test pins the new behaviour; the default `max_sources` of 4 does not hide it.

  **Behaviour change under `max_tool_calls: 1`.** The same plan costs 2 tool calls, so the gate rejects it `over_tool_call_budget` and the run stops `budget_exhausted` (`plan_over_budget`) with no answer, where dev.29 ran `cve_search`. A configured model is consulted once, but any round-1 plan it proposes must reach both baseline sources, costs at least 2, and is rejected the same way. A regression test pins this too.
- **Refinement R1-R3 is unchanged.** No rule plans `fight_direct_search`. If it ran and the need stayed open, nothing else can serve it, so unless R3 serves an open implementation need the run stops with basis `no_refinement_available` and the reason `decide_open_stop` gives any open need: `needs_unmet` when the answer lists something (CVEs, or techniques C1b judged insufficient), else `no_evidence`.
- **Version.** `DETERMINISTIC_POLICY_VERSION = "m7b.2"`. The module docstring and m4 doc gain the round-1 row: one call, or two for `mixed` free text.

### 2.4 Execution

`TopicContextService.search_fight_directly(request: TopicContextRequest, fight_terms: Sequence[str]) -> TopicContextResponse` works as follows:

- The resolution is `registry.resolve(request.query)`, which is unresolved by the gate's invariant, with the `topic_not_resolved` warning.
- It makes one FiGHT search through a private `_search_fight(terms, limit, warnings, reports_unindexed_terms: bool)`, extracted from `explore_with_omissions` and shared by both methods. It keeps `require_sent_terms`, `require_matched_count` and `_summarize_fight`, and appends, in this order, the excerpt warning, one `term_not_indexed` per `unindexed_terms` entry (only when `reports_unindexed_terms`, which only the direct path sets; §6), then `protocol_context_truncated`.
- `_seal` runs with scope `protocol_context_only`, FiGHT as the only source outcome, no candidates and no CVE template search, and passes the sent `fight_terms` to `validate_topic_context_response` as `sent_fight_terms`.

In `ToolExecutor.execute`:

- A `FightDirectSearchCall` runs `search_fight_directly(build_fight_request(request), require_fight_terms(request, registry))`; `require_fight_terms` returns `list_fight_terms(request.query, registry)` and raises `LookupError` when they are empty.
- `build_fight_request` builds `TopicContextRequest(query=request.query, scope=PROTOCOL_CONTEXT_ONLY, limit=cap, max_results_per_search=cap)`, where cap is `request.budget.max_results_per_call`.
- The result fills `ToolExecution.topic_response`.

The rest of the pipeline already reads any `topic_response`, so it is unchanged:

- `build_tool_step`, `collect_protocol_context`, `collect_evidence`, `count_topic_cuts`;
- `answer_truncated = |K| - |L| + F`;
- `observe_step`.

`explore`, `explore_with_omissions`, MCP `search_fight` and the CLI `topic` command keep their admission: FiGHT is reached only through a resolved topic, and an unresolved query consults nothing (decision 5). Their FiGHT order is the shared order of §4, so with C2 their listed techniques and, after the limit cut, which techniques they return can change.

### 2.5 Planner

- `build_planning_input` (investigate.py) offers `ToolCost(FIGHT_DIRECT_SEARCH, 1)` when the scope is not `implementation_only` and `fight_terms` is non-empty. The existing filter that drops a tool alone over `max_sources` applies.
- `required_tools` picks the tool up from the policy's round-1 plan, so a model's round-1 plan must include it (`missing_baseline_source`).
- `PLANNER_INSTRUCTIONS` (adapters/planner/openai_compatible.py) adds the shape `{"tool": "fight_direct_search"}` and one rule: "fight_direct_search takes no arguments; it searches MITRE FiGHT with the question's own words and is offered only when no topic resolved".
- The model can use the tool only through the gate.
- Interplay with dev.29: under `max_sources: 1` a mixed free-text plan whose `fight_terms` are non-empty uses 2 sources, so the model is not consulted and the run stops `budget_exhausted`. That is what a mixed topic query does. The default `max_sources` is 4.

## 3. Exclusions and provenance

**Boundary 1: no topic identity.** A technique found by `fight_direct_search`:

- carries no `topic_id`, relevance tier or review status;
- sits in a response whose resolution has no match and that keeps `topic_not_resolved`;
- cannot trigger `topic_pending_review`, which is keyed on a match;
- is described by the claim template as "MITRE FiGHT lists X as … protocol threat context" (no topic named).

The `ThreatContextItem.matched_terms` description becomes "Terms the server sent to FiGHT that the technique holds: a resolved topic's name, aliases and entities, or with no topic the question's own words". Finding a technique says only that relevant protocol threat material was found.

**Boundary 2: exclusions still apply.**

- Any excluded term blocks the direct search. Words are never stripped and searched around.
- A word the registry reads alone as an excluded term or topic also blocks it.
- While a card resolves, only the card's terms reach FiGHT, and `fight_direct_search` is barred.
- A card alias word on its own is never claimed as protocol relevance.

**Tripwire.** Add a test asserting that no packaged card has a contextual alias. A contextual alias used without its context is not reported by the resolution, so `find_fight_block` cannot see it. The 5G-AKA card has `contextual_aliases: []`. The test forces this rule to be revisited when a card first gains one.

## 4. FiGHT ranking

**Change (stage C2, measured on its own).** One order replaces count-then-ID inside `PinnedFightYamlSource.search`. It serves both the card path and the direct path.

This is a deliberate change of retrieval behaviour, not a result-preserving optimisation. The scoring rule, stated in full:

- **Tokenization is the matcher's own.** A technique's five fields (name, BLUF, description, procedure examples, tactic names) are split by `split_terms`: NFKC, casefold, invisible formatting characters removed, Unicode words, and words joined only across whitespace or one unspaced `-`/`_`. A sent term is matched as a phrase by `alias_key` / `find_spans`, exactly as under dev.29; sent terms with the same `alias_key` count once.
- **The scoring unit is the sent term**, so a term scores only where it matches. tf is the term's spans summed over the five fields, which are weighted alike. df is the number of techniques holding the term.
- **Length.** A technique's length is its word count over the five fields, boundaries excluded, computed once at index time as `IndexedTechnique.word_count`; the average is over the snapshot's techniques.
- **Formula.** Okapi BM25: IDF `ln(1 + (N - df + 0.5) / (df + 0.5))`, term weight `IDF * tf * (k1 + 1) / (tf + k1 * (1 - b + b * length / average))`, summed over the matched terms in ascending `alias_key` order, as the CVE index sums in sorted term order, so the query's word order cannot change a score. k1 = 1.2 and b = 0.75 are the textbook defaults, fitted neither to the CVE corpus nor to FiGHT; tuning them for FiGHT would be its own measured change.
- **Order.** Score rounded to 6 places, descending; ties by technique ID, ascending.
- **No filter.** No admission rule, frequency threshold or minimum score (§9, and unlike the rejected A2 rule). A sent term no technique holds adds nothing to any score; with the direct search it raises `term_not_indexed` (§5).
- The matched set, `matched_count`, `matched_terms`, `matched_fields` and anchors are unchanged. Only the order, and so the techniques kept at the limit, changes.

**Reuse.** Move `TERM_SATURATION_K1`, `LENGTH_NORMALIZATION_B`, `SCORE_DECIMALS` and the IDF, length-saturation and term-weight formulas from `adapters/lexical/bm25_index.py` into a pure `domain/bm25.py`. Both indexes import it. The float expression `idf*tf*(K1+1)/(tf+saturation)` keeps its order, so A1's byte-equality tests over the CVE index guard that nothing moved.

**Measured (FiGHT 3.1.0, 183 techniques):**

| Path | Order | Matched | Required ranks | Top 10 | Top 20 |
|---|---|---|---|---|---|
| gtp words (gtp 9, vulnerabilities 14, mobile 20, core 45) | count, ID | 71 | 3, 7, 11, 23, 24, 29, 30, 69 | 2/8 | 3/8 |
| | phrase BM25 | 71 | 1, 2, 4, 8, 9, 10, 11, 12 | 6/8 | 8/8 |
| | count, then BM25 | 71 | n/a | 3/8 | 8/8 |

| 5G-AKA card order | FGT5044 rank | Top-20 changes |
|---|---|---|
| dev.29 (count, ID) | 30 | n/a |
| Phrase BM25 (adopted) | 27 | 5 allowed swapped for 5 allowed |
| Count, then phrase BM25 | 27 | 5 |
| Word-level BM25 (not adopted) | 16 | 6 |

- FGT1499.503 stays 1st and FGT1036.501 is unmatched under every order.
- Word-level BM25 reaches 16th only through partial-name credit. Of FGT5044's score, 3.66 comes from `authentication`, a word of the canonical name that matches 0 techniques as a phrase. It would also let the `aka` of `5G-AKA` raise any technique that mentions EAP-AKA, which boundary 2 forbids.
- The scoring unit must equal the matching unit, so phrase BM25 is adopted.

**Card-term what-if (not part of C).** Adding `authentication vector` and `authentication vectors` as card terms:

| Order | FGT1036.501 | FGT5044 | Matched |
|---|---|---|---|
| dev.29 (count, ID) | 14 | 13 | 31 |
| Phrase BM25 | 15 | 11 | 31 |

**The 5G-AKA card.** C replaces the count-then-ID order with one shared phrase-BM25 scorer (ties still go to technique ID), because the direct path needs it (gtp goes from 3/8 to 8/8 in the top 20). It does **not** fix the 5G-AKA card. FGT5044 matches only `SUPI`, the commonest card term (19 techniques), so it stays cut at 27th. FGT1036.501 needs a reviewed card-term change. That is a separate, measured card-review step after C.

The ranking change also reorders the packaged excerpt: FGT5019 and FGT5019.005 swap. The hand-labelled orders in `eval/gold/m3_topic_queries.yaml:25,39`, `eval/gold/m4_trajectories.yaml:101` and `eval/gold/m5_tool_queries.yaml:89`, and the `SUCI` excerpt order asserted in `tests/integration/test_fight_fixture.py:39` where C2 changes it, are edited in C2, each with its old order, new order and reason.

## 5. Evidence needs (B stays consistent)

`judge_protocol_context` reads `interpretation.fight_terms`; its signature is unchanged.

**`not_evaluated` (decision 10), for every need kind but affectedness.** A need is `not_evaluated` when no admitted step of a tool that serves it has a result: no step of that tool ran, or none was admitted (`timed_out`, `discarded_after_deadline`, `discarded_over_context_budget` or `rejected_invalid_evidence`). Whether the need is met cannot yet be judged; the outcome does not claim that no call was made. It is checked after `unsupported` and before every other outcome, so an admitted step whose source failed gives `source_unavailable`, never `not_evaluated`. Like `not_found` it is open: refinement may plan a call for it, but a breached budget or the deadline still decides the stop first, and no call is retried for it. Affectedness stays `source_unavailable`. The evaluation reads every outcome but `found` as a gap, as before.

1. **Topic resolved:** unchanged. The serving steps are admitted `TopicContextCall` steps.
2. **No topic and `fight_terms` empty → `unsupported`.** With the direct search, a missing topic card alone no longer makes the need unsupported; only a block does. `NeedOutcome.UNSUPPORTED` keeps its value. Its producer narrows to "the words may not enter a FiGHT search without a reviewed topic", and the set records the reason and its subject in `interpretation.fight_block`. This is what keeps `EPS AKA crash` under `mixed` at dev.29's `needs_unmet`.
3. **No topic and `fight_terms` non-empty:** the serving steps are admitted `FightDirectSearchCall` steps; with none, `not_evaluated`.
   - **(C1b)** `not_found` when a serving step warned `term_not_indexed` for a term that `list_explained_terms` does not explain. This is a conservative check of term coverage, not a judgement of semantic relevance: `not_found` says the evidence does not meet the whole protocol need, never that FiGHT holds nothing relevant. It removes no answer item, and the step's `term_not_indexed` topic warning names the uncovered word (`catcher` in `IMSI catcher threats`), as B's CVE-side warning does. It mirrors B's CVE rule.
   - `found` when the answer lists a technique a serving step returned.
   - `source_unavailable` when a serving step's FiGHT outcome failed.
   - Otherwise `not_found`: the search was allowed and ran, and its evidence does not meet the need.

   A breached cap or a failed source still decides the stop first (B's assess order), so a FiGHT search the budget cut off stops `budget_exhausted` and a failed FiGHT source `source_unavailable`; neither is read as blocked or as no evidence; a FiGHT search with no admitted result is `not_evaluated`.

`judge_named_cve` and `judge_implementation_cves` gain the same `not_evaluated` check over their serving steps (admitted exact lookups naming the ID; admitted CVE searches and topic calls). `judge_implementation_cves` keeps `CveSearchCall | TopicContextCall` as its serving steps. FiGHT's `term_not_indexed` lives in `topic_warnings`, never in `search_warnings`, so it cannot make implementation `not_found`. "Found" is still met only by FiGHT evidence that an admitted step returned and the answer lists.

## 6. Contract

C moves contracts to **2.0.0-dev.30** (`domain/search.py:35`) and the deterministic policy to `m7b.2`, once for the whole package:

- **Added:**
  - `ToolName.fight_direct_search`, `FightDirectSearchCall`;
  - `NeedOutcome.not_evaluated`, for every need kind but affectedness (B's judging changes with it);
  - `StepReason.query_terms_fight`;
  - `PlanRejectionCode.fight_direct_search_blocked`;
  - `Interpretation.fight_terms` and `Interpretation.fight_block` (`FightBlock`, `FightBlockReason`: `topic_resolved`, `excluded_term`, `cve_id_named`, `term_reads_as_topic`), both required;
  - `TopicContextWarningCode.term_not_indexed`. Its position in `TOPIC_WARNING_ORDER` comes after `source_snapshot_is_excerpt` and before `protocol_context_truncated`. It is emitted only on the direct path, so no card response carries it, even though card terms such as K_SEAF are held by no technique.
- **Internal:** `ThreatContextOutcome.unindexed_terms: tuple[str, ...] = ()`. It holds sent terms no technique holds, first spelling per `alias_key`, in sent order, only on success. `require_sent_terms` also checks that they were sent.
- **Descriptions:** `matched_terms`, `FightBackendRequest` ("a topic's names, aliases and entities, or the interpretation's fight_terms"), `backend_requests`.
- **Regenerated:** every `schemas/v2` snapshot that carries `schema_version` (its version const), with content changes in `query_plan`, `knowledge_evidence_set` and `topic_context_response`; and `manifest.json`.
- **No enum value is removed.** dev.29 sets do not parse under dev.30. Re-run them rather than convert them.

C1b changes need judging only, and C2 changes the published FiGHT order on the card path as well. Both are part of the same version step (decision 8).

## 7. Gate, validator, audit, replay

**Gate** (`application/plan_gate.py`):

- `find_call_rejection` gets an explicit `FightDirectSearchCall` branch after the scope check: empty `fight_terms` → `fight_direct_search_blocked`. The topic branch becomes an explicit `elif isinstance(call, TopicContextCall)`.
- Scope, repeat, `missing_baseline_source`, `over_tool_call_budget` and `over_source_budget` work through the explicit cost and source branches.
- `canonicalize_call` returns the call unchanged.
- The module docstring gains check 5 (`topic_not_resolved` / `fight_direct_search_blocked`) and the constant key under check 6.

**Topic-response validator** (`domain/validation.py`):

- `find_topic_status_violations`: an unresolved response names either no source outcome, or exactly `(MITRE_FIGHT,)` under `protocol_context_only` with no excluded term in its resolution.
- `find_topic_warning_violations` gains `is_resolved: bool`, `sent_terms: Sequence[str]` and `listed_matched_terms`, and checks `term_not_indexed` through `find_unindexed_term_violations`. `validate_topic_context_response` passes whether `response.resolution.matches` is non-empty, its keyword `sent_fight_terms` (the direct path's `fight_terms`, none for a topic's exploration) and the matched terms of the techniques it lists; `find_step_topic_warning_violations` passes whether the step's call is a `TopicContextCall`, the terms of the step's `FightBackendRequest` (none when it has none) and the matched terms of the answer's techniques the step returned. `term_not_indexed` appears only when `is_resolved` is false and the FiGHT outcome is `ok` or `no_match`; each subject appears once, is among `sent_terms`, and is in no listed item's `matched_terms`.

**Evidence-set validator** (`domain/investigation_validation.py`):

- `find_backend_request_violations` takes the interpretation. A `fight_direct_search` step's requests equal `(FightBackendRequest(MITRE_FIGHT, interpretation.fight_terms, max_results_per_call),)`, mirroring the CVE branch.
- An interpretation invariant (`find_interpretation_fight_violations`): `fight_terms` is `()` or exactly `search_terms`; it is non-empty exactly when `fight_block` is None and `search_terms` is non-empty, and then the intent is `free_text` with no match and no excluded term. A `topic_resolved` block requires a match, an `excluded_term` block an excluded term, and a `cve_id_named` block an ID in `interpretation.cve_ids`, each with the first one as its subject; a `term_reads_as_topic` block's subject is one of `search_terms`, and the audit recomputes the registry reading.
- New `find_fight_step_violations`:
  - (a) at most one step per run consults `MITRE_FIGHT`;
  - (b) a `fight_direct_search` step appears only with an unresolved interpretation and non-empty `fight_terms`, and a `topic_context` step only with a resolved one;
  - (c) every `protocol_context` item was returned by an admitted step of the permitted kind, and its `matched_terms` are a subset of that step's `FightBackendRequest` terms (`find_threat_context_source_violations`). This also tightens the card path.
- Truncation (`protocol_context_truncated` in `topic_warnings`, `answer_truncated`), round and step-reason, charge and step topic-warning rules apply unchanged.

**Decision-path audit:**

- It needs one new branch. It recomputes the interpretation (`fight_terms` included), the stop table, `plan_first_round`, the gate and `judge_needs`, and it re-derives each step's requests through `list_backend_requests`.
- `list_backend_requests` raises `LookupError` for a `fight_direct_search` with empty terms, as it does for an unknown topic. `find_issued_request_violations` gets a pre-check beside the unknown-topic one: a `fight_direct_search` step whose recomputed `fight_terms` are empty is reported ("step N searches FiGHT with words the interpretation does not allow") and skipped, so `list_backend_requests` is never reached for it.
- Tampering is caught: adding `aka` to a recorded request, or relabelling `unsupported` as `found`, both fail.
- The docstring is updated.

**Replay** reruns the controller and needs no tool-specific code.

## 8. Evaluation and measurement plan

Each stage is measured on its own, before the next is added, against the dev.29 run (B's "Measured" format). The stages are working-tree states of one package; their runs stay under `~/data/cve-kgrag/` and are not replayed later. Since a report's `source_revision` reads only `<commit>+dirty` for a working tree, each stage's run directory also keeps the stage's full diff against the base commit, new files included (`git add -N` on the new files, then `git diff --binary <base>`), and the environment settings the run used (no key), and the measured row names the base commit, the diff's SHA-256 and the run directory:

| Row | Contents |
|---|---|
| dev.29 | baseline |
| C1 | direct search, contract, gate, validators, `NeedOutcome.not_evaluated`; FiGHT order unchanged; no unindexed-term need rule |
| C1 + C1b | the `term_not_indexed` → `not_found` need rule |
| C1 + C1b + C2 | phrase-unit BM25 order |

**Steps:**

1. `cve-kgrag eval gold-sets --gold eval/gold/m7b_cases.yaml --check eval/gold/m7b_sets.json`.
2. A deterministic planner eval over the 13 baseline cases (2026-10-27 store, FiGHT 3.1.0, default budgets) for each row.
3. **C1 against C1 + C1b, case by case**, beside the totals. Each row gives the need outcome, the stop and the uncovered words:
   - `sip ims signalling attacks` and `sip ims signaling attacks`: the verdict changes with spelling alone;
   - `IMSI catcher threats`: relevant results judged a gap, the cost;
   - `PFCP`, `Bluetooth`, `MQTT` and `WPA3` threat queries, and `srsRAN vulnerabilities` under `mixed`: generic matches no longer meet the need, the gain.
4. A **pre-registered synthetic table**, copied into the C section of `m7b-work-packages.md` and frozen before any run. Its queries come from the C probe list, with no NAS, Diameter or PJSIP subjects. Per query it reports `fight_terms`, matched count, subject@10 and @20, `term_not_indexed` subjects and the need outcome per row. Preliminary probe figures (phrase BM25, subject techniques in the top 20):
   - SS7 8, fake base station 18, network slicing 5, NRF 9, SEPP 7, authentication vector theft 10, LTE downgrade 4, GTP-U TEID 4, GTP and UPF 8, UPF user plane 20, UDM 17, AMF 16, IMSI catcher 14.
   - No-subject probes: PFCP 38, Bluetooth 28, MQTT 3, WPA3 29.
5. An **exclusion table**. These issue no FiGHT step, and each row states the expected `fight_block` reason and subject: `aka attacks`, `EPS AKA crash` (both scopes), `EAP-AKA' threats` and `5G, aka NR GTP threats` (`excluded_term`); `5Géaka threats` (`term_reads_as_topic`, `aka`); `CVE-x GTP threats` under `mixed` (`cve_id_named`). A model plan that adds `fight_direct_search` to them is rejected `fight_direct_search_blocked`.

No DeepSeek run is needed to land C. A later model run is its own step.

The predictions below are probe figures. Each stage is accepted on its end-to-end run over the baseline cases, which reports regressions beside improvements; the holdout cases are not run for tuning.

**Baseline predictions.** These are probe predictions stated before the run. A rise in `wrong_stop` is a quality gap C leaves open, reported as such beside the coverage gain, never offset by it. The predicted C1 → C1b drop from 5/13 to 4/13 rests on one spelling (below); it is a spelling-sensitive probe prediction, not a measured gain.

| Figure | dev.29 | C1 | C1+C1b | C1+C1b+C2 |
|---|---|---|---|---|
| wrong_stop | 3/13 | 5/13 | 4/13 | 4/13 |
| Protocol coverage mean (3 measured) | 0.222 | 0.347 | 0.347 | 0.556 |
| Protocol irrelevant items | 0 | 5 | 5 | 7 |
| false_gap | 0/5 | 0/5 | 0/5 | 0/5 |
| need_agreement | 13/13 | 13/13 | 13/13 | 13/13 |

**Unchanged in every row:**

- the 8 `implementation_only` cases (the tool is barred);
- named-cve-mixed (`exact_id`; `fight_terms` empty because a CVE ID is named);
- judged sufficiency (5/6/2).

5g-aka-threats and 5g-aka-implementations keep their steps, listed items, need outcomes and stop through C1b; only the schema and policy versions and the new interpretation fields differ. In C2, 5 allowed techniques swap for 5 others, FGT5044 moves from 30th to 27th and stays cut, and coverage stays 0.333 each. Both remain wrong stops.

**gtp-mobile-core (mixed, no topic).**

- Round 1 is `cve_search` plus `fight_direct_search` over (gtp, vulnerabilities, mobile, core): 71 matched, 20 listed, `protocol_context_truncated` 51.
- Every word is held, so the protocol need moves from `unsupported` to `found`. The run stops `sufficient` / ok.
- It is judged partial on implementation (0.333), so it is a **new wrong stop**. B cannot see an implementation shortfall.
- Protocol coverage: 0.0 → 0.375 (C1) → 1.0 (C2).

**sip-ims-threats (protocol_context_only, labelled insufficient).**

- It no longer stops before planning. `fight_direct_search` over (sip, signalling, attacks, ims) matches 36.
  - In C1 it stops `sufficient`, a wrong stop.
  - With C1b, `signalling` is held by no technique, so the need is `not_found` and the run stops `needs_unmet` / partial with its techniques listed. It is not a wrong stop.
- Irrelevant items in the top 20: 5 under the dev.29 order, 7 under BM25.
- The C1b saving rests on spelling: "signaling" is held by 36 techniques.

### 8.1 Measured

The stage rows, the case-by-case notes and the measured synthetic and exclusion tables
are in the C section of [`m7b-work-packages.md`](m7b-work-packages.md#c--fight-search-from-the-questions-own-words).
In short, against dev.29: `wrong_stop` 3 → 5 (C1) → 4 (C1 + C1b) → 4 (C2); protocol
coverage 0.222 → 0.347 → 0.347 → 0.556; protocol irrelevant items 0 → 5 → 5 → 7; every
case keeps its CVE answers in every row. The baseline predictions above held for every
figure. The synthetic subject counts in §8 step 4 were probe figures and differ from the
measured C2 counts on several queries (for example `UDM threats` 17 predicted, 9
measured, in the top 20); the measured table is the record.

**Fixture order edits (C2).** Only orders changed; no relevance label, expected technique
set or assertion was weakened. Each gold file states the order rule in a comment.

| Where | Old order | New order | Reason (phrase-BM25 scores) |
|---|---|---|---|
| `eval/gold/m3_topic_queries.yaml` (`5gaka`; `5G Authentication and Key Agreement`), `eval/gold/m4_trajectories.yaml` (`protocol_5gaka`), `eval/gold/m5_tool_queries.yaml` (`fight_5gaka`) | FGT1499.503, FGT5040, FGT5019, FGT5019.005, FGT5044 | FGT1499.503, FGT5040, FGT5019.005, FGT5019, FGT5044 | 5.974, 2.678, 1.829, 1.305, 0.237: FGT5019.005 names SUPI 8 times and UDM 10 times |
| `eval/gold/m4_trajectories.yaml` (`protocol_free_text`: `suci`, `discovery`) | FGT5019, FGT5040, FGT1499.503, FGT5019.005 | FGT5040, FGT5019, FGT5019.005, FGT1499.503 | 2.084, 2.047, 0.705, 0.514: FGT5040 names SUCI 11 times; FGT1499.503 names it once in the longest technique |
| `eval/gold/m4_trajectories.yaml` (`mixed_free_text`: `suci`, `concealment`) | FGT1499.503, FGT5019, FGT5040 | FGT5040, FGT5019, FGT1499.503 | 2.343, 1.817, 1.028 |
| `tests/integration/test_fight_fixture.py` (`SUCI`) | FGT1499.503, FGT5019, FGT5040 | FGT5040, FGT5019, FGT1499.503 | 1.379, 0.908, 0.514 |

## 9. What C does not do

- **Open explore, MCP `search_fight` or the CLI `topic` command to direct search.** Which queries reach FiGHT through them stays as ADR 0003 publishes it: only through a resolved topic. Their result order, and with it the techniques left after the limit cut, follows the shared order of §4 (decision 7).
- **Change the 5G-AKA card's terms**, or fix FGT5044 or FGT1036.501. That is a separate, reviewed card step, backed by the what-if in §4.
- **Add an admission rule, a frequency threshold, a "rarest word" rule or any word list.** Generic words in a 183-technique corpus produce large, reported truncation: 51 unlisted for gtp-mobile-core.
- **Fix the existing CVE-side `5Géaka` leak.** `interpret_request("5Géaka threats").search_terms` is `(5g, aka, threats)`, so `cve_search` sends `aka`. C blocks it on the FiGHT side only. Fixing the CVE side changes A1's search terms, so it is a separate, measured follow-up after C, with `5Géaka threats` as its regression case.
- **Add a refinement rule**, a second FiGHT step per run, or a model-chosen FiGHT vocabulary.
- **Detect an implementation shortfall** behind a met protocol need (B's stated limit).
- **Judge semantic sufficiency.** A protocol need C1b leaves `found` has every sent word held by some technique and a technique listed; that is not evidence that the techniques answer the question. This gap stays open.

**Known effect.** A mixed free-text product question such as `srsRAN vulnerabilities` will list FiGHT techniques matched only by `vulnerabilities` (14). With C1b the need is `not_found` because `srsran` is unheld, but the items are shown.

## 10. Decisions

1. **An excluded term blocks the direct search entirely.** *Settled by the owner on 2026-10-29: block.* The question is whether the words as a whole may enter a FiGHT search; removing the word that triggered a limit and sending the rest would bypass that question, and the remaining generic words could meet the need falsely. The recall lost is accepted over such a false match. Cost: `5G, aka NR GTP threats` gets no FiGHT search and its protocol need is `unsupported` with the `excluded_term` block recorded. Without the block, `aka attacks` would return 28 generic techniques, and `EPS AKA threats` and `EAP-AKA' threats` 3 each.
2. **A word the registry reads alone as a topic or excluded term blocks the search (all words or none).** *Settled with decision 1: block.*
   - This keeps one tokenization for CVE and FiGHT, recorded in `Interpretation` and checkable in the domain.
   - Rejected: sending the matcher's Unicode words (`5géaka`, `threats`) creates two word sets per query; dropping the word sends fragments; a non-ASCII character-class block turns away every accented or CJK question.
   - The owner's constraints with it: `fight_terms` is empty or all of `search_terms`, never a subset; the planner, gate, executor, validator and audit apply the one rule (§2.1); a blocked search makes the protocol need `unsupported` with the block's reason recorded, an allowed search that ran and did not meet the need makes it `not_found`, and a failed source or a breached budget is decided by the stop (§5).
3. **The unindexed-word need rule (C1b).** *Settled by the owner on 2026-10-29: adopt, measured as its own stage.* "Any technique returned meets the need" is too loose: generic matches can hide that the question's subject has no evidence. C1b closes part of that; mirroring B is a side benefit. It is a conservative term-coverage check, not a relevance judgement (§5). The stage table keeps its costs beside its gains (§8):
   - the `IMSI catcher threats` false gap (`catcher` is held by 0 techniques, although 12 of its 16 listed techniques name IMSI, as measured in §8.1): the results stay listed and the warning names `catcher`;
   - the `signalling`/`signaling` spelling dependence.
4. **Mixed free text plans two calls in round 1, not a round-2 rule.** *Settled by the owner on 2026-10-29: round 1, `cve_search` first.* The two needs are fixed before planning and the FiGHT search does not depend on the CVE results, so the complete round-1 plan goes through the existing budget pre-check; agreeing with the topic path follows from that. The `max_sources: 1` change (answer of CVEs → `budget_exhausted` with no answer) is documented in §2.3 and covered by a regression test.
5. **Explore, MCP and CLI stay topic-only.** *Settled by the owner on 2026-10-29: their admission is unchanged in C; direct search is open only inside an investigation.* C fills the protocol need of free text in an investigation; widening a public retrieval interface is a separate interface change, decided and accepted on its own. Admission and order are separate: admission stays as it is, while the shared order of decision 7 can change their order and the techniques they return after the limit cut. The two tools differ in capability, so their descriptions say so (decision 9).
6. **Gate code.** *Settled by the owner on 2026-10-29: the new `fight_direct_search_blocked`*, meaning the interpretation does not allow a direct FiGHT search, whatever the reason (excluded term, CVE ID, resolved topic, a word read alone as a topic). `PlanRejection` stays `code` + `step_position`; the reason and subject are read from `interpretation.fight_block`, which the audit recomputes, so no field repeats them. `term_outside_vocabulary` and `topic_not_resolved` would each misstate the fact: the call adds no word of its own, and a block can come from a resolved topic.
7. **Ranking (C2) inside package C, measured as its own stage after C1b.** *Settled by the owner on 2026-10-29: yes, and the card-path reorder is accepted.* One FiGHT order is simpler than two. It is a deliberate change of retrieval behaviour. The owner's conditions:
   - the scoring rule and tokenization are written out (§4), CVE-corpus parameters are not assumed to fit, no frequency filter is added, and ties go to technique ID;
   - C2 is measured after C1b against the baseline, improvements and regressions alike, and nothing is tuned on the holdout cases;
   - fixture gold order assertions may be updated, each with its old order, new order and reason; no relevance label changes to fit a result and no test is weakened;
   - the M7b gold-set labels do not change, but the new order changes which techniques are in the top 20, so coverage and stop quality are re-measured end to end; the predictions in §8 do not stand in for that run.
   FGT5044 and FGT1036.501 stay with the later card-term review, not tuned in C2.
8. **Versioning.** *Settled by the owner on 2026-10-29:* one step for the whole package, contracts dev.30 and policy m7b.2, on the existing axes, landed as one commit as B was. Each stage's measurement keeps its code diff and settings (§8) so the rows stay traceable.
9. **Tool name.** *Settled by the owner on 2026-10-29: `fight_direct_search`; the step reason stays `query_terms_fight`.* The name says how the call differs from the public MCP `search_fight`: it searches FiGHT with the query's own words, without a topic card, and only inside an investigation, while `search_fight` keeps its published meaning. Plans, trajectories, planner instructions, the gate code (`fight_direct_search_blocked`) and the docs use the one name; nothing is published yet, so no other name is kept.
10. **The outcome of a need no admitted step has a result for.** *Settled by the owner on 2026-10-29: a new `NeedOutcome.not_evaluated`*, defined as "no admitted result of a step that can serve the need, so whether it is met cannot yet be judged". `not_searched` was rejected: a timed-out or discarded call may have run, so "not searched" would mislead. `unsupported` comes first and means the need truly cannot be served, which after C no longer follows from a missing card alone; an admitted step whose source failed gives `source_unavailable`; `not_evaluated` and `not_found` are both open, with budget and deadline stops first and no extra retry; affectedness is unchanged; the evaluation still reads non-`found` as a gap. It lands in dev.30 with the schemas, B's document, and the audit and replay tests.

## 11. Files

**Production**

- `src/cve_kgrag/domain/planning.py`: tool, call, key, permit, sources, rejection code.
- `src/cve_kgrag/domain/investigation.py`: `NeedOutcome.NOT_EVALUATED`, `Interpretation.fight_terms`, `fight_block`, `StepReason`, `POLICY_STEP_TOOL_AND_ROUND`, `FightBackendRequest` docstring.
- `src/cve_kgrag/domain/search.py`: contract version.
- `src/cve_kgrag/domain/threat_context.py`: `unindexed_terms`, `matched_terms` description.
- `src/cve_kgrag/domain/topic_context.py`: warning code and order.
- `src/cve_kgrag/domain/validation.py`: unresolved-response source and warning rules (`is_direct_fight_search`, `find_unindexed_term_violations`, `collect_matched_terms`).
- `src/cve_kgrag/domain/investigation_validation.py`: backend request, interpretation invariant (`find_interpretation_fight_violations`), `find_fight_step_violations`, step topic-warning rules.
- `src/cve_kgrag/domain/evidence_needs.py`: protocol-context judging; `not_evaluated` for every need kind but affectedness; `is_need_open` counts it open; one explanation rule for both sides (`filter_unexplained_terms`, `list_unexplained_unindexed_fight_terms`).
- `src/cve_kgrag/domain/bm25.py` (new, C2).
- `src/cve_kgrag/application/investigation_policy.py`: `list_kept_cve_ids`, `find_fight_block`, `list_fight_terms`, `interpret_request`, stop table, round 1, costs, version.
- `src/cve_kgrag/application/plan_gate.py`.
- `src/cve_kgrag/application/investigation_tools.py`: explicit branches, `build_fight_request`, `require_fight_terms`, `build_topic_execution`.
- `src/cve_kgrag/application/topic_context.py`: `search_fight_directly`, extracted `_search_fight` and its `FightSearch`; `require_sent_terms` also checks `unindexed_terms`.
- `src/cve_kgrag/application/investigate.py`: planning input.
- `src/cve_kgrag/application/investigation_answer.py`: docstrings and comments only.
- `src/cve_kgrag/application/decision_path_audit.py`: the `fight_direct_search` pre-check in `find_issued_request_violations` (§7) and docstrings.
- `src/cve_kgrag/adapters/fight/pinned_yaml.py`: `unindexed_terms` (C1); BM25 order and `word_count`, with `list_term_keys`, `match_technique` and `TechniqueMatch` (C2).
- `src/cve_kgrag/adapters/lexical/bm25_index.py`: imports the shared formula (C2).
- `src/cve_kgrag/adapters/planner/openai_compatible.py`: instructions.
- `src/cve_kgrag/interfaces/knowledge_tools.py`: the `search_fight` description (requires a query that resolves to a reviewed topic; the investigation searches FiGHT from free text on its own).

**Schemas and gold**

- `schemas/v2/`: every snapshot carrying `schema_version`, with content changes in `query_plan`, `knowledge_evidence_set` and `topic_context_response`; and `manifest.json`, regenerated.
- `eval/gold/m3_topic_queries.yaml:25,39`, `eval/gold/m4_trajectories.yaml:101`, `eval/gold/m5_tool_queries.yaml:89` and `tests/integration/test_fight_fixture.py:39` (C2 order edits; each records the old order, the new order and the reason; no relevance label changes).
- `eval/gold/m4_trajectories.yaml`: new hand-labelled rows `protocol_free_text`, `mixed_free_text` and `excluded_term_protocol` over the packaged card, FiGHT excerpt and synthetic CVEs.

**Tests**

- Unit:
  - `find_fight_block` and `list_fight_terms` over the exclusion table, each block's reason and subject;
  - gate (topic resolved, excluded term, CVE ID, a word read alone as a topic (`5Géaka threats`), `implementation_only`, repeated);
  - planning input: `fight_direct_search` offered only when `fight_terms` is non-empty and the scope is not `implementation_only`;
  - `max_tool_calls: 1` with `mixed` free text: `budget_exhausted`, no step;
  - round 1 per scope;
  - `max_sources: 1` with `mixed` free text: `budget_exhausted`, no model call, no step;
  - needs outcomes;
  - the contextual-alias tripwire;
  - BM25 order and ties on the excerpt (excerpt orders only, never full-snapshot ranks);
  - A1 byte-equality.
- Integration:
  - an investigation over the excerpt for `protocol_context_only` and `mixed` free text;
  - FiGHT unavailable → `source_unavailable`;
  - `not_evaluated`: a round-1 plan over the source budget, a timed-out and a discarded step, and the `max_rounds: 1` topic call after named IDs, each beside a run whose admitted step failed its source (`source_unavailable`);
  - validator tamper cases;
  - decision-path audit, including a set with a `not_evaluated` need and a tamper that relabels it `not_found` or `found`;
  - a replay round trip, including a set with a `not_evaluated` need;
  - explore and MCP `search_fight` on an unresolved, non-excluded query under `protocol_context_only` (e.g. `gtp threats`) send no FiGHT search and record no source outcome (decision 5).
- Updates: `tests/integration/test_investigation_needs.py:92-101`, `tests/integration/test_decision_path_audit.py:961-966` and `tests/unit/application/test_investigation_policy.py:173-177` (the `crash` row now plans; the stop row moves to `EPS AKA crash`). In C2, `tests/unit/adapters/test_fight_source.py:131` is renamed and re-checked for the BM25 order instead of the distinct-term count.
- Fakes implementing `FightSource` are unchanged: the port gains no method.
- Files: new `tests/integration/test_investigation_fight_direct_search.py`, `tests/unit/domain/test_bm25.py` and `tests/unit/domain/test_evidence_needs.py`; the tripwire in `tests/integration/test_topic_cards.py`; updates in `tests/integration/test_decision_path_audit.py`, `test_fight_fixture.py`, `test_investigation_needs.py`, `test_investigation_replay.py`, `test_investigation_service.py`, `test_investigation_validation.py` and `test_topic_context_service.py`, `tests/unit/adapters/test_fight_source.py`, `tests/unit/application/test_investigation_policy.py` and `test_plan_gate.py`, and `tests/unit/domain/test_threat_context.py`; helpers in `tests/support/investigation.py` and `tests/support/investigation_runs.py`.

**Docs**

- `docs/rebuild/m7b-c-fight-direct-search.md` (this design).
- `docs/rebuild/m3-topics-and-threat-context.md`: the shared phrase-BM25 order under the FiGHT section (C2); beside topic context step 1 (an unresolved query consults no source), that an investigation can also search FiGHT with the question's own words (`fight_direct_search`) while explore keeps its rule.
- `docs/rebuild/m4-bounded-investigation.md`: tool list (Contracts), stop row, round-1 table (Policy m7b.2), costs (`max_tool_calls`), golden trajectory rows `protocol_free_text`, `mixed_free_text` and `excluded_term_protocol`, and the validator's step rules (a `fight_direct_search` step's backend request; its `term_not_indexed` topic warning only for its own sent terms).
- `docs/rebuild/adr/0002-bounded-investigation.md`: §2, `fight_direct_search` costs 1; a new decision: the card owns FiGHT when a topic resolves, otherwise one FiGHT search of the query's own words, never past an excluded term, a CVE ID or a word the registry reads alone; rejected alternatives; phrase BM25 rather than word-level BM25; §8, the FiGHT side blocks where the CVE side strips excluded-term tokens; §12, a `fight_direct_search` step warns `term_not_indexed` only for its own sent terms.
- `docs/rebuild/m5-mcp-and-sources.md` (the `matched_terms` rule): a FiGHT item's `matched_terms` are among the resolved topic's terms or, with no topic, the interpretation's `fight_terms`.
- `docs/rebuild/adr/0003-sources-and-mcp.md`: the investigation's `fight_direct_search` is the only direct path; the public `search_fight` still requires a resolved topic; with C2, its order is the shared FiGHT order.
- `docs/rebuild/adr/0005-model-planner-adapter.md`: planner instruction line.
- `docs/rebuild/PLAN.md` (the FiGHT line of the migration map): "matched by reviewed topic terms, or by the question's own words without a card; never derived from CVEs".
- `docs/rebuild/m7b-b-evidence-needs.md`: `not_evaluated` in the outcomes and the judging order; narrowed `unsupported`; the FiGHT term rule.
- `docs/rebuild/m7b-work-packages.md`: C section with the pre-registered tables and measured rows.
- `docs/rebuild/adr/0009-store-activation-and-serving.md` §11a: the warning order with `term_not_indexed`, and F counting the techniques of the one step that searched FiGHT.
- `README.md` (contract version) and `docs/runbook.md` (a direct FiGHT search can be truncated too).

**Size.** About 300–350 production lines in C1 + C1b and about 60 in C2. About 400–500 test lines, about 150 doc lines, and the regenerated schemas.
