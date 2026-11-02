# Work package B: evidence needs decide when an investigation stops

Status: rules settled by the owner on 2026-10-29; implementation follows them. Baseline:
commit 06427e3, contracts `2.0.0-dev.27`.

## Problem

`decide_assessment` stops `sufficient` as soon as any answer source returned anything. The
first model run ([`m7b-results-2026-10-28.md`](m7b-results-2026-10-28.md#causes)) showed
four failures: a `mixed` question with CVEs and no protocol context stops `sufficient`; a
product question answered only by matches of its other words stops `sufficient` (no record
names `srsran`, and the search warns `term_not_indexed`); a version question written only
in text ("Is Kamailio 5.8.2 affected by known vulnerabilities") never engages
affectedness, since only product filters do; and round 2 asks the model for a plan when no
legal action is left.

B changes when a run stops and whether it refines. It never removes or reorders an answer.

## Needs

A need has a kind, a subject and an outcome. Kinds: `named_cve` (subject: the ID),
`implementation_cves`, `protocol_context`, `affectedness` (subject: the filter value or the
product and version the text names). Outcomes: `found`, `matches_unassessed`,
`not_found`, `source_unavailable`, `unsupported`, `not_evaluated`. `not_evaluated`,
`not_found` and `matches_unassessed` are open; `source_unavailable` and `unsupported` are
final. The needs are derived by code from the request and its interpretation, never from
gold, in this order:

1. One `named_cve` per CVE ID the query names.
2. A text target. Without IDs, the query's search terms or a resolved topic are one. With
   IDs, only a resolved topic is: "What is CVE-X" is answered by the named lookup, and text
   B cannot recognise as a further target adds no need. For a text target, `mixed` and
   `implementation_only` add `implementation_cves`, and `mixed` and
   `protocol_context_only` add `protocol_context`. `mixed` allows both kinds of evidence; a
   query of IDs alone needs only the named CVEs.
3. Unless the scope is `protocol_context_only`, one `affectedness` per filter vendor,
   product and purl, then one per product version the text asks affectedness of.

**Product versions the text asks affectedness of.** A word, one space and a dotted number
(`kamailio 5.8.2`, `open5gs v2.7.2`), read from the normalized query, where the word is a
whole vendor or product name some stored record carries as affected or of unknown status,
and the query holds one of the
words `affect`, `affected`, `affecting`, `affects` or `vulnerable`. Four parts of at most
255 read as an IPv4 address and never count. Without one of those words a product and
version is a search term, not a need: of the whole names in the 2026-10-27 store,
`release`, `server`, `core`, `network` and `update` are names, so "release 15.2" alone must
not raise one. The pairs are recorded in `interpretation.affectedness_mentions`.

Each candidate's optional `nvd_version_notes` annotates those mentions against the
record's retained NVD CPE version conditions, matching whole vendor or product names
case-insensitively. One note per mention reports `hit` with the matching entry and
condition, `no_hit` without claiming the version is unaffected, or `unknown` with
`no_matching_product`, `no_version_condition` or `version_not_comparable`. Numeric dot
segments compare numerically (5.10 > 5.9), padding trailing segments with zero
(2.7 == 2.7.0); a non-digit segment is uncomparable, except an exact condition may match
by trimmed string equality. Any hit wins; without one, a missing or uncomparable
condition keeps the note unknown. The full configuration and environment conditions
were not evaluated because the configuration tree and non-vulnerable CPE conditions
are not retained. The note changes no need, stop rule, retrieval or Trustify behavior.

So "Is Open5GS 2.7.2 affected by CVE-X" needs the named CVE and affectedness; adding "and
which 5G-AKA threats apply" resolves a topic, which also adds `implementation_cves` and,
under `mixed`, `protocol_context`.

## When a need is met

Judged from the admitted steps and the answer only. Which tool can serve a need is fixed:
`cve_exact_lookup` the named CVEs, `cve_search` implementation CVEs, `topic_context`
implementation CVEs and protocol context, `fight_direct_search` protocol context when no
topic resolved ([`m7b-c-fight-direct-search.md`](m7b-c-fight-direct-search.md)), no tool
affectedness.

**The rule.** A need is `found` only through an exact correspondence or a reviewed
mapping: an exact lookup that returned the named CVE, or the topic call of a resolved,
reviewed topic that returned evidence. The resolved card must have review status
`reviewed`; a `pending_review` card can retrieve evidence but cannot establish `found`.
Matches from a pending-review topic or a search on the question's own words
(`cve_search` or `fight_direct_search`) give `matches_unassessed`: matches were found and
their relevance was not assessed. It is not a finding that no relevant evidence exists,
and the answer keeps every match. The current version does not judge free-text results
sufficient automatically; it has no relevance judge for a question no reviewed topic
covers, so it says that the matches are unassessed rather than calling them enough.

The basis of `found` is how the evidence was reached, not proof that the answer is
sufficient: "a trusted source returned it" does not make an answer complete. A topic's
card maps the topic to its searches and techniques, and that mapping can still list CVEs
that do not answer the question, or miss ones that do, so a topic run can stop
`sufficient` wrongly. Nothing here judges the relevance of what a topic call lists.

Every need but affectedness is `not_evaluated` when no admitted step of a tool that
serves it has a result: no such step ran, or none was admitted (`timed_out`, discarded
after the deadline or over the context budget, or `rejected_invalid_evidence`). Whether
it is met cannot yet be judged; the outcome does not claim that no call was made. It is
checked after `unsupported` and before every other outcome, so an admitted step whose
source failed gives `source_unavailable`, never `not_evaluated`.

- **named_cve(ID)**: `not_evaluated` without an admitted exact lookup naming the ID;
  `found` when such a lookup returned the ID; `source_unavailable` when its CVE source
  failed; else `not_found`, and the step's `unknown_cve_id` or `excluded_by_filters`
  warning says why.
- **protocol_context**: with a resolved topic, the serving steps are the admitted topic
  steps. Without one, `unsupported` when the query's words may not enter a FiGHT search
  without a reviewed topic (`interpretation.fight_terms` is empty and
  `interpretation.fight_block` records the reason and its subject: an excluded term, a CVE
  ID, or a word the registry reads alone as a topic or excluded term); otherwise the
  serving steps are the admitted direct FiGHT searches (`fight_direct_search`). Then
  `not_evaluated` without a serving step; without a topic, `not_found` when a serving
  step warned `term_not_indexed` for a sent word the interpretation does not explain
  (the FiGHT term-coverage rule below); when the answer lists a technique a serving step
  returned, `found` from a reviewed topic step and `matches_unassessed` from a
  pending-review topic or a direct search; `source_unavailable` when a serving step's
  FiGHT source failed; else `not_found`.
- **affectedness**: `source_unavailable`, since no deployment serves it (ADR 0003); the
  answer carries `applicability_unknown` for the subject.
- **implementation_cves**: `not_evaluated` without an admitted CVE search or topic
  step; `not_found` when an admitted search warned `term_not_indexed`
  for a search term the interpretation does not explain. The words of a matched alias
  or context term, and those words written together, explain a term, so `5GAKA` and
  `5G-AKA` judge alike; so do, in a question whether a product version is affected, the
  words of the version and the word that asks it. Otherwise, with a
  resolved topic, `found` when the answer lists a CVE an admitted reviewed topic step found,
  at whatever relevance tier the card gave it, and `matches_unassessed` when only a
  pending-review topic or an admitted search of words (a model's plan) found the listed
  CVEs. Without a topic, `matches_unassessed` when the admitted searches together sent
  every search term and one of them returned a CVE. `source_unavailable` when a CVE source
  failed; else `not_found`.

The term-coverage check is a conservative check of the retrieval process: it catches a
word no record holds and a plan that dropped a word. It judges no relevance, so a query
whose every word some record holds ("srs ran vulnerabilities") is not thereby met; its
matches stay `matches_unassessed`.

The protocol need of a direct FiGHT search has the same term-coverage check. FiGHT's
`term_not_indexed` is a topic warning a direct search raises for each sent word no
technique holds (a topic's card search never raises it); the explanation rule is the
CVE side's (`list_explained_terms`). It is a conservative check of what the retrieval
covered, not a judgement of relevance: `not_found` says the evidence does not meet the
whole protocol need, never that FiGHT holds nothing relevant, and a direct search whose
every word some technique holds gives `matches_unassessed`; it removes no technique,
and the warning names the uncovered word (`catcher` in `IMSI catcher threats`). FiGHT's
warning never reaches the implementation need, whose rule reads search warnings only.

## Control flow

The state machine is unchanged; assess, refine and the stop rules change.

- **Assess**, in order: invalid evidence (`invalid_evidence`); a breached cap
  (`budget_exhausted`); an admitted step saw an answer source fail (`source_unavailable`);
  every need `found` (`sufficient`, `answer_found`); an answer whose only unmet needs are
  affectedness (`source_unavailable`, `affectedness_unavailable`); otherwise the run moves
  to refine (`needs_open`).
- **Refine** plans at most one call for an open (`not_found`, `not_evaluated` or
  `matches_unassessed`) implementation or protocol need, never retrying a call already
  issued; a named CVE no lookup found is met by no other call, so an unknown ID beside
  plain text refines nothing. With a resolved topic not yet called and such a need open,
  the topic call (`topic_after_unknown_ids` when every named ID is unknown,
  `topic_after_literal_miss` when a literal search of a topic query, which only a
  model's plan issues, did not meet the need, else `topic_for_open_need`); else, with
  implementation CVEs open, search terms the admitted searches did not all send and no
  unexplained unindexed term, the search of all of them (`query_terms_for_open_need`).
  With no such call the run stops (`no_refinement_available`); under `max_rounds` 1 a
  call breaches the round cap. Round 2 runs, and a configured model is consulted for it,
  only when there is a call. Free text whose matches are unassessed has none: every
  search term was sent and no rule plans FiGHT, so the run ends without a repeated
  search.
- **Stopping with open needs**: an answer gives `needs_unmet` (status `partial`); no
  answer gives `no_evidence`, or `source_unavailable` when affectedness was needed. After
  round 2 the basis is `needs_open_after_refinement`.

## Contract

Contracts move to `2.0.0-dev.28`; the deterministic policy to `m7b.1`.

- `CoverageAssessment.needs`: the needs, in derivation order, with their outcomes.
- `Interpretation.affectedness_mentions`; `ProductKind` gains `product_version`, so
  `product_applicability` lists each mention with status `unknown`.
- `StopReason.needs_unmet`; `DecisionBasis` `no_answer_refinable` and
  `no_answer_after_refinement` become `needs_open` and `needs_open_after_refinement`;
  `StepReason` gains `topic_for_open_need` and `query_terms_for_open_need`.
- `EvidenceCatalog.names_product`; `interpret_request` and the decision-path audit take the
  evidence catalog, which both callers already hold.
- `NeedOutcome.matches_unassessed` (contracts `2.0.0-dev.34`, policy `m7b.4`; package 2 in
  [`m7b-work-packages.md`](m7b-work-packages.md#package-2--topic-first-and-unassessed-matches)).

## Verification and replay

The audit recomputes the interpretation, the needs after each round and every decision
from the recorded set, and checks `coverage.needs` against the needs the answer and admitted
steps give. The validator checks the stop's direct consequences without restating the
assess order: a `sufficient` run has every need `found`, and a `needs_unmet` run has an
answer and an unmet need other than affectedness. A budget, invalid-evidence or
source-failure stop takes precedence over the needs, so a run whose needs are all met can
still stop on a breach. Replay already compares `coverage` and `interpretation`.

## Evaluation

Runtime never reads gold. The report reads gaps from `coverage.needs`: a needed category
signals a gap when its need is not `found`. `false_gap` counts runs judged sufficient whose
stop is not `sufficient`, the counterweight to `wrong_stop`; `need_agreement` counts runs
whose need kinds equal the case's. `evaluation_format_version` moves to 3.

## What B does not do

- It removes and reorders no answer, and adds no admission rule, word list for products or
  fillers, or frequency threshold.
- It cannot tell generic matches from relevant ones when every query word is held by some
  record: it labels them `matches_unassessed` instead. It cannot see a shortfall of
  relevant evidence in what a topic call lists either (`5g-aka-threats`,
  `5g-aka-implementations` in the first run).
- It does not search FiGHT without a card. That is C's direct FiGHT search
  ([`m7b-c-fight-direct-search.md`](m7b-c-fight-direct-search.md)), so a protocol need is
  `unsupported` only when the query's words may not enter a FiGHT search.
- It misses versions written with a word between ("kamailio version 5.8.2"), multi-word
  products ("linux kernel 5.10.1") and hyphenated forms.
- "What is CVE-X" searches no residual words; text B cannot recognise as a target is
  a stated limit.
- The round-1 model call when the policy's own round-1 plan is over the source budget is
  a separate change after B ([`PLAN.md`](PLAN.md#follow-up-model-planner-adapter)).

## Measured on the 13 baseline cases

A deterministic M7b run over the 2026-10-27 store and FiGHT 3.1.0 (`gold-sets --check`
passed first), against the same run before B. These figures are B's, under policy
`m7b.1`; package 2's rule moves them (wrong_stop 2/13, false_gap 4/5), see
[`m7b-work-packages.md`](m7b-work-packages.md#package-2--topic-first-and-unassessed-matches). Every case returns the same answers in the
same order and keeps its judged sufficiency (5 sufficient, 6 partial, 2 insufficient);
coverage is unchanged (named CVEs 1.0, implementation CVEs 0.83, protocol context 0.22).

| Figure | Before | After |
|---|---|---|
| `wrong_stop` | 7/13 | 3/13 |
| `unflagged_gap` | 2/2 | 0/2 |
| `false_gap` | not measured | 0/5 |
| `premature_no_evidence` | 0/11 | 0/11 |
| `need_agreement` | not measured | 13/13 |

- `gtp-mobile-core` stops `needs_unmet`: implementation CVEs found, protocol context
  `unsupported`.
- `kamailio-version-affected` and `open5gs-named-affected` stop `source_unavailable`
  (`affectedness_unavailable`), with `kamailio 5.8.2` and `open5gs 2.7.2` as
  `product_version` entries of unknown applicability.
- `srsran-negative` stops `needs_unmet` with its 20 answers kept: `srsran` is held by no
  record.
- The three wrong stops left are shortfalls of relevant evidence B cannot see:
  `5g-aka-threats` and `5g-aka-implementations` (FiGHT recall and ranking, C's work) and
  `oai-cn5g` (top-20 ranking).

The holdout cases were run with the others and not read.
