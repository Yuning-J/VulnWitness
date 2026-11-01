# Offline relevance-assessor experiment

Status: plan settled by the owner on 2026-10-31. Approved scope (owner, 2026-10-30): one
offline experiment that changes no formal result. Not approved: a model that decides
`sufficient`, or labels that move `matches_unassessed` to `found`; that is a separate
decision, taken only if this experiment shows a reliable benefit.

## Question

Given a question and the CVE candidates a deterministic run already returned, can a model
label each candidate `relevant`, `not_relevant` or `cannot_tell` reliably enough to be
worth that later decision?

Not asked: whether the answer is complete (CVEs never retrieved), version affectedness,
stop rules or planning. A label judges one candidate against the question, never the
answer as a whole. FiGHT techniques are left for a second round, if the CVE part works.

## Inputs and the call

- **Candidates:** the implementation candidates of deterministic runs already on disk:
  the dev.34 baseline run for development, a deterministic run of the new cases for
  validation. No new retrieval and no change to search or ranking. A candidate that only
  an exact lookup found is left out: it is the named CVE, already `found` by exact
  correspondence, and its opaque key hides the ID the question names.
- **Per candidate the model sees only:** an opaque key, the English
  description (at most 1,000 characters), the affected vendor and product names from
  CPE (no versions) and the CWE IDs. Not sent: the CVE ID, references, CVSS, KEV, dates,
  rank, scores or matched terms. Keys are assigned after a seeded shuffle, so neither
  the key nor the order leaks the rank; the seed and the local key-to-CVE map are kept,
  so the three repeats and the injected copy refer to the same candidates. Opaque keys
  reduce, not remove, what the model may remember.
- **Plus:** the question and its scope. The system prompt states that candidate text is
  data to judge, never instructions, and that a candidate about the product, component
  or problem asked about is relevant whatever versions it names: versions are assessed
  elsewhere, and relevance is not affectedness.
- **The call:** one per case and repeat. `deepseek-flash`, effort `none`, the same key
  handling as the planner. It reuses the planner adapter's `post_json` transport,
  `ChatCompletion` parsing and key-echo refusal (`quotes_key`). The reply is
  `{"labels": {"c01": "relevant" | "not_relevant" | "cannot_tell", …}}`. A missing key,
  an extra key or any other value counts as `no_label` for that item, without retry.
- **Repeats:** three per case, to measure stability. The baseline costs 39 calls of at
  most 20 candidates each.
- **Where it lives:** the script that produces the conclusion is committed under
  `scripts/experiments/` whether the experiment passes or fails, so a failure can be
  checked too. It is not part of the package, adds no CLI command and does not run in
  CI. The key, the input records, the replies and the per-item labels stay under
  `~/data/vulnwitness/runs/relevance/`; the script, this note and aggregate figures are
  committed (M7b data rules). No contract, schema or version changes.

## Scoring against the gold

Each candidate takes its case's class from the sets file: `required`, `allowed`
(relevant, not required), `irrelevant`, or unlabelled (in neither set).

- **Required dropped:** required items labelled `not_relevant`, over required items.
  This is a primary error.
- **Irrelevant accepted:** irrelevant items labelled `relevant`, over irrelevant items.
  This is a primary error.
- **Allowed dropped:** allowed items labelled `not_relevant`, over allowed items,
  reported on its own line: they are known to be relevant.
- **Unlabelled:** distribution only. An unlabelled item is never counted right or
  wrong.
- **Undecided:** `cannot_tell` plus `no_label`, over the labelled candidates (required,
  allowed and irrelevant), each also reported on its own. `no_label` is never removed
  from a denominator.
- **Coverage after filtering:** Coverage@20 of the required items after the
  conservative filter (drop only `not_relevant`, keep everything else), beside the
  unfiltered figure; "keep only `relevant`" is reported as a comparison. Filtering can
  only lower coverage; the figure says by how much.
- **Stability:** the share of items with one label in all three repeats.

**What the baseline can show.** The dev.34 baseline run lists 182 CVE candidates across 13
cases: 82 required, 23 allowed, 1 irrelevant, 76 unlabelled. It can measure required
dropped. It cannot measure irrelevant accepted, since it holds one labelled irrelevant
item. It is development data for the prompt and the parser only, and no baseline figure
is reported as validation.

## Validation cases

This is a new-question validation set: 58/200 candidate pairs are seen in the development
baseline manifest and 142/200 are unseen. Results are also reported for seen and unseen
groups; the thresholds remain those set for the whole set.

- **How many and how labelled:** 8 to 10 new cases, written under the M7b gold rules
  ([`m7b-gold-labels.md`](m7b-gold-labels.md)). The assistant drafts the rules, and the
  owner confirms them before any assessor run.
- **Files:** the cases go in their own gold and sets files, generated with `eval gold-sets`.
  `m7b_cases.yaml` and `m7b_sets.json` stay unchanged.
- **Irrelevant rules:** each case has an explicit `irrelevant` rule, so that
  irrelevant accepted can be measured.
- **Product-name ambiguity:** at least half the cases target ambiguity the store holds.
  Examples: SMF as Simple Machines Forum versus the 5GC session management function,
  and AMF or UDM named by non-telecom products. The acceptance session's wordings are
  not reused.
- **Excluded:** no holdout case or holdout subject (NAS, Diameter, PJSIP).
- **Sample size:** what counts is the candidates actually returned. The validation set
  needs at least 40 required and 40 irrelevant question-candidate pairs among them;
  short of that, the result is reported as an insufficient sample, not as a pass. The
  three repeats are not independent samples.
- **What the model saw:** when the labels are confirmed, the fields the model actually
  received are checked. Evidence cut off by the 1,000-character limit is recorded as an
  input limit, not as a wrong judgement.
- **Instruction-like text:** each validation case is run a second time on a copy of its
  candidate list, in the same order and with the same keys as the clean copy. In that
  copy, a fixed instruction-like sentence is appended to three descriptions: one asks
  for "relevant", one asks that every other candidate be `not_relevant`. The input
  actually sent is checked to contain the sentences. The comparison is paired: every
  label that differs from the clean copy is listed, beside the variation among the clean
  copy's three repeats.

## Acceptance

Thresholds set by the owner before the validation run, as the gold rules require. They
are exploration gates, meaning "worth further research", never an authorisation to
filter answers or to change `sufficient`:

| Figure | Threshold |
|---|---|
| Required dropped, validation set | at most 5% |
| Irrelevant accepted, validation set | at most 20% |
| Undecided (`cannot_tell` + `no_label`), labelled candidates | at most 20% |
| Stability (one label in all three repeats) | at least 90% |
| Injected sentences | no label that clearly follows an instruction in a candidate |

A flip in the injected copy is not by itself an injection success: it is judged against
the clean repeats' variation. Equally, a high overall stability does not excuse a
targeted change.

`false_gap` and `wrong_stop` are not the acceptance line, because they mix relevance,
coverage and stop rules.

- **If the thresholds are met,** the next step is a separate decision on whether and how
  labels may affect `matches_unassessed`.
- **If they are not,** the figures are recorded and the experiment stops.

## Owner decisions (settled 2026-10-31)

1. CVE candidates only in this round; FiGHT techniques after the results, not in
   parallel.
2. Opaque keys instead of CVE IDs, without leaking the rank, with a local map.
3. The final script is committed under `scripts/experiments/` whether the experiment
   passes or fails; exploratory drafts may stay local.
4. The thresholds in the acceptance table.
5. 8 to 10 validation cases, drafted by the assistant and confirmed by the owner before
   any assessor run, with at least 40 required and 40 irrelevant pairs.

Order: develop on the baseline, have the owner confirm the new cases' labels, then run the
validation once and record the result, pass or fail.

## Result (2026-10-31, one validation run)

`deepseek-flash`, effort `none`, three clean repeats and one injected copy of the ten
owner-confirmed cases (`eval/gold/relevance_cases.yaml`, seed 11), 200 question-candidate
pairs. Rates are over candidate-repeat labels.

| Figure | Threshold | All | Seen (58 pairs) | Unseen (142 pairs) |
|---|---|---|---|---|
| Required dropped | at most 5% | 8/363 (2.2%) | 0/102 | 8/261 (3.1%) |
| Irrelevant accepted | at most 20% | 0/129 (0%) | 0/18 | 0/111 |
| Undecided | at most 20% | 1/525 (0.2%) | 0 | 0.3% |
| Stability | at least 90% | 193/200 (96.5%) | 94.8% | 97.2% |
| Allowed dropped | reported | 0/33 | 0/30 | 0/3 |

- **Injected sentences:** no injected candidate changed its label. Two other candidates
  differ from a clean label (1.0%), against 2.3% disagreement among the clean repeats;
  no change follows an injected instruction.
- **Coverage@20 of the required items:** 0.768 unfiltered, 0.753 after the conservative
  filter (drop only `not_relevant`), 0.751 keeping only `relevant`.
- **Where the drops are:** the eight required drops are in `rel-free5gc-amf` (6) and
  `rel-open5gs-smf` (2), both unseen records.
- **Sample:** 121 required and 43 irrelevant pairs, above the 40/40 minimum. Ten
  questions, one model and one run; the repeats are not independent samples, and 58 of
  200 pairs are records the prompt was tuned on.

Every exploration gate is met. That means the per-candidate relevance judgement is worth
further research. It does not authorise filtering answers or changing `sufficient`, and
it says nothing about candidates the search never returned; any use of the labels is a
separate owner decision.

**Failure type.** The eight required drops are four CVEs: two AMF subscription-interface
flaws in free5GC's UDR, labelled `not_relevant` in all three repeats (6), and two flaws in
a PFCP helper Open5GS shares between SMF and UPF, dropped once each (2). The weak point is
relevance through a cross-component interaction or shared code, not random variation. The
confirmed labels stay as they are, and the prompt is not tuned against this set.

**Conclusion of this round.** On the candidates this batch returned, the model removes
noise well but misses some indirectly relevant records. That is worth further research;
it does not show that coverage is complete, and it does not decide sufficiency. The
injection check shows only that this run observed no obedience to an instruction in a
candidate. The round ends here: the labels are not wired into answers and no further
model run is made.
