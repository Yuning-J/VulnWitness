# M7b — gold cases and sufficiency labels

M7b repeats the M7a planner evaluation ([`m7a-planner-baseline.md`](m7a-planner-baseline.md))
on an imported corpus store, and adds what M7a could not measure: recall, whether an
answer's evidence suffices, and wrong stops. This file fixes how the truth those need is
written down, before any case is run.

## Who labels, and in what order

The assistant drafts each case and its proposed label; the owner confirms or changes it,
case by case. Each case's CVE sets come from rules a script evaluates over the store's
records, never from what the search service or a model returns. Cases are chosen as an
analyst would ask them, before any of them is run through the system, so that the drafter
cannot pick questions the current implementation answers well. The planner model under
evaluation takes no part; the assistant drafts and the owner alone confirms or changes each
label.

1. The owner calibrates this rubric on the examples below.
2. The assistant drafts the remaining cases; the owner confirms each one.
3. Cases, sets and labels are committed before the first M7b run, and never edited to fit
   a result. A later change is an ordinary commit whose message gives the reason; the
   report names the commit and the corpus it ran on.

## Evidence categories

An answer's evidence falls into these categories. A case lists the ones its goal needs.

| Category | What it is | Where it comes from |
|---|---|---|
| `named_cve` | the record of a CVE the query names | the corpus store |
| `implementation_cves` | CVE records of the product or component the question is about | the corpus store |
| `protocol_context` | FiGHT techniques describing threats to the protocol or procedure | FiGHT 3.1.0, full snapshot |
| `affectedness` | a verdict that a given product version is or is not affected | a verified affectedness source: none is available in M7b |

A CVE count never stands in for `protocol_context`, and `protocol_context` never stands
in for CVEs. With no verified affectedness source, no evidence of the `affectedness`
category exists, so the only correct product applicability is `unknown`.

## A case

Each case records:

- `id`, `split` (`baseline` or `holdout`) and `goal`: one sentence saying what the analyst
  wants to know;
- `request`: the query, the scope and any filters, exactly as the evaluation sends them;
- `needs`: the evidence categories the goal needs;
- `rules`: the rules that derive its sets (below);
- `sets`, derived by the rules over the store:
  - `required`: the gold-relevant pool a sufficient answer draws on. With 20 items or fewer,
    a sufficient answer holds all of them; with more, it holds any 20 (the server keeps at
    most 20 per answer section), and an item left out beyond that cap is not a miss. The 20
    is the server's cap, not a request's `max_results_per_call`: a request that asks for
    fewer results does not lower the bar;
  - `allowed`: relevant to the goal, may be returned, never required;
  - `irrelevant`: explicitly wrong for the goal, such as the same component in another
    product; returning one is counted;
- `label`: the human sufficiency label of the case, with its reason (below);
- `drafted_by: assistant`, `confirmed_by: owner`, `confirmed_on` and the
  `corpus_content_sha256` of the store its sets were derived from.

A returned CVE in none of the three sets is reported as unjudged, never as an error, so a
reasonable answer is not penalised for an item no rule anticipated.

## Rules

A rule is data the rule engine evaluates over the store's records (and, for techniques,
over the FiGHT snapshot). A prose description alone is never a rule. The engine derives
`allowed` as relevant minus required and refuses a case whose `required` is not a subset
of its relevant set, or whose `irrelevant` set overlaps it.

A rule tree nests at most 8 levels, joins at most 20 rules in one combinator, holds at
most 50 rules in all, and lists at most 50 values in one predicate, so a gold file cannot
make matching every record of a store arbitrarily slow.

A relevant rule may be broad. A required rule is narrow:

- a CVE is required only when it names the product, by CPE or by the product's name or a
  fixed alias as a whole word in its description, **and** meets the case's component or
  context condition. Many recent NVD records have no CPE yet, so a CPE-only rule would
  drop them silently;
- an acronym alone (GTP, AMF, UDM) never makes a CVE required: the description must also
  place it in a mobile-core context;
- required techniques are an explicit `technique_ids` list, each with a short reason. Term
  rules over FiGHT only propose the relevant set.

Predicates over a CVE record:

- `cpe`: `vendor:product` pairs, matched case-insensitively against the vendor and product
  parts of each affected product's CPE 2.3 name; `cpe_vendor` matches the vendor part alone;
- `description_any` / `description_all`: terms matched case-insensitively, as whole words,
  in the record's English descriptions;
- `reference_contains`: URL fragments, such as a project's repository, matched in the
  record's reference URLs;
- `cve_ids`: an explicit list of IDs with a `reasons` entry for each;
- `kev`: whether the record is in the KEV catalog;
- `all_of`, `any_of`, `none_of`: combinators.

Predicates over a FiGHT technique: `technique_ids` (with a `reasons` entry for each ID)
and `technique_any`, terms matched as whole words in its narrative fields: name,
description, `bluf`, `addendums`, `procedureexamples`, `preconditions` and
`postconditions`. FiGHT names
telecom functions mostly in procedure examples and addendums, rarely in the description.
Mitigations and references describe other objects and are not matched.

A case meant as negative also carries a `wide_check` rule (see the rubric below); its hits
are listed for the owner, never scored.

## The files and the command

- `eval/gold/m7b_cases.yaml`, written by hand: the `corpus_content_sha256` and the FiGHT
  snapshot SHA-256 the labels were confirmed against, then the cases.
- `eval/gold/m7b_sets.json`, generated, never edited: `gold_file_sha256`, the SHA-256 of
  the gold file it was derived from, those two digests, and each case's `required`,
  `allowed`, `irrelevant` and, when the case has one, `wide_check`, per subject kind, as
  JSON with sorted keys.

`cve-kgrag eval gold-sets --gold eval/gold/m7b_cases.yaml` derives the sets from the
store `ACTIVE` names under `CVE_KGRAG_STORE_ROOT`, read record by record (the stored records
for the 396,211-record store), and from the operator FiGHT snapshot
(`CVE_KGRAG_FIGHT_SNAPSHOT_PATH` and `_SHA256`), and prints them. With
`--check eval/gold/m7b_sets.json` it compares them with the recorded file instead and
names the cases that differ. Either way it refuses (exit 1) a store or snapshot other than
the ones the gold file names, and a case whose sets do not support its label:

- `sufficient` needs a non-empty required set for every needed category, so a case
  that needs `affectedness` is never `sufficient`;
- `partial` needs a needed category with required items and one without;
- `insufficient` needs every needed category's required set empty, and a wide check
  whose every hit is explicitly `irrelevant`;
- `uncertain` is the owner's call and is not checked.

The gold file and the sets file are committed together, and `--check` passes before an
M7b run, so a gold file never silently scores against data its sets were not derived
from.

## The sufficiency rubric

There are two levels. The case label is human; the run's judged sufficiency is computed
mechanically from it.

### Case label: what this corpus and these sources can support

- `sufficient`: every category the goal needs exists in the corpus and sources, and every
  set the goal needs is non-empty.
- `partial`: at least one needed category exists and at least one does not. A question
  that needs `affectedness` is at best `partial` in M7b.
- `insufficient`: no needed category exists. For a case meant as negative, this needs a
  wider check than the case's own rules: a `wide_check` rule over vendor-only CPE matches,
  the product's names and aliases in descriptions, and its project domains in references.
  An empty search result alone never makes a case `insufficient`.
- `uncertain`: the wide check finds candidates the owner cannot settle, or the owner cannot
  judge the goal. An `uncertain` case is run and reported, but kept out of every score.

The label states the evidence and the goal, never what the deterministic policy or a model
concluded about the case.

### Run's judged sufficiency

For each run, over the candidates and protocol context its answer lists (items the answer
truncated do not count):

- a needed category is covered when its required set is non-empty and the answer holds
  at least min(|required|, 20) of its required items. A category with an empty required
  set is never covered, so an empty answer never makes a negative case sufficient, and
  `affectedness`, which has no evidence in M7b, is never covered;
- `sufficient` when every needed category is covered;
- `partial` when it is not sufficient and the answer holds at least one required item of
  a needed category;
- `insufficient` when the answer holds no required item.

### What is scored

- **Coverage@20** of `required`, per category: required items returned over
  min(|required|, 20). With 20 or fewer, this is recall; with more, any 20 score in full.
  With an empty required set it is `null` (not applicable), never 0 or 1.
- **Irrelevant returns**: count of `irrelevant` items returned; unjudged items are counted
  apart.
- **Wrong stop**: the run stopped as `sufficient` while its judged sufficiency is not
  `sufficient`.
- **Premature no-evidence**: the run stopped with `no_evidence` while the case label is
  `sufficient` or `partial`.
- **Unflagged gap**: the case is `partial` and the answer does not signal the missing
  category: `applicability_unknown` for `affectedness`; `topic_not_resolved`,
  `topic_pending_review` or a FiGHT source outcome other than ok for `protocol_context`.
- **Affectedness violation**: any applicability other than `unknown`.

Implementation figures (`named_cve`, `implementation_cves`) and protocol figures
(`protocol_context`) are reported apart, and the parts of a `mixed` case go to each.
Baseline and holdout cases are reported apart. Nothing is averaged across the two groups
of figures or the two splits.

## Holdout

About a quarter of the cases are `holdout`. Their sets and labels are settled with the
others, but no prompt, gate or policy change may be tuned on their results; a change
proposed after M7b is argued from baseline cases and then checked on the holdout.

## Scale

The initial set is 20 to 30 cases. It is a baseline for comparing planner variants on one
corpus, not a representative sample of telecom questions, and no figure from it is
reported as one.

## What is committed

The gold file (queries, scopes, CVE IDs, technique IDs, rules, labels and reasons), the
generated sets file (IDs and digests only), the rule engine and this rubric. Never NVD or KEV text, model replies, evidence sets, or local
paths (see the M7b data rules in [`docs/runbook.md`](../runbook.md)).
