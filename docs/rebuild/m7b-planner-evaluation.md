# M7b — planner evaluation on an imported store

Status: accepted by the owner and implemented.

M7b runs the M7a planner evaluation ([`m7a-planner-baseline.md`](m7a-planner-baseline.md))
on the active corpus store and the operator FiGHT snapshot, and scores each run against the
hand-labelled gold cases ([`m7b-gold-labels.md`](m7b-gold-labels.md)). The planner, the
runner and the behaviour figures are M7a's, unchanged; M7b adds where the cases run, what
binds them to their data, a dataset identity, and a `sufficiency` section.

## The command

```bash
cve-kgrag eval planner --gold eval/gold/m7b_cases.yaml --sets eval/gold/m7b_sets.json \
  --out eval-results [--model-runs N]
```

The gold file is read once, within the existing 1 MiB cap, and parsed once with
`load_strict_yaml`, the one YAML entry point both loaders use; no other parser or text scan
looks at it. Its top-level keys then decide which evaluation runs:

| Top-level keys | Evaluation | `--sets` |
|---|---|---|
| `trajectories`, and none of the M7b keys | M7a: the packaged fixture, each case's FiGHT choice | refused (exit 2) |
| `cases`, `corpus_content_sha256` and `fight_snapshot_sha256`, and no `trajectories` | M7b: the active store and the operator FiGHT snapshot | required (exit 2 without it) |
| some but not all of the three M7b keys, such as `cases` alone | none | exit 2 |
| `trajectories` with any M7b key, or none of them | none | exit 2 |

The parsed document then goes to its format's loader (`load_gold_cases` or
`load_gold_file`), which validates it whole; the classification looks at the key names
only. Every refusal is the server's sentence, never a quotation of the file.

Every other rule of the command is M7a's: `--model-runs`, the planner settings, `--out`
outside the package and the store root, the owner-only result directory, the stop
conditions. An M7b evaluation additionally needs
`CVE_KGRAG_STORE_ROOT` and the operator FiGHT snapshot (exit 2 without them).

## Binding the files to the data

`eval gold-sets` writes `gold_file_sha256`, the SHA-256 of the gold file's bytes, into the
sets file beside the two data digests, so a sets file derived from an earlier revision of
the gold file is refused even over the same data. It is a digest of what the sets were
derived from, not a version: `--check` still re-derives the sets, and passes before an M7b
run is made, so the evaluation does not repeat that derivation.

Before the first case runs, in this order, and nothing runs if a step fails: a sets file
that is not one, or a digest that disagrees, ends the command with exit 1 and one line
naming it; missing settings or a store or snapshot that cannot be served are usage errors
(exit 2), as for every command:

1. Read the gold file (above) and the sets file. The sets file is read within the 4 MiB cap
   `eval gold-sets --check` uses and validated by a strict, bounded model: a JSON parse
   error, deep nesting (`RecursionError`) or a validation error ends the command with
   exit 1 and a fixed sentence, never a traceback or a key of the file. The model refuses
   any key it does not name, at the top level and in each case; requires the file's case
   IDs to be exactly the gold file's; allows in each case only the subject kinds the
   case's gold rules have; requires every ID to be a well-formed CVE or FiGHT technique
   ID by kind, listed once and in sorted order (the file cap bounds how many); and
   refuses a case whose `required`, `allowed` and `irrelevant` lists overlap. It does not
   re-derive the sets: their content is `--check`'s to prove, and this model only stops a
   malformed or hand-edited file from producing scores that look trustworthy.
2. Compare the digests the files state: the sets file's `gold_file_sha256` with the gold
   file's bytes, and its corpus and FiGHT digests with the gold file's; the configured
   snapshot's SHA-256 with the gold file's.
3. Load and verify the store `ACTIVE` names (`load_served_corpus`) and the operator
   snapshot (`load_fight_source`), once each.
4. Compare the loaded store's `corpus_content_sha256` with the gold file's.
5. Build one serving data plane over them, which every run of every case shares.

## Loading once

The data plane is read-only, so all runs share it: the 396,211-record store uses time and memory
to load (PLAN.md), and loading it per case or per run is not an option.
`CaseRunner` therefore receives its data planes instead of building them from a fixture
bundle per case: for M7a one over the packaged excerpt and one with FiGHT unavailable,
built once each from the fixture, chosen by each case's `sources.mitre_fight`; for M7b
the one plane above.

Everything else stays as in M7a. A case builds its deterministic service once, and its
model service once for all its model runs; the one `ThreadedCallRunner` serves the whole
evaluation. What is each run's own is what each `investigate()` call creates: its budget,
deadline, trajectory and result. Before each run the runner still waits for calls earlier
runs abandoned and checks the package digest.

## Cases

An M7b case is named in the report by `case_sha256`, the canonical SHA-256 of its request
and the FiGHT source it runs on (`operator`), as an M7a case is by its request and FiGHT
choice; the behaviour sections key their entries by it. The `sufficiency` section carries
both `case_sha256` and the gold file's `case_id`, so a reader sees which case an entry is
and the two sections join on the hash, never on array order.

Two cases with different IDs can carry the same request, and so the same `case_sha256`;
they would overwrite each other's evidence-set files and break the join. The M7b loader
therefore refuses a repeated `case_sha256`, as the M7a loader refuses a repeated case.
The 17 committed cases have 17 distinct hashes.

A case needs at most one CVE category: the gold loader refuses one that needs both
`named_cve` and `implementation_cves`, so each run's CVE figures go to exactly one of them.

## Identity

`identity` gains `dataset`:

- M7b: `cve_search_version` (`corpus-store-v1@sha256:<corpus_content_sha256>`),
  `fight_snapshot_sha256`, and `sets_sha256`, the SHA-256 of the sets file's bytes;
- M7a: the fixture's `cve_search_version`, and `fight_profile: per_case`, since its
  cases choose between the packaged excerpt and no FiGHT source.

Two reports compare only when their identities are equal, so protocol figures over
different FiGHT snapshots never compare. `evaluation_format_version` stays 1: no live
report has been made in format 1, so it is completed before its first use, not replaced.

## The `sufficiency` section

Present for an M7b evaluation only, with a `deterministic` part and a `model` part (null
without model runs), never averaged together. Each part holds `cases`,
`evidence_quality` and `run_quality`.

### What a run is judged on

Only what the answer lists: the CVE IDs of `implementation_candidates` and the technique
IDs of `protocol_context`. Items the answer truncated do not count. For each category the
case needs, against that category's sets (`cves` for `named_cve` and
`implementation_cves`, `techniques` for `protocol_context`):

- **coverage@20**: required items listed over min(|required|, 20), where 20 is the
  server's cap on an answer section, whatever `max_results_per_call` the request set;
  `null` when required is empty;
- **covered**: required is non-empty and the coverage is 1;
- **irrelevant items** and **unjudged items** listed (unjudged: in none of required,
  allowed or irrelevant).

`affectedness` has no evidence and is never covered. The run's **judged sufficiency** is
`sufficient` when every needed category is covered, `partial` when not and the answer
lists a required item of some needed category, `insufficient` otherwise. Then, for the
whole run:

- **wrong stop**: `stop_reason` is `sufficient` and the judged sufficiency is not;
- **premature no-evidence**: `stop_reason` is `no_evidence` and the label is `sufficient`
  or `partial`;
- **unflagged gap**: the label is `partial` and the answer gives no signal for a needed
  category the gold sets hold no evidence for (`affectedness` always, or a category whose
  required set is empty): `applicability_unknown` for `affectedness`;
  `topic_not_resolved`, `topic_pending_review` or a FiGHT source outcome other than `ok`
  for `protocol_context`. A CVE category with an empty required set has no defined
  signal, so `eval gold-sets` refuses a `partial` case with one; a run that misses
  evidence the gold sets do hold is measured by coverage and wrong stop, not here;
- **affectedness violation**: a product applicability other than `unknown`.

### `cases`

One entry per case: `case_sha256`, `case_id`, `split`, `label`, `runs`, the judged
sufficiency counts, a `RateSpread` of coverage@20 per needed category over the case's
runs, the irrelevant and unjudged item counts per category, and the counts of each of
the four run judgements.

### `evidence_quality`

By split (`baseline`, `holdout`), then by category (`named_cve`, `implementation_cves`,
`protocol_context`), over the runs of non-`uncertain` cases that need the category; a
`mixed` case's runs count in each category it needs:

- `category_runs`;
- `coverage`: a `RateSpread` of coverage@20 over the category-runs whose required set is
  non-empty, with `measured` their count;
- `covered`: a `Proportion` over the same category-runs;
- `irrelevant_items` and `unjudged_items`: totals, and `runs_with_irrelevant`: a
  `Proportion` over all category-runs, which includes negative cases, where a returned
  irrelevant item is the false positive the case exists to catch.

`implementation_family` adds `named_cve` and `implementation_cves` together beside them,
never in their place.

### `run_quality`

By split only, counting each run once whatever categories it needs:

| Field | Counts | Over |
|---|---|---|
| `runs` | every run | — |
| `uncertain_runs` | runs of `uncertain` cases | — |
| `judged` | runs by judged sufficiency | runs of non-`uncertain` cases |
| `wrong_stop` | wrong stops | runs of non-`uncertain` cases |
| `premature_no_evidence` | premature no-evidence | runs of `sufficient` or `partial` cases |
| `unflagged_gap` | unflagged gaps | runs of `partial` cases |
| `affectedness_violation` | affectedness violations | every run, `uncertain` included |

Each rate is a `Proportion`. An `uncertain` case is run and its runs are counted, but it
enters no figure that depends on its label; affectedness is an invariant and is counted
over every run.

## What the report holds

Counts, rates, hashes, case IDs from the committed gold file, and labels: no query, plan
text, model reply, endpoint or path, so its aggregate figures may be committed under the
M7b data rules. Per-run detail is not repeated in a further file: the evidence sets in the
local result directory are the record every figure is recomputed from.

## Changes to M7a

The M7a design record gains two small notes: `identity.dataset`, and that format 1 was
completed with the M7b sections before its first live use, with a link here. M7a's runs,
cases and behaviour figures are unchanged; its report differs only by `dataset`.

## Tests

- Dispatch: each row of the format table, including a partial M7b signature, both and
  neither, `--sets` given or missing for each format, a file over the cap, and YAML the
  strict loader refuses; no refusal quotes the file.
- Cases: two cases with different IDs and the same request are refused.
- Sets file: malformed JSON, deep nesting, an unknown key at the top and in a case, case
  IDs that differ from the gold file's, a subject kind the case has no rules for, a
  malformed, repeated or unsorted ID, and overlapping lists each end the command with
  exit 1, no traceback and no key of the file in the message.
- Binding: each digest mismatch of steps 2 and 4 stops the command before any run; a sets
  file from another gold file revision is refused.
- Loading once: an M7b evaluation over a synthetic store builds one data plane for all
  cases and runs.
- Judgement: each category's coverage, covered and irrelevant/unjudged counts, judged
  sufficiency, and each run judgement on hand-built evidence sets, including empty
  required sets, truncated items, `uncertain` cases and a `mixed` case counted once in
  `run_quality` and in each category of `evidence_quality`.
- The M7a evaluation over its gold file still gives its baseline, with `dataset` added.
