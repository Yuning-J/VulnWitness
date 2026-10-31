# Evaluation and reproduction

Evaluation is a local operator tool, not a REST or MCP endpoint. It separates
planner behaviour, returned-evidence quality and stop decisions. None of these
alone proves overall telecom coverage.

## Offline checks

Install the locked development checkout as described in the [runbook](runbook.md#install).
Once its environment is installed, these checks require no external data or endpoint:

```sh
.venv/bin/ruff check
.venv/bin/ruff format --check
.venv/bin/mypy
.venv/bin/cve-kgrag schema check
.venv/bin/pytest -q
```

Tests use synthetic records, packaged FiGHT/MITRE excerpts, temporary imported
synthetic stores and local fake endpoints. They block non-loopback network access.
The fixture and offline tests reproduce directly from the checkout and locked
Python/dependencies. Schema snapshots are under `schemas/v2/`; their
[manifest](../schemas/v2/manifest.json) names the current contract.
CI's `scripts/ci/offline_lane.sh` also installs/checks the lock;
`scripts/ci/core_only_lane.sh` checks a built wheel without the development group
or optional extras. Those setup lanes can require package downloads.
`uv lock --check` checks lock metadata separately.

A fixture planner evaluation needs no external data or model:

```sh
.venv/bin/cve-kgrag eval planner \
  --gold eval/gold/m4_trajectories.yaml --out /data/cve-kgrag/evaluation
```

The `trajectories` format selects synthetic CVEs and each case's packaged/unavailable
FiGHT choice. `--sets` is not allowed for this format. This checks behaviour and
wiring; it is not a real-data recall benchmark.

## Real-store evaluation

Follow the [runbook](runbook.md) to activate an imported store and configure the
full catalogued FiGHT snapshot. The case file binds the corpus and FiGHT identities;
the generated sets additionally bind the exact case-file bytes.

```sh
.venv/bin/cve-kgrag eval gold-sets --gold /data/evaluation/cases.yaml \
  --check /data/evaluation/sets.json
.venv/bin/cve-kgrag eval planner --gold /data/evaluation/cases.yaml \
  --sets /data/evaluation/sets.json --out /data/cve-kgrag/evaluation
```

Paths above are operator-owned placeholders. Real-data runs need the exact archived
raw inputs/acquisition metadata or verified store, reviewed case/sets files, full
catalogued FiGHT snapshot, matching package/settings and any configured MITRE mapping.
Run `--check` before evaluation. To generate sets for a new, reviewed case file,
omit `--check` and save stdout outside the repository before reviewing the result.
Do not relabel existing cases or regenerate their identities merely to make a
changed dataset pass.

The gold loader parses at most 1 MiB once. Top-level `trajectories` selects the
fixture format; `cases`, `corpus_content_sha256` and `fight_snapshot_sha256`
together select the store format. Partial, mixed or unrecognized shapes are rejected.
Store evaluations require `--sets`. Their bounded strict loader checks case IDs,
subject kinds, ID syntax/order/uniqueness, disjoint sets and file/data bindings.
Only after these checks are the store and snapshot loaded, verified and shared
across runs. A case must not need both CVE categories.

`eval planner` has no split-selection flag. Do not use it as a development-only
runner for a protected test set without a separately authorized baseline-only
input. Public benchmark cases are no longer unseen acceptance data.

## Optional live model checks

Live calls cost money and send the submitted query and model-facing input to the
configured endpoint. Configure credentials in the environment, never CLI arguments:

```sh
export CVE_KGRAG_PLANNER_ENABLED=true
export CVE_KGRAG_PLANNER_BASE_URL=https://model.example.com
export CVE_KGRAG_PLANNER_MODEL_NAME=your-model
# Optional: CVE_KGRAG_PLANNER_REASONING_EFFORT, if supported by the endpoint.
# Supply CVE_KGRAG_PLANNER_API_KEY securely in the environment.
.venv/bin/cve-kgrag eval planner --gold eval/gold/m4_trajectories.yaml \
  --out /data/cve-kgrag/evaluation --model-runs 2
```

Use a currently available model name compatible with the configured endpoint.
`--model-runs` ranges from 0 (default, no calls) to 20. Model runs require an
enabled, usable planner; evaluation does not silently report fallback-only runs
as successful model tests. For adapter integration tests:

```sh
CVE_KGRAG_LIVE_TESTS=1 .venv/bin/pytest tests/live -q
```

Never use `--showlocals` for live tests. REST and MCP always plan deterministically;
testing through them does not test the model. In CLI/evaluation, free-text round 1
is also policy-planned, but a configured relevance assessor may still call the model.
Inspect both planning and assessment records when counting calls.

## Artifacts and identity

Every invocation writes a new owner-only `planner-*` directory under `--out`:
one deterministic evidence set per case, optional numbered model sets and
`report.json`. It never overwrites a run; an interrupted run retains completed sets
without a final report. Keep outputs outside the package and store root.

Evidence sets include queries, filters, model replies and trajectories: do not commit
them. Reports contain counts, codes and identities, not record text or generated
queries. Aggregate summaries and case IDs can be published after content review.

The report format is `evaluation_format_version: 5`, independent of the knowledge
contract. Identity includes the package, schema, source revision, gold bytes, planner
identities, model-run count and dataset. Store datasets include the corpus, FiGHT
and sets-file identities; fixture datasets record the per-case FiGHT profile.
Package bytes are checked before each run and after the last. Dependencies are
not included in that digest. A Git `+dirty` suffix alone does not identify the diff.

Compare like-for-like data and metric definitions. A deliberate code/policy change
must be identified rather than presented as another repeat of the same experiment.
Fixture checks reproduce directly. Historical real-data figures require the exact
archived feeds, acquisition metadata, snapshots, case/sets files, package and settings.
Refetching today's feeds can change records, evidence identities and scores.
Live replies and latency are not deterministic, even with the same configuration.

## Gold format and rubric

Cases describe identity, split, goal, request, evidence needs, derivation rules,
human label/reason and authorship/confirmation metadata. Review the case format
and rules before generating sets; labels must be independent of the tested output.

Required, allowed and irrelevant sets are derived from explicit rules over the
identified corpus and FiGHT snapshot, not from retrieval output or model labels.
Unlabelled returns are reported separately, never silently called incorrect.
Required must be within relevant; allowed is relevant minus required; irrelevant
must not overlap relevant. Rule trees are bounded (depth 8, 50 rules overall,
20 children per combinator and 50 values per predicate).

CVE rules support CPE vendor/product pairs, CPE vendor, whole-word description
any/all, reference URL fragments, explicit CVE IDs with reasons, KEV and
`all_of`/`any_of`/`none_of` combinations. Technique rules support explicit IDs with
reasons and whole-word narrative terms. Required techniques are explicitly justified,
not inferred from a keyword hit. A negative case also needs a wider corpus check;
a failed search alone cannot establish absence.

Evidence categories stay separate:

- `named_cve`: the exact record the question names.
- `implementation_cves`: records relevant to the product/component goal.
- `protocol_context`: relevant FiGHT techniques.
- `affectedness`: a verified version-affectedness verdict; currently unavailable.

Human case labels describe what the selected sources can support: sufficient when
all needed categories have evidence, partial when some do, insufficient when none do
(with a justified wide check for negatives), uncertain when the owner cannot settle it.
These are not the service's status labels.

Only items actually listed in the answer count. For each needed category:

`Coverage@20 = required items listed / min(number of required items, 20)`.

An empty required set gives null coverage and is never covered. Twenty is the
server's answer-section cap, not the request's lower per-call budget. A run is
gold-judged sufficient when every needed category is covered, partial when it lists
some required evidence but not all categories are covered, otherwise insufficient.
Affectedness is never covered in this version.

## Metrics and denominators

Evidence quality is reported by split and category. Mixed questions participate in
each needed category; `implementation_family` is an extra combined view, not a
replacement for the separate CVE figures. Coverage/covered exclude empty required
sets and uncertain cases. Irrelevant and unjudged counts include negative cases.

Run quality counts a run once within its split:

| Metric | Event | Denominator |
|---|---|---|
| wrong_stop | stopped sufficient but not gold-judged sufficient | non-uncertain runs |
| premature_no_evidence | stopped no_evidence despite sufficient/partial case label | sufficient/partial case runs |
| unflagged_gap | no non-found need signals a category with no gold evidence | partial case runs |
| affectedness_violation | applicability is not unknown | all runs, including uncertain |
| false_gap | gold-judged sufficient but did not stop sufficient | gold-judged sufficient non-uncertain runs |
| need_agreement | runtime need kinds equal the case's needs | non-uncertain runs |

A missing required item in a category that has gold evidence is measured by coverage
and stop quality, not by unflagged_gap. Wrong stop does not mean “should have stopped
but continued”. Rates with zero denominators are null.

Planner figures separate accepted plans, fallback attempts, executed fallbacks,
timeouts and deadline skips. `model_not_consulted` rounds remain in outcome counts
but are excluded from rates over rounds delegated to planning. Gate acceptance is
accepted / (accepted + rejected); fallback execution is executed / attempted fallback.
An attempted fallback that cannot fit the budget is not an executed fallback.

`matches_deterministic_ending` compares status and stop reason only.
`matches_deterministic_answers` compares per-section ID sets, not counts or order.
Plan divergence compares only rounds reached from comparable prior calls and
observations. Agreement on policy-routed questions is not a model-quality result.

## Interpreting results

The policy can add a bounded named-product read to free-text investigations and
merge it using product-name support; it does not grant evidence needs. Pending
cards and model relevance labels also cannot establish `found`. See
[architecture](architecture.md#named-product-step-and-merge-order) for admission
and ordering, and [needs and stopping](architecture.md#needs-and-stopping).
Weakness associations are lookup-only, so they do not enter investigation context,
planner inputs, relevance labels or Coverage@20.

No real-data score is claimed here. Reproducing real-data scores requires the
archived inputs and identified program/settings used to obtain them. Refetching
the same source URLs does not guarantee the same records, identities or score.
Model replies, latency and live endpoint behaviour are not deterministic. Keep
method, source coverage, evidence quality and stop quality separate when reporting.
