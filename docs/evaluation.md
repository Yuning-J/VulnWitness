# Evaluation and reproduction

Local evaluation measures planner, evidence and stop quality separately, without proving full coverage.

## Offline checks

Install the locked checkout using the [runbook](runbook.md#install), then run:

```sh
.venv/bin/ruff check
.venv/bin/ruff format --check
.venv/bin/mypy
.venv/bin/cve-kgrag schema check
.venv/bin/pytest -q
.venv/bin/cve-kgrag eval planner \
  --gold eval/gold/m4_trajectories.yaml --out /data/cve-kgrag/evaluation
```

Tests use synthetic records/stores, packaged FiGHT/MITRE excerpts and fake local
endpoints, blocking non-loopback traffic. No model or external store is needed.
Fixture `trajectories` cases select packaged/unavailable FiGHT per case and forbid
`--sets`; this checks behaviour, without benchmarking real-data recall.

## Real-store evaluation

Activate an imported store/full catalogued FiGHT snapshot using the runbook. Supply
reviewed operator-owned cases/sets binding the corpus, FiGHT and exact case bytes:

```sh
.venv/bin/cve-kgrag eval gold-sets --gold /data/evaluation/cases.yaml \
  --check /data/evaluation/sets.json
.venv/bin/cve-kgrag eval planner --gold /data/evaluation/cases.yaml \
  --sets /data/evaluation/sets.json --out /data/cve-kgrag/evaluation
```

Use exact archived feeds/acquisition metadata or a verified store, matching
package/settings and any MITRE mapping. Check sets first. To generate for a new
reviewed case file, omit `--check`, save stdout outside the repo and review it.
Do not relabel cases/regenerate identities to accommodate changed data. Store cases
require `--sets`; invalid formats, sets or bindings fail before sources load.
There is no split-selection flag: use separately authorized inputs for protected
cases. Public benchmarks cannot be treated as unseen acceptance data.

## Optional live model checks

Live calls cost money and send queries/model input to the endpoint. Configure
`CVE_KGRAG_PLANNER_ENABLED=true`, `CVE_KGRAG_PLANNER_BASE_URL`,
`CVE_KGRAG_PLANNER_MODEL_NAME` and `CVE_KGRAG_PLANNER_API_KEY` in the environment,
never credentials in arguments. Optional `CVE_KGRAG_PLANNER_REASONING_EFFORT` needs
endpoint support. Add `--model-runs 2` to evaluation (0–20, default 0). Runs need a
usable enabled planner; fallback-only runs do not pass as model tests.
Adapter checks: `CVE_KGRAG_LIVE_TESTS=1 .venv/bin/pytest tests/live -q`; never use
`--showlocals`. REST/MCP are deterministic. Free-text round 1 is policy-planned but
may call the assessor; inspect both planning and assessment records.

## Artifacts and reproducibility

Each invocation creates an owner-only `planner-*` directory under `--out` with a
deterministic set per case, optional numbered model sets and `report.json`. Runs
never overwrite; interruptions retain completed sets without a final report.
Keep outputs outside the package/store root and version control: sets contain
queries, filters, model replies and trajectories. Reports hold counts/codes/identities;
review summaries and case IDs before publication. Report format 5 is separate from
the knowledge contract. Identity binds package/schema, source revision, gold bytes,
planner, model-run count, dataset and store/FiGHT/sets or fixture FiGHT profile.
Package checks exclude dependencies; Git `+dirty` alone does not identify a diff. Archive program, lock,
settings, sources and case/sets files. Fixture checks reproduce from the locked
checkout. Refetched feeds can change records, identities and scores; live replies
and latency are nondeterministic. Compare like-for-like inputs, metric definitions
and identified code/policy. No real-data score is claimed here.

## Gold and metrics

Labels/rules must be independent of tested output. Required is relevant; allowed is
relevant minus required; irrelevant is disjoint; unlabelled stays unjudged. Negative
cases need a wider corpus check. Human sufficient/partial/insufficient/uncertain
labels describe source support, separately from runtime status. Categories are named
CVE, implementation CVEs, protocol context and affectedness (unavailable).
Only listed answers count: `Coverage@20 = required listed / min(required count, 20)`.
Empty required sets give null coverage, never covered. Gold sufficiency needs every
needed category covered; partial needs some required evidence; otherwise insufficient.
Coverage excludes uncertain cases/empty required sets; irrelevant/unjudged counts
include negatives. Mixed cases count in each category; combined views do not replace them.

| Run metric | Event | Denominator |
|---|---|---|
| `wrong_stop` | sufficient stop without gold sufficiency | non-uncertain runs |
| `premature_no_evidence` | no-evidence stop with sufficient/partial label | sufficient/partial runs |
| `unflagged_gap` | no non-found need signals a category without gold evidence | partial runs |
| `affectedness_violation` | applicability not unknown | all runs |
| `false_gap` | gold sufficient without sufficient stop | gold-sufficient non-uncertain runs |
| `need_agreement` | runtime need kinds equal case needs | non-uncertain runs |

Zero denominators give null. Planning rates exclude `model_not_consulted` rounds;
gate acceptance is accepted/(accepted+rejected), fallback execution executed/attempted.
Timeouts/deadline skips and unexecuted attempts stay separate. Ending agreement compares
status/stop; answer agreement compares per-section ID sets; plan divergence requires
comparable prior calls/observations. Policy-routed agreement is no model-quality result.
Product steps, pending cards and model labels grant no needs; lookup-only weakness paths
are excluded. See [stopping](architecture.md#needs-and-stopping).
