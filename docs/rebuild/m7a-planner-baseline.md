# M7a — planner behaviour baseline

Schema version `2.0.0-dev.24`, unchanged: M7a adds a local evaluation tool and changes no
contract, agent behaviour, search vocabulary or round count.

M7a measures whether the model planner takes part in decisions at all, before the
read-only importer (WP9) and store activation (WP10). M7b repeats the same evaluation on
imported data with hand-labelled sufficiency; only then are evidence gaps, controlled
term expansion and more refinement rounds decided.

## What it measures, and what it cannot

The gold investigation file (`eval/gold/m4_trajectories.yaml`) runs on the synthetic
fixture, and its labels were written for the deterministic policy. Over that data the
evaluation can measure:

- whether the model planner answered, and how often its plans passed the gate;
- how often the policy planned in its place, and why;
- whether repeated runs of one case were stable;
- whether accepted model plans differ from the policy's.

It cannot measure recall, whether an answer's evidence suffices, wrong stops, whether a
further round helps or whether free search terms would help: the sets do not hold the
truth those need, and the fixture does not hold the data. A plan that differs from the
policy's is reported as different, never as better. If the model nearly always falls back,
or its accepted plans nearly always equal the policy's, the model planner adds little
autonomy today; only plans that are different, accepted and cheaper argue for extending it.

## The command

`cve-kgrag eval planner --gold FILE --out DIR [--model-runs N]` is a reviewer and operator
tool, served by neither the REST API nor MCP.

- Each case runs once with the deterministic policy. With `--model-runs N` (1 to 20) it
  then runs N times with the model planner the settings enable. The default, 0, calls no
  endpoint.
- Model runs need `CVE_KGRAG_PLANNER_ENABLED`: without it, `--model-runs` is a usage error
  (exit 2). An enabled planner that cannot plan (no key, no usable adapter) ends the
  command with its reason (exit 1). The evaluation never reports model runs it did not make.
- The gold file must be an investigation gold file: a `trajectories` list whose rows hold
  a `request` and `sources.mitre_fight` (`packaged` or `unavailable`). The labels are not
  read. At most 100 cases and 1 MiB; a row repeating an earlier one is refused. A problem
  is reported in the server's words, never by quoting the file, with a request's problems
  bounded as a verification report bounds its violations (exit 2).
- Each case runs on the packaged fixture with the FiGHT source its row names and the
  production clocks. The runs go one after another on one call runner, and a run starts
  only once every call an earlier run abandoned has returned. It waits up to 60 seconds,
  which gives an adapter that honours its timeout time to finish trying each address of
  its endpoint. A call still running after that stops the command (exit 1). Since no run
  starts while a call is live, the process never holds more abandoned calls than one
  investigation may leave, three ([ADR 0005 §2](adr/0005-model-planner-adapter.md)).
- `--out` must not lie inside the installed package, since the files a run writes there
  would change the package the report names (exit 2).

## Output and its sensitivity

Every run creates a new directory, `DIR/planner-*`, readable by its owner only (0700):

- `deterministic/<case_sha256>.json`, one evidence set per case;
- `model/<case_sha256>-NN.json`, one per model run;
- `report.json`, which is also printed.

No file is ever overwritten. A stopped evaluation keeps the sets it wrote and writes no
report.
The evidence sets hold each query, the model's plan text, the
trajectory and the filters, so the directory is sensitive and untrusted: never commit it.
`eval-results/` is ignored by git for that reason.

The report holds counts, codes and hashes only: no query, plan text, model reply,
exception text, endpoint, key, model name or path. A case is named by `case_sha256`, the
hash of its request and FiGHT source; a plan by the hash of its call keys
(`compute_call_key`) in plan order.

## The report

The report is the evaluation's own format (`evaluation_format_version: 1`), not part of
the v2 knowledge contract, so it is not under `schemas/v2`. It is JSON with sorted keys,
and the analysis is a pure function of the sets: equal sets give byte-equal reports.

`identity` says what was measured: the evidence-set schema version, the package digest,
the source revision, the gold file's SHA-256, the hashes of the deterministic and model
planner identities, and the model runs per case. The identity is built before any case
runs. Two reports compare only when their identities are equal.

- `package_sha256` names what ran: the digest of every file of the installed package
  except compiled bytecode, meaning each file's relative path and content hash, in path
  order. Code, topic cards, fixtures and FiGHT snapshots are all packaged files. A source
  checkout and an installed wheel are both covered, and so is a change to a file no
  repository tracks. Hidden and editor files count too, since the loaders' globs match
  hidden files; a symlinked directory is not followed, and the package holds none.
  The digest is read again before every run and after the last. A change, or a file
  that cannot be read, stops the command before the report (exit 1). Third-party
  dependencies are not in it.
- `source_revision` says where the package came from, for a reader: the git commit, SHA-1
  or SHA-256, with `+dirty` for uncommitted changes to tracked files, or `unavailable`
  outside a checkout or inside another repository. Two different dirty states share a
  revision, so the revision never decides whether two reports compare. Reading it takes
  no optional git lock, so it never rewrites the checkout's index.

`deterministic` lists each case's run: per round, the planner outcome, the plan
fingerprint and the steps executed; then status, stop reason, tool calls and the hash of
the evidence IDs. With its counts of statuses and stop reasons, it is the reference the
model runs are set beside. It has no gate or fallback figures, since the policy's plan is
not gated as a proposal.

`model` (null without model runs) is kept apart from the deterministic section, never
averaged with it. Every rate is a `Proportion`: `count`, its denominator `of`, and `rate`
rounded to four places, null when `of` is 0. Every outcome, failure detail, rejection code
and reason is listed, zero included, so two reports compare key by key.

### Round outcomes

`round_one`, `round_two` and `all_rounds` count the model runs' rounds. Unless stated, a
rate is over every round in the group.

| Field | Counts | Over |
|---|---|---|
| `gate_acceptance` | `model_accepted` | rounds whose reply held plan text in time: `model_accepted` and `model_rejected` |
| `fallback_attempt` | `model_rejected` and `model_unavailable`: the policy's plan was tried | every round |
| `fallback_executed` | fallback rounds that executed at least one step | the fallback rounds |
| `timed_out_fallback` | `model_unavailable` whose reply detail is `timed_out` | every round |
| `deadline_no_execution` | `model_timed_out` and `model_reply_after_deadline`: nothing ran | every round |
| `skipped_before_planning` | `model_skipped_at_deadline`: the model was never called | every round |

`timed_out_fallback` is a subset of `fallback_attempt`. It joins two causes the sets do not
tell apart: the planner's share of the run ending (`PLANNER_CAP_REPLY`) and the adapter
reporting a timeout, an HTTP 408, 504 or 524. Telling them apart would need a new failure
detail, a contract change outside M7a. `unavailable_details` breaks every
`model_unavailable` round down by detail. `rejection_codes` counts every code the
fallback-attempt rounds record: the model reply's (`planner_unavailable` for a reply
without a plan), then the fallback plan's when the gate rejected that too. A round
records both in one list, so the two cannot be counted apart without a contract change.

A fallback that executed nothing, because the gate rejected the policy's own plan as over
budget or the policy had no refinement, counts in `fallback_attempt` but not in
`fallback_executed`.

### Divergence from the policy

`round_one_divergence` and `round_two_divergence` take each model run's `model_accepted`
round and set its plan fingerprint beside the deterministic run's same round. Rounds the
model did not plan are left out. A round compares only when the deterministic run reached
it from the same state, meaning both runs issued the same earlier calls in the same order
and the planner was shown the same observations of them. Otherwise it is counted under
`not_comparable` by reason: `deterministic_run_lacks_round`, `round_one_calls_differ`
or `round_one_observations_differ`. Round 1 is always comparable when both runs have it.

One gold case skews the round-2 figures. `unknown_id_alone` (`CVE-9999-4242`,
`implementation_only`) reaches a model round 2 in which no offered call can pass the gate,
so that round is rejected whatever the model replies. Read gate quality from `round_one`,
or discount that case's round 2. The fix, consulting no model in such a round, is a
[`PLAN.md`](PLAN.md#follow-up-model-planner-adapter) follow-up.

### Runs and cases

`executed_model_step` is the share of model runs that executed at least one step the model
planned. An accepted plan that the deadline stopped before its first step does not count.
`tool_calls_against_deterministic` counts the model runs that charged fewer, as many or
more tool calls than the deterministic run of the same case. `planner_durations` gives
the count, minimum, lower median and maximum planner call time in milliseconds. These
are measured times, so they vary between runs; they are excluded from the sets' hashes,
but the report states them. Each entry of `cases` reports, over that case's model runs:

- `distinct_run_plans`: distinct fingerprints of the runs' plans, round by round, and
  `run_plans`: how many runs gave each fingerprint;
- `distinct_results`: distinct status and stop reason pairs;
- `matches_deterministic_result`: runs that ended with the deterministic run's status and
  stop reason;
- `executed_model_step`;
- `gate_acceptance` over every round of the case's runs, and `run_gate_acceptance`: the
  mean, minimum and maximum of each run's own gate acceptance;
- `switches_planner`: in some round, one run's model plan passed the gate while another
  run fell back to the policy's;
- `min_tool_calls`, `max_tool_calls` and `tool_calls_against_deterministic`.

`case_gate_acceptance` gives the mean, minimum and maximum of the per-case gate acceptance.
Every such spread counts in `measured` the cases or runs where the rate has a denominator.

## The deterministic baseline

On `eval/gold/m4_trajectories.yaml` (18 cases, SHA-256
`fd14db0693f733d3a39444e69f75c182d8555a8fff7ac34a69418b60f3a02b11`), the deterministic
runs end as the gold labels say. By status: 8 `ok`, 5 `no_match`, 3 `partial`, 1
`policy_blocked` and 1 `source_unavailable`. By stop reason: 8 `sufficient`, 5
`no_evidence`, 4 `source_unavailable` and 1 `policy_blocked`.

## Live runs

Model runs call the configured endpoint and are made by hand, by the owner, in their own
terminal. They are never part of CI. The command is in [`PLAN.md`](PLAN.md#live-lane-opt-in).
Five runs per case over the 18 gold cases make at most 180 planner calls (one per round,
at most two rounds per run). Share the printed report; keep the result directory local.

## Tests

The offline lanes cover the evaluation with recorded and scripted replies and a loopback
chat server; the network guard refuses any other connection.

- The analyzer: each outcome over its denominator, fallbacks that executed nothing, every
  `not_comparable` reason (calls in another order and each kind of observation
  difference included), plan fingerprints that keep plan order, per-case stability and
  planner switches in either round, tool calls against the deterministic run, model
  results counted apart from the deterministic ones, the duration median, byte-equal
  reports for equal sets, and no query, plan text, model name or adapter in the report.
- The runner: gold-file refusals that never quote the file, bounded request problems, case
  hashes, the source revision (commit, `+dirty`, untracked files ignored, the index never
  rewritten, unavailable outside a checkout or inside another repository), planner
  hashes, owner-only directories and files that are never overwritten, an identity
  checked before any case runs, the sets and report it writes, and no report when the
  last run changed the package.
- The package digest: two edits of one file, an untracked data file, bytecode ignored,
  the same content wherever it lies.
- The case runner: a run after one whose planner ignores its timeout never starts, under
  either FiGHT source, with one planner call made; a run after the package changed never
  starts; a package file that cannot be read stops the evaluation.
- The CLI: exit codes for every refusal, `--model-runs` outside 0 to 20 refused before
  any call, no endpoint call without `--model-runs`, the gold hash, schema version and
  checkout in the identity, model runs through the installed adapter, accepted or
  failing, whose report holds no query, plan text, endpoint text, endpoint, model name
  or key, a silent endpoint whose runs all complete, since the adapter times out, the
  package digest in the identity, and an `--out` inside the package refused.
