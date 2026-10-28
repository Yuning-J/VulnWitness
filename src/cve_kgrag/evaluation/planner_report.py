"""The planner evaluation report: counts, codes and hashes measured from the evidence sets
of a deterministic run and repeated model runs of the same gold cases.

The report is the evaluation's own format (``evaluation_format_version``), not part of
the v2 knowledge contract, so it is not published under ``schemas/v2``. It never holds a
query, plan text, model reply, exception text, endpoint, key or file path: each case is
named by ``case_sha256`` and each plan by a fingerprint of its call keys.

Every rate is a ``Proportion``: the count, its denominator and the rate rounded to
``RATE_DECIMALS`` places, ``null`` when the denominator is zero, so a reader can always
check what a rate was measured over.

An evaluation of M7b's labelled cases adds the ``sufficiency`` section, which also names
each case by the ``case_id`` of the committed gold file
(``docs/rebuild/m7b-planner-evaluation.md``).
"""

import json
from enum import StrEnum
from typing import Literal

from pydantic import Field

from cve_kgrag.domain.contract_model import ContractModel
from cve_kgrag.domain.investigation import PlannerOutcome, StopReason
from cve_kgrag.domain.planning import SHA256_HEX_PATTERN
from cve_kgrag.domain.taxonomy import ResultStatus
from cve_kgrag.evaluation.labelled_cases import EvidenceCategory, Split, Sufficiency

EVALUATION_FORMAT_VERSION: Literal[1] = 1
RATE_DECIMALS = 4
# A git commit ID, SHA-1 or SHA-256.
GIT_COMMIT_PATTERN = r"[0-9a-f]{40}(?:[0-9a-f]{24})?"
# A git commit, ``+dirty`` when the checkout had uncommitted changes to tracked files, or
# ``unavailable`` when the installed package is not a git checkout.
SOURCE_REVISION_PATTERN = rf"^(?:{GIT_COMMIT_PATTERN}(?:\+dirty)?|unavailable)$"


class Proportion(ContractModel):
    count: int = Field(ge=0)
    of: int = Field(ge=0)
    rate: float | None = Field(description="count / of, rounded; null when of is 0.")


def measure_proportion(count: int, of: int) -> Proportion:
    rate = None if of == 0 else round(count / of, RATE_DECIMALS)
    return Proportion(count=count, of=of, rate=rate)


class FightProfile(StrEnum):
    """Which FiGHT source the cases ran on: each M7a case's own choice between the
    packaged excerpt and none, or the operator snapshot for every M7b case."""

    PER_CASE = "per_case"
    OPERATOR_SNAPSHOT = "operator_snapshot"


class DatasetIdentity(ContractModel):
    """The data the cases ran on; reports over different data never compare."""

    cve_search_version: str = Field(
        min_length=1, description="The served dataset's cve_search capability version."
    )
    fight_profile: FightProfile
    fight_snapshot_sha256: str | None = Field(
        pattern=SHA256_HEX_PATTERN, description="The operator snapshot; null per case."
    )
    sets_sha256: str | None = Field(
        pattern=SHA256_HEX_PATTERN,
        description="SHA-256 of the gold sets file's bytes; null for M7a's gold file.",
    )


class EvaluationIdentity(ContractModel):
    """What a report measured, so two reports can be told apart before they are compared."""

    evaluation_format_version: Literal[1] = EVALUATION_FORMAT_VERSION
    evidence_set_schema_version: str
    source_revision: str = Field(
        pattern=SOURCE_REVISION_PATTERN,
        description="Where the package came from, for a reader; package_sha256 says what ran.",
    )
    package_sha256: str = Field(
        pattern=SHA256_HEX_PATTERN,
        description="Digest of every file of the installed package, code and packaged data, "
        "but compiled bytecode; the same before the first run and after the last.",
    )
    gold_sha256: str = Field(
        pattern=SHA256_HEX_PATTERN, description="SHA-256 of the gold file's bytes."
    )
    dataset: DatasetIdentity
    deterministic_planner_sha256: str = Field(pattern=SHA256_HEX_PATTERN)
    model_planner_sha256: str | None = Field(
        pattern=SHA256_HEX_PATTERN, description="Null when no model run was made."
    )
    model_runs_per_case: int = Field(ge=0)


class RoundPlanSummary(ContractModel):
    round_number: int = Field(ge=1)
    planner_outcome: PlannerOutcome
    plan_fingerprint: str = Field(
        pattern=SHA256_HEX_PATTERN,
        description="SHA-256 of the round's accepted plan as its call keys, in plan order.",
    )
    executed_steps: int = Field(ge=0)


class RunSummary(ContractModel):
    rounds: tuple[RoundPlanSummary, ...]
    status: ResultStatus
    stop_reason: StopReason
    tool_calls: int = Field(ge=0)
    evidence_ids_sha256: str = Field(pattern=SHA256_HEX_PATTERN)


class DeterministicCase(ContractModel):
    case_sha256: str = Field(pattern=SHA256_HEX_PATTERN)
    run: RunSummary


class ResultCounts(ContractModel):
    """How many runs ended with each status and each stop reason; every value is listed."""

    statuses: dict[ResultStatus, int]
    stop_reasons: dict[StopReason, int]


class DeterministicSection(ContractModel):
    runs: int = Field(ge=0)
    results: ResultCounts
    cases: tuple[DeterministicCase, ...]


class RoundOutcomeMetrics(ContractModel):
    """The planner outcomes of a set of model-run rounds. Unless a field says otherwise, a
    rate is over every round in the set."""

    rounds: int = Field(ge=0)
    outcomes: dict[PlannerOutcome, int]
    gate_acceptance: Proportion = Field(
        description="model_accepted over the rounds whose reply held plan text in time: "
        "model_accepted and model_rejected."
    )
    fallback_attempt: Proportion = Field(
        description="model_rejected and model_unavailable: the policy's plan was tried instead."
    )
    fallback_executed: Proportion = Field(
        description="Of the fallback-attempt rounds, those that executed at least one step."
    )
    timed_out_fallback: Proportion = Field(
        description="model_unavailable with the timed_out detail: the planner's share of the "
        "run ended, or the adapter reported a timeout, an HTTP 408, 504 or 524. A subset of "
        "fallback_attempt."
    )
    deadline_no_execution: Proportion = Field(
        description="model_timed_out and model_reply_after_deadline: the run's deadline "
        "passed and the round executed nothing."
    )
    skipped_before_planning: Proportion = Field(
        description="model_skipped_at_deadline: the model was never called."
    )
    unavailable_details: dict[str, int] = Field(
        description="Of the model_unavailable rounds, how many carried each failure detail, "
        "by the detail's name."
    )
    rejection_codes: dict[str, int] = Field(
        description="Every rejection code the fallback-attempt rounds record: the model "
        "reply's (planner_unavailable for a reply without a plan), then the fallback plan's "
        "when the gate rejected that too."
    )


class NotComparableReason(StrEnum):
    """Why a model-accepted round has no deterministic round to compare its plan with."""

    DETERMINISTIC_RUN_LACKS_ROUND = "deterministic_run_lacks_round"
    ROUND_ONE_CALLS_DIFFER = "round_one_calls_differ"
    ROUND_ONE_OBSERVATIONS_DIFFER = "round_one_observations_differ"


class PlanDivergence(ContractModel):
    """The model-accepted rounds of one round number against the deterministic run's same
    round. A round 2 compares only when both runs issued the same round-1 calls, observed
    the same round-1 results and reached round 2."""

    model_accepted_rounds: int = Field(ge=0)
    differs: Proportion = Field(
        description="Rounds whose accepted plan differs from the deterministic plan, over "
        "the comparable rounds."
    )
    not_comparable: dict[NotComparableReason, int]


class DurationSummary(ContractModel):
    """Planner call durations in milliseconds; the median is the lower one for an even
    count, and every value but count is null when there were no calls."""

    count: int = Field(ge=0)
    min_ms: int | None
    median_ms: int | None
    max_ms: int | None


class RateSpread(ContractModel):
    """A rate's mean, minimum and maximum over the cases or runs where it has a
    denominator; ``measured`` counts those, and the rest are null when it is 0."""

    measured: int = Field(ge=0)
    mean: float | None
    min: float | None
    max: float | None


class ToolCallComparison(ContractModel):
    """How many model runs charged fewer, as many or more tool calls than the deterministic
    run of the same case."""

    fewer: int = Field(ge=0)
    same: int = Field(ge=0)
    more: int = Field(ge=0)


class ModelCase(ContractModel):
    case_sha256: str = Field(pattern=SHA256_HEX_PATTERN)
    runs: int = Field(ge=1)
    distinct_run_plans: int = Field(
        ge=1, description="Distinct fingerprints of the runs' accepted plans, round by round."
    )
    run_plans: dict[str, int] = Field(description="How many runs gave each of those fingerprints.")
    distinct_results: int = Field(ge=1, description="Distinct status and stop reason pairs.")
    matches_deterministic_result: Proportion
    executed_model_step: Proportion = Field(
        description="Runs that executed at least one step the model planned."
    )
    gate_acceptance: Proportion = Field(description="Over every round of the case's runs.")
    run_gate_acceptance: RateSpread = Field(
        description="Each run's own gate acceptance, over the runs where it has a denominator."
    )
    switches_planner: bool = Field(
        description="In some round, one run's model plan passed the gate while another run "
        "fell back to the policy's."
    )
    min_tool_calls: int = Field(ge=0)
    max_tool_calls: int = Field(ge=0)
    tool_calls_against_deterministic: ToolCallComparison


class ModelSection(ContractModel):
    runs: int = Field(ge=0)
    results: ResultCounts
    executed_model_step: Proportion
    tool_calls_against_deterministic: ToolCallComparison
    round_one: RoundOutcomeMetrics
    round_two: RoundOutcomeMetrics
    all_rounds: RoundOutcomeMetrics
    round_one_divergence: PlanDivergence
    round_two_divergence: PlanDivergence
    planner_durations: DurationSummary
    case_gate_acceptance: RateSpread
    cases: tuple[ModelCase, ...]


class JudgedSufficiency(StrEnum):
    SUFFICIENT = "sufficient"
    PARTIAL = "partial"
    INSUFFICIENT = "insufficient"


class CaseCategoryFigures(ContractModel):
    """One needed evidence category over a case's runs."""

    coverage: RateSpread = Field(
        description="Coverage@20 over the runs; measured is 0 when required is empty."
    )
    covered: Proportion = Field(description="Runs that covered it, over the measured runs.")
    irrelevant_items: int = Field(ge=0)
    unjudged_items: int = Field(ge=0)


class RunJudgementCounts(ContractModel):
    wrong_stop: int = Field(ge=0)
    premature_no_evidence: int = Field(ge=0)
    unflagged_gap: int = Field(ge=0)
    affectedness_violation: int = Field(ge=0)


class SufficiencyCase(ContractModel):
    case_sha256: str = Field(pattern=SHA256_HEX_PATTERN)
    case_id: str = Field(description="The case's ID in the committed gold file.")
    split: Split
    label: Sufficiency
    runs: int = Field(ge=1)
    judged: dict[JudgedSufficiency, int]
    categories: dict[EvidenceCategory, CaseCategoryFigures] = Field(
        description="Each needed category that can have evidence: affectedness has none."
    )
    run_judgements: RunJudgementCounts


class CategoryQuality(ContractModel):
    """One evidence category over the runs of a split's non-uncertain cases needing it."""

    category_runs: int = Field(ge=0)
    coverage: RateSpread = Field(
        description="Coverage@20 over the category-runs whose required set is non-empty."
    )
    covered: Proportion = Field(description="Over the same category-runs as coverage.")
    irrelevant_items: int = Field(ge=0)
    unjudged_items: int = Field(ge=0)
    runs_with_irrelevant: Proportion = Field(description="Over every category-run.")


class SplitEvidenceQuality(ContractModel):
    named_cve: CategoryQuality
    implementation_cves: CategoryQuality
    protocol_context: CategoryQuality
    implementation_family: CategoryQuality = Field(
        description="named_cve and implementation_cves together, beside them."
    )


class RunQuality(ContractModel):
    """A split's runs, each counted once whatever categories it needs."""

    runs: int = Field(ge=0)
    uncertain_runs: int = Field(ge=0)
    judged: dict[JudgedSufficiency, int] = Field(
        description="Runs of non-uncertain cases by judged sufficiency."
    )
    wrong_stop: Proportion = Field(description="Over runs of non-uncertain cases.")
    premature_no_evidence: Proportion = Field(
        description="Over runs of cases labelled sufficient or partial."
    )
    unflagged_gap: Proportion = Field(description="Over runs of cases labelled partial.")
    affectedness_violation: Proportion = Field(description="Over every run.")


class SufficiencyPart(ContractModel):
    cases: tuple[SufficiencyCase, ...]
    evidence_quality: dict[Split, SplitEvidenceQuality]
    run_quality: dict[Split, RunQuality]


class SufficiencySection(ContractModel):
    """The runs scored against the labelled cases; deterministic and model runs apart."""

    deterministic: SufficiencyPart
    model: SufficiencyPart | None = Field(description="Null when no model run was made.")


class PlannerEvaluationReport(ContractModel):
    identity: EvaluationIdentity
    deterministic: DeterministicSection
    model: ModelSection | None = Field(description="Null when no model run was made.")
    sufficiency: SufficiencySection | None = Field(
        description="Null for a gold file of investigation trajectories, which has no labels."
    )


def format_report(report: PlannerEvaluationReport) -> bytes:
    """The report as indented JSON with sorted keys: equal reports give equal bytes."""
    report_json = json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True)
    return f"{report_json}\n".encode()
