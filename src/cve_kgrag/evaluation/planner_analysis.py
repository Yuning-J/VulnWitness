"""Measures how a model planner behaves from the evidence sets of the runs alone.

The analysis is a pure function of the sets: it reads their trajectories, never calls a
planner, runs a tool, reads the environment or touches a file, so equal sets always give
an equal report. What it can measure is whether the model was available, whether its
plans passed the gate, how often the policy planned instead, how stable repeated runs
were and whether accepted plans differ from the policy's. Whether an answer is right or
complete is not in the sets, so it is not measured here.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from cve_kgrag.application.investigate import observe_step
from cve_kgrag.domain.hashing import canonical_sha256
from cve_kgrag.domain.investigation import (
    KnowledgeEvidenceSet,
    PlannerOutcome,
    RoundRecord,
    StopReason,
)
from cve_kgrag.domain.planning import (
    ModelReplyFailureDetail,
    PlannerKind,
    PlanRejectionCode,
    ToolCall,
    compute_call_key,
)
from cve_kgrag.domain.taxonomy import ResultStatus
from cve_kgrag.evaluation.labelled_cases import SubjectKind
from cve_kgrag.evaluation.planner_report import (
    RATE_DECIMALS,
    DeterministicCase,
    DeterministicSection,
    DurationSummary,
    EvaluationIdentity,
    ModelCase,
    ModelSection,
    NotComparableReason,
    PlanDivergence,
    PlannerEvaluationReport,
    RateSpread,
    ResultCounts,
    RoundOutcomeMetrics,
    RoundPlanSummary,
    RunSummary,
    SufficiencySection,
    ToolCallComparison,
    measure_proportion,
)

# Outcomes of a round whose model reply gave no usable plan, so the policy's plan was tried.
FALLBACK_OUTCOMES = frozenset({PlannerOutcome.MODEL_REJECTED, PlannerOutcome.MODEL_UNAVAILABLE})
# Outcomes of a round the run's deadline ended before anything ran.
DEADLINE_OUTCOMES = frozenset(
    {PlannerOutcome.MODEL_TIMED_OUT, PlannerOutcome.MODEL_REPLY_AFTER_DEADLINE}
)
# Outcomes of a round whose reply held plan text in time, which the gate then judged.
GATED_OUTCOMES = frozenset({PlannerOutcome.MODEL_ACCEPTED, PlannerOutcome.MODEL_REJECTED})


@dataclass(frozen=True)
class CaseRuns:
    """One gold case's deterministic run and its model runs, in the order they ran."""

    case_sha256: str
    deterministic_set: KnowledgeEvidenceSet
    model_sets: tuple[KnowledgeEvidenceSet, ...]


def list_answer_ids(evidence_set: KnowledgeEvidenceSet, subject_kind: SubjectKind) -> set[str]:
    listed_ids: set[str] = set()
    if subject_kind is SubjectKind.CVES:
        for candidate in evidence_set.implementation_candidates:
            listed_ids.add(candidate.candidate.record.cve_id)
    else:
        for threat_context_item in evidence_set.protocol_context:
            listed_ids.add(threat_context_item.technique_id)
    return listed_ids


def has_same_answers(
    evidence_set: KnowledgeEvidenceSet, other_evidence_set: KnowledgeEvidenceSet
) -> bool:
    """Whether both sets list the same IDs in each answer section, in any order."""
    return all(
        list_answer_ids(evidence_set, subject_kind)
        == list_answer_ids(other_evidence_set, subject_kind)
        for subject_kind in SubjectKind
    )


def fingerprint_plan(calls: Sequence[ToolCall]) -> str:
    """SHA-256 of the calls' keys in plan order: two plans issuing the same backend queries
    in the same order share it."""
    call_keys: list[str] = []
    for call in calls:
        call_keys.append(compute_call_key(call))
    return canonical_sha256(call_keys)


def fingerprint_run_plans(evidence_set: KnowledgeEvidenceSet) -> str:
    """SHA-256 of each round's number and plan fingerprint, in round order."""
    round_plans: list[list[object]] = []
    for round_record in evidence_set.trajectory.rounds:
        round_plans.append(
            [round_record.round_number, fingerprint_plan(round_record.accepted_plan)]
        )
    return canonical_sha256(round_plans)


def summarize_run(evidence_set: KnowledgeEvidenceSet) -> RunSummary:
    round_summaries: list[RoundPlanSummary] = []
    for round_record in evidence_set.trajectory.rounds:
        round_summaries.append(
            RoundPlanSummary(
                round_number=round_record.round_number,
                planner_outcome=round_record.planner_outcome,
                plan_fingerprint=fingerprint_plan(round_record.accepted_plan),
                executed_steps=len(round_record.executed_step_indices),
            )
        )
    return RunSummary(
        rounds=tuple(round_summaries),
        status=evidence_set.status,
        stop_reason=evidence_set.stop_reason,
        tool_calls=evidence_set.trajectory.budget_used.tool_calls,
        evidence_ids_sha256=canonical_sha256(list(evidence_set.trajectory.evidence_ids)),
    )


def count_results(evidence_sets: Iterable[KnowledgeEvidenceSet]) -> ResultCounts:
    statuses: dict[ResultStatus, int] = dict.fromkeys(ResultStatus, 0)
    stop_reasons: dict[StopReason, int] = dict.fromkeys(StopReason, 0)
    for evidence_set in evidence_sets:
        statuses[evidence_set.status] += 1
        stop_reasons[evidence_set.stop_reason] += 1
    return ResultCounts(statuses=statuses, stop_reasons=stop_reasons)


def find_round(evidence_set: KnowledgeEvidenceSet, round_number: int) -> RoundRecord | None:
    for round_record in evidence_set.trajectory.rounds:
        if round_record.round_number == round_number:
            return round_record
    return None


def list_rounds(
    evidence_sets: Iterable[KnowledgeEvidenceSet], round_number: int | None
) -> list[RoundRecord]:
    """The sets' rounds with ``round_number``, or all of them for ``None``."""
    round_records: list[RoundRecord] = []
    for evidence_set in evidence_sets:
        for round_record in evidence_set.trajectory.rounds:
            if round_number is None or round_record.round_number == round_number:
                round_records.append(round_record)
    return round_records


def read_unavailable_detail(round_record: RoundRecord) -> ModelReplyFailureDetail | None:
    """Why a ``model_unavailable`` round's model gave no plan; ``None`` for any other round.

    Validation requires such a round to record its failed reply, which carries its detail;
    a round without one is a defect, raised rather than left uncounted.
    """
    if round_record.planner_outcome is not PlannerOutcome.MODEL_UNAVAILABLE:
        return None
    if round_record.model_reply is None:
        raise ValueError("a model_unavailable round records the reply it fell back from")
    return round_record.model_reply.detail


def measure_rounds(round_records: Sequence[RoundRecord]) -> RoundOutcomeMetrics:
    outcomes: dict[PlannerOutcome, int] = dict.fromkeys(PlannerOutcome, 0)
    unavailable_details: dict[str, int] = {}
    for failure_detail in ModelReplyFailureDetail:
        unavailable_details[failure_detail.name.lower()] = 0
    rejection_codes: dict[str, int] = {}
    for rejection_code in PlanRejectionCode:
        rejection_codes[rejection_code.value] = 0
    fallback_executed_rounds = 0
    timed_out_fallback_rounds = 0
    for round_record in round_records:
        planner_outcome = round_record.planner_outcome
        outcomes[planner_outcome] += 1
        if planner_outcome in FALLBACK_OUTCOMES and round_record.executed_step_indices:
            fallback_executed_rounds += 1
        unavailable_detail = read_unavailable_detail(round_record)
        if unavailable_detail is not None:
            unavailable_details[unavailable_detail.name.lower()] += 1
        if unavailable_detail is ModelReplyFailureDetail.TIMED_OUT:
            timed_out_fallback_rounds += 1
        if planner_outcome in FALLBACK_OUTCOMES:
            for rejection in round_record.rejections:
                rejection_codes[rejection.code.value] += 1
    round_count = len(round_records)
    # A round the policy planned without consulting the model says nothing of how the
    # model behaves, so the per-round model rates leave it out of their denominator.
    model_left_rounds = round_count - outcomes[PlannerOutcome.MODEL_NOT_CONSULTED]
    fallback_rounds = sum(outcomes[outcome] for outcome in FALLBACK_OUTCOMES)
    return RoundOutcomeMetrics(
        rounds=round_count,
        outcomes=outcomes,
        gate_acceptance=measure_proportion(
            outcomes[PlannerOutcome.MODEL_ACCEPTED],
            sum(outcomes[outcome] for outcome in GATED_OUTCOMES),
        ),
        fallback_attempt=measure_proportion(fallback_rounds, model_left_rounds),
        fallback_executed=measure_proportion(fallback_executed_rounds, fallback_rounds),
        timed_out_fallback=measure_proportion(timed_out_fallback_rounds, model_left_rounds),
        deadline_no_execution=measure_proportion(
            sum(outcomes[outcome] for outcome in DEADLINE_OUTCOMES), model_left_rounds
        ),
        skipped_before_planning=measure_proportion(
            outcomes[PlannerOutcome.MODEL_SKIPPED_AT_DEADLINE], model_left_rounds
        ),
        unavailable_details=unavailable_details,
        rejection_codes=rejection_codes,
    )


def list_call_keys_before(evidence_set: KnowledgeEvidenceSet, round_number: int) -> list[str]:
    """The call keys of the steps issued before round ``round_number``, in issue order."""
    call_keys: list[str] = []
    for step in evidence_set.trajectory.steps:
        if step.round_number < round_number:
            call_keys.append(step.call_key)
    return call_keys


def fingerprint_observations_before(evidence_set: KnowledgeEvidenceSet, round_number: int) -> str:
    """SHA-256 of what a planner of round ``round_number`` was shown of the earlier steps."""
    observations: list[object] = []
    for step in evidence_set.trajectory.steps:
        if step.round_number < round_number:
            observations.append(observe_step(step).model_dump(mode="json"))
    return canonical_sha256(observations)


def find_comparable_round(
    model_set: KnowledgeEvidenceSet, deterministic_set: KnowledgeEvidenceSet, round_number: int
) -> RoundRecord | NotComparableReason:
    """The deterministic run's round ``round_number`` when it was planned from the same
    state as the model run's: the same earlier calls, observed alike. Otherwise why the two
    cannot be set side by side."""
    deterministic_round = find_round(deterministic_set, round_number)
    if deterministic_round is None:
        return NotComparableReason.DETERMINISTIC_RUN_LACKS_ROUND
    model_call_keys = list_call_keys_before(model_set, round_number)
    if model_call_keys != list_call_keys_before(deterministic_set, round_number):
        return NotComparableReason.ROUND_ONE_CALLS_DIFFER
    model_observations = fingerprint_observations_before(model_set, round_number)
    if model_observations != fingerprint_observations_before(deterministic_set, round_number):
        return NotComparableReason.ROUND_ONE_OBSERVATIONS_DIFFER
    return deterministic_round


def measure_divergence(case_runs: Sequence[CaseRuns], round_number: int) -> PlanDivergence:
    model_accepted_rounds = 0
    compared_rounds = 0
    differing_rounds = 0
    not_comparable: dict[NotComparableReason, int] = dict.fromkeys(NotComparableReason, 0)
    for case in case_runs:
        for model_set in case.model_sets:
            model_round = find_round(model_set, round_number)
            if model_round is None or model_round.planner_outcome is not (
                PlannerOutcome.MODEL_ACCEPTED
            ):
                continue
            model_accepted_rounds += 1
            comparison = find_comparable_round(model_set, case.deterministic_set, round_number)
            if isinstance(comparison, NotComparableReason):
                not_comparable[comparison] += 1
                continue
            compared_rounds += 1
            model_plan = fingerprint_plan(model_round.accepted_plan)
            if model_plan != fingerprint_plan(comparison.accepted_plan):
                differing_rounds += 1
    return PlanDivergence(
        model_accepted_rounds=model_accepted_rounds,
        differs=measure_proportion(differing_rounds, compared_rounds),
        not_comparable=not_comparable,
    )


def summarize_durations(evidence_sets: Iterable[KnowledgeEvidenceSet]) -> DurationSummary:
    durations_ms: list[int] = []
    for evidence_set in evidence_sets:
        durations_ms.extend(evidence_set.timings.planner_durations_ms)
    if not durations_ms:
        return DurationSummary(count=0, min_ms=None, median_ms=None, max_ms=None)
    durations_ms.sort()
    return DurationSummary(
        count=len(durations_ms),
        min_ms=durations_ms[0],
        median_ms=durations_ms[(len(durations_ms) - 1) // 2],
        max_ms=durations_ms[-1],
    )


def has_model_step(evidence_set: KnowledgeEvidenceSet) -> bool:
    return any(step.planned_by is PlannerKind.MODEL for step in evidence_set.trajectory.steps)


def count_run_plans(model_sets: Iterable[KnowledgeEvidenceSet]) -> dict[str, int]:
    """How many runs gave each run-plan fingerprint (``fingerprint_run_plans``)."""
    run_plans: dict[str, int] = {}
    for model_set in model_sets:
        run_plan = fingerprint_run_plans(model_set)
        run_plans[run_plan] = run_plans.get(run_plan, 0) + 1
    return run_plans


def has_planner_switch(model_sets: Iterable[KnowledgeEvidenceSet]) -> bool:
    """Whether, in some round, one run's model plan passed the gate while another run fell
    back to the policy's."""
    outcomes_by_round: dict[int, set[PlannerOutcome]] = {}
    for model_set in model_sets:
        for round_record in model_set.trajectory.rounds:
            round_outcomes = outcomes_by_round.setdefault(round_record.round_number, set())
            round_outcomes.add(round_record.planner_outcome)
    for round_outcomes in outcomes_by_round.values():
        if PlannerOutcome.MODEL_ACCEPTED in round_outcomes and round_outcomes & FALLBACK_OUTCOMES:
            return True
    return False


def compare_tool_calls(
    model_sets: Iterable[KnowledgeEvidenceSet], deterministic_tool_calls: int
) -> ToolCallComparison:
    fewer = same = more = 0
    for model_set in model_sets:
        tool_calls = model_set.trajectory.budget_used.tool_calls
        if tool_calls < deterministic_tool_calls:
            fewer += 1
        elif tool_calls == deterministic_tool_calls:
            same += 1
        else:
            more += 1
    return ToolCallComparison(fewer=fewer, same=same, more=more)


def summarize_model_case(case: CaseRuns) -> ModelCase:
    run_endings: set[tuple[ResultStatus, StopReason]] = set()
    deterministic_ending = (case.deterministic_set.status, case.deterministic_set.stop_reason)
    runs_matching_ending = 0
    runs_matching_answers = 0
    runs_with_model_step = 0
    run_acceptance_rates: list[float | None] = []
    tool_calls: list[int] = []
    for model_set in case.model_sets:
        run_ending = (model_set.status, model_set.stop_reason)
        run_endings.add(run_ending)
        if run_ending == deterministic_ending:
            runs_matching_ending += 1
        if has_same_answers(model_set, case.deterministic_set):
            runs_matching_answers += 1
        if has_model_step(model_set):
            runs_with_model_step += 1
        run_acceptance = measure_rounds(model_set.trajectory.rounds).gate_acceptance
        run_acceptance_rates.append(run_acceptance.rate)
        tool_calls.append(model_set.trajectory.budget_used.tool_calls)
    run_count = len(case.model_sets)
    run_plans = count_run_plans(case.model_sets)
    return ModelCase(
        case_sha256=case.case_sha256,
        runs=run_count,
        distinct_run_plans=len(run_plans),
        run_plans=run_plans,
        distinct_endings=len(run_endings),
        matches_deterministic_ending=measure_proportion(runs_matching_ending, run_count),
        matches_deterministic_answers=measure_proportion(runs_matching_answers, run_count),
        executed_model_step=measure_proportion(runs_with_model_step, run_count),
        gate_acceptance=measure_rounds(list_rounds(case.model_sets, None)).gate_acceptance,
        run_gate_acceptance=spread_rates(run_acceptance_rates),
        switches_planner=has_planner_switch(case.model_sets),
        min_tool_calls=min(tool_calls),
        max_tool_calls=max(tool_calls),
        tool_calls_against_deterministic=compare_tool_calls(
            case.model_sets, case.deterministic_set.trajectory.budget_used.tool_calls
        ),
    )


def spread_rates(rates: Sequence[float | None]) -> RateSpread:
    measured_rates: list[float] = []
    for rate in rates:
        if rate is not None:
            measured_rates.append(rate)
    if not measured_rates:
        return RateSpread(measured=0, mean=None, min=None, max=None)
    return RateSpread(
        measured=len(measured_rates),
        mean=round(sum(measured_rates) / len(measured_rates), RATE_DECIMALS),
        min=min(measured_rates),
        max=max(measured_rates),
    )


def build_model_section(case_runs: Sequence[CaseRuns]) -> ModelSection:
    model_sets: list[KnowledgeEvidenceSet] = []
    model_cases: list[ModelCase] = []
    case_acceptance_rates: list[float | None] = []
    runs_with_model_step = 0
    fewer_tool_calls = same_tool_calls = more_tool_calls = 0
    for case in case_runs:
        model_sets.extend(case.model_sets)
        model_case = summarize_model_case(case)
        model_cases.append(model_case)
        case_acceptance_rates.append(model_case.gate_acceptance.rate)
        runs_with_model_step += model_case.executed_model_step.count
        fewer_tool_calls += model_case.tool_calls_against_deterministic.fewer
        same_tool_calls += model_case.tool_calls_against_deterministic.same
        more_tool_calls += model_case.tool_calls_against_deterministic.more
    return ModelSection(
        runs=len(model_sets),
        results=count_results(model_sets),
        executed_model_step=measure_proportion(runs_with_model_step, len(model_sets)),
        tool_calls_against_deterministic=ToolCallComparison(
            fewer=fewer_tool_calls, same=same_tool_calls, more=more_tool_calls
        ),
        round_one=measure_rounds(list_rounds(model_sets, 1)),
        round_two=measure_rounds(list_rounds(model_sets, 2)),
        all_rounds=measure_rounds(list_rounds(model_sets, None)),
        round_one_divergence=measure_divergence(case_runs, 1),
        round_two_divergence=measure_divergence(case_runs, 2),
        planner_durations=summarize_durations(model_sets),
        case_gate_acceptance=spread_rates(case_acceptance_rates),
        cases=tuple(model_cases),
    )


def analyze_planner_runs(
    identity: EvaluationIdentity,
    case_runs: Sequence[CaseRuns],
    sufficiency: SufficiencySection | None = None,
) -> PlannerEvaluationReport:
    """The report on ``case_runs``, measured under ``identity``, with ``sufficiency`` when
    the cases were labelled; without model runs (``model_runs_per_case`` 0) it has no
    model section."""
    deterministic_sets: list[KnowledgeEvidenceSet] = []
    deterministic_cases: list[DeterministicCase] = []
    for case in case_runs:
        deterministic_sets.append(case.deterministic_set)
        deterministic_cases.append(
            DeterministicCase(
                case_sha256=case.case_sha256, run=summarize_run(case.deterministic_set)
            )
        )
    model_section = None
    if identity.model_runs_per_case > 0:
        model_section = build_model_section(case_runs)
    return PlannerEvaluationReport(
        identity=identity,
        deterministic=DeterministicSection(
            runs=len(deterministic_sets),
            results=count_results(deterministic_sets),
            cases=tuple(deterministic_cases),
        ),
        model=model_section,
        sufficiency=sufficiency,
    )
