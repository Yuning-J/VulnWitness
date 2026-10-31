"""The planner analysis measures outcomes, fallbacks, plan divergence and stability from
the evidence sets alone, over stated denominators, and its report holds no text a run
was given or produced."""

from collections.abc import Mapping
from typing import TypeVar

import pytest

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.application.investigate import PLANNER_CAP_REPLY
from cve_kgrag.domain.investigation import (
    KnowledgeEvidenceSet,
    PlannerOutcome,
    RoundRecord,
    StopReason,
)
from cve_kgrag.domain.planning import ModelReply, PlanRejection, PlanRejectionCode
from cve_kgrag.domain.search import SearchWarning, SearchWarningCode
from cve_kgrag.domain.taxonomy import ResultStatus
from cve_kgrag.domain.topic import ReviewStatus
from cve_kgrag.evaluation.planner_analysis import CaseRuns, analyze_planner_runs
from cve_kgrag.evaluation.planner_report import (
    ModelSection,
    NotComparableReason,
    PlannerEvaluationReport,
    Proportion,
    RunSummary,
    ToolCallComparison,
    format_report,
)
from tests.support.evaluation import build_identity, run_deterministically, run_with_replies
from tests.support.investigation import reseal_evidence_set, rewrite_step, update_trajectory
from tests.support.planners import (
    SCRIPTED_PLANNER,
    UNAVAILABLE_REPLY,
    build_plan_reply,
    build_text_reply,
)

SEARCH_AUSF_SUCI = {"tool": "cve_search", "query": "ausf suci"}
SEARCH_5GAKA = {"tool": "cve_search", "query": "5gaka"}
SEARCH_AKA = {"tool": "cve_search", "query": "aka"}
SEARCH_5G_AKA = {"tool": "cve_search", "query": "5g aka"}
SEARCH_ZZQX = {"tool": "cve_search", "query": "zzqx"}
TOPIC_5G_AKA = {"tool": "topic_context", "topic_id": "3gpp:5g-aka"}
# No fixture record names open5gs.
OPEN5GS_FILTERS = {"products": ["open5gs"]}
# Text that must never reach a report: in a query, in plan text, and the planner's names.
QUERY_MARKER = "querymarkerzq"
PLAN_MARKER = "PLAN-MARKER-7f3e"

KeyT = TypeVar("KeyT")


def build_case(
    deterministic_set: KnowledgeEvidenceSet, *model_sets: KnowledgeEvidenceSet, name: str = "a"
) -> CaseRuns:
    return CaseRuns(
        case_sha256=name * 64, deterministic_set=deterministic_set, model_sets=model_sets
    )


def analyze(*case_runs: CaseRuns) -> PlannerEvaluationReport:
    model_runs = len(case_runs[0].model_sets)
    return analyze_planner_runs(build_identity(model_runs), case_runs)


def keep_counted(counts: Mapping[KeyT, int]) -> dict[KeyT, int]:
    """The entries that counted something."""
    counted: dict[KeyT, int] = {}
    for key, count in counts.items():
        if count:
            counted[key] = count
    return counted


def describe_round_plans(run: RunSummary) -> list[tuple[int, int]]:
    """Each round as (round number, steps executed)."""
    round_plans: list[tuple[int, int]] = []
    for round_plan in run.rounds:
        round_plans.append((round_plan.round_number, round_plan.executed_steps))
    return round_plans


def require_model_section(report: PlannerEvaluationReport) -> ModelSection:
    assert report.model is not None
    return report.model


def run_5g_aka(
    fixture_bundle: FixtureBundle, *replies: ModelReply, seconds_per_call: float = 0.0
) -> KnowledgeEvidenceSet:
    """A model run of the 5G-AKA question, which the policy answers in round 1."""
    return run_with_replies(
        fixture_bundle,
        "5G-AKA",
        "implementation_only",
        *replies,
        seconds_per_call=seconds_per_call,
        review_status=ReviewStatus.REVIEWED,
    )


def run_open5gs_deterministically(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """The policy's two rounds of a 5G-AKA question about open5gs: the topic finds no
    open5gs record, so round 2 searches the question's own words."""
    return run_deterministically(
        fixture_bundle, "5gaka", "implementation_only", filters=OPEN5GS_FILTERS
    )


def run_open5gs_with_replies(
    fixture_bundle: FixtureBundle, *replies: ModelReply
) -> KnowledgeEvidenceSet:
    """A model run of the same question, its planner answering round by round."""
    return run_with_replies(
        fixture_bundle, "5gaka", "implementation_only", *replies, filters=OPEN5GS_FILTERS
    )


def replace_round_one(
    evidence_set: KnowledgeEvidenceSet, round_one: RoundRecord
) -> KnowledgeEvidenceSet:
    """The set with its only round replaced, nothing executed: a round the deadline ended,
    which a scripted planner on a stepping clock cannot produce."""
    return update_trajectory(evidence_set, rounds=(round_one,), steps=())


def build_deadline_round(planner_outcome: PlannerOutcome) -> RoundRecord:
    rejections: tuple[PlanRejection, ...] = ()
    if planner_outcome is PlannerOutcome.MODEL_TIMED_OUT:
        rejections = (PlanRejection(code=PlanRejectionCode.PLANNER_TIMED_OUT),)
    return RoundRecord(
        round_number=1,
        planner_outcome=planner_outcome,
        rejections=rejections,
        accepted_plan=(),
        executed_step_indices=(),
    )


def test_deterministic_baseline_alone_has_no_model_section_and_counts_its_results(
    fixture_bundle: FixtureBundle,
) -> None:
    topic_set = run_deterministically(
        fixture_bundle, "5gaka", "implementation_only", review_status=ReviewStatus.REVIEWED
    )
    exact_set = run_deterministically(fixture_bundle, "CVE-9999-4242", "implementation_only")

    report = analyze(build_case(topic_set, name="a"), build_case(exact_set, name="b"))

    assert report.model is None
    assert report.deterministic.runs == 2
    assert report.deterministic.results.statuses[ResultStatus.OK] == 1
    assert report.deterministic.results.statuses[ResultStatus.NO_MATCH] == 1
    assert report.deterministic.results.stop_reasons[StopReason.SUFFICIENT] == 1
    assert report.deterministic.results.stop_reasons[StopReason.NO_EVIDENCE] == 1
    topic_run = report.deterministic.cases[0].run
    assert describe_round_plans(topic_run) == [(1, 1)]
    assert topic_run.tool_calls == topic_set.trajectory.budget_used.tool_calls


def test_round_outcomes_are_counted_over_their_stated_denominators(
    fixture_bundle: FixtureBundle,
) -> None:
    after_deadline_set = run_5g_aka(
        fixture_bundle, build_plan_reply(SEARCH_AUSF_SUCI), seconds_per_call=31
    )
    model_sets = (
        run_5g_aka(fixture_bundle, build_plan_reply(TOPIC_5G_AKA)),
        run_5g_aka(fixture_bundle, build_text_reply("not json")),
        run_5g_aka(fixture_bundle, UNAVAILABLE_REPLY),
        run_5g_aka(fixture_bundle, PLANNER_CAP_REPLY),
        after_deadline_set,
        replace_round_one(after_deadline_set, build_deadline_round(PlannerOutcome.MODEL_TIMED_OUT)),
        replace_round_one(
            after_deadline_set, build_deadline_round(PlannerOutcome.MODEL_SKIPPED_AT_DEADLINE)
        ),
        # A rejected plan whose fallback the gate rejects as over budget: nothing runs.
        run_with_replies(
            fixture_bundle,
            "5gaka",
            "mixed",
            build_text_reply("not json"),
            budget={"max_tool_calls": 4},
        ),
        # The policy's round-1 plan is over the source budget: the model is not consulted.
        run_with_replies(fixture_bundle, "5gaka", "mixed", budget={"max_sources": 1}),
    )
    deterministic_set = run_deterministically(
        fixture_bundle, "5G-AKA", "implementation_only", review_status=ReviewStatus.REVIEWED
    )

    model_section = require_model_section(analyze(build_case(deterministic_set, *model_sets)))

    round_one = model_section.round_one
    assert round_one.rounds == 9
    assert round_one.outcomes == {
        PlannerOutcome.DETERMINISTIC: 0,
        PlannerOutcome.MODEL_ACCEPTED: 1,
        PlannerOutcome.MODEL_REJECTED: 2,
        PlannerOutcome.MODEL_UNAVAILABLE: 2,
        PlannerOutcome.MODEL_REPLY_AFTER_DEADLINE: 1,
        PlannerOutcome.MODEL_TIMED_OUT: 1,
        PlannerOutcome.MODEL_SKIPPED_AT_DEADLINE: 1,
        PlannerOutcome.MODEL_NOT_CONSULTED: 1,
    }
    assert round_one.gate_acceptance == Proportion(count=1, of=3, rate=0.3333)
    # Eight of the nine rounds were left to the model; the unconsulted one is not.
    assert round_one.fallback_attempt == Proportion(count=4, of=8, rate=0.5)
    assert round_one.fallback_executed == Proportion(count=3, of=4, rate=0.75)
    assert round_one.timed_out_fallback == Proportion(count=1, of=8, rate=0.125)
    assert round_one.deadline_no_execution == Proportion(count=2, of=8, rate=0.25)
    assert round_one.skipped_before_planning == Proportion(count=1, of=8, rate=0.125)
    assert keep_counted(round_one.unavailable_details) == {
        "unreachable": 1,
        "timed_out": 1,
    }
    assert keep_counted(round_one.rejection_codes) == {
        "malformed_plan": 2,
        "over_tool_call_budget": 1,
        "planner_unavailable": 2,
    }
    assert model_section.round_two.rounds == 0
    assert model_section.round_two.fallback_attempt == Proportion(count=0, of=0, rate=None)
    assert model_section.all_rounds == round_one


def test_model_rates_are_null_when_the_policy_left_no_round_to_the_model(
    fixture_bundle: FixtureBundle,
) -> None:
    """Free text is planned by the policy alone: its rounds are counted, under
    ``model_not_consulted``, but measure nothing of the model."""
    deterministic_set = run_deterministically(
        fixture_bundle, "sql injection gateway", "implementation_only"
    )
    model_set = run_with_replies(fixture_bundle, "sql injection gateway", "implementation_only")

    all_rounds = require_model_section(analyze(build_case(deterministic_set, model_set))).all_rounds

    no_round = Proportion(count=0, of=0, rate=None)
    assert all_rounds.rounds == 1
    assert keep_counted(all_rounds.outcomes) == {PlannerOutcome.MODEL_NOT_CONSULTED: 1}
    assert all_rounds.gate_acceptance == no_round
    assert all_rounds.fallback_attempt == no_round
    assert all_rounds.fallback_executed == no_round
    assert all_rounds.timed_out_fallback == no_round
    assert all_rounds.deadline_no_execution == no_round
    assert all_rounds.skipped_before_planning == no_round
    assert keep_counted(all_rounds.unavailable_details) == {}
    assert keep_counted(all_rounds.rejection_codes) == {}


def test_every_outcome_detail_and_code_is_listed_even_when_none_occurred(
    fixture_bundle: FixtureBundle,
) -> None:
    """A report always has the same keys, so two reports compare key by key."""
    deterministic_set = run_deterministically(
        fixture_bundle, "5G-AKA", "implementation_only", review_status=ReviewStatus.REVIEWED
    )
    model_set = run_5g_aka(fixture_bundle, build_plan_reply(TOPIC_5G_AKA))

    round_one = require_model_section(analyze(build_case(deterministic_set, model_set))).round_one

    assert set(round_one.outcomes) == set(PlannerOutcome)
    assert len(round_one.unavailable_details) == 7
    assert list(round_one.rejection_codes) == list(PlanRejectionCode)


@pytest.mark.parametrize(
    ("round_one_plan", "round_two_plan", "expected_differs"),
    [
        (TOPIC_5G_AKA, SEARCH_5GAKA, Proportion(count=0, of=1, rate=0.0)),
        (TOPIC_5G_AKA, SEARCH_5G_AKA, Proportion(count=1, of=1, rate=1.0)),
    ],
    ids=["same_refinement", "other_refinement"],
)
def test_round_two_plan_is_compared_when_both_runs_reached_it_from_the_same_state(
    fixture_bundle: FixtureBundle,
    round_one_plan: dict[str, str],
    round_two_plan: dict[str, str],
    expected_differs: Proportion,
) -> None:
    deterministic_set = run_open5gs_deterministically(fixture_bundle)
    model_set = run_open5gs_with_replies(
        fixture_bundle, build_plan_reply(round_one_plan), build_plan_reply(round_two_plan)
    )

    model_section = require_model_section(analyze(build_case(deterministic_set, model_set)))

    assert model_section.round_one_divergence.differs == Proportion(count=0, of=1, rate=0.0)
    assert model_section.round_two_divergence.model_accepted_rounds == 1
    assert model_section.round_two_divergence.differs == expected_differs


def test_round_one_plan_unlike_the_policy_s_counts_as_differing(
    fixture_bundle: FixtureBundle,
) -> None:
    deterministic_set = run_deterministically(
        fixture_bundle, "5G-AKA", "implementation_only", review_status=ReviewStatus.REVIEWED
    )
    model_set = run_5g_aka(fixture_bundle, build_plan_reply(SEARCH_AUSF_SUCI), UNAVAILABLE_REPLY)

    divergence = require_model_section(
        analyze(build_case(deterministic_set, model_set))
    ).round_one_divergence

    assert divergence.differs == Proportion(count=1, of=1, rate=1.0)


@pytest.mark.parametrize(
    "expected_reason",
    list(NotComparableReason),
    ids=str,
)
def test_round_two_from_another_state_is_not_comparable_and_says_why(
    fixture_bundle: FixtureBundle, expected_reason: NotComparableReason
) -> None:
    model_set = run_open5gs_with_replies(
        fixture_bundle, build_plan_reply(TOPIC_5G_AKA), build_plan_reply(SEARCH_5GAKA)
    )
    same_state_set = run_open5gs_deterministically(fixture_bundle)
    deterministic_sets = {
        # The policy answers "5G-AKA" in round 1, so it plans no round 2.
        NotComparableReason.DETERMINISTIC_RUN_LACKS_ROUND: run_deterministically(
            fixture_bundle, "5G-AKA", "implementation_only", review_status=ReviewStatus.REVIEWED
        ),
        # Its round 1 looks an ID up instead of exploring the topic.
        NotComparableReason.ROUND_ONE_CALLS_DIFFER: run_deterministically(
            fixture_bundle, "CVE-9999-4242 5G-AKA", "mixed"
        ),
        # The same round-1 call, observed with an answer the model run did not see.
        NotComparableReason.ROUND_ONE_OBSERVATIONS_DIFFER: rewrite_step(
            same_state_set, 1, answer_ids=("CVE-9999-0003",)
        ),
    }

    divergence = require_model_section(
        analyze(build_case(deterministic_sets[expected_reason], model_set))
    ).round_two_divergence

    assert divergence.model_accepted_rounds == 1
    assert divergence.differs == Proportion(count=0, of=0, rate=None)
    assert keep_counted(divergence.not_comparable) == {expected_reason: 1}


def run_5gaka_zzqx(
    fixture_bundle: FixtureBundle, *round_one_plan: dict[str, str]
) -> KnowledgeEvidenceSet:
    """A model run of a question round 1's searches leave unanswered, refined in round 2
    with the topic context."""
    return run_with_replies(
        fixture_bundle,
        "5gaka zzqx",
        "implementation_only",
        build_plan_reply(*round_one_plan),
        build_plan_reply(TOPIC_5G_AKA),
    )


def test_round_two_after_the_same_calls_in_another_order_is_not_comparable(
    fixture_bundle: FixtureBundle,
) -> None:
    """The model runs below differ only in their round-1 order; one stands in for the
    deterministic run, since the comparison reads nothing but the trajectories."""
    model_set = run_5gaka_zzqx(fixture_bundle, SEARCH_5GAKA, SEARCH_ZZQX)
    reordered_set = run_5gaka_zzqx(fixture_bundle, SEARCH_ZZQX, SEARCH_5GAKA)

    divergence = require_model_section(
        analyze(build_case(reordered_set, model_set))
    ).round_two_divergence

    assert keep_counted(divergence.not_comparable) == {
        NotComparableReason.ROUND_ONE_CALLS_DIFFER: 1
    }


@pytest.mark.parametrize(
    "step_changes",
    [
        {"answer_ids": ("CVE-9999-0003",)},
        {"status": ResultStatus.OK},
        {"search_warnings": (SearchWarning(code=SearchWarningCode.BACKEND_ERROR, subject="x"),)},
    ],
    ids=["answer_count", "status", "warning_codes"],
)
def test_any_difference_in_what_round_two_s_planner_was_shown_makes_it_not_comparable(
    fixture_bundle: FixtureBundle, step_changes: dict[str, object]
) -> None:
    model_set = run_open5gs_with_replies(
        fixture_bundle, build_plan_reply(TOPIC_5G_AKA), build_plan_reply(SEARCH_5GAKA)
    )
    deterministic_set = rewrite_step(
        run_open5gs_deterministically(fixture_bundle), 1, **step_changes
    )

    divergence = require_model_section(
        analyze(build_case(deterministic_set, model_set))
    ).round_two_divergence

    assert keep_counted(divergence.not_comparable) == {
        NotComparableReason.ROUND_ONE_OBSERVATIONS_DIFFER: 1
    }


def test_rounds_the_model_did_not_plan_are_left_out_of_the_divergence(
    fixture_bundle: FixtureBundle,
) -> None:
    deterministic_set = run_deterministically(
        fixture_bundle, "5G-AKA", "implementation_only", review_status=ReviewStatus.REVIEWED
    )
    model_set = run_5g_aka(fixture_bundle, UNAVAILABLE_REPLY)

    divergence = require_model_section(
        analyze(build_case(deterministic_set, model_set))
    ).round_one_divergence

    assert divergence.model_accepted_rounds == 0
    assert divergence.differs == Proportion(count=0, of=0, rate=None)


def test_each_case_reports_its_stability_and_the_cases_spread_their_acceptance(
    fixture_bundle: FixtureBundle,
) -> None:
    deterministic_set = run_deterministically(
        fixture_bundle, "5G-AKA", "implementation_only", review_status=ReviewStatus.REVIEWED
    )
    accepted_set = run_5g_aka(fixture_bundle, build_plan_reply(SEARCH_AUSF_SUCI), UNAVAILABLE_REPLY)
    unavailable_set = run_5g_aka(fixture_bundle, UNAVAILABLE_REPLY)
    rejected_set = run_5g_aka(fixture_bundle, build_text_reply("not json"))
    switching_case = build_case(deterministic_set, accepted_set, unavailable_set, name="a")
    half_accepted_case = build_case(deterministic_set, accepted_set, rejected_set, name="b")
    unavailable_case = build_case(deterministic_set, unavailable_set, unavailable_set, name="c")

    model_section = require_model_section(
        analyze(switching_case, half_accepted_case, unavailable_case)
    )

    switching, half_accepted, unavailable = model_section.cases
    assert (switching.runs, switching.distinct_run_plans, switching.distinct_endings) == (2, 2, 1)
    assert sorted(switching.run_plans.values()) == [1, 1]
    assert switching.switches_planner is True
    assert switching.matches_deterministic_ending == Proportion(count=2, of=2, rate=1.0)
    assert switching.executed_model_step == Proportion(count=1, of=2, rate=0.5)
    assert switching.gate_acceptance == Proportion(count=1, of=1, rate=1.0)
    assert half_accepted.gate_acceptance == Proportion(count=1, of=2, rate=0.5)
    assert half_accepted.run_gate_acceptance.model_dump() == {
        "measured": 2,
        "mean": 0.5,
        "min": 0.0,
        "max": 1.0,
    }
    assert half_accepted.switches_planner is True
    assert (unavailable.distinct_run_plans, unavailable.switches_planner) == (1, False)
    assert list(unavailable.run_plans.values()) == [2]
    assert unavailable.gate_acceptance == Proportion(count=0, of=0, rate=None)
    assert unavailable.run_gate_acceptance.measured == 0
    assert model_section.case_gate_acceptance.model_dump() == {
        "measured": 2,
        "mean": 0.75,
        "min": 0.5,
        "max": 1.0,
    }
    assert model_section.runs == 6
    assert model_section.executed_model_step == Proportion(count=2, of=6, rate=0.3333)


def test_runs_falling_back_in_different_ways_do_not_switch_planner(
    fixture_bundle: FixtureBundle,
) -> None:
    deterministic_set = run_deterministically(
        fixture_bundle, "5G-AKA", "implementation_only", review_status=ReviewStatus.REVIEWED
    )
    rejected_set = run_5g_aka(fixture_bundle, build_text_reply("not json"))
    unavailable_set = run_5g_aka(fixture_bundle, UNAVAILABLE_REPLY)

    (model_case,) = require_model_section(
        analyze(build_case(deterministic_set, rejected_set, unavailable_set))
    ).cases

    assert model_case.switches_planner is False


def test_plan_switch_in_round_two_counts_as_switching_planner(
    fixture_bundle: FixtureBundle,
) -> None:
    deterministic_set = run_deterministically(
        fixture_bundle, "5gaka", "implementation_only", review_status=ReviewStatus.REVIEWED
    )
    accepted_set = run_with_replies(
        fixture_bundle,
        "5gaka",
        "implementation_only",
        build_plan_reply(SEARCH_5GAKA),
        build_plan_reply(TOPIC_5G_AKA),
        review_status=ReviewStatus.REVIEWED,
    )
    fallback_set = run_with_replies(
        fixture_bundle,
        "5gaka",
        "implementation_only",
        build_plan_reply(SEARCH_5GAKA),
        UNAVAILABLE_REPLY,
        review_status=ReviewStatus.REVIEWED,
    )

    (model_case,) = require_model_section(
        analyze(build_case(deterministic_set, accepted_set, fallback_set))
    ).cases

    assert model_case.switches_planner is True


def test_run_ending_for_another_reason_does_not_match_the_deterministic_ending(
    fixture_bundle: FixtureBundle,
) -> None:
    deterministic_set = run_deterministically(
        fixture_bundle, "5G-AKA", "implementation_only", review_status=ReviewStatus.REVIEWED
    )
    accepted_set = run_5g_aka(fixture_bundle, build_plan_reply(SEARCH_AUSF_SUCI), UNAVAILABLE_REPLY)
    same_status_other_stop_set = reseal_evidence_set(
        accepted_set, stop_reason=StopReason.SOURCE_UNAVAILABLE
    )

    (model_case,) = require_model_section(
        analyze(build_case(deterministic_set, accepted_set, same_status_other_stop_set))
    ).cases

    assert model_case.matches_deterministic_ending == Proportion(count=1, of=2, rate=0.5)
    assert model_case.distinct_endings == 2


@pytest.mark.parametrize("answer_section", ["implementation_candidates", "protocol_context"])
def test_reordered_answers_match_and_other_answer_ids_do_not_match_the_deterministic_answers(
    fixture_bundle: FixtureBundle, answer_section: str
) -> None:
    deterministic_set = run_deterministically(
        fixture_bundle, "5G-AKA", "mixed", review_status=ReviewStatus.REVIEWED
    )
    answers = getattr(deterministic_set, answer_section)
    assert len(answers) >= 2
    reordered_set = reseal_evidence_set(deterministic_set, **{answer_section: answers[::-1]})
    # As many answers as the deterministic run, one ID repeated in place of another.
    replaced_set = reseal_evidence_set(
        deterministic_set, **{answer_section: (*answers[1:], answers[1])}
    )
    dropped_set = reseal_evidence_set(deterministic_set, **{answer_section: answers[1:]})

    (model_case,) = require_model_section(
        analyze(build_case(deterministic_set, reordered_set, replaced_set, dropped_set))
    ).cases

    assert model_case.matches_deterministic_ending == Proportion(count=3, of=3, rate=1.0)
    assert model_case.matches_deterministic_answers == Proportion(count=1, of=3, rate=0.3333)


def test_accepted_model_plan_that_executed_nothing_is_no_executed_model_step(
    fixture_bundle: FixtureBundle,
) -> None:
    deterministic_set = run_deterministically(
        fixture_bundle, "5G-AKA", "implementation_only", review_status=ReviewStatus.REVIEWED
    )
    accepted_set = run_5g_aka(fixture_bundle, build_plan_reply(TOPIC_5G_AKA))
    accepted_round = accepted_set.trajectory.rounds[0].model_copy(
        update={"executed_step_indices": ()}
    )
    # The deadline passed after the gate accepted the plan and before its first step.
    unexecuted_set = update_trajectory(accepted_set, rounds=(accepted_round,), steps=())

    model_section = require_model_section(analyze(build_case(deterministic_set, unexecuted_set)))

    assert model_section.round_one.outcomes[PlannerOutcome.MODEL_ACCEPTED] == 1
    assert model_section.executed_model_step == Proportion(count=0, of=1, rate=0.0)


def test_model_section_counts_only_the_model_runs_results(fixture_bundle: FixtureBundle) -> None:
    deterministic_set = run_deterministically(
        fixture_bundle, "5G-AKA", "implementation_only", review_status=ReviewStatus.REVIEWED
    )
    after_deadline_set = run_5g_aka(
        fixture_bundle, build_plan_reply(SEARCH_AUSF_SUCI), seconds_per_call=31
    )

    report = analyze(build_case(deterministic_set, after_deadline_set))

    model_results = require_model_section(report).results
    assert keep_counted(model_results.statuses) == {ResultStatus.PARTIAL: 1}
    assert keep_counted(model_results.stop_reasons) == {StopReason.BUDGET_EXHAUSTED: 1}
    assert keep_counted(report.deterministic.results.statuses) == {ResultStatus.OK: 1}


def test_tool_calls_set_each_model_run_beside_the_deterministic_run(
    fixture_bundle: FixtureBundle,
) -> None:
    deterministic_set = run_deterministically(
        fixture_bundle, "5G-AKA", "implementation_only", review_status=ReviewStatus.REVIEWED
    )
    same_cost_set = run_5g_aka(fixture_bundle, build_plan_reply(TOPIC_5G_AKA))
    costlier_set = run_5g_aka(fixture_bundle, build_plan_reply(SEARCH_5G_AKA, TOPIC_5G_AKA))
    cheaper_set = run_5g_aka(
        fixture_bundle, build_plan_reply(SEARCH_AUSF_SUCI), seconds_per_call=31
    )

    model_section = require_model_section(
        analyze(build_case(deterministic_set, same_cost_set, costlier_set, cheaper_set))
    )

    (model_case,) = model_section.cases
    comparison = ToolCallComparison(fewer=1, same=1, more=1)
    assert model_case.tool_calls_against_deterministic == comparison
    assert model_section.tool_calls_against_deterministic == comparison
    assert model_case.min_tool_calls == 0
    assert model_case.max_tool_calls == costlier_set.trajectory.budget_used.tool_calls


def test_run_plan_fingerprint_keeps_the_plan_order(fixture_bundle: FixtureBundle) -> None:
    deterministic_set = run_deterministically(fixture_bundle, "5gaka zzqx", "implementation_only")
    model_set = run_5gaka_zzqx(fixture_bundle, SEARCH_5GAKA, SEARCH_ZZQX)
    reordered_set = run_5gaka_zzqx(fixture_bundle, SEARCH_ZZQX, SEARCH_5GAKA)

    (model_case,) = require_model_section(
        analyze(build_case(deterministic_set, model_set, reordered_set))
    ).cases

    assert model_case.distinct_run_plans == 2


def test_evidence_ids_hash_tells_runs_with_other_evidence_apart(
    fixture_bundle: FixtureBundle,
) -> None:
    lookup_set = run_deterministically(fixture_bundle, "CVE-9999-0005", "implementation_only")
    search_set = run_deterministically(
        fixture_bundle, "5G-AKA", "implementation_only", review_status=ReviewStatus.REVIEWED
    )

    report = analyze(build_case(lookup_set, name="a"), build_case(search_set, name="b"))

    lookup_case, search_case = report.deterministic.cases
    assert lookup_set.trajectory.evidence_ids != search_set.trajectory.evidence_ids
    assert lookup_case.run.evidence_ids_sha256 != search_case.run.evidence_ids_sha256


def test_planner_durations_give_the_lower_median_of_an_even_count(
    fixture_bundle: FixtureBundle,
) -> None:
    deterministic_set = run_deterministically(
        fixture_bundle, "5G-AKA", "implementation_only", review_status=ReviewStatus.REVIEWED
    )
    model_sets: list[KnowledgeEvidenceSet] = []
    for seconds_per_call in (1, 3, 2, 4):
        model_sets.append(
            run_5g_aka(
                fixture_bundle,
                build_plan_reply(TOPIC_5G_AKA),
                seconds_per_call=seconds_per_call,
            )
        )

    durations = require_model_section(
        analyze(build_case(deterministic_set, *model_sets))
    ).planner_durations

    assert durations.model_dump() == {
        "count": 4,
        "min_ms": 1000,
        "median_ms": 2000,
        "max_ms": 4000,
    }


def test_equal_sets_give_byte_equal_reports_however_they_were_loaded(
    fixture_bundle: FixtureBundle,
) -> None:
    deterministic_set = run_deterministically(
        fixture_bundle, "5gaka", "implementation_only", review_status=ReviewStatus.REVIEWED
    )
    model_sets = (
        run_with_replies(
            fixture_bundle,
            "5gaka",
            "implementation_only",
            build_plan_reply(SEARCH_5GAKA),
            build_plan_reply(SEARCH_AKA),
            review_status=ReviewStatus.REVIEWED,
        ),
        run_with_replies(
            fixture_bundle,
            "5gaka",
            "implementation_only",
            UNAVAILABLE_REPLY,
            UNAVAILABLE_REPLY,
            review_status=ReviewStatus.REVIEWED,
        ),
    )
    reloaded_sets: list[KnowledgeEvidenceSet] = []
    for evidence_set in (deterministic_set, *model_sets):
        reloaded_sets.append(
            KnowledgeEvidenceSet.model_validate_json(evidence_set.model_dump_json())
        )

    first_report = format_report(analyze(build_case(deterministic_set, *model_sets)))
    second_report = format_report(analyze(build_case(deterministic_set, *model_sets)))
    reloaded_report = format_report(analyze(build_case(reloaded_sets[0], *reloaded_sets[1:])))

    assert first_report == second_report == reloaded_report


def test_report_holds_no_query_plan_text_or_planner_name(fixture_bundle: FixtureBundle) -> None:
    # The marker term is indexed by no record, so the policy refines with the topic call
    # and each model run is asked for a round-2 plan too.
    query = f"5G-AKA {QUERY_MARKER}"
    deterministic_set = run_deterministically(fixture_bundle, query, "implementation_only")
    model_sets = (
        run_with_replies(
            fixture_bundle,
            query,
            "implementation_only",
            build_text_reply(f"{PLAN_MARKER} not json"),
            build_text_reply(f"{PLAN_MARKER} not json"),
        ),
        run_with_replies(
            fixture_bundle,
            query,
            "implementation_only",
            build_plan_reply({"tool": "cve_search", "query": f"5g aka {QUERY_MARKER}"}),
            build_plan_reply(TOPIC_5G_AKA),
        ),
    )

    report_text = format_report(analyze(build_case(deterministic_set, *model_sets))).decode()

    assert QUERY_MARKER in deterministic_set.model_dump_json()
    assert PLAN_MARKER in model_sets[0].model_dump_json()
    for marker in (
        QUERY_MARKER,
        PLAN_MARKER,
        SCRIPTED_PLANNER.model_name,
        SCRIPTED_PLANNER.adapter,
    ):
        assert marker not in report_text
