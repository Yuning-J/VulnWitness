"""The decision-path audit rejects a resealed set whose recorded decisions the controller
would not have made, even when every part of the forgery agrees with every other."""

from collections.abc import Callable
from typing import Any

import pytest

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.application.decision_path_audit import audit_decision_path
from cve_kgrag.application.investigation_policy import interpret_request
from cve_kgrag.composition import build_topic_registry
from cve_kgrag.domain.budget import BudgetBreach
from cve_kgrag.domain.evidence_catalog import EvidenceCatalog
from cve_kgrag.domain.investigation import (
    BackendRequest,
    CveBackendRequest,
    DecisionBasis,
    EvidenceNeed,
    EvidenceNeedKind,
    InvestigationWarning,
    InvestigationWarningCode,
    KnowledgeEvidenceSet,
    NeedOutcome,
    PlannerOutcome,
    StateTransition,
    StepReason,
    StopReason,
    ToolStep,
    derive_investigation_id,
)
from cve_kgrag.domain.investigation_validation import validate_knowledge_evidence_set
from cve_kgrag.domain.planning import (
    CveExactLookupCall,
    CveSearchCall,
    PlannerKind,
    PlanRejection,
    PlanRejectionCode,
    QueryIntent,
    compute_call_key,
    compute_model_reply_sha256,
    format_cve_tool_query,
)
from cve_kgrag.domain.search import SearchWarning, SearchWarningCode
from cve_kgrag.domain.taxonomy import ResultStatus
from cve_kgrag.domain.text import normalize_query
from cve_kgrag.domain.threat_context import KnownFightSnapshot
from cve_kgrag.domain.topic import ReviewStatus
from cve_kgrag.domain.topic_context import KnowledgeSource, SourceOutcome
from cve_kgrag.domain.validation import EvidenceValidationError
from cve_kgrag.topics.registry import TopicRegistry
from tests.support.investigation import (
    RANKING_VIOLATION,
    build_exact_lookup_call,
    build_investigation_request,
    build_productless_catalog,
    build_search_call,
    reseal_evidence_set,
    rewrite_step,
    rewrite_the_ranking,
    update_trajectory,
    verify_as_sealed,
)
from tests.support.investigation_runs import (
    investigate,
    investigate_with_model_replies,
    run_cve_under_protocol_scope,
    run_exact_id,
    run_five_g_aka,
    run_five_g_aka_mixed,
    run_model_accepted,
    run_model_low_signal_search,
    run_model_not_consulted,
    run_model_rejected,
    run_model_skipped_at_deadline,
    run_over_the_byte_cap,
    run_policy_plan_over_budget,
    run_refinement,
)
from tests.support.planners import UNAVAILABLE_REPLY, build_plan_reply

Forgery = Callable[[KnowledgeEvidenceSet], KnowledgeEvidenceSet]
Run = Callable[[FixtureBundle], KnowledgeEvidenceSet]
# A severity filter CVE-9999-0003 does not match, so its lookup finds it excluded.
LOW_SEVERITY_FILTERS = {"severities": ["LOW"]}
# Two CVE IDs written against Chinese text, with no space around either.
CJK_QUERY = "CVE-9999-0003和CVE-9999-0004的影响"


def run_unknown_id_under_filters(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """An unknown ID with ``ausf`` under a filter: round 2 searches ``ausf`` (R1)."""
    return investigate(
        fixture_bundle, "CVE-9999-4242 ausf", "implementation_only", filters=LOW_SEVERITY_FILTERS
    )


def run_semantic_without_adapter(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """A semantic request on a deployment without a semantic adapter: the search is partial."""
    return investigate(fixture_bundle, "5G-AKA", "implementation_only", semantic=True)


def run_refinement_under_one_round(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """The same run allowed one round: the refinement breaches the round cap."""
    return investigate(fixture_bundle, "5gaka", "implementation_only", budget={"max_rounds": 1})


def run_search_of_every_term_after_a_dropped_word(
    fixture_bundle: FixtureBundle,
) -> KnowledgeEvidenceSet:
    """The model's round 1 searches one of three words; round 2 falls back to the policy's
    search of all of them (R3)."""
    return investigate_with_model_replies(
        fixture_bundle,
        build_investigation_request("sql injection gateway", "implementation_only"),
        build_plan_reply({"tool": "cve_search", "query": "gateway"}),
        UNAVAILABLE_REPLY,
    )


def run_unknown_id_without_answer(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """An unknown ID, then a topic exploration whose searches the filters leave empty."""
    return investigate(
        fixture_bundle,
        "CVE-9999-4242 5gaka",
        "implementation_only",
        filters=LOW_SEVERITY_FILTERS,
    )


def run_excluded_term_only(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """``aka`` alone is an excluded term: the run stops at interpretation."""
    return investigate(fixture_bundle, "aka", "mixed")


def run_excluded_term_with_free_text(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """``EPS AKA crash`` resolves no topic, records ``aka`` as excluded and searches ``crash``."""
    return investigate(fixture_bundle, "EPS AKA crash", "mixed")


def run_model_rejected_twice(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """Both rounds reject the model's plan, so the policy's search and topic call run."""
    invented_lookup = build_plan_reply({"tool": "cve_exact_lookup", "cve_ids": ["CVE-9999-0004"]})
    return investigate_with_model_replies(
        fixture_bundle,
        build_investigation_request("5gaka", "implementation_only"),
        invented_lookup,
        invented_lookup,
    )


def run_model_unavailable(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """The model planner fails, so the policy's lookup runs and finds CVE-9999-0003."""
    return investigate_with_model_replies(
        fixture_bundle,
        build_investigation_request("CVE-9999-0003", "implementation_only"),
        UNAVAILABLE_REPLY,
    )


def run_model_lookup_of_one_named_id(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """One round whose model plan, ``cve_exact_lookup(["CVE-9999-0003"])``, looks up the one
    ID the caller named, so it passes the gate and runs."""
    return investigate_with_model_replies(
        fixture_bundle,
        build_investigation_request("CVE-9999-0003", "implementation_only"),
        build_plan_reply({"tool": "cve_exact_lookup", "cve_ids": ["CVE-9999-0003"]}),
    )


def run_search_of_the_cjk_query_tokens(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """A free-text search of the ASCII tokens of ``CJK_QUERY``: the run a reader blind to an
    ID written against CJK text would give that query."""
    return investigate(fixture_bundle, "cve 9999 0003 0004", "implementation_only")


def replace_call(
    evidence_set: KnowledgeEvidenceSet,
    step_index: int,
    call: CveExactLookupCall | CveSearchCall,
) -> KnowledgeEvidenceSet:
    """The step, and its round's accepted plan, run ``call`` instead: its call key and backend
    request are recomputed to match, as a forger holding the set could do."""
    trajectory = evidence_set.trajectory
    steps = list(trajectory.steps)
    step = steps[step_index - 1]
    backend_request = CveBackendRequest(
        source=KnowledgeSource.CVE_SEARCH,
        query=format_cve_tool_query(call),
        limit=evidence_set.request.budget.max_results_per_call,
    )
    steps[step_index - 1] = step.model_copy(
        update={
            "call": call,
            "call_key": compute_call_key(call),
            "backend_requests": (backend_request,),
        }
    )
    rounds = list(trajectory.rounds)
    round_position = step.round_number - 1
    accepted_plan: list[Any] = []
    for planned_call in rounds[round_position].accepted_plan:
        accepted_plan.append(call if planned_call == step.call else planned_call)
    rounds[round_position] = rounds[round_position].model_copy(
        update={"accepted_plan": tuple(accepted_plan)}
    )
    return update_trajectory(evidence_set, steps=tuple(steps), rounds=tuple(rounds))


def update_interpretation(
    evidence_set: KnowledgeEvidenceSet, **changes: Any
) -> KnowledgeEvidenceSet:
    return reseal_evidence_set(
        evidence_set, interpretation=evidence_set.interpretation.model_copy(update=changes)
    )


def update_topic_match(evidence_set: KnowledgeEvidenceSet, **changes: Any) -> KnowledgeEvidenceSet:
    resolution = evidence_set.interpretation.resolution
    topic_match = resolution.matches[0].model_copy(update=changes)
    return update_interpretation(
        evidence_set, resolution=resolution.model_copy(update={"matches": (topic_match,)})
    )


def restate_the_stop(
    evidence_set: KnowledgeEvidenceSet,
    stop_reason: StopReason,
    basis: DecisionBasis,
    **changes: Any,
) -> KnowledgeEvidenceSet:
    """The run claims another stop: the transition into validate, the coverage basis and the
    stop reason agree with it, plus any other ``changes`` to the set."""
    transitions = list(evidence_set.trajectory.transitions)
    into_validate = transitions[-2]
    transitions[-2] = StateTransition(
        from_state=into_validate.from_state, to_state=into_validate.to_state, basis=basis
    )
    forged_set = update_trajectory(evidence_set, transitions=tuple(transitions))
    coverage = forged_set.coverage.model_copy(update={"basis": basis})
    return reseal_evidence_set(forged_set, stop_reason=stop_reason, coverage=coverage, **changes)


def turn_the_interpretation_into_free_text(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    """The reviewer's forgery (a): free text with forged search terms and a CVE ID."""
    return update_interpretation(
        evidence_set,
        intent=QueryIntent.FREE_TEXT,
        search_terms=("ausf", "crash"),
        cve_ids=("CVE-9999-0004",),
    )


def search_an_unrelated_query(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The reviewer's forgery (b): the policy's ``cve_search("5g aka")`` becomes another query,
    with its call key, accepted plan and backend request updated to match."""
    return replace_call(evidence_set, 1, build_search_call("open5gs crash"))


def add_a_search_term(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return update_interpretation(evidence_set, search_terms=("5g", "aka", "ausf"))


def add_a_cve_id(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return update_interpretation(evidence_set, cve_ids=("CVE-9999-0004",))


def call_the_topic_free_text(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return update_interpretation(evidence_set, intent=QueryIntent.FREE_TEXT)


def bump_the_topic_version(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return update_topic_match(evidence_set, topic_version="9.9.9")


def swap_the_topic_hash(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return update_topic_match(evidence_set, topic_sha256="0" * 64)


def mark_the_topic_reviewed(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return update_topic_match(evidence_set, review_status=ReviewStatus.REVIEWED)


def drop_the_excluded_term(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    resolution = evidence_set.interpretation.resolution
    return update_interpretation(
        evidence_set, resolution=resolution.model_copy(update={"excluded_terms": ()})
    )


def blame_no_searchable_terms(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """An excluded-term-only query claims it had no searchable terms instead."""
    return restate_the_stop(evidence_set, StopReason.NO_EVIDENCE, DecisionBasis.NO_SEARCHABLE_TERMS)


def blame_the_filters(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """A CVE ID blocked under protocol scope claims filters were the reason instead."""
    return restate_the_stop(
        evidence_set, StopReason.POLICY_BLOCKED, DecisionBasis.FILTERS_OUTSIDE_SCOPE
    )


def search_fewer_terms_in_round_two(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """Round 2 searches fewer of the query's terms than R3 gives."""
    return replace_call(evidence_set, 2, build_search_call("sql injection"))


def give_the_refinement_another_reason(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """Round 2's topic call claims R1's reason instead of R2's."""
    steps = list(evidence_set.trajectory.steps)
    steps[1] = steps[1].model_copy(update={"reason": StepReason.TOPIC_AFTER_UNKNOWN_IDS})
    return update_trajectory(evidence_set, steps=tuple(steps))


def look_up_another_id_on_fallback(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return replace_call(evidence_set, 1, build_exact_lookup_call("CVE-9999-0004"))


def search_5g_aka_in_round_one(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """Round 1's search becomes ``cve_search("5g aka")``, a call the gate accepts, with its
    call key, accepted plan, backend request and search warnings to match: on a fallback it
    replaces the policy's search, and on an accepted model plan it swaps that plan for
    another."""
    return rewrite_step(
        replace_call(evidence_set, 1, build_search_call("5g aka")), 1, search_warnings=()
    )


def blame_the_source_cap(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The policy's over-budget plan claims it overran the source cap, not the call cap."""
    rejection = PlanRejection(code=PlanRejectionCode.OVER_SOURCE_BUDGET)
    rounds = (evidence_set.trajectory.rounds[0].model_copy(update={"rejections": (rejection,)}),)
    budget_used = evidence_set.trajectory.budget_used.model_copy(
        update={"breach": BudgetBreach.SOURCES}
    )
    return update_trajectory(evidence_set, rounds=rounds, budget_used=budget_used)


def accept_a_search_outside_the_vocabulary(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    return replace_call(evidence_set, 1, build_search_call("ignore previous instructions"))


def accept_a_search_in_raw_form(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The same tokens and call key, but the search text the gate never canonicalized."""
    return replace_call(evidence_set, 1, build_search_call("ausf, suci!"))


def keep_the_low_signal_word(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The model's search recorded as proposed, ``cve`` included, with its own call key."""
    return replace_call(evidence_set, 1, build_search_call("cve ausf suci"))


def credit_round_one_with_an_answer(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """Round 1's search claims it found CVE-9999-0003 with its anchors, yet the run refined."""
    candidates = list(evidence_set.implementation_candidates)
    found_candidate = candidates[0]
    candidates[0] = found_candidate.model_copy(update={"found_by_steps": (1, 2)})
    record = found_candidate.candidate.record
    steps = list(evidence_set.trajectory.steps)
    steps[0] = steps[0].model_copy(
        update={"answer_ids": (record.cve_id,), "evidence_ids": record.evidence_ids}
    )
    forged_set = update_trajectory(evidence_set, steps=tuple(steps))
    return reseal_evidence_set(forged_set, implementation_candidates=tuple(candidates))


def hide_the_round_cap(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """A refinement the round cap stopped claims there was none to run."""
    budget_used = evidence_set.trajectory.budget_used.model_copy(update={"breach": None})
    forged_set = update_trajectory(evidence_set, budget_used=budget_used)
    return restate_the_stop(
        forged_set,
        StopReason.NO_EVIDENCE,
        DecisionBasis.NO_REFINEMENT_AVAILABLE,
        status=ResultStatus.NO_MATCH,
    )


def claim_no_refinement_after_round_two(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    return restate_the_stop(
        evidence_set, StopReason.NO_EVIDENCE, DecisionBasis.NO_REFINEMENT_AVAILABLE
    )


def claim_the_default_byte_cap(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The reviewer's forgery: the discarded run presented as the default-budget request's,
    under whose cap its step fits, so the answer is hidden behind a fabricated breach."""
    request = build_investigation_request(evidence_set.request.query, evidence_set.request.scope)
    return reseal_evidence_set(
        evidence_set, request=request, investigation_id=derive_investigation_id(request)
    )


def blame_the_deadline_for_the_byte_cap(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    """The byte breach named wall_time, with a wall time at the cap so the timings agree."""
    budget_used = evidence_set.trajectory.budget_used.model_copy(
        update={"breach": BudgetBreach.WALL_TIME}
    )
    cap_ms = evidence_set.request.budget.max_wall_time_seconds * 1000
    timings = evidence_set.timings.model_copy(update={"wall_time_ms": cap_ms})
    forged_set = update_trajectory(evidence_set, budget_used=budget_used)
    return reseal_evidence_set(forged_set, timings=timings)


def blame_the_call_cap_for_the_round_cap(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    budget_used = evidence_set.trajectory.budget_used.model_copy(
        update={"breach": BudgetBreach.TOOL_CALLS}
    )
    return update_trajectory(evidence_set, budget_used=budget_used)


def warn_unknown(evidence_set: KnowledgeEvidenceSet, cve_id: str) -> KnowledgeEvidenceSet:
    """Step 1 warns ``cve_id`` unknown, in place of its own warnings."""
    steps = list(evidence_set.trajectory.steps)
    unknown_warning = SearchWarning(code=SearchWarningCode.UNKNOWN_CVE_ID, subject=cve_id)
    steps[0] = steps[0].model_copy(update={"search_warnings": (unknown_warning,)})
    return update_trajectory(evidence_set, steps=tuple(steps))


def warn_unindexed(
    evidence_set: KnowledgeEvidenceSet, term: str, **step_changes: Any
) -> KnowledgeEvidenceSet:
    """Step 1 also warns that ``term`` matched no record, with ``step_changes`` applied."""
    first_step = evidence_set.trajectory.steps[0]
    unindexed_warning = SearchWarning(code=SearchWarningCode.TERM_NOT_INDEXED, subject=term)
    return rewrite_step(
        evidence_set,
        1,
        search_warnings=(*first_step.search_warnings, unindexed_warning),
        **step_changes,
    )


def warn_an_unsearched_term_unindexed(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """Step 1 warns that ``srsran``, a word its search never sent, matched no record."""
    return warn_unindexed(evidence_set, "srsran")


def warn_unindexed_without_the_lexical_channel(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    """Step 1 warns its own search term ``crash`` unindexed, but records no lexical run."""
    return warn_unindexed(evidence_set, "crash", channels_executed=())


def report_the_found_id_unknown(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return warn_unknown(evidence_set, "CVE-9999-0003")


def report_a_filtered_known_id_unknown(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    """The reviewer's forgery: the refined run presented as the one for the known, filtered
    CVE-9999-0003 (which stops after round 1): step 1 looks it up, with its call key, plan
    and backend request, and warns it unknown, so R1 appears to refine; the request,
    interpretation and ID are that query's."""
    request = build_investigation_request(
        "CVE-9999-0003 ausf", "implementation_only", filters=LOW_SEVERITY_FILTERS
    )
    interpretation = interpret_request(request, build_topic_registry(), build_productless_catalog())
    forged_set = warn_unknown(
        replace_call(evidence_set, 1, build_exact_lookup_call("CVE-9999-0003")), "CVE-9999-0003"
    )
    return reseal_evidence_set(
        forged_set,
        request=request,
        interpretation=interpretation,
        investigation_id=derive_investigation_id(request),
        normalized_query=interpretation.normalized_query,
    )


def name_a_second_cve_id(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The reviewer's repro as a forgery: the accepted lookup of CVE-9999-0003 presented as
    the run for ``CVE-9999-0003 CVE-9999-0004``, so the model's plan appears accepted while
    it leaves CVE-9999-0004 unlooked-up; the request, interpretation and ID are that
    query's."""
    request = build_investigation_request("CVE-9999-0003 CVE-9999-0004", "implementation_only")
    interpretation = interpret_request(request, build_topic_registry(), build_productless_catalog())
    return reseal_evidence_set(
        evidence_set,
        request=request,
        interpretation=interpretation,
        investigation_id=derive_investigation_id(request),
        normalized_query=interpretation.normalized_query,
    )


def present_as_the_cjk_query(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The free-text search presented as the run for ``CJK_QUERY``: request, ID and
    normalized query are that query's, while the interpretation keeps finding no CVE ID."""
    request = build_investigation_request(CJK_QUERY, "implementation_only")
    normalized_query = normalize_query(CJK_QUERY)
    interpretation = evidence_set.interpretation.model_copy(
        update={"normalized_query": normalized_query}
    )
    return reseal_evidence_set(
        evidence_set,
        request=request,
        interpretation=interpretation,
        investigation_id=derive_investigation_id(request),
        normalized_query=normalized_query,
    )


def update_topic_step_requests(
    evidence_set: KnowledgeEvidenceSet, backend_requests: list[BackendRequest]
) -> KnowledgeEvidenceSet:
    """The topic step sends ``backend_requests``, charged one tool call each."""
    topic_step = evidence_set.trajectory.steps[0].model_copy(
        update={
            "backend_requests": tuple(backend_requests),
            "charged_tool_calls": len(backend_requests),
        }
    )
    budget_used = evidence_set.trajectory.budget_used.model_copy(
        update={"tool_calls": len(backend_requests)}
    )
    return update_trajectory(evidence_set, steps=(topic_step,), budget_used=budget_used)


def trim_the_topic_fan_out(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The reviewer's forgery: the topic step keeps its FiGHT search and one template search,
    understating its charge and widening the budget left for a later plan."""
    return update_topic_step_requests(
        evidence_set, list(evidence_set.trajectory.steps[0].backend_requests[:2])
    )


def replace_a_template_search(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    backend_requests = list(evidence_set.trajectory.steps[0].backend_requests)
    backend_requests[1] = backend_requests[1].model_copy(update={"query": "open5gs crash ausf"})
    return update_topic_step_requests(evidence_set, backend_requests)


def drop_warning(
    evidence_set: KnowledgeEvidenceSet, code: InvestigationWarningCode
) -> KnowledgeEvidenceSet:
    kept_warnings: list[InvestigationWarning] = []
    for warning in evidence_set.warnings:
        if warning.code is not code:
            kept_warnings.append(warning)
    return reseal_evidence_set(evidence_set, warnings=tuple(kept_warnings))


def relabel_round_one_accepted(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The reviewer's forgery: round 1's fallback presented as the model's accepted plan. The
    outcome is relabelled, the rejections and their warning dropped, and the round's steps
    credited to the model; the recorded reply and its hash stay as they were."""
    trajectory = evidence_set.trajectory
    rounds = list(trajectory.rounds)
    rounds[0] = rounds[0].model_copy(
        update={"planner_outcome": PlannerOutcome.MODEL_ACCEPTED, "rejections": ()}
    )
    steps: list[ToolStep] = []
    for step in trajectory.steps:
        if step.round_number != 1:
            steps.append(step)
            continue
        credited_step = step.model_copy(
            update={"planned_by": PlannerKind.MODEL, "reason": StepReason.MODEL_PROPOSAL}
        )
        steps.append(credited_step)
    forged_set = update_trajectory(evidence_set, rounds=tuple(rounds), steps=tuple(steps))
    return drop_warning(forged_set, InvestigationWarningCode.MODEL_PLAN_REJECTED)


def blame_another_gate_check(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The rejected reply claims a vocabulary rejection, with a warning to match, instead of
    the invented ID the gate finds in it."""
    vocabulary_rejection = PlanRejection(
        step_position=0, code=PlanRejectionCode.TERM_OUTSIDE_VOCABULARY
    )
    rounds = (
        evidence_set.trajectory.rounds[0].model_copy(
            update={"rejections": (vocabulary_rejection,)}
        ),
    )
    forged_set = update_trajectory(evidence_set, rounds=rounds)
    warnings: list[InvestigationWarning] = []
    for warning in forged_set.warnings:
        if warning.code is not InvestigationWarningCode.MODEL_PLAN_REJECTED:
            warnings.append(warning)
            continue
        warnings.append(warning.model_copy(update={"subject": "round 1: term_outside_vocabulary"}))
    return reseal_evidence_set(forged_set, warnings=tuple(warnings))


def hide_the_pending_review(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return drop_warning(evidence_set, InvestigationWarningCode.TOPIC_PENDING_REVIEW)


def hide_the_excluded_term(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return drop_warning(evidence_set, InvestigationWarningCode.EXCLUDED_TERM)


def hide_the_unresolved_topic(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return drop_warning(evidence_set, InvestigationWarningCode.TOPIC_NOT_RESOLVED)


def rename_the_excluded_term(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The excluded-term warning kept, its subject rewritten: the codes still agree."""
    renamed_warnings: list[InvestigationWarning] = []
    for warning in evidence_set.warnings:
        if warning.code is InvestigationWarningCode.EXCLUDED_TERM:
            warning = warning.model_copy(update={"subject": "a forged subject"})
        renamed_warnings.append(warning)
    return reseal_evidence_set(evidence_set, warnings=tuple(renamed_warnings))


def hide_the_model_rejection(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return drop_warning(evidence_set, InvestigationWarningCode.MODEL_PLAN_REJECTED)


def hide_the_discarded_evidence(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return drop_warning(evidence_set, InvestigationWarningCode.EVIDENCE_DISCARDED)


def deny_the_refinement(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    coverage = evidence_set.coverage.model_copy(update={"refinement_applied": False})
    return reseal_evidence_set(evidence_set, coverage=coverage)


def hide_the_failing_channel(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The coverage's CVE outcome no longer names the semantic channel that failed."""
    coverage_outcomes: list[SourceOutcome] = []
    for outcome in evidence_set.coverage.source_outcomes:
        coverage_outcomes.append(outcome.model_copy(update={"channel_failures": ()}))
    coverage = evidence_set.coverage.model_copy(
        update={"source_outcomes": tuple(coverage_outcomes)}
    )
    return reseal_evidence_set(evidence_set, coverage=coverage)


def name_another_policy_version(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    planner = evidence_set.trajectory.planner.model_copy(
        update={"policy_version": "forged-policy-v9"}
    )
    return update_trajectory(evidence_set, planner=planner)


@pytest.mark.parametrize(
    ("run", "forgery", "expected_violation"),
    [
        (
            run_five_g_aka,
            turn_the_interpretation_into_free_text,
            "interpretation.intent is not the one the request gives",
        ),
        (
            run_five_g_aka,
            search_an_unrelated_query,
            "round 1 accepts another plan than the controller's decisions choose",
        ),
        (
            run_over_the_byte_cap,
            claim_the_default_byte_cap,
            "step 1 was discarded over max_context_bytes, but its",
        ),
        (
            run_unknown_id_under_filters,
            report_a_filtered_known_id_unknown,
            "step 1 search_warnings[0]: warns of an unknown ID that is not one the step looked "
            "up that the catalog lacks",
        ),
        (
            run_five_g_aka_mixed,
            trim_the_topic_fan_out,
            "step 1 records other backend requests than its call sends under the request and "
            "the registry's card",
        ),
        (
            run_five_g_aka_mixed,
            hide_the_pending_review,
            "the run records the warnings [], but its interpretation and decisions give other "
            "warnings: [topic_pending_review]",
        ),
        (
            run_search_of_the_cjk_query_tokens,
            present_as_the_cjk_query,
            "interpretation.intent is not the one the request gives",
        ),
    ],
    ids=[
        "free_text_interpretation",
        "unrelated_policy_search",
        "admitted_step_relabelled_over_the_byte_cap",
        "filtered_known_id_reported_unknown",
        "topic_fan_out_trimmed",
        "pending_review_warning_dropped",
        "cve_ids_against_cjk_text_read_as_free_text",
    ],
)
def test_reviewer_forgery_is_rejected_after_reseal(
    fixture_bundle: FixtureBundle,
    pinned_fight_snapshot: KnownFightSnapshot,
    packaged_evidence_catalog: EvidenceCatalog,
    topic_registry: TopicRegistry,
    run: Run,
    forgery: Forgery,
    expected_violation: str,
) -> None:
    evidence_set = run(fixture_bundle)

    forged_set = forgery(evidence_set)

    with pytest.raises(EvidenceValidationError) as raised:
        verify_as_sealed(
            forged_set,
            pinned_fight_snapshot,
            packaged_evidence_catalog,
            evidence_set.source_capabilities,
            topic_registry,
        )
    assert any(expected_violation in violation for violation in raised.value.violations)


@pytest.mark.parametrize(
    ("run", "forgery", "expected_violation"),
    [
        (run_five_g_aka, add_a_search_term, "interpretation.search_terms is not the one"),
        (run_five_g_aka, add_a_cve_id, "interpretation.cve_ids is not the one"),
        (run_refinement, call_the_topic_free_text, "interpretation.intent is not the one"),
        (run_refinement, bump_the_topic_version, "interpretation.resolution is not the one"),
        (run_refinement, swap_the_topic_hash, "interpretation.resolution is not the one"),
        (run_refinement, mark_the_topic_reviewed, "interpretation.resolution is not the one"),
        (
            run_excluded_term_with_free_text,
            drop_the_excluded_term,
            "interpretation.resolution is not the one",
        ),
        (
            run_excluded_term_only,
            blame_no_searchable_terms,
            "transition 1 is interpret -> validate (no_searchable_terms), but the controller's "
            "decisions give interpret -> validate (excluded_terms_only)",
        ),
        (
            run_cve_under_protocol_scope,
            blame_the_filters,
            "decisions give interpret -> validate (cve_ids_outside_scope)",
        ),
        (
            run_search_of_every_term_after_a_dropped_word,
            search_fewer_terms_in_round_two,
            "round 2 accepts another plan than the controller's decisions choose",
        ),
        (
            run_refinement,
            give_the_refinement_another_reason,
            "step 2's reason is topic_after_unknown_ids, but the controller's decisions give "
            "topic_after_literal_miss",
        ),
        (
            run_model_rejected,
            look_up_another_id_on_fallback,
            "round 1 accepts another plan than the controller's decisions choose",
        ),
        (
            run_model_rejected_twice,
            search_5g_aka_in_round_one,
            "round 1 accepts another plan than the controller's decisions choose",
        ),
        (
            run_policy_plan_over_budget,
            blame_the_source_cap,
            "round 1 records the rejections [over_source_budget], but the gate gives "
            "[over_tool_call_budget]",
        ),
        (
            run_model_accepted,
            accept_a_search_outside_the_vocabulary,
            "round 1 accepts another plan than the controller's decisions choose",
        ),
        (
            run_model_accepted,
            accept_a_search_in_raw_form,
            "round 1 accepts another plan than the controller's decisions choose",
        ),
        (
            run_model_low_signal_search,
            keep_the_low_signal_word,
            "round 1 accepts another plan than the controller's decisions choose",
        ),
        (
            run_refinement,
            credit_round_one_with_an_answer,
            "transition 4 is assess -> refine (needs_open), but the controller's "
            "decisions give assess -> validate (answer_found)",
        ),
        (
            run_refinement_under_one_round,
            hide_the_round_cap,
            "decisions give refine -> validate (round_cap_reached)",
        ),
        (
            run_unknown_id_without_answer,
            claim_no_refinement_after_round_two,
            "decisions give assess -> validate (needs_open_after_refinement)",
        ),
        (
            run_over_the_byte_cap,
            blame_the_deadline_for_the_byte_cap,
            "the run names the breach wall_time, but the controller's decisions breach "
            "context_bytes",
        ),
        (
            run_refinement_under_one_round,
            blame_the_call_cap_for_the_round_cap,
            "the run names the breach tool_calls, but the controller's decisions breach rounds",
        ),
        (
            run_exact_id,
            report_the_found_id_unknown,
            "step 1 search_warnings[0]: warns of an unknown ID that is not one the step looked "
            "up that the catalog lacks",
        ),
        (
            run_excluded_term_with_free_text,
            warn_an_unsearched_term_unindexed,
            "warns of an unindexed term that is not one of the search terms its lexical "
            "channel was sent",
        ),
        (
            run_excluded_term_with_free_text,
            warn_unindexed_without_the_lexical_channel,
            "warns of an unindexed term that is not one of the search terms its lexical "
            "channel was sent",
        ),
        (
            run_five_g_aka_mixed,
            replace_a_template_search,
            "step 1 records other backend requests than its call sends under the request and "
            "the registry's card",
        ),
        (
            run_excluded_term_with_free_text,
            hide_the_excluded_term,
            "the run records the warnings [topic_not_resolved], but its interpretation and "
            "decisions give other warnings: [excluded_term, topic_not_resolved]",
        ),
        (
            run_excluded_term_with_free_text,
            hide_the_unresolved_topic,
            "the run records the warnings [excluded_term], but its interpretation and "
            "decisions give other warnings: [excluded_term, topic_not_resolved]",
        ),
        (
            run_excluded_term_with_free_text,
            rename_the_excluded_term,
            "the run's decision warning 1 (excluded_term) has another subject than its "
            "interpretation and decisions give",
        ),
        (
            run_model_rejected,
            hide_the_model_rejection,
            "the run records the warnings [], but its interpretation and decisions give other "
            "warnings: [model_plan_rejected]",
        ),
        (
            run_over_the_byte_cap,
            hide_the_discarded_evidence,
            "but its interpretation and decisions give other warnings: [topic_pending_review, "
            "evidence_discarded]",
        ),
        (
            run_refinement,
            deny_the_refinement,
            "coverage.refinement_applied must say whether a round-2 step ran",
        ),
        (
            run_semantic_without_adapter,
            hide_the_failing_channel,
            "coverage.source_outcomes do not summarize the admitted steps' outcomes",
        ),
        (
            run_five_g_aka,
            rewrite_the_ranking,
            RANKING_VIOLATION,
        ),
        (
            run_five_g_aka,
            name_another_policy_version,
            "the planner names a policy other than m7b.1, the one whose decisions the audit "
            "re-derives",
        ),
    ],
    ids=[
        "forged_search_terms",
        "forged_cve_ids",
        "forged_intent",
        "forged_topic_version",
        "forged_topic_hash",
        "forged_review_status",
        "dropped_excluded_term",
        "forged_interpretation_stop_basis",
        "forged_interpretation_stop_reason",
        "forged_refinement_call",
        "forged_refinement_reason",
        "forged_fallback_after_model_rejected",
        "forged_fallback_after_model_rejected_twice",
        "forged_policy_plan_rejection",
        "model_plan_outside_the_gate",
        "model_plan_not_canonical",
        "model_plan_keeping_a_low_signal_word",
        "refined_despite_a_round_one_answer",
        "hidden_round_cap",
        "forged_stop_after_round_two",
        "byte_breach_named_wall_time",
        "round_cap_breach_named_tool_calls",
        "found_id_reported_unknown",
        "unsearched_term_reported_unindexed",
        "unindexed_term_without_a_lexical_run",
        "template_search_replaced",
        "excluded_term_warning_dropped",
        "topic_not_resolved_warning_dropped",
        "excluded_term_warning_renamed",
        "model_plan_rejected_warning_dropped",
        "evidence_discarded_warning_dropped",
        "refinement_denied",
        "coverage_detail_hidden",
        "ranking_rewritten",
        "deterministic_policy_version_rewritten",
    ],
)
def test_forged_decision_is_rejected_after_reseal(
    fixture_bundle: FixtureBundle,
    pinned_fight_snapshot: KnownFightSnapshot,
    packaged_evidence_catalog: EvidenceCatalog,
    topic_registry: TopicRegistry,
    run: Run,
    forgery: Forgery,
    expected_violation: str,
) -> None:
    evidence_set = run(fixture_bundle)

    forged_set = forgery(evidence_set)

    with pytest.raises(EvidenceValidationError) as raised:
        verify_as_sealed(
            forged_set,
            pinned_fight_snapshot,
            packaged_evidence_catalog,
            evidence_set.source_capabilities,
            topic_registry,
        )
    assert any(expected_violation in violation for violation in raised.value.violations)


def run_mixed_free_text(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """Free text under ``mixed`` with no topic: implementation CVEs found, protocol context
    unsupported, so the run stops ``needs_unmet``."""
    return investigate(fixture_bundle, "sql injection gateway", "mixed")


def claim_protocol_context_searchable(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The unsupported protocol need is relabelled ``not_found``, as if a tool could still
    serve it; the stop, which needs an unmet need either way, is left as recorded."""
    needs: list[EvidenceNeed] = []
    for need in evidence_set.coverage.needs:
        recorded_need = need
        if need.kind is EvidenceNeedKind.PROTOCOL_CONTEXT:
            recorded_need = need.model_copy(update={"outcome": NeedOutcome.NOT_FOUND})
        needs.append(recorded_need)
    coverage = evidence_set.coverage.model_copy(update={"needs": tuple(needs)})
    return reseal_evidence_set(evidence_set, coverage=coverage)


def claim_the_model_was_consulted(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """Round 1, which no model plan could pass, claims the model replied unavailable and the
    policy's over-budget plan was rejected after it, with the call, its hash, the planner
    duration and the rejection warning all recorded."""
    round_one = evidence_set.trajectory.rounds[0]
    rejections = (PlanRejection(code=PlanRejectionCode.PLANNER_UNAVAILABLE), *round_one.rejections)
    consulted_round = round_one.model_copy(
        update={
            "planner_outcome": PlannerOutcome.MODEL_UNAVAILABLE,
            "rejections": rejections,
            "model_reply": UNAVAILABLE_REPLY,
            "model_reply_sha256": compute_model_reply_sha256(UNAVAILABLE_REPLY),
        }
    )
    budget_used = evidence_set.trajectory.budget_used.model_copy(update={"planner_calls": 1})
    timings = evidence_set.timings.model_copy(update={"planner_durations_ms": (0,)})
    forged_set = update_trajectory(evidence_set, rounds=(consulted_round,), budget_used=budget_used)
    return reseal_evidence_set(forged_set, timings=timings)


def erase_the_skipped_round_two(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """Round 2, which the deadline stopped before its planner ran, is dropped from the
    record, so the run appears to have stopped at refine without planning it."""
    budget_used = evidence_set.trajectory.budget_used.model_copy(update={"rounds": 1})
    return update_trajectory(
        evidence_set, rounds=evidence_set.trajectory.rounds[:1], budget_used=budget_used
    )


@pytest.mark.parametrize(
    ("run", "forgery", "expected_violation"),
    [
        (
            run_model_rejected,
            relabel_round_one_accepted,
            "round 1 is model_accepted, but the controller's decisions over its recorded reply "
            "give model_rejected",
        ),
        (
            run_model_unavailable,
            relabel_round_one_accepted,
            "round 1 is model_accepted, but the controller's decisions over its recorded reply "
            "give model_unavailable",
        ),
        (
            run_model_accepted,
            search_5g_aka_in_round_one,
            "round 1 accepts another plan than the controller's decisions choose",
        ),
        (
            run_model_rejected,
            blame_another_gate_check,
            "round 1 records the rejections [term_outside_vocabulary at 0], but the gate gives "
            "[invented_cve_id at 0, missing_named_cve_id]",
        ),
        (
            run_model_lookup_of_one_named_id,
            name_a_second_cve_id,
            "round 1 is model_accepted, but the controller's decisions over its recorded reply "
            "give model_rejected",
        ),
        (
            run_model_skipped_at_deadline,
            erase_the_skipped_round_two,
            "the controller's decisions plan round 2, but the run records no such round",
        ),
        (
            run_model_not_consulted,
            claim_the_model_was_consulted,
            "round 1 is model_unavailable, but the controller's decisions over its recorded "
            "reply give model_not_consulted",
        ),
        (
            run_mixed_free_text,
            claim_protocol_context_searchable,
            "coverage.needs are not the needs the request gives, judged over the admitted "
            "steps and the answer",
        ),
    ],
    ids=[
        "rejected_reply_relabelled_accepted",
        "unavailable_reply_relabelled_accepted",
        "accepted_plan_swapped_for_another_gate_valid_plan",
        "rejection_codes_rewritten",
        "accepted_plan_omitting_a_named_cve_id",
        "planned_round_two_erased",
        "unconsultable_round_claims_a_model_reply",
        "need_outcome_rewritten",
    ],
)
def test_planner_record_the_validator_accepts_is_rejected_by_the_audit(
    fixture_bundle: FixtureBundle,
    pinned_fight_snapshot: KnownFightSnapshot,
    packaged_evidence_catalog: EvidenceCatalog,
    topic_registry: TopicRegistry,
    run: Run,
    forgery: Forgery,
    expected_violation: str,
) -> None:
    evidence_set = run(fixture_bundle)
    forged_set = forgery(evidence_set)
    # The forgery is consistent: every part agrees with every other, reply hash included.
    validate_knowledge_evidence_set(
        forged_set,
        pinned_fight_snapshot,
        packaged_evidence_catalog,
        evidence_set.source_capabilities,
    )

    with pytest.raises(EvidenceValidationError) as raised:
        audit_decision_path(forged_set, topic_registry, packaged_evidence_catalog)

    assert expected_violation in raised.value.violations
