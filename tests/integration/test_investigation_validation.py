"""Final validation fails closed: a forged evidence set, even resealed, is rejected."""

import threading
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from pydantic import ValidationError

from cve_kgrag.adapters.fight.pinned_yaml import UnavailableFightSource
from cve_kgrag.adapters.fixture.synthetic_fixture import (
    FixtureBundle,
    default_fixture_dir,
    load_fixture_bundle,
)
from cve_kgrag.composition import (
    build_evidence_catalog,
    build_investigation_service,
    build_serving_data_plane,
    load_packaged_fight_source,
)
from cve_kgrag.domain.budget import BudgetBreach
from cve_kgrag.domain.evidence import Claim, EvidenceAnchor, derive_evidence_id
from cve_kgrag.domain.evidence_catalog import EvidenceCatalog
from cve_kgrag.domain.investigation import (
    ApplicabilityBasis,
    ApplicabilityStatus,
    CveBackendRequest,
    DecisionBasis,
    ExcludedInvestigationCandidate,
    FightBackendRequest,
    FightBlock,
    FightBlockReason,
    InvestigationState,
    InvestigationWarning,
    InvestigationWarningCode,
    KnowledgeEvidenceSet,
    NeedOutcome,
    PlannerOutcome,
    ProductApplicability,
    RoundRecord,
    StateTransition,
    StepAdmission,
    StepReason,
    StopReason,
    format_threat_context_statement,
)
from cve_kgrag.domain.investigation_validation import (
    sends_searchable_text,
    validate_knowledge_evidence_set,
)
from cve_kgrag.domain.planning import (
    PlannerKind,
    PlanRejection,
    PlanRejectionCode,
    ToolCall,
    compute_call_key,
    compute_model_reply_sha256,
)
from cve_kgrag.domain.search import SearchWarning, SearchWarningCode
from cve_kgrag.domain.taxonomy import ResultStatus, SourceType
from cve_kgrag.domain.threat_context import (
    KnownFightSnapshot,
    ObservationStatus,
    ThreatContextItem,
)
from cve_kgrag.domain.topic_context import (
    KnowledgeSource,
    QueryScope,
    TopicContextWarning,
    TopicContextWarningCode,
)
from cve_kgrag.domain.validation import EvidenceValidationError
from tests.support.builders import build_bundle_with
from tests.support.clocks import LATE_START_SECONDS, LateStartClock, SteppingClock, read_fixed_clock
from tests.support.fakes import InventingRetriever
from tests.support.investigation import (
    ONE_SECOND_REQUEST,
    build_blocking_investigation_service,
    build_exact_lookup_call,
    build_investigation_request,
    build_search_call,
    build_test_investigation_service,
    build_topic_call,
    reseal_evidence_set,
    rewrite_step,
    update_interpretation,
    update_trajectory,
)
from tests.support.investigation_runs import (
    investigate,
    run_cve_under_protocol_scope,
    run_exact_id,
    run_fight_direct_search,
    run_fight_direct_search_fight_failing,
    run_fight_direct_search_of_an_unindexed_word,
    run_five_g_aka,
    run_five_g_aka_mixed,
    run_free_text_under_a_model_planner,
    run_mixed_fight_direct_search,
    run_model_accepted,
    run_model_not_consulted,
    run_model_refinement_unavailable,
    run_model_rejected,
    run_model_reply_after_deadline,
    run_model_skipped_at_deadline,
    run_model_unavailable,
    run_policy_plan_over_budget,
    run_refinement,
)
from tests.support.planners import (
    UNAVAILABLE_REPLY,
    BlockingModelPort,
    build_plan_reply,
)
from tests.support.services import build_fixture_service

Forgery = Callable[[KnowledgeEvidenceSet, FixtureBundle], KnowledgeEvidenceSet]
TrajectoryRun = Callable[[FixtureBundle], KnowledgeEvidenceSet]
UNHELD_EVIDENCE_ID = "ev:" + "f" * 24


def update_usage(evidence_set: KnowledgeEvidenceSet, **changes: Any) -> KnowledgeEvidenceSet:
    budget_used = evidence_set.trajectory.budget_used.model_copy(update=changes)
    return update_trajectory(evidence_set, budget_used=budget_used)


def find_claim_index(evidence_set: KnowledgeEvidenceSet, claim_id: str) -> int:
    for claim_index, claim in enumerate(evidence_set.claims):
        if claim.claim_id == claim_id:
            return claim_index
    raise LookupError(claim_id)


def find_anchor_index(evidence_set: KnowledgeEvidenceSet, record_id: str) -> int:
    for anchor_index, anchor in enumerate(evidence_set.evidence):
        if anchor.authoritative_record_id == record_id:
            return anchor_index
    raise LookupError(record_id)


def move_excluded_cve_into_the_answer(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    excluded_candidates = evidence_set.excluded_implementation_candidates
    return reseal_evidence_set(
        evidence_set,
        implementation_candidates=(excluded_candidates[0].candidate,),
        excluded_implementation_candidates=excluded_candidates[1:],
    )


def add_implementation_claim(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    implementation_set = investigate(fixture_bundle, "CVE-9999-0003", "implementation_only")
    claims = sorted(
        [*evidence_set.claims, *implementation_set.claims], key=lambda claim: claim.claim_id
    )
    evidence = sorted(
        [*evidence_set.evidence, *implementation_set.evidence],
        key=lambda anchor: anchor.evidence_id,
    )
    return reseal_evidence_set(evidence_set, claims=tuple(claims), evidence=tuple(evidence))


def cite_another_records_anchor(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    claim_index = find_claim_index(evidence_set, "cve:CVE-9999-0003")
    other_anchor = evidence_set.evidence[find_anchor_index(evidence_set, "CVE-9999-0004")]
    claims = list(evidence_set.claims)
    claims[claim_index] = claims[claim_index].model_copy(
        update={"evidence_ids": (other_anchor.evidence_id,)}
    )
    return reseal_evidence_set(evidence_set, claims=tuple(claims))


def add_uncited_anchor(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    evidence = sorted(
        [*evidence_set.evidence, fixture_bundle.evidence[0]],
        key=lambda anchor: anchor.evidence_id,
    )
    return reseal_evidence_set(evidence_set, evidence=tuple(evidence))


def report_ok_for_an_unavailable_source(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    return reseal_evidence_set(evidence_set, status=ResultStatus.OK)


def report_no_evidence_despite_a_failed_source(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    return reseal_evidence_set(
        evidence_set, stop_reason=StopReason.NO_EVIDENCE, status=ResultStatus.NO_MATCH
    )


def repeat_a_call_key(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    first_step, second_step = evidence_set.trajectory.steps
    repeated_step = second_step.model_copy(update={"call_key": first_step.call_key})
    return update_trajectory(evidence_set, steps=(first_step, repeated_step))


def add_a_third_round(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    rounds = evidence_set.trajectory.rounds
    return update_trajectory(evidence_set, rounds=(*rounds, rounds[-1]))


def skip_assess(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    transitions = list(evidence_set.trajectory.transitions)
    transitions[2:4] = [
        StateTransition(
            from_state=InvestigationState.RETRIEVE,
            to_state=InvestigationState.VALIDATE,
            basis=DecisionBasis.ANSWER_FOUND,
        )
    ]
    return update_trajectory(evidence_set, transitions=tuple(transitions))


def undercount_tool_calls(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    return update_usage(evidence_set, tool_calls=evidence_set.trajectory.budget_used.tool_calls - 1)


def admit_a_late_step(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    late_timing = evidence_set.timings.steps[0].model_copy(update={"duration_ms": 31_000})
    timings = evidence_set.timings.model_copy(update={"steps": (late_timing,)})
    return reseal_evidence_set(evidence_set, timings=timings)


def breach_without_stopping(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    return update_usage(evidence_set, breach=BudgetBreach.WALL_TIME)


def move_fight_anchor_off_the_pin(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    anchor_index = find_anchor_index(evidence_set, "FGT5040")
    evidence = list(evidence_set.evidence)
    evidence[anchor_index] = evidence[anchor_index].model_copy(
        update={"source_version": "3.0.0+sha256:" + "f" * 64}
    )
    return reseal_evidence_set(evidence_set, evidence=tuple(evidence))


def remove_the_fgt5040_anchor(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    anchor_index = find_anchor_index(evidence_set, "FGT5040")
    evidence = list(evidence_set.evidence)
    del evidence[anchor_index]
    evidence_ids: list[str] = []
    for anchor in evidence:
        evidence_ids.append(anchor.evidence_id)
    trajectory = evidence_set.trajectory.model_copy(update={"evidence_ids": tuple(evidence_ids)})
    return reseal_evidence_set(evidence_set, evidence=tuple(evidence), trajectory=trajectory)


def tamper_the_fgt5040_content_hash(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    anchor_index = find_anchor_index(evidence_set, "FGT5040")
    evidence = list(evidence_set.evidence)
    evidence[anchor_index] = evidence[anchor_index].model_copy(update={"content_sha256": "f" * 64})
    return reseal_evidence_set(evidence_set, evidence=tuple(evidence))


def claim_the_product_is_affected(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    affected_applicability = evidence_set.product_applicability[0].model_copy(
        update={"status": "affected"}
    )
    return reseal_evidence_set(evidence_set, product_applicability=(affected_applicability,))


def tamper_the_hash(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    return evidence_set.model_copy(update={"result_sha256": "f" * 64})


def list_evidence_ids(evidence_set: KnowledgeEvidenceSet) -> tuple[str, ...]:
    evidence_ids: list[str] = []
    for anchor in evidence_set.evidence:
        evidence_ids.append(anchor.evidence_id)
    return tuple(evidence_ids)


def add_items_of(
    evidence_set: KnowledgeEvidenceSet, other_set: KnowledgeEvidenceSet, **sections: Any
) -> KnowledgeEvidenceSet:
    """``evidence_set`` with ``sections`` replaced and ``other_set``'s claims and anchors added,
    kept in order, as a forger keeping the set self-consistent would."""
    claims = sorted([*evidence_set.claims, *other_set.claims], key=lambda claim: claim.claim_id)
    evidence = sorted(
        [*evidence_set.evidence, *other_set.evidence], key=lambda anchor: anchor.evidence_id
    )
    forged_set = evidence_set.model_copy(
        update={"claims": tuple(claims), "evidence": tuple(evidence)}
    )
    trajectory = forged_set.trajectory.model_copy(
        update={"evidence_ids": list_evidence_ids(forged_set)}
    )
    return reseal_evidence_set(forged_set, trajectory=trajectory, **sections)


def inject_an_unretrieved_candidate(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    other_set = investigate(fixture_bundle, "CVE-9999-0005", "implementation_only")
    unretrieved_candidate = other_set.implementation_candidates[0].model_copy(
        update={"rank": 2, "found_by_steps": (1,)}
    )
    return add_items_of(
        evidence_set,
        other_set,
        implementation_candidates=(*evidence_set.implementation_candidates, unretrieved_candidate),
    )


def add_threat_context_to_an_implementation_answer(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    protocol_set = investigate(fixture_bundle, "5gaka", "protocol_context_only")
    return add_items_of(evidence_set, protocol_set, protocol_context=protocol_set.protocol_context)


def add_a_threat_context_claim(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    protocol_set = investigate(fixture_bundle, "5gaka", "protocol_context_only")
    return add_items_of(evidence_set, protocol_set)


def drop_the_claim(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    return reseal_evidence_set(evidence_set, claims=())


def add_a_claim_without_an_answer_item(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    return add_items_of(
        evidence_set, investigate(fixture_bundle, "CVE-9999-0005", "implementation_only")
    )


def rewrite_the_claim_statement(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    rewritten_claim = evidence_set.claims[0].model_copy(
        update={"statement": "CVE-9999-0003 proves a protocol-design flaw in 5G-AKA."}
    )
    return reseal_evidence_set(evidence_set, claims=(rewritten_claim,))


def update_first_step(evidence_set: KnowledgeEvidenceSet, **changes: Any) -> KnowledgeEvidenceSet:
    steps = list(evidence_set.trajectory.steps)
    steps[0] = steps[0].model_copy(update=changes)
    return update_trajectory(evidence_set, steps=tuple(steps))


def update_last_step(evidence_set: KnowledgeEvidenceSet, **changes: Any) -> KnowledgeEvidenceSet:
    steps = list(evidence_set.trajectory.steps)
    steps[-1] = steps[-1].model_copy(update=changes)
    return update_trajectory(evidence_set, steps=tuple(steps))


def raise_a_template_search_limit(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    """The topic step's second template search asked for 20 under a cap of 1."""
    backend_requests = list(evidence_set.trajectory.steps[-1].backend_requests)
    backend_requests[1] = backend_requests[1].model_copy(update={"limit": 20})
    return update_last_step(evidence_set, backend_requests=tuple(backend_requests))


def drop_a_template_search(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    backend_requests = evidence_set.trajectory.steps[-1].backend_requests
    return update_last_step(evidence_set, backend_requests=backend_requests[:-1])


def swap_a_template_search_for_fight(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    """An implementation_only topic step claims a FiGHT search in place of a CVE search."""
    fight_request = FightBackendRequest(
        source=KnowledgeSource.MITRE_FIGHT, terms=("5G AKA",), limit=1
    )
    backend_requests = evidence_set.trajectory.steps[-1].backend_requests
    return update_last_step(evidence_set, backend_requests=(fight_request, *backend_requests[1:]))


def raise_the_lookup_limit(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    lookup_request = CveBackendRequest(
        source=KnowledgeSource.CVE_SEARCH, query="CVE-9999-0003", limit=20
    )
    return update_first_step(evidence_set, backend_requests=(lookup_request,))


def overrun_tool_calls(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    return update_usage(evidence_set, tool_calls=2)


def overrun_sources(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    return update_usage(
        evidence_set, sources=(KnowledgeSource.CVE_SEARCH, KnowledgeSource.MITRE_FIGHT)
    )


def overrun_context_bytes(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    return update_usage(evidence_set, context_bytes=5001)


def overrun_planner_calls(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    return update_usage(evidence_set, planner_calls=2)


def forge_the_investigation_id(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    return reseal_evidence_set(evidence_set, investigation_id="inv:" + "0" * 24)


def claim_another_schema_version(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    return reseal_evidence_set(evidence_set, schema_version="2.0.0-dev.8")


def forge_the_normalized_query(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    return reseal_evidence_set(evidence_set, normalized_query="cve-9999-0004")


def widen_the_applied_scope(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    return reseal_evidence_set(evidence_set, applied_scope=QueryScope.MIXED)


def assess_a_product_under_protocol_scope(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    product_applicability = ProductApplicability(
        product_kind="product",
        product="f5gc",
        status=ApplicabilityStatus.UNKNOWN,
        basis=ApplicabilityBasis.NO_VERIFIED_AFFECTEDNESS_SOURCE,
    )
    return reseal_evidence_set(evidence_set, product_applicability=(product_applicability,))


def exclude_a_candidate_outside_protocol_scope(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    excluded_candidate = ExcludedInvestigationCandidate(
        candidate=evidence_set.implementation_candidates[0], reason="not an answer"
    )
    return reseal_evidence_set(
        evidence_set, excluded_implementation_candidates=(excluded_candidate,)
    )


def drop_the_relevance_of_a_found_candidate(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    candidates = list(evidence_set.implementation_candidates)
    candidates[0] = candidates[0].model_copy(update={"relevance": None})
    return reseal_evidence_set(evidence_set, implementation_candidates=tuple(candidates))


def assess_relevance_without_a_topic(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    mixed_set = investigate(fixture_bundle, "5gaka", "mixed")
    candidates = list(evidence_set.implementation_candidates)
    candidates[0] = candidates[0].model_copy(
        update={"relevance": mixed_set.implementation_candidates[0].relevance}
    )
    return reseal_evidence_set(evidence_set, implementation_candidates=tuple(candidates))


def credit_a_step_that_never_ran(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    candidates = list(evidence_set.implementation_candidates)
    candidates[0] = candidates[0].model_copy(update={"found_by_steps": (2,)})
    return reseal_evidence_set(evidence_set, implementation_candidates=tuple(candidates))


def desync_the_trajectory_evidence_ids(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    return update_trajectory(evidence_set, evidence_ids=())


def drop_the_applicability_entry(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    return reseal_evidence_set(evidence_set, product_applicability=())


def drop_the_applicability_warning(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    kept_warnings: list[InvestigationWarning] = []
    for warning in evidence_set.warnings:
        if warning.code is not InvestigationWarningCode.APPLICABILITY_UNKNOWN:
            kept_warnings.append(warning)
    return reseal_evidence_set(evidence_set, warnings=tuple(kept_warnings))


def update_coverage(evidence_set: KnowledgeEvidenceSet, **changes: Any) -> KnowledgeEvidenceSet:
    return reseal_evidence_set(
        evidence_set, coverage=evidence_set.coverage.model_copy(update=changes)
    )


def add_a_fight_answer_source(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    return update_coverage(
        evidence_set, answer_sources=(KnowledgeSource.CVE_SEARCH, KnowledgeSource.MITRE_FIGHT)
    )


def add_an_outcome_for_a_non_answer_source(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    source_outcomes = evidence_set.coverage.source_outcomes
    fight_outcome = source_outcomes[0].model_copy(update={"source": KnowledgeSource.MITRE_FIGHT})
    return update_coverage(evidence_set, source_outcomes=(*source_outcomes, fight_outcome))


def repeat_an_outcome(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    source_outcomes = evidence_set.coverage.source_outcomes
    return update_coverage(evidence_set, source_outcomes=(*source_outcomes, source_outcomes[0]))


def misstate_the_coverage_basis(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    return update_coverage(evidence_set, basis=DecisionBasis.STEPS_FINISHED)


def mark_a_found_need_unmet(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    """The run still stops sufficient, but its one need now reads not found."""
    unmet_need = evidence_set.coverage.needs[0].model_copy(
        update={"outcome": NeedOutcome.NOT_FOUND}
    )
    return update_coverage(evidence_set, needs=(unmet_need,))


def relabel_the_unassessed_matches_found(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    """The free-text run still stops needs_unmet, but its one need, matches whose relevance
    was not assessed, now reads found."""
    found_need = evidence_set.coverage.needs[0].model_copy(update={"outcome": NeedOutcome.FOUND})
    return update_coverage(evidence_set, needs=(found_need,))


def report_unassessed_matches_sufficient(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    """The free-text run claims to stop sufficient on its matches, still unassessed."""
    return reseal_evidence_set(
        evidence_set, stop_reason=StopReason.SUFFICIENT, status=ResultStatus.OK
    )


def relabel_a_met_run_needs_unmet(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    """A run whose every need was found claims to stop with needs unmet."""
    return reseal_evidence_set(
        evidence_set, stop_reason=StopReason.NEEDS_UNMET, status=ResultStatus.PARTIAL
    )


def report_a_status_the_outcomes_do_not_decide(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    return reseal_evidence_set(evidence_set, status=ResultStatus.SOURCE_UNAVAILABLE)


def drop_the_first_transition(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    return update_trajectory(evidence_set, transitions=evidence_set.trajectory.transitions[1:])


def drop_a_middle_transition(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    transitions = list(evidence_set.trajectory.transitions)
    del transitions[1]
    return update_trajectory(evidence_set, transitions=tuple(transitions))


def drop_the_last_transition(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    return update_trajectory(evidence_set, transitions=evidence_set.trajectory.transitions[:-1])


def refine_twice(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    # assess -> refine -> retrieve -> assess, walked a second time.
    transitions = list(evidence_set.trajectory.transitions)
    transitions[6:6] = transitions[3:6]
    return update_trajectory(evidence_set, transitions=tuple(transitions))


def swap_the_round_numbers(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    first_round, second_round = evidence_set.trajectory.rounds
    return update_trajectory(evidence_set, rounds=(second_round, first_round))


def renumber_the_step(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    return update_first_step(evidence_set, step_index=2)


def step_back_a_round(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    first_step, second_step = evidence_set.trajectory.steps
    return update_trajectory(
        evidence_set,
        steps=(
            first_step.model_copy(update={"round_number": 2}),
            second_step.model_copy(update={"round_number": 1}),
        ),
    )


def move_the_step_into_round_two(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    return update_first_step(evidence_set, round_number=2)


def drop_the_consulted_sources(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    return update_usage(evidence_set, sources=())


def inflate_the_admitted_bytes(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    return update_usage(
        evidence_set, context_bytes=evidence_set.trajectory.budget_used.context_bytes + 1
    )


def drop_the_step_timings(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    timings = evidence_set.timings.model_copy(update={"steps": ()})
    return reseal_evidence_set(evidence_set, timings=timings)


def discard_an_in_time_step_as_late(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    return update_first_step(evidence_set, admission=StepAdmission.DISCARDED_AFTER_DEADLINE)


def move_the_fight_outcome_off_the_pin(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    fight_outcome = evidence_set.coverage.source_outcomes[0].model_copy(
        update={"source_version": "3.0.0+sha256:" + "f" * 64}
    )
    return update_coverage(evidence_set, source_outcomes=(fight_outcome,))


def forge_a_record_description(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    """The reviewer's forgery: the first candidate's record says something its source never
    did, behind its genuine anchors."""
    investigation_candidate = evidence_set.implementation_candidates[0]
    record = investigation_candidate.candidate.record
    forged_description = record.descriptions[0].model_copy(update={"value": "FORGED description"})
    forged_record = record.model_copy(update={"descriptions": (forged_description,)})
    forged_candidate = investigation_candidate.model_copy(
        update={
            "candidate": investigation_candidate.candidate.model_copy(
                update={"record": forged_record}
            )
        }
    )
    return reseal_evidence_set(
        evidence_set,
        implementation_candidates=(
            forged_candidate,
            *evidence_set.implementation_candidates[1:],
        ),
    )


def observe_and_rename_a_technique(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    """The reviewer's forgery: a proof-of-concept technique turned observed and renamed, its
    claim re-templated to match."""
    protocol_context: list[ThreatContextItem] = []
    forged_item: ThreatContextItem | None = None
    for item in evidence_set.protocol_context:
        if item.technique_id == "FGT1499.503":
            item = item.model_copy(
                update={
                    "status": ObservationStatus.OBSERVED,
                    "source_status": "Observed",
                    "name": "FORGED name",
                }
            )
            forged_item = item
        protocol_context.append(item)
    assert forged_item is not None
    claims: list[Claim] = []
    for claim in evidence_set.claims:
        if claim.subject_id == forged_item.technique_id:
            claim = claim.model_copy(
                update={"statement": format_threat_context_statement(forged_item)}
            )
        claims.append(claim)
    return reseal_evidence_set(
        evidence_set, protocol_context=tuple(protocol_context), claims=tuple(claims)
    )


def cite_evidence_no_source_holds_in_a_step(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    """The reviewer's forgery: the admitted step claims it returned an anchor no source holds."""
    first_step = evidence_set.trajectory.steps[0]
    return update_first_step(
        evidence_set, evidence_ids=(UNHELD_EVIDENCE_ID, *first_step.evidence_ids)
    )


def return_an_unanchored_answer_id_in_a_step(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    first_step = evidence_set.trajectory.steps[0]
    return update_first_step(evidence_set, answer_ids=("CVE-0000-0000", *first_step.answer_ids))


def drop_an_answer_anchor_from_the_step(
    evidence_set: KnowledgeEvidenceSet, fixture_bundle: FixtureBundle
) -> KnowledgeEvidenceSet:
    """The only step no longer lists the anchor of a technique the answer still serves."""
    first_step = evidence_set.trajectory.steps[0]
    dropped_anchor = evidence_set.evidence[find_anchor_index(evidence_set, "FGT5040")]
    kept_evidence_ids: list[str] = []
    for evidence_id in first_step.evidence_ids:
        if evidence_id != dropped_anchor.evidence_id:
            kept_evidence_ids.append(evidence_id)
    return update_first_step(evidence_set, evidence_ids=tuple(kept_evidence_ids))


PROTOCOL_5GAKA = ("5gaka", "protocol_context_only", {})
# The external reviewer's runs: the topic asked by its canonical name.
CANONICAL_MIXED = ("5G AKA", "mixed", {})
CANONICAL_PROTOCOL = ("5G AKA", "protocol_context_only", {})
MIXED_5GAKA = ("5gaka", "mixed", {})
OPEN5GS = ("5gaka", "implementation_only", {"filters": {"products": ["open5gs"]}})
# The topic finds no open5gs record, so round 2 searches the words: two rounds of one step.
IMPLEMENTATION_REFINES = OPEN5GS
F5GC = ("5gaka", "implementation_only", {"filters": {"products": ["f5gc"]}})
EXACT_ID = ("CVE-9999-0003", "implementation_only", {})
# A search on the question's own words: its one need is matches_unassessed.
FREE_TEXT = ("sql injection gateway", "implementation_only", {})
# The topic's four template searches under implementation_only, all capped at 1.
IMPLEMENTATION_TOPIC_CAPPED = (
    "5gaka",
    "implementation_only",
    {"budget": {"max_results_per_call": 1}},
)


def build_exact_id_request(**budget: int) -> tuple[str, str, dict[str, Any]]:
    """The exact-ID request under a lowered budget."""
    return ("CVE-9999-0003", "implementation_only", {"budget": budget})


@pytest.mark.parametrize(
    ("base_request", "forgery", "expected_violation"),
    [
        (PROTOCOL_5GAKA, move_excluded_cve_into_the_answer, "cannot contain CVE candidates"),
        (PROTOCOL_5GAKA, add_implementation_claim, "cannot make implementation claims"),
        (MIXED_5GAKA, cite_another_records_anchor, "about another record than its subject"),
        (EXACT_ID, add_uncited_anchor, "evidence must be exactly the cited anchors"),
        (OPEN5GS, report_ok_for_an_unavailable_source, "cannot report stop reason"),
        (OPEN5GS, report_no_evidence_despite_a_failed_source, "no_evidence holds no answer"),
        (IMPLEMENTATION_REFINES, repeat_a_call_key, "repeats an issued call"),
        (IMPLEMENTATION_REFINES, add_a_third_round, "exceed max_rounds"),
        (EXACT_ID, skip_assess, "illegal transition retrieve -> validate"),
        (EXACT_ID, undercount_tool_calls, "differ from the 1 charged"),
        (EXACT_ID, admit_a_late_step, "admitted after the deadline"),
        (EXACT_ID, breach_without_stopping, "budget_exhausted is the stop reason exactly"),
        (PROTOCOL_5GAKA, move_fight_anchor_off_the_pin, "provenance differs from the pinned"),
        (PROTOCOL_5GAKA, remove_the_fgt5040_anchor, "claims[3]: cites unknown evidence"),
        (PROTOCOL_5GAKA, tamper_the_fgt5040_content_hash, "not derived from the anchor's"),
        pytest.param(
            F5GC,
            claim_the_product_is_affected,
            "product_applicability[0]: applicability must be unknown without an affectedness "
            "source",
            # The forged status is outside the enum, so pydantic warns while hashing it.
            marks=pytest.mark.filterwarnings("ignore::UserWarning"),
        ),
        (EXACT_ID, tamper_the_hash, "result_sha256 does not match"),
        (EXACT_ID, inject_an_unretrieved_candidate, "not returned by any admitted step"),
        (
            EXACT_ID,
            add_threat_context_to_an_implementation_answer,
            "implementation_only answer cannot contain threat context",
        ),
        (EXACT_ID, add_a_threat_context_claim, "cannot make threat-context claims"),
        (EXACT_ID, drop_the_claim, "claims must be exactly one per answer item"),
        (EXACT_ID, add_a_claim_without_an_answer_item, "no answer item for this claim"),
        (EXACT_ID, rewrite_the_claim_statement, "differs from the templated claim"),
        (
            build_exact_id_request(max_results_per_call=1),
            raise_the_lookup_limit,
            "asks cve_search for 20 results, more than max_results_per_call",
        ),
        (
            IMPLEMENTATION_TOPIC_CAPPED,
            raise_a_template_search_limit,
            "step 1 asks cve_search for 20 results, more than max_results_per_call",
        ),
        (
            IMPLEMENTATION_TOPIC_CAPPED,
            drop_a_template_search,
            "step 1 is charged 4 tool calls for 3 backend requests",
        ),
        (
            IMPLEMENTATION_TOPIC_CAPPED,
            swap_a_template_search_for_fight,
            "step 1 sends requests to other sources than it names",
        ),
        (
            build_exact_id_request(max_tool_calls=1),
            overrun_tool_calls,
            "tool calls exceed max_tool_calls",
        ),
        (build_exact_id_request(max_sources=1), overrun_sources, "sources exceed max_sources"),
        (
            build_exact_id_request(max_context_bytes=5000),
            overrun_context_bytes,
            "context bytes exceed max_context_bytes",
        ),
        (
            build_exact_id_request(max_rounds=1),
            overrun_planner_calls,
            "rounds or planner calls exceed max_rounds",
        ),
        (EXACT_ID, forge_the_investigation_id, "investigation_id is not derived"),
        (EXACT_ID, claim_another_schema_version, "schema_version is not"),
        (EXACT_ID, forge_the_normalized_query, "normalized_query does not match"),
        (EXACT_ID, widen_the_applied_scope, "requested and applied scope"),
        (
            PROTOCOL_5GAKA,
            assess_a_product_under_protocol_scope,
            "cannot assess product applicability",
        ),
        (
            MIXED_5GAKA,
            exclude_a_candidate_outside_protocol_scope,
            "only a protocol_context_only answer excludes",
        ),
        (
            MIXED_5GAKA,
            drop_the_relevance_of_a_found_candidate,
            "relevance is assessed for every candidate the caller did not name",
        ),
        (
            EXACT_ID,
            assess_relevance_without_a_topic,
            "relevance is assessed only when a topic resolved",
        ),
        (EXACT_ID, credit_a_step_that_never_ran, "which is not an admitted step"),
        (EXACT_ID, desync_the_trajectory_evidence_ids, "trajectory.evidence_ids must list"),
        (F5GC, drop_the_applicability_entry, "must list each named product once"),
        (F5GC, drop_the_applicability_warning, "needs one applicability_unknown warning"),
        (EXACT_ID, add_a_fight_answer_source, "coverage.answer_sources do not match"),
        (EXACT_ID, add_an_outcome_for_a_non_answer_source, "which is not an answer source"),
        (EXACT_ID, repeat_an_outcome, "names a source more than once"),
        (EXACT_ID, misstate_the_coverage_basis, "coverage.basis must be the basis"),
        (EXACT_ID, mark_a_found_need_unmet, "sufficient needs every need found"),
        (
            FREE_TEXT,
            relabel_the_unassessed_matches_found,
            "needs_unmet needs an answer and an unmet need other than affectedness",
        ),
        (FREE_TEXT, report_unassessed_matches_sufficient, "sufficient needs every need found"),
        (
            EXACT_ID,
            relabel_a_met_run_needs_unmet,
            "needs_unmet needs an answer and an unmet need other than affectedness",
        ),
        (OPEN5GS, report_a_status_the_outcomes_do_not_decide, "should be partial"),
        (EXACT_ID, drop_the_first_transition, "transitions must start at interpret"),
        (EXACT_ID, drop_a_middle_transition, "does not follow on"),
        (EXACT_ID, drop_the_last_transition, "transitions must end validate -> return"),
        (IMPLEMENTATION_REFINES, refine_twice, "refine may be entered at most once"),
        (IMPLEMENTATION_REFINES, swap_the_round_numbers, "rounds are numbered [2, 1]"),
        (EXACT_ID, renumber_the_step, "should be numbered 1"),
        (IMPLEMENTATION_REFINES, step_back_a_round, "goes back to round 1"),
        (
            build_exact_id_request(max_rounds=1),
            move_the_step_into_round_two,
            "runs beyond max_rounds",
        ),
        (EXACT_ID, move_the_step_into_round_two, "runs round 2 without an assess -> refine"),
        (EXACT_ID, drop_the_consulted_sources, "sources must be the steps' sources"),
        (EXACT_ID, inflate_the_admitted_bytes, "context_bytes must be the sum"),
        (EXACT_ID, drop_the_step_timings, "timings must hold one entry per step"),
        (
            build_exact_id_request(max_context_bytes=1024),
            discard_an_in_time_step_as_late,
            "was discarded before the deadline",
        ),
        (
            PROTOCOL_5GAKA,
            move_the_fight_outcome_off_the_pin,
            "names another snapshot than the pinned one",
        ),
        (
            CANONICAL_MIXED,
            forge_a_record_description,
            "differs from the record this service's sources hold",
        ),
        (
            CANONICAL_PROTOCOL,
            observe_and_rename_a_technique,
            "FGT1499.503: differs from the technique this service's sources hold",
        ),
        (
            CANONICAL_MIXED,
            cite_evidence_no_source_holds_in_a_step,
            f"step 1 returns evidence {UNHELD_EVIDENCE_ID}, which this service's sources do "
            "not hold",
        ),
        (
            CANONICAL_MIXED,
            return_an_unanchored_answer_id_in_a_step,
            "step 1 answer_ids[0]: returned without a catalogued anchor for it",
        ),
        (
            PROTOCOL_5GAKA,
            drop_an_answer_anchor_from_the_step,
            ": not returned by any admitted step",
        ),
    ],
    ids=[
        "cve_in_protocol_answer",
        "implementation_claim_under_protocol_scope",
        "claim_citing_other_records_anchor",
        "uncited_anchor",
        "ok_with_source_unavailable",
        "no_evidence_with_failed_outcome",
        "duplicate_call_key",
        "three_rounds",
        "illegal_transition",
        "tool_calls_not_summed_charges",
        "admitted_step_after_deadline",
        "breach_without_budget_exhausted",
        "fight_anchor_not_from_pin",
        "removed_fgt5040_anchor",
        "tampered_fgt5040_content_hash",
        "non_unknown_applicability",
        "tampered_hash",
        "unretrieved_candidate",
        "threat_context_in_implementation_answer",
        "threat_context_claim_in_implementation_answer",
        "missing_claim",
        "claim_without_an_answer_item",
        "rewritten_claim_statement",
        "lookup_limit_above_max_results_per_call",
        "template_search_limit_above_max_results_per_call",
        "template_search_dropped_from_the_charge",
        "fight_search_under_implementation_only",
        "tool_calls_above_cap",
        "sources_above_cap",
        "context_bytes_above_cap",
        "planner_calls_above_max_rounds",
        "forged_investigation_id",
        "another_schema_version",
        "forged_normalized_query",
        "widened_applied_scope",
        "applicability_under_protocol_scope",
        "excluded_candidate_outside_protocol_scope",
        "found_candidate_without_relevance",
        "relevance_without_a_topic",
        "candidate_credited_to_a_step_that_never_ran",
        "trajectory_evidence_ids_out_of_sync",
        "missing_applicability_entry",
        "missing_applicability_warning",
        "extra_answer_source",
        "outcome_for_a_non_answer_source",
        "repeated_outcome",
        "misstated_coverage_basis",
        "sufficient_with_an_unmet_need",
        "unassessed_matches_relabelled_found",
        "sufficient_on_unassessed_matches",
        "needs_unmet_with_every_need_met",
        "status_not_decided_by_outcomes",
        "transitions_not_starting_at_interpret",
        "transition_not_following_on",
        "transitions_not_ending_at_return",
        "refine_entered_twice",
        "rounds_out_of_order",
        "misnumbered_step",
        "step_going_back_a_round",
        "step_beyond_max_rounds",
        "round_two_step_without_refine",
        "consulted_sources_out_of_sync",
        "admitted_bytes_out_of_sync",
        "missing_step_timings",
        "step_discarded_as_late_in_time",
        "fight_outcome_not_from_pin",
        "forged_record_description",
        "fight_technique_observed_and_renamed",
        "step_citing_evidence_no_source_holds",
        "step_returning_an_unanchored_answer_id",
        "answer_anchor_no_admitted_step_returned",
    ],
)
def test_forged_evidence_set_is_rejected(
    fixture_bundle: FixtureBundle,
    pinned_fight_snapshot: KnownFightSnapshot,
    base_request: tuple[str, str, dict[str, Any]],
    forgery: Forgery,
    expected_violation: str,
    packaged_evidence_catalog: EvidenceCatalog,
) -> None:
    query, scope, request_fields = base_request
    evidence_set = investigate(fixture_bundle, query, scope, **request_fields)
    validate_knowledge_evidence_set(
        evidence_set,
        pinned_fight_snapshot,
        packaged_evidence_catalog,
        evidence_set.source_capabilities,
    )

    forged_set = forgery(evidence_set, fixture_bundle)

    with pytest.raises(EvidenceValidationError) as raised:
        validate_knowledge_evidence_set(
            forged_set,
            pinned_fight_snapshot,
            packaged_evidence_catalog,
            evidence_set.source_capabilities,
        )
    assert any(expected_violation in violation for violation in raised.value.violations)


def test_invalid_evidence_set_carrying_an_answer_is_rejected(
    fixture_bundle: FixtureBundle,
    pinned_fight_snapshot: KnownFightSnapshot,
    packaged_evidence_catalog: EvidenceCatalog,
) -> None:
    service = build_test_investigation_service(
        fixture_bundle, lexical_retriever=InventingRetriever()
    )
    evidence_set = service.investigate(build_investigation_request("crash", "implementation_only"))
    validate_knowledge_evidence_set(
        evidence_set,
        pinned_fight_snapshot,
        packaged_evidence_catalog,
        evidence_set.source_capabilities,
    )
    found_set = investigate(fixture_bundle, "CVE-9999-0003", "implementation_only")

    forged_set = reseal_evidence_set(
        evidence_set,
        implementation_candidates=found_set.implementation_candidates,
        claims=found_set.claims,
        evidence=found_set.evidence,
    )

    with pytest.raises(EvidenceValidationError, match="invalid_evidence returns nothing"):
        validate_knowledge_evidence_set(
            forged_set,
            pinned_fight_snapshot,
            packaged_evidence_catalog,
            evidence_set.source_capabilities,
        )


def test_fight_evidence_is_rejected_where_no_snapshot_is_pinned(
    fixture_bundle: FixtureBundle, packaged_evidence_catalog: EvidenceCatalog
) -> None:
    evidence_set = investigate(fixture_bundle, "5gaka", "protocol_context_only")

    with pytest.raises(EvidenceValidationError, match="no FiGHT snapshot is pinned"):
        validate_knowledge_evidence_set(
            evidence_set, None, packaged_evidence_catalog, evidence_set.source_capabilities
        )


def test_deserialized_set_with_three_rounds_is_rejected_at_the_boundary(
    fixture_bundle: FixtureBundle,
) -> None:
    evidence_set = investigate(
        fixture_bundle, "5gaka", "implementation_only", filters={"products": ["open5gs"]}
    )
    rounds = evidence_set.trajectory.rounds
    forged_set = update_trajectory(evidence_set, rounds=(*rounds, rounds[-1]))

    with pytest.raises(ValidationError, match="rounds"):
        KnowledgeEvidenceSet.model_validate_json(forged_set.model_dump_json())


# The external reviewer's forgery of a real CVE anchor's provenance.
FORGED_SOURCE_FIELDS = {
    "source_uri": "https://attacker.invalid/forged",
    "excerpt": "FORGED SOURCE EXCERPT",
}


def forge_first_cve_anchor_source(
    evidence_set: KnowledgeEvidenceSet,
) -> tuple[KnowledgeEvidenceSet, EvidenceAnchor]:
    """The set, resealed, with its first CVE candidate's anchor pointing at a forged URI
    and excerpt under its genuine evidence ID; and that forged anchor."""
    record_id = evidence_set.implementation_candidates[0].candidate.record.cve_id
    anchor_index = find_anchor_index(evidence_set, record_id)
    forged_anchor = evidence_set.evidence[anchor_index].model_copy(update=FORGED_SOURCE_FIELDS)
    forged_evidence = list(evidence_set.evidence)
    forged_evidence[anchor_index] = forged_anchor
    forged_set = reseal_evidence_set(evidence_set, evidence=tuple(forged_evidence))
    return forged_set, forged_anchor


def test_resealed_set_with_a_forged_anchor_source_is_rejected(
    fixture_bundle: FixtureBundle,
    pinned_fight_snapshot: KnownFightSnapshot,
    packaged_evidence_catalog: EvidenceCatalog,
) -> None:
    evidence_set = investigate(fixture_bundle, "5gaka", "mixed")

    forged_set, forged_anchor = forge_first_cve_anchor_source(evidence_set)

    with pytest.raises(EvidenceValidationError) as raised:
        validate_knowledge_evidence_set(
            forged_set,
            pinned_fight_snapshot,
            packaged_evidence_catalog,
            evidence_set.source_capabilities,
        )
    assert raised.value.violations == (
        f"{forged_anchor.evidence_id}: not derived from the anchor's provenance fields",
        f"{forged_anchor.evidence_id}: differs from the anchor this service's sources hold",
    )


def test_forged_anchor_source_with_a_recomputed_id_is_rejected(
    fixture_bundle: FixtureBundle,
    pinned_fight_snapshot: KnownFightSnapshot,
    packaged_evidence_catalog: EvidenceCatalog,
) -> None:
    evidence_set = investigate(fixture_bundle, "5gaka", "mixed")
    forged_set, forged_anchor = forge_first_cve_anchor_source(evidence_set)
    recomputed_evidence_id = derive_evidence_id(forged_anchor)

    # A holder re-derives the ID and rewrites every citation of it, then reseals.
    rewritten_json = forged_set.model_dump_json().replace(
        forged_anchor.evidence_id, recomputed_evidence_id
    )
    recomputed_set = reseal_evidence_set(KnowledgeEvidenceSet.model_validate_json(rewritten_json))

    with pytest.raises(EvidenceValidationError) as raised:
        validate_knowledge_evidence_set(
            recomputed_set,
            pinned_fight_snapshot,
            packaged_evidence_catalog,
            evidence_set.source_capabilities,
        )
    # The rewrite also reaches the record's and the step's citations of the forged ID.
    cve_id = forged_anchor.authoritative_record_id
    assert raised.value.violations == (
        f"{recomputed_evidence_id}: not an anchor this service's sources hold",
        f"{cve_id}: differs from the record this service's sources hold",
        f"step 1 returns evidence {recomputed_evidence_id}, which this service's sources do "
        "not hold",
        "step 1 answer_ids[0]: returned without a catalogued anchor for it",
    )


def test_anchor_absent_from_the_catalog_is_rejected(
    fixture_bundle: FixtureBundle, pinned_fight_snapshot: KnownFightSnapshot
) -> None:
    evidence_set = investigate(fixture_bundle, "5gaka", "protocol_context_only")
    catalog_without_fight = build_evidence_catalog(fixture_bundle, UnavailableFightSource())

    with pytest.raises(EvidenceValidationError) as raised:
        validate_knowledge_evidence_set(
            evidence_set,
            pinned_fight_snapshot,
            catalog_without_fight,
            evidence_set.source_capabilities,
        )
    expected_violations: list[str] = []
    for anchor in evidence_set.evidence:
        if anchor.source_type is SourceType.MITRE_FIGHT_YAML:
            expected_violations.append(
                f"{anchor.evidence_id}: not an anchor this service's sources hold"
            )
    for item in evidence_set.protocol_context:
        expected_violations.append(
            f"{item.technique_id}: not a technique this service's sources hold"
        )
    assert expected_violations
    assert set(expected_violations) <= set(raised.value.violations)


def test_service_rejects_an_anchor_its_catalog_does_not_hold(
    fixture_bundle: FixtureBundle,
) -> None:
    serving_bundle = build_bundle_with(
        fixture_bundle, "CVE-9999-0601", "[SYNTHETIC] 5G-AKA replay in demo_gateway."
    )
    fight_source, pinned_fight_snapshot = load_packaged_fight_source(read_fixed_clock)
    service = build_investigation_service(
        build_serving_data_plane(
            fixture_bundle,
            search_service=build_fixture_service(serving_bundle),
            fight_source=fight_source,
            pinned_fight_snapshot=pinned_fight_snapshot,
        ),
        wall_clock=read_fixed_clock,
        monotonic_clock=SteppingClock().read,
    )

    with pytest.raises(EvidenceValidationError, match="not an anchor this service's sources hold"):
        service.investigate(build_investigation_request("CVE-9999-0601", "implementation_only"))


def run_planned_past_the_deadline(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """Every clock read moves 31 seconds, so round 1 is planned past the 30-second deadline
    and no step runs."""
    service = build_test_investigation_service(
        fixture_bundle, monotonic_clock=SteppingClock(seconds_per_read=31).read
    )
    return service.investigate(build_investigation_request("5G-AKA", "implementation_only"))


def finish_in_three_milliseconds(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    timings = evidence_set.timings.model_copy(update={"wall_time_ms": 3})
    return reseal_evidence_set(evidence_set, timings=timings)


@pytest.mark.parametrize(
    "run",
    [run_planned_past_the_deadline, run_model_skipped_at_deadline, run_model_reply_after_deadline],
    ids=["round_planned_past_the_deadline", "planner_skipped", "planner_reply_late"],
)
def test_deadline_found_in_a_run_shorter_than_the_cap_is_rejected(
    fixture_bundle: FixtureBundle,
    pinned_fight_snapshot: KnownFightSnapshot,
    packaged_evidence_catalog: EvidenceCatalog,
    run: TrajectoryRun,
) -> None:
    """The deadline outcomes at a planner or before a step name no step timing; the run's
    own wall time still has to reach the cap."""
    evidence_set = run(fixture_bundle)
    assert evidence_set.trajectory.budget_used.breach is BudgetBreach.WALL_TIME

    forged_set = finish_in_three_milliseconds(evidence_set)

    with pytest.raises(EvidenceValidationError) as raised:
        validate_knowledge_evidence_set(
            forged_set,
            pinned_fight_snapshot,
            packaged_evidence_catalog,
            evidence_set.source_capabilities,
        )
    assert "the run found the deadline, but its wall time is under the cap" in (
        raised.value.violations
    )


# Each timed-out run below waits out a real one-second deadline, so each set is built once
# per module; the sets are immutable and every forgery copies them.
@pytest.fixture(scope="module")
def timed_out_step_set() -> Iterator[KnowledgeEvidenceSet]:
    """A genuine set whose one lexical search never returned before the deadline."""
    release = threading.Event()
    service = build_blocking_investigation_service(
        load_fixture_bundle(default_fixture_dir()), "lexical", release
    )
    yield service.investigate(ONE_SECOND_REQUEST)
    release.set()


@pytest.fixture(scope="module")
def timed_out_planner_set() -> Iterator[KnowledgeEvidenceSet]:
    """A genuine set whose round-1 planner never replied before the deadline."""
    release = threading.Event()
    service = build_test_investigation_service(
        load_fixture_bundle(default_fixture_dir()),
        model_port=BlockingModelPort(release),
        monotonic_clock=LateStartClock(LATE_START_SECONDS).read,
    )
    yield service.investigate(ONE_SECOND_REQUEST)
    release.set()


def finish_the_timed_out_step_in_time(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    step_timing = evidence_set.timings.steps[0].model_copy(
        update={"started_offset_ms": 0, "duration_ms": 10}
    )
    timings = evidence_set.timings.model_copy(update={"steps": (step_timing,)})
    return reseal_evidence_set(evidence_set, timings=timings)


def blame_the_context_bytes_cap(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return update_usage(evidence_set, breach=BudgetBreach.CONTEXT_BYTES)


def run_a_step_after_the_timed_out_one(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    timed_out_step = evidence_set.trajectory.steps[0]
    later_step = timed_out_step.model_copy(update={"step_index": 2, "call_key": "0" * 64})
    later_timing = evidence_set.timings.steps[0].model_copy(update={"step_index": 2})
    timings = evidence_set.timings.model_copy(
        update={"steps": (*evidence_set.timings.steps, later_timing)}
    )
    forged_set = update_trajectory(evidence_set, steps=(timed_out_step, later_step))
    return reseal_evidence_set(forged_set, timings=timings)


def record_a_reply_the_planner_never_gave(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    """The timed-out round claims the model replied, with the reply's own hash."""
    planner_round = evidence_set.trajectory.rounds[0].model_copy(
        update={
            "model_reply": UNAVAILABLE_REPLY,
            "model_reply_sha256": compute_model_reply_sha256(UNAVAILABLE_REPLY),
        }
    )
    return update_trajectory(evidence_set, rounds=(planner_round,))


def accept_a_plan_the_planner_never_gave(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    planner_round = evidence_set.trajectory.rounds[0].model_copy(
        update={"accepted_plan": (build_search_call("5g aka"),)}
    )
    return update_trajectory(evidence_set, rounds=(planner_round,))


SetForgery = Callable[[KnowledgeEvidenceSet], KnowledgeEvidenceSet]


@pytest.mark.parametrize(
    ("forgery", "expected_violation"),
    [
        (finish_the_timed_out_step_in_time, "step 1 timed out before the deadline"),
        (blame_the_context_bytes_cap, "step 1 ran into the deadline, but the breach is not"),
        (run_a_step_after_the_timed_out_one, "step 2 runs after step 1, which was not admitted"),
    ],
    ids=["finished_before_the_deadline", "breach_not_wall_time", "step_after_the_timeout"],
)
def test_forged_timed_out_step_is_rejected(
    timed_out_step_set: KnowledgeEvidenceSet,
    pinned_fight_snapshot: KnownFightSnapshot,
    packaged_evidence_catalog: EvidenceCatalog,
    forgery: SetForgery,
    expected_violation: str,
) -> None:
    validate_knowledge_evidence_set(
        timed_out_step_set,
        pinned_fight_snapshot,
        packaged_evidence_catalog,
        timed_out_step_set.source_capabilities,
    )

    forged_set = forgery(timed_out_step_set)

    with pytest.raises(EvidenceValidationError) as raised:
        validate_knowledge_evidence_set(
            forged_set,
            pinned_fight_snapshot,
            packaged_evidence_catalog,
            timed_out_step_set.source_capabilities,
        )
    assert any(expected_violation in violation for violation in raised.value.violations)


@pytest.mark.parametrize(
    ("forgery", "expected_violation"),
    [
        (
            record_a_reply_the_planner_never_gave,
            "round 1 records a reply its model_timed_out planner never gave",
        ),
        (accept_a_plan_the_planner_never_gave, "round 1 runs a plan after its planner ran into"),
        (blame_the_context_bytes_cap, "round 1's planner ran into the deadline, but the breach"),
    ],
    ids=["recorded_reply", "accepted_plan", "breach_not_wall_time"],
)
def test_forged_timed_out_planner_round_is_rejected(
    timed_out_planner_set: KnowledgeEvidenceSet,
    pinned_fight_snapshot: KnownFightSnapshot,
    packaged_evidence_catalog: EvidenceCatalog,
    forgery: SetForgery,
    expected_violation: str,
) -> None:
    validate_knowledge_evidence_set(
        timed_out_planner_set,
        pinned_fight_snapshot,
        packaged_evidence_catalog,
        timed_out_planner_set.source_capabilities,
    )

    forged_set = forgery(timed_out_planner_set)

    with pytest.raises(EvidenceValidationError) as raised:
        validate_knowledge_evidence_set(
            forged_set,
            pinned_fight_snapshot,
            packaged_evidence_catalog,
            timed_out_planner_set.source_capabilities,
        )
    assert any(expected_violation in violation for violation in raised.value.violations)


def test_deserialized_timed_out_step_carrying_a_hash_is_rejected_at_the_boundary(
    timed_out_step_set: KnowledgeEvidenceSet,
) -> None:
    forged_set = update_first_step(timed_out_step_set, result_sha256="0" * 64)

    with pytest.raises(ValidationError, match="timed out carries nothing from a response"):
        KnowledgeEvidenceSet.model_validate_json(forged_set.model_dump_json())


def run_protocol_topic(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """One deterministic round: the topic under protocol_context_only."""
    return investigate(fixture_bundle, "5gaka", "protocol_context_only")


def update_round(
    evidence_set: KnowledgeEvidenceSet, round_position: int, **changes: Any
) -> KnowledgeEvidenceSet:
    rounds = list(evidence_set.trajectory.rounds)
    rounds[round_position] = rounds[round_position].model_copy(update=changes)
    return update_trajectory(evidence_set, rounds=tuple(rounds))


def forge_the_call_key(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The reviewer's forgery: an arbitrary 64-hex call key on a real step."""
    return update_first_step(evidence_set, call_key="ab" * 32)


def empty_the_executed_rounds_plan(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The reviewer's forgery: an executed round claims it accepted no plan."""
    return update_round(evidence_set, 0, accepted_plan=())


def swap_the_call_with_a_derived_key(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The step and its round claim another lookup, its key recomputed to match."""
    other_call = build_exact_lookup_call("CVE-9999-0004")
    forged_set = update_first_step(
        evidence_set, call=other_call, call_key=compute_call_key(other_call)
    )
    return update_round(forged_set, 0, accepted_plan=(other_call,))


def list_a_later_step_in_round_one(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return update_round(evidence_set, 0, executed_step_indices=(1, 2))


def plan_another_call_first(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    accepted_plan = evidence_set.trajectory.rounds[0].accepted_plan
    return update_round(evidence_set, 0, accepted_plan=(build_search_call("crash"), *accepted_plan))


def credit_the_step_to_the_model(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return update_first_step(evidence_set, planned_by=PlannerKind.MODEL)


def give_the_step_a_model_reason(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return update_first_step(evidence_set, reason=StepReason.MODEL_PROPOSAL)


def claim_a_model_outcome_for_the_policy(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    return update_round(evidence_set, 0, planner_outcome=PlannerOutcome.MODEL_UNAVAILABLE)


def record_the_skipped_planner_as_deterministic(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    return update_round(evidence_set, 1, planner_outcome=PlannerOutcome.DETERMINISTIC)


def reject_the_accepted_plan(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    rejection = PlanRejection(step_position=0, code=PlanRejectionCode.REPEATED_CALL)
    return update_round(evidence_set, 0, rejections=(rejection,))


def record_a_malformed_plan(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return update_round(
        evidence_set, 0, rejections=(PlanRejection(code=PlanRejectionCode.MALFORMED_PLAN),)
    )


def blame_a_missing_named_id(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The policy's rejected plan claims it left a named CVE ID unlooked-up, which only a
    model's plan can do."""
    rejection = PlanRejection(code=PlanRejectionCode.MISSING_NAMED_CVE_ID)
    return update_round(evidence_set, 0, rejections=(rejection,))


def drop_the_model_reply_hash(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return update_round(evidence_set, 0, model_reply_sha256=None)


def rewrite_the_reply_without_rehashing(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    """The recorded reply becomes another gate-valid plan, under the original reply's hash."""
    return update_round(
        evidence_set, 0, model_reply=build_plan_reply({"tool": "cve_search", "query": "5g aka"})
    )


def hash_a_reply_the_policy_never_had(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return update_round(evidence_set, 0, model_reply_sha256="0" * 64)


def drop_the_planner_call(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return update_usage(evidence_set, planner_calls=0)


def count_a_round_never_recorded(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return update_usage(evidence_set, rounds=2)


def drop_the_refinement_round(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return update_trajectory(evidence_set, rounds=evidence_set.trajectory.rounds[:1])


def retrieve_round_two_without_accepting_its_plan(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    transitions: list[StateTransition] = []
    for transition in evidence_set.trajectory.transitions:
        if transition.from_state is InvestigationState.REFINE:
            transition = transition.model_copy(update={"basis": DecisionBasis.NEEDS_OPEN})
        transitions.append(transition)
    return update_trajectory(evidence_set, transitions=tuple(transitions))


def name_fight_for_a_cve_tool_step(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return update_first_step(evidence_set, sources=(KnowledgeSource.MITRE_FIGHT,))


def add_rounds(
    evidence_set: KnowledgeEvidenceSet, *added_rounds: RoundRecord
) -> KnowledgeEvidenceSet:
    """``evidence_set`` with ``added_rounds`` recorded and counted."""
    trajectory = evidence_set.trajectory
    rounds = (*trajectory.rounds, *added_rounds)
    budget_used = trajectory.budget_used.model_copy(update={"rounds": len(rounds)})
    return update_trajectory(evidence_set, rounds=rounds, budget_used=budget_used)


def build_planless_round(round_number: int, *rejections: PlanRejection) -> RoundRecord:
    return RoundRecord.model_validate(
        {
            "round_number": round_number,
            "planner_outcome": PlannerOutcome.DETERMINISTIC,
            "rejections": rejections,
            "accepted_plan": (),
            "executed_step_indices": (),
        }
    )


def add_a_phantom_round_two(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The reviewer's forgery: a round 2 that planned and ran nothing, though the run never
    refined."""
    return add_rounds(evidence_set, build_planless_round(2))


def add_a_phantom_round_two_rejecting_the_policy_plan(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    invented_id_rejection = PlanRejection(code=PlanRejectionCode.INVENTED_CVE_ID)
    return add_rounds(evidence_set, build_planless_round(2, invented_id_rejection))


def add_a_round_to_a_run_that_never_planned(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    invented_id_rejection = PlanRejection(code=PlanRejectionCode.INVENTED_CVE_ID)
    return add_rounds(evidence_set, build_planless_round(1, invented_id_rejection))


def append_to_the_accepted_plan(
    evidence_set: KnowledgeEvidenceSet, *appended_calls: ToolCall
) -> KnowledgeEvidenceSet:
    accepted_plan = evidence_set.trajectory.rounds[0].accepted_plan
    return update_round(evidence_set, 0, accepted_plan=(*accepted_plan, *appended_calls))


def plan_a_search_that_never_ran(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The reviewer's forgery: a fully admitted round accepted one more search it never ran."""
    return append_to_the_accepted_plan(
        evidence_set, build_search_call("ignore previous instructions")
    )


def plan_a_topic_that_never_ran(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return append_to_the_accepted_plan(evidence_set, build_topic_call())


def repeat_the_accepted_plan(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return append_to_the_accepted_plan(
        evidence_set, *evidence_set.trajectory.rounds[0].accepted_plan
    )


def plan_a_cve_search_under_protocol_scope(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    return append_to_the_accepted_plan(evidence_set, build_search_call("5g aka"))


def give_the_lookup_a_search_reason(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The reviewer's forgery: the exact lookup claims the policy's literal-search reason."""
    return update_first_step(evidence_set, reason=StepReason.QUERY_TERMS)


def give_the_lookup_a_topic_reason(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return update_first_step(evidence_set, reason=StepReason.REVIEWED_TOPIC)


def give_the_lookup_a_refinement_reason(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    return update_first_step(evidence_set, reason=StepReason.TOPIC_AFTER_LITERAL_MISS)


def time_planner_calls_never_made(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The reviewer's forgery: a deterministic run reports two planner durations."""
    timings = evidence_set.timings.model_copy(update={"planner_durations_ms": (5, 7)})
    return reseal_evidence_set(evidence_set, timings=timings)


def lead_the_rejection_with_planner_unavailable(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    """A rejected model plan whose rejections start with a code only an unavailable planner
    records."""
    rejections = evidence_set.trajectory.rounds[0].rejections
    unavailable_rejection = PlanRejection(code=PlanRejectionCode.PLANNER_UNAVAILABLE)
    return update_round(evidence_set, 0, rejections=(unavailable_rejection, *rejections))


def drop_round_one_rejections(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return update_round(evidence_set, 0, rejections=())


@pytest.mark.parametrize(
    ("run", "forgery", "expected_violation"),
    [
        (run_exact_id, forge_the_call_key, "step 1's call_key is not derived from its call"),
        (run_exact_id, empty_the_executed_rounds_plan, "round 1 runs steps without an accepted"),
        (
            run_exact_id,
            swap_the_call_with_a_derived_key,
            "step 1 records other backend requests than its call sends",
        ),
        (
            run_refinement,
            list_a_later_step_in_round_one,
            "round 1 lists steps [1, 2], but its steps are [1]",
        ),
        (
            run_exact_id,
            plan_another_call_first,
            "round 1's steps do not run the leading calls of its accepted plan in order",
        ),
        (
            run_exact_id,
            credit_the_step_to_the_model,
            "step 1 is planned by model, but round 1's planner outcome is deterministic",
        ),
        (
            run_exact_id,
            give_the_step_a_model_reason,
            "step 1's reason model_proposal does not match its planner deterministic",
        ),
        (
            run_exact_id,
            claim_a_model_outcome_for_the_policy,
            "planner outcome model_unavailable is not one a deterministic planner records",
        ),
        (
            run_model_skipped_at_deadline,
            record_the_skipped_planner_as_deterministic,
            "round 2's planner outcome deterministic is not one a model planner records",
        ),
        (
            run_model_accepted,
            reject_the_accepted_plan,
            "round 1 is model_accepted and runs its plan, but records rejections",
        ),
        (
            run_model_unavailable,
            drop_round_one_rejections,
            "round 1 is model_unavailable but records no rejection",
        ),
        (
            run_model_unavailable,
            record_a_malformed_plan,
            "round 1 is model_unavailable, so its first rejection is planner_unavailable",
        ),
        (
            run_exact_id,
            record_a_malformed_plan,
            "round 1 records malformed_plan, but its outcome deterministic rejected no model",
        ),
        (
            run_policy_plan_over_budget,
            blame_a_missing_named_id,
            "round 1 records missing_named_cve_id, but its outcome deterministic rejected no "
            "model reply",
        ),
        (
            run_model_accepted,
            drop_the_model_reply_hash,
            "round 1's model_reply_sha256 is not the hash of its recorded reply",
        ),
        (
            run_model_accepted,
            rewrite_the_reply_without_rehashing,
            "round 1's model_reply_sha256 is not the hash of its recorded reply",
        ),
        (
            run_exact_id,
            hash_a_reply_the_policy_never_had,
            "round 1 hashes a reply it does not record",
        ),
        (
            run_model_accepted,
            drop_the_planner_call,
            "planner_calls 0 differ from the 2 rounds that consulted the model",
        ),
        (
            run_exact_id,
            count_a_round_never_recorded,
            "budget_used.rounds 2 differs from the 1 rounds recorded",
        ),
        (
            run_refinement,
            drop_the_refinement_round,
            "step 2 runs in round 2, which has no round record",
        ),
        (
            run_refinement,
            retrieve_round_two_without_accepting_its_plan,
            "1 plan_accepted transitions for 2 rounds with an accepted plan",
        ),
        (
            run_exact_id,
            name_fight_for_a_cve_tool_step,
            "step 1 names other sources than its call consults under the scope",
        ),
        (
            run_model_skipped_at_deadline,
            blame_the_context_bytes_cap,
            "round 2's planner ran into the deadline, but the breach is not wall_time",
        ),
        (run_exact_id, add_a_phantom_round_two, "round 2 is recorded without an assess -> refine"),
        (
            run_exact_id,
            add_a_phantom_round_two_rejecting_the_policy_plan,
            "round 2 records the policy plan's rejection, but the run stops sufficient",
        ),
        (
            run_cve_under_protocol_scope,
            add_a_round_to_a_run_that_never_planned,
            "round 1 is recorded exactly when the run moves interpret -> plan",
        ),
        (
            run_exact_id,
            plan_a_search_that_never_ran,
            "round 1 leaves calls of its accepted plan unrun, though every step was admitted",
        ),
        (
            run_exact_id,
            plan_a_topic_that_never_ran,
            "round 1 leaves calls of its accepted plan unrun, though every step was admitted",
        ),
        (
            run_exact_id,
            repeat_the_accepted_plan,
            "round 1 accepts a cve_exact_lookup call twice",
        ),
        (
            run_protocol_topic,
            plan_a_cve_search_under_protocol_scope,
            "round 1 accepts cve_search, which protocol_context_only bars",
        ),
        (
            run_exact_id,
            give_the_lookup_a_search_reason,
            "step 1's reason query_terms is given to cve_search in round 1, not to "
            "cve_exact_lookup in round 1",
        ),
        (
            run_exact_id,
            give_the_lookup_a_topic_reason,
            "step 1's reason reviewed_topic is given to topic_context in round 1",
        ),
        (
            run_exact_id,
            give_the_lookup_a_refinement_reason,
            "step 1's reason topic_after_literal_miss is given to topic_context in round 2",
        ),
        (
            run_exact_id,
            time_planner_calls_never_made,
            "timings hold 2 planner durations for 0 planner calls",
        ),
        (
            run_model_rejected,
            lead_the_rejection_with_planner_unavailable,
            "round 1 is model_rejected, but its first rejection is planner_unavailable",
        ),
        (
            run_policy_plan_over_budget,
            drop_round_one_rejections,
            "round 1 runs no plan, though its plan was not rejected and the deadline was not "
            "reached",
        ),
    ],
    ids=[
        "arbitrary_call_key",
        "executed_round_without_accepted_plan",
        "swapped_call_with_recomputed_key",
        "round_listing_another_rounds_step",
        "plan_not_led_by_the_executed_calls",
        "deterministic_step_credited_to_the_model",
        "deterministic_step_with_model_reason",
        "model_outcome_under_deterministic_planner",
        "skipped_planner_recorded_as_deterministic",
        "accepted_plan_with_rejections",
        "rejected_model_reply_without_rejections",
        "unavailable_planner_with_wrong_first_rejection",
        "model_rejection_under_deterministic_outcome",
        "missing_named_id_under_deterministic_outcome",
        "model_reply_hash_dropped",
        "model_reply_rewritten_without_rehashing",
        "reply_hash_without_a_reply",
        "planner_calls_not_counted_from_rounds",
        "rounds_not_counted_from_rounds",
        "step_in_unrecorded_round",
        "plan_accepted_transitions_not_counted",
        "cve_step_naming_fight",
        "skipped_planner_without_wall_time_breach",
        "phantom_round_two_without_refine",
        "phantom_round_two_with_a_policy_rejection",
        "round_without_interpret_plan",
        "unrun_search_in_a_completed_round",
        "unrun_topic_in_a_completed_round",
        "call_accepted_twice",
        "cve_tool_accepted_under_protocol_scope",
        "lookup_with_a_search_reason",
        "lookup_with_a_topic_reason",
        "lookup_with_a_refinement_reason",
        "planner_durations_without_planner_calls",
        "rejected_model_plan_led_by_a_fixed_code",
        "policy_round_without_plan_or_rejection",
    ],
)
def test_forged_trajectory_is_rejected(
    fixture_bundle: FixtureBundle,
    pinned_fight_snapshot: KnownFightSnapshot,
    packaged_evidence_catalog: EvidenceCatalog,
    run: TrajectoryRun,
    forgery: SetForgery,
    expected_violation: str,
) -> None:
    evidence_set = run(fixture_bundle)
    validate_knowledge_evidence_set(
        evidence_set,
        pinned_fight_snapshot,
        packaged_evidence_catalog,
        evidence_set.source_capabilities,
    )

    forged_set = forgery(evidence_set)

    with pytest.raises(EvidenceValidationError) as raised:
        validate_knowledge_evidence_set(
            forged_set,
            pinned_fight_snapshot,
            packaged_evidence_catalog,
            evidence_set.source_capabilities,
        )
    assert any(expected_violation in violation for violation in raised.value.violations)


@pytest.fixture(scope="module")
def sets_by_planner_outcome(
    timed_out_planner_set: KnowledgeEvidenceSet,
) -> dict[PlannerOutcome, KnowledgeEvidenceSet]:
    """A genuine set with a round of each planner outcome; the sets are immutable, so they
    are built once per module."""
    fixture_bundle = load_fixture_bundle(default_fixture_dir())
    return {
        PlannerOutcome.DETERMINISTIC: run_exact_id(fixture_bundle),
        PlannerOutcome.MODEL_ACCEPTED: run_model_accepted(fixture_bundle),
        PlannerOutcome.MODEL_REJECTED: run_model_rejected(fixture_bundle),
        PlannerOutcome.MODEL_UNAVAILABLE: run_model_unavailable(fixture_bundle),
        PlannerOutcome.MODEL_REPLY_AFTER_DEADLINE: run_model_reply_after_deadline(fixture_bundle),
        PlannerOutcome.MODEL_TIMED_OUT: timed_out_planner_set,
        PlannerOutcome.MODEL_SKIPPED_AT_DEADLINE: run_model_skipped_at_deadline(fixture_bundle),
        PlannerOutcome.MODEL_NOT_CONSULTED: run_model_not_consulted(fixture_bundle),
    }


# What the validator says once the round of each outcome drops the reply it records, or
# records one it never got, with that reply's own hash.
REPLY_RECORD_VIOLATIONS: dict[PlannerOutcome, str] = {
    PlannerOutcome.DETERMINISTIC: "round 1 records a reply its deterministic planner never gave",
    PlannerOutcome.MODEL_ACCEPTED: (
        "round 1 is model_accepted but does not record the model's reply"
    ),
    PlannerOutcome.MODEL_REJECTED: (
        "round 1 is model_rejected but does not record the model's reply"
    ),
    PlannerOutcome.MODEL_UNAVAILABLE: (
        "round 1 is model_unavailable but does not record the model's reply"
    ),
    PlannerOutcome.MODEL_REPLY_AFTER_DEADLINE: (
        "round 1 is model_reply_after_deadline but does not record the model's reply"
    ),
    PlannerOutcome.MODEL_TIMED_OUT: (
        "round 1 records a reply its model_timed_out planner never gave"
    ),
    PlannerOutcome.MODEL_SKIPPED_AT_DEADLINE: (
        "round 2 records a reply its model_skipped_at_deadline planner never gave"
    ),
    PlannerOutcome.MODEL_NOT_CONSULTED: (
        "round 1 records a reply its model_not_consulted planner never gave"
    ),
}


def find_round_position(evidence_set: KnowledgeEvidenceSet, planner_outcome: PlannerOutcome) -> int:
    for round_position, round_record in enumerate(evidence_set.trajectory.rounds):
        if round_record.planner_outcome is planner_outcome:
            return round_position
    raise LookupError(planner_outcome)


def drop_or_record_the_model_reply(
    evidence_set: KnowledgeEvidenceSet, round_position: int
) -> KnowledgeEvidenceSet:
    """The round drops the reply it records, with its hash; or, when it records none, it
    records a reply with that reply's own hash."""
    if evidence_set.trajectory.rounds[round_position].model_reply is not None:
        return update_round(evidence_set, round_position, model_reply=None, model_reply_sha256=None)
    return update_round(
        evidence_set,
        round_position,
        model_reply=UNAVAILABLE_REPLY,
        model_reply_sha256=compute_model_reply_sha256(UNAVAILABLE_REPLY),
    )


@pytest.mark.parametrize("planner_outcome", list(PlannerOutcome), ids=str)
def test_round_missing_its_reply_or_holding_an_unexpected_one_is_rejected(
    sets_by_planner_outcome: dict[PlannerOutcome, KnowledgeEvidenceSet],
    pinned_fight_snapshot: KnownFightSnapshot,
    packaged_evidence_catalog: EvidenceCatalog,
    planner_outcome: PlannerOutcome,
) -> None:
    evidence_set = sets_by_planner_outcome[planner_outcome]
    expected_violation = REPLY_RECORD_VIOLATIONS[planner_outcome]

    forged_set = drop_or_record_the_model_reply(
        evidence_set, find_round_position(evidence_set, planner_outcome)
    )

    with pytest.raises(EvidenceValidationError) as raised:
        validate_knowledge_evidence_set(
            forged_set,
            pinned_fight_snapshot,
            packaged_evidence_catalog,
            evidence_set.source_capabilities,
        )
    assert expected_violation in raised.value.violations


def drop_the_policy_rejections(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return update_round(evidence_set, 0, rejections=())


def drop_the_policy_rejections_at_the_deadline(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    """A deadline before planning records ``model_skipped_at_deadline`` when a model is
    configured, so it never excuses a ``model_not_consulted`` round that runs nothing."""
    return update_usage(drop_the_policy_rejections(evidence_set), breach=BudgetBreach.WALL_TIME)


def record_a_policy_rejection(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """Round 1, whose policy plan ran, also records the gate rejecting that plan."""
    return update_round(
        evidence_set, 0, rejections=(PlanRejection(code=PlanRejectionCode.OVER_TOOL_CALL_BUDGET),)
    )


def relabel_round_two_not_consulted(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """Round 2, whose model replied unavailable, claims it was never consulted."""
    return update_round(
        evidence_set,
        1,
        planner_outcome=PlannerOutcome.MODEL_NOT_CONSULTED,
        model_reply=None,
        model_reply_sha256=None,
    )


@pytest.mark.parametrize(
    ("run", "forgery", "expected_violation"),
    [
        (
            run_model_refinement_unavailable,
            relabel_round_two_not_consulted,
            "round 2 is model_not_consulted: only round 1 is",
        ),
        (
            run_free_text_under_a_model_planner,
            record_a_policy_rejection,
            "round 1 is model_not_consulted and runs its plan, but records rejections",
        ),
        (
            run_model_not_consulted,
            drop_the_policy_rejections,
            "round 1 is model_not_consulted and runs no plan, though its plan was not rejected",
        ),
        (
            run_model_not_consulted,
            drop_the_policy_rejections_at_the_deadline,
            "round 1 is model_not_consulted and runs no plan, though its plan was not rejected",
        ),
    ],
    ids=[
        "in_round_two",
        "running_its_plan_with_rejections",
        "running_nothing_unrejected",
        "running_nothing_unrejected_at_the_deadline",
    ],
)
def test_round_not_consulting_its_model_is_rejected_unless_it_is_round_one_of_the_policy_plan(
    fixture_bundle: FixtureBundle,
    pinned_fight_snapshot: KnownFightSnapshot,
    packaged_evidence_catalog: EvidenceCatalog,
    run: TrajectoryRun,
    forgery: SetForgery,
    expected_violation: str,
) -> None:
    forged_set = forgery(run(fixture_bundle))

    with pytest.raises(EvidenceValidationError) as raised:
        validate_knowledge_evidence_set(
            forged_set,
            pinned_fight_snapshot,
            packaged_evidence_catalog,
            forged_set.source_capabilities,
        )
    assert expected_violation in raised.value.violations


@pytest.mark.parametrize(
    ("search_text", "expected_searchable"),
    [("ausf", True), ("cve", False), ("CVEs, the CVE-9999-0003", False)],
    ids=["term", "low_signal_word", "low_signal_words_stopword_and_id"],
)
def test_search_sends_searchable_text_only_with_a_term_beyond_ids_and_low_signal_words(
    fixture_bundle: FixtureBundle, search_text: str, expected_searchable: bool
) -> None:
    search_step = run_five_g_aka(fixture_bundle).trajectory.steps[0]
    sent_request = search_step.backend_requests[0].model_copy(update={"query": search_text})

    is_searchable = sends_searchable_text(
        search_step.model_copy(update={"backend_requests": (sent_request,)})
    )

    assert is_searchable is expected_searchable


# --- Truncation (ADR 0009 §11a) -------------------------------------------------------

ONE_RESULT_BUDGET = {"budget": {"max_results_per_call": 1}}


def run_cut_five_g_aka(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """A mixed 5G-AKA run at a cap of one: its topic step cuts one CVE and four techniques."""
    return investigate(fixture_bundle, "5G-AKA", "mixed", **ONE_RESULT_BUDGET)


def rewrite_answer_truncation(
    evidence_set: KnowledgeEvidenceSet, *subjects: str
) -> KnowledgeEvidenceSet:
    """The set with its answer_truncated warnings replaced by one per subject."""
    warnings: list[InvestigationWarning] = []
    for warning in evidence_set.warnings:
        if warning.code is not InvestigationWarningCode.ANSWER_TRUNCATED:
            warnings.append(warning)
    for subject in subjects:
        warnings.append(
            InvestigationWarning(code=InvestigationWarningCode.ANSWER_TRUNCATED, subject=subject)
        )
    return reseal_evidence_set(evidence_set, warnings=tuple(warnings))


def rewrite_topic_warning(
    evidence_set: KnowledgeEvidenceSet, code: TopicContextWarningCode, subject: str
) -> KnowledgeEvidenceSet:
    topic_step = evidence_set.trajectory.steps[0]
    topic_warnings: list[TopicContextWarning] = []
    for warning in topic_step.topic_warnings:
        if warning.code is code:
            warning = warning.model_copy(update={"subject": subject})
        topic_warnings.append(warning)
    return rewrite_step(evidence_set, topic_step.step_index, topic_warnings=tuple(topic_warnings))


def test_set_whose_topic_step_cut_its_sections_counts_every_cut_and_validates(
    fixture_bundle: FixtureBundle,
    pinned_fight_snapshot: KnownFightSnapshot,
    packaged_evidence_catalog: EvidenceCatalog,
) -> None:
    evidence_set = run_cut_five_g_aka(fixture_bundle)

    validate_knowledge_evidence_set(
        evidence_set,
        pinned_fight_snapshot,
        packaged_evidence_catalog,
        evidence_set.source_capabilities,
    )
    answer_warnings: list[tuple[str, str]] = []
    for warning in evidence_set.warnings:
        answer_warnings.append((warning.code.value, warning.subject))
    assert ("answer_truncated", "5") in answer_warnings
    assert evidence_set.status is ResultStatus.OK


@pytest.mark.parametrize(
    ("forge", "violation"),
    [
        (
            lambda evidence_set: rewrite_answer_truncation(evidence_set, "4"),
            "fewer items than the adopted steps left out",
        ),
        (
            lambda evidence_set: rewrite_answer_truncation(evidence_set, "5", "5"),
            "answer_truncated warning appears more than once",
        ),
        (
            lambda evidence_set: rewrite_answer_truncation(evidence_set, "five"),
            "not a positive count",
        ),
        (
            lambda evidence_set: rewrite_answer_truncation(evidence_set, "1" + "0" * 5000),
            "not a positive count",
        ),
        (
            lambda evidence_set: rewrite_topic_warning(
                evidence_set, TopicContextWarningCode.PROTOCOL_CONTEXT_TRUNCATED, "4" * 5000
            ),
            "not a positive count",
        ),
        (
            lambda evidence_set: rewrite_topic_warning(
                evidence_set, TopicContextWarningCode.PROTOCOL_CONTEXT_TRUNCATED, "9"
            ),
            "more techniques than the pinned snapshot holds",
        ),
        (
            lambda evidence_set: rewrite_topic_warning(
                evidence_set, TopicContextWarningCode.CANDIDATES_TRUNCATED, "0"
            ),
            "not a positive count",
        ),
    ],
    ids=[
        "count_below_the_topic_cuts",
        "count_given_twice",
        "count_not_a_number",
        "count_too_long_to_read",
        "topic_count_too_long_to_read",
        "technique_cut_beyond_the_snapshot",
        "candidate_cut_of_zero",
    ],
)
def test_forged_truncation_is_rejected(
    fixture_bundle: FixtureBundle,
    pinned_fight_snapshot: KnownFightSnapshot,
    packaged_evidence_catalog: EvidenceCatalog,
    forge: Callable[[KnowledgeEvidenceSet], KnowledgeEvidenceSet],
    violation: str,
) -> None:
    evidence_set = run_cut_five_g_aka(fixture_bundle)

    with pytest.raises(EvidenceValidationError) as raised:
        validate_knowledge_evidence_set(
            forge(evidence_set),
            pinned_fight_snapshot,
            packaged_evidence_catalog,
            evidence_set.source_capabilities,
        )

    assert any(violation in found for found in raised.value.violations)


def test_truncation_in_a_run_with_no_adopted_step_is_rejected(
    fixture_bundle: FixtureBundle,
    pinned_fight_snapshot: KnownFightSnapshot,
    packaged_evidence_catalog: EvidenceCatalog,
) -> None:
    evidence_set = investigate(fixture_bundle, "cve", "implementation_only")
    assert evidence_set.trajectory.steps == ()
    forged_set = rewrite_answer_truncation(evidence_set, "1")

    with pytest.raises(EvidenceValidationError) as raised:
        validate_knowledge_evidence_set(
            forged_set,
            pinned_fight_snapshot,
            packaged_evidence_catalog,
            evidence_set.source_capabilities,
        )

    assert any(
        "needs a step the answer was assembled from" in found for found in raised.value.violations
    )


# --- What the answer repeats from its steps -------------------------------------------

STEP_NOTICE_VIOLATION = (
    "the result_limit_reached and term_not_indexed warnings are not the ones the adopted "
    "steps raise"
)


def run_cut_search_of_an_unindexed_word(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """``gateway gatewy`` at a cap of one: its search fills the cap and warns that no record
    holds ``gatewy``, so the answer warns ``result_limit_reached`` then ``term_not_indexed``."""
    return investigate(fixture_bundle, "gateway gatewy", "implementation_only", **ONE_RESULT_BUDGET)


def drop_the_unindexed_term_notice(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    kept_warnings: list[InvestigationWarning] = []
    for warning in evidence_set.warnings:
        if warning.code is not InvestigationWarningCode.TERM_NOT_INDEXED:
            kept_warnings.append(warning)
    return reseal_evidence_set(evidence_set, warnings=tuple(kept_warnings))


def repeat_the_unindexed_term_notice(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return reseal_evidence_set(
        evidence_set, warnings=(*evidence_set.warnings, evidence_set.warnings[-1])
    )


def swap_the_step_notices(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    limit_notice, term_notice = evidence_set.warnings
    return reseal_evidence_set(evidence_set, warnings=(term_notice, limit_notice))


def run_cut_protocol_context_of_five_g_aka(
    fixture_bundle: FixtureBundle,
) -> KnowledgeEvidenceSet:
    """``5gaka`` under protocol_context_only at a cap of one: the topic card's CVE searches
    reach the limit, and the answer, which can list none of their CVEs, does not warn it."""
    return investigate(fixture_bundle, "5gaka", "protocol_context_only", **ONE_RESULT_BUDGET)


def warn_the_answer_reached_the_limit(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return reseal_evidence_set(
        evidence_set,
        warnings=(
            *evidence_set.warnings,
            InvestigationWarning(code=InvestigationWarningCode.RESULT_LIMIT_REACHED, subject="1"),
        ),
    )


def warn_an_unfilled_search_reached_its_limit(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    """The search returned two CVEs under a limit of 20, yet warns, and so does the answer,
    that it reached its limit."""
    search_step = evidence_set.trajectory.steps[0]
    forged_set = rewrite_step(
        evidence_set,
        search_step.step_index,
        search_warnings=(
            *search_step.search_warnings,
            SearchWarning(code=SearchWarningCode.RESULT_LIMIT_REACHED, subject="20"),
        ),
    )
    return reseal_evidence_set(
        forged_set,
        warnings=(
            *forged_set.warnings,
            InvestigationWarning(code=InvestigationWarningCode.RESULT_LIMIT_REACHED, subject="20"),
        ),
    )


def test_set_whose_answer_repeats_its_step_notices_validates(
    fixture_bundle: FixtureBundle,
    pinned_fight_snapshot: KnownFightSnapshot,
    packaged_evidence_catalog: EvidenceCatalog,
) -> None:
    evidence_set = run_cut_search_of_an_unindexed_word(fixture_bundle)

    validate_knowledge_evidence_set(
        evidence_set,
        pinned_fight_snapshot,
        packaged_evidence_catalog,
        evidence_set.source_capabilities,
    )

    answer_warnings: list[tuple[str, str]] = []
    for warning in evidence_set.warnings:
        answer_warnings.append((warning.code.value, warning.subject))
    assert answer_warnings == [("result_limit_reached", "1"), ("term_not_indexed", "gatewy")]


@pytest.mark.parametrize(
    ("run", "forge", "violation"),
    [
        (
            run_cut_search_of_an_unindexed_word,
            drop_the_unindexed_term_notice,
            STEP_NOTICE_VIOLATION,
        ),
        (
            run_cut_search_of_an_unindexed_word,
            repeat_the_unindexed_term_notice,
            STEP_NOTICE_VIOLATION,
        ),
        (run_cut_search_of_an_unindexed_word, swap_the_step_notices, STEP_NOTICE_VIOLATION),
        (
            lambda fixture_bundle: investigate(fixture_bundle, "gateway", "implementation_only"),
            warn_an_unfilled_search_reached_its_limit,
            "warns the result limit was reached, but the step did not return as many CVEs as "
            "the limit it sent",
        ),
        (
            run_cut_protocol_context_of_five_g_aka,
            warn_the_answer_reached_the_limit,
            STEP_NOTICE_VIOLATION,
        ),
    ],
    ids=[
        "term_notice_missing",
        "term_notice_repeated",
        "notices_reordered",
        "limit_warned_on_an_unfilled_search",
        "limit_warned_on_a_protocol_context_only_answer",
    ],
)
def test_forged_step_notice_is_rejected(
    fixture_bundle: FixtureBundle,
    pinned_fight_snapshot: KnownFightSnapshot,
    packaged_evidence_catalog: EvidenceCatalog,
    run: TrajectoryRun,
    forge: Callable[[KnowledgeEvidenceSet], KnowledgeEvidenceSet],
    violation: str,
) -> None:
    evidence_set = run(fixture_bundle)

    with pytest.raises(EvidenceValidationError) as raised:
        validate_knowledge_evidence_set(
            forge(evidence_set),
            pinned_fight_snapshot,
            packaged_evidence_catalog,
            evidence_set.source_capabilities,
        )

    assert any(violation in found for found in raised.value.violations)


def drop_a_fight_term(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The interpretation sends FiGHT only some of its search terms."""
    return update_interpretation(
        evidence_set, fight_terms=evidence_set.interpretation.fight_terms[:1]
    )


def blame_a_cve_id_for_the_block(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The interpretation claims a CVE ID it does not hold bars the direct search."""
    return update_interpretation(
        evidence_set,
        fight_terms=(),
        fight_block=FightBlock(reason=FightBlockReason.CVE_ID_NAMED, subject="CVE-9999-0003"),
    )


def blame_an_absent_word_for_the_block(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The interpretation claims ``aka``, a word the query lacks, reads alone as a topic."""
    return update_interpretation(
        evidence_set,
        fight_terms=(),
        fight_block=FightBlock(reason=FightBlockReason.TERM_READS_AS_TOPIC, subject="aka"),
    )


def send_aka_to_fight(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The direct search's recorded request adds the excluded alias ``aka``."""
    fight_request = evidence_set.trajectory.steps[0].backend_requests[0]
    forged_request = fight_request.model_copy(update={"terms": (*fight_request.terms, "aka")})
    return rewrite_step(evidence_set, 1, backend_requests=(forged_request,))


def explain_a_technique_with_an_unsent_term(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    """The first technique claims a match on ``aka``, a word the search never sent."""
    protocol_context = list(evidence_set.protocol_context)
    protocol_context[0] = protocol_context[0].model_copy(update={"matched_terms": ("aka",)})
    return reseal_evidence_set(evidence_set, protocol_context=tuple(protocol_context))


def append_unindexed_warning(
    evidence_set: KnowledgeEvidenceSet, step_index: int, subject: str
) -> KnowledgeEvidenceSet:
    step = evidence_set.trajectory.steps[step_index - 1]
    topic_warnings = (
        *step.topic_warnings,
        TopicContextWarning(code=TopicContextWarningCode.TERM_NOT_INDEXED, subject=subject),
    )
    return rewrite_step(evidence_set, step_index, topic_warnings=topic_warnings)


def warn_an_unsent_term_unindexed(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return append_unindexed_warning(evidence_set, 1, "aka")


def warn_a_held_term_unindexed(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return append_unindexed_warning(evidence_set, 1, "suci")


def warn_a_card_term_unindexed(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """A topic step names a card term unindexed, which only a direct search may report."""
    return append_unindexed_warning(evidence_set, 1, "K_SEAF")


def clear_the_topic_block(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """A resolved topic's interpretation claims nothing bars sending its words to FiGHT."""
    return update_interpretation(
        evidence_set, fight_block=None, fight_terms=evidence_set.interpretation.search_terms
    )


def drop_a_returned_technique(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The direct search's step no longer returns the first technique the answer lists."""
    answer_ids = evidence_set.trajectory.steps[0].answer_ids
    return rewrite_step(evidence_set, 1, answer_ids=answer_ids[1:])


def repeat_the_unindexed_warning(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The direct search's step names its unindexed word twice."""
    topic_warnings = evidence_set.trajectory.steps[0].topic_warnings
    return rewrite_step(evidence_set, 1, topic_warnings=(*topic_warnings, topic_warnings[-1]))


def warn_a_word_of_a_failed_search_unindexed(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    """A direct search whose FiGHT outcome failed claims ``suci`` is held by no technique."""
    return append_unindexed_warning(evidence_set, 1, "suci")


def clear_the_topic_resolution(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The interpretation of a run that explored a topic claims no topic resolved."""
    resolution = evidence_set.interpretation.resolution
    return update_interpretation(
        evidence_set, resolution=resolution.model_copy(update={"matches": ()})
    )


def search_fight_twice(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The mixed run's direct FiGHT step appears again as a third step."""
    fight_step = evidence_set.trajectory.steps[1]
    repeated_step = fight_step.model_copy(update={"step_index": 3})
    return update_trajectory(evidence_set, steps=(*evidence_set.trajectory.steps, repeated_step))


@pytest.mark.parametrize(
    ("run", "forgery", "expected_violation"),
    [
        (
            run_mixed_fight_direct_search,
            drop_a_fight_term,
            "interpretation.fight_terms must be every search term",
        ),
        (
            run_mixed_fight_direct_search,
            blame_a_cve_id_for_the_block,
            "interpretation.fight_block names a reason the interpretation does not show",
        ),
        (
            run_mixed_fight_direct_search,
            blame_an_absent_word_for_the_block,
            "interpretation.fight_block names a reason the interpretation does not show",
        ),
        (
            run_mixed_fight_direct_search,
            blame_a_cve_id_for_the_block,
            "searches FiGHT directly, which the interpretation does not allow",
        ),
        (
            run_fight_direct_search,
            send_aka_to_fight,
            "step 1 records other backend requests than its call sends",
        ),
        (
            run_fight_direct_search,
            explain_a_technique_with_an_unsent_term,
            "matched by a term step 1 did not send",
        ),
        (
            run_fight_direct_search,
            warn_an_unsent_term_unindexed,
            "term_not_indexed names a term the FiGHT search did not send",
        ),
        (
            run_fight_direct_search,
            warn_a_held_term_unindexed,
            "term_not_indexed names a term a listed technique holds",
        ),
        (
            run_five_g_aka_mixed,
            warn_a_card_term_unindexed,
            "term_not_indexed needs a direct FiGHT search",
        ),
        (
            run_mixed_fight_direct_search,
            search_fight_twice,
            "each search FiGHT; a run holds one",
        ),
        (
            run_five_g_aka,
            clear_the_topic_block,
            "interpretation.fight_block does not give the first reason the interpretation shows",
        ),
        (
            run_five_g_aka,
            clear_the_topic_block,
            "interpretation.fight_terms are only free text's",
        ),
        (
            run_fight_direct_search,
            drop_a_returned_technique,
            "not returned by an admitted step that may search FiGHT",
        ),
        (
            run_fight_direct_search_of_an_unindexed_word,
            repeat_the_unindexed_warning,
            "step 1: term_not_indexed names a term more than once",
        ),
        (
            run_fight_direct_search_fight_failing,
            warn_a_word_of_a_failed_search_unindexed,
            "term_not_indexed needs a direct FiGHT search whose FiGHT outcome was served",
        ),
        (
            run_five_g_aka_mixed,
            clear_the_topic_resolution,
            "step 1 explores a topic, but no topic resolved",
        ),
    ],
    ids=[
        "fight_terms_a_subset",
        "block_blaming_an_absent_cve_id",
        "block_blaming_a_word_the_query_lacks",
        "direct_search_beside_a_block",
        "aka_added_to_the_request",
        "technique_explained_by_an_unsent_term",
        "unindexed_term_never_sent",
        "unindexed_term_a_technique_holds",
        "unindexed_term_on_a_topic_step",
        "second_fight_search",
        "topic_block_cleared",
        "fight_terms_beside_a_resolved_topic",
        "technique_no_step_returned",
        "unindexed_term_named_twice",
        "unindexed_term_on_a_failed_fight_search",
        "topic_step_without_a_resolved_topic",
    ],
)
def test_forged_direct_fight_search_is_rejected(
    fixture_bundle: FixtureBundle,
    pinned_fight_snapshot: KnownFightSnapshot,
    packaged_evidence_catalog: EvidenceCatalog,
    run: TrajectoryRun,
    forgery: Callable[[KnowledgeEvidenceSet], KnowledgeEvidenceSet],
    expected_violation: str,
) -> None:
    evidence_set = run(fixture_bundle)

    forged_set = forgery(evidence_set)

    with pytest.raises(EvidenceValidationError) as raised:
        validate_knowledge_evidence_set(
            forged_set,
            pinned_fight_snapshot,
            packaged_evidence_catalog,
            evidence_set.source_capabilities,
        )
    assert any(expected_violation in violation for violation in raised.value.violations)
