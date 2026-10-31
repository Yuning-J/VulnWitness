"""Whole-result context admission, checked through sealing, audit and replay on fixtures."""

import json
from dataclasses import dataclass
from typing import Literal

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.application.deadline_checkpoint import ignore_checkpoint
from cve_kgrag.application.decision_path_audit import audit_decision_path
from cve_kgrag.application.investigate import InvestigationService
from cve_kgrag.application.investigation_deployment import InvestigationDeployment
from cve_kgrag.application.planner_setup import DeterministicPlanning
from cve_kgrag.application.trajectory_replay import (
    ReplayCompleted,
    ReplayDifference,
    replay_evidence_set,
)
from cve_kgrag.domain.hashing import canonical_json_bytes
from cve_kgrag.domain.investigation import (
    KnowledgeEvidenceSet,
    StepAdmission,
    build_prefix_omitted_warning,
)
from cve_kgrag.domain.investigation_validation import validate_knowledge_evidence_set
from cve_kgrag.domain.result_prefix import (
    build_prefix_admission,
    measure_response_bytes,
    slice_response,
)
from cve_kgrag.domain.search import SearchResponse
from cve_kgrag.domain.topic import ReviewStatus
from cve_kgrag.domain.topic_context import TopicContextResponse
from cve_kgrag.domain.validation import EvidenceValidationError
from tests.support.investigation import (
    FIGHT_FREE_TEXT_QUERY,
    build_exact_lookup_call,
    build_investigation_request,
    build_search_call,
    build_test_deployment,
    build_topic_call,
    reseal_evidence_set,
    rewrite_step,
    update_trajectory,
)
from tests.support.paths import REPOSITORY_SCHEMA_DIR
from tests.support.planners import ScriptedModelPort, build_plan_reply, plan_with

EXACT_QUERY = "CVE-9999-0001 CVE-9999-0002 CVE-9999-0003"
Forgery = Literal[
    "too_short",
    "too_long",
    "partial_record",
    "wrong_counts",
    "missing_warning",
    "wrong_bytes",
    "wrong_next_bytes",
    "plausible_next_bytes",
    "wrong_digest",
    "coordinated_bytes",
]


@dataclass(frozen=True)
class PrefixRun:
    evidence_set: KnowledgeEvidenceSet
    deployment: InvestigationDeployment
    original_search: SearchResponse


@pytest.fixture
def prefix_run(fixture_bundle: FixtureBundle) -> PrefixRun:
    deployment = build_test_deployment(fixture_bundle)
    request = build_investigation_request(EXACT_QUERY, "implementation_only")
    execution = deployment.tool_executor.execute(
        build_exact_lookup_call("CVE-9999-0001", "CVE-9999-0002", "CVE-9999-0003"), request
    )
    assert execution.search_response is not None
    two_candidates = slice_response(execution.search_response, {"candidates": 2})
    cap = len(canonical_json_bytes(two_candidates.model_dump(mode="json")))
    bounded_request = request.model_copy(
        update={"budget": request.budget.model_copy(update={"max_context_bytes": cap})}
    )
    evidence_set = InvestigationService(
        deployment, DeterministicPlanning(), ignore_checkpoint
    ).investigate(bounded_request)
    return PrefixRun(evidence_set, deployment, execution.search_response)


def forge_prefix(prefix_run: PrefixRun, forgery: Forgery) -> KnowledgeEvidenceSet:
    evidence_set = prefix_run.evidence_set
    step = evidence_set.trajectory.steps[0]
    prefix_admission = step.prefix_admission
    assert prefix_admission is not None
    original_response = prefix_run.original_search
    if forgery in ("too_short", "too_long"):
        kept = 1 if forgery == "too_short" else 3
        prefix = slice_response(original_response, {"candidates": kept})
        answer_ids = []
        evidence_ids = []
        for candidate in prefix.candidates:
            answer_ids.append(candidate.record.cve_id)
        for anchor in prefix.evidence:
            evidence_ids.append(anchor.evidence_id)
        changes = {
            "answer_ids": tuple(answer_ids),
            "evidence_ids": tuple(evidence_ids),
            "context_bytes": measure_response_bytes(prefix),
            "result_sha256": prefix.result_sha256,
        }
        if forgery == "too_short":
            changes["prefix_admission"] = build_prefix_admission(original_response, prefix)
        else:
            count = prefix_admission.counts[0].model_copy(update={"kept": 3, "omitted": 0})
            changes["prefix_admission"] = prefix_admission.model_copy(
                update={"counts": (count,), "charged_bytes": changes["context_bytes"]}
            )
        forged_set = rewrite_step(evidence_set, 1, **changes)
        warnings = []
        for warning in forged_set.warnings:
            if warning.code == "evidence_prefix_omitted":
                warnings.append(build_prefix_omitted_warning(1, changes["prefix_admission"]))
            else:
                warnings.append(warning)
        return reseal_evidence_set(forged_set, warnings=tuple(warnings))
    if forgery == "wrong_counts":
        count = prefix_admission.counts[0].model_copy(update={"omitted": 10})
        return rewrite_step(
            evidence_set,
            1,
            prefix_admission=prefix_admission.model_copy(update={"counts": (count,)}),
        )
    if forgery in ("wrong_next_bytes", "plausible_next_bytes", "wrong_digest"):
        field_name = "original_result_sha256" if forgery == "wrong_digest" else "next_result_bytes"
        replacement = (
            "0" * 64
            if forgery == "wrong_digest"
            else 0
            if forgery == "wrong_next_bytes"
            else prefix_admission.next_result_bytes + 1
        )
        return rewrite_step(
            evidence_set,
            1,
            prefix_admission=prefix_admission.model_copy(update={field_name: replacement}),
        )
    if forgery == "coordinated_bytes":
        return forge_consistent_charge(evidence_set, 1)
    if forgery == "wrong_bytes":
        return rewrite_step(evidence_set, 1, context_bytes=step.context_bytes - 1)
    if forgery == "missing_warning":
        return reseal_evidence_set(evidence_set, warnings=())
    candidates = list(evidence_set.implementation_candidates)
    candidate = candidates[0].candidate
    partial_record = candidate.record.model_copy(update={"descriptions": ()})
    candidates[0] = candidates[0].model_copy(
        update={"candidate": candidate.model_copy(update={"record": partial_record})}
    )
    return reseal_evidence_set(evidence_set, implementation_candidates=tuple(candidates))


def forge_consistent_charge(
    evidence_set: KnowledgeEvidenceSet, step_index: int
) -> KnowledgeEvidenceSet:
    step = evidence_set.trajectory.steps[step_index - 1]
    assert step.prefix_admission is not None
    forged_set = rewrite_step(
        evidence_set,
        step_index,
        context_bytes=step.context_bytes - 1,
        prefix_admission=step.prefix_admission.model_copy(
            update={"charged_bytes": step.context_bytes - 1}
        ),
    )
    usage = evidence_set.trajectory.budget_used
    return update_trajectory(
        forged_set, budget_used=usage.model_copy(update={"context_bytes": usage.context_bytes - 1})
    )


def test_lookup_keeps_the_longest_ranked_whole_prefix_without_a_breach(
    prefix_run: PrefixRun,
) -> None:
    # Arrange
    evidence_set = prefix_run.evidence_set
    step = evidence_set.trajectory.steps[0]

    # Act
    prefix = step.prefix_admission

    # Assert
    assert step.admission is StepAdmission.ADMITTED_PREFIX
    assert prefix is not None
    assert prefix.original_result_sha256 == prefix_run.original_search.result_sha256
    assert step.answer_ids == ("CVE-9999-0001", "CVE-9999-0002")
    count_values = []
    for count in prefix.counts:
        count_values.append((count.name, count.kept, count.omitted))
    assert count_values == [("candidates", 2, 1)]
    assert evidence_set.warnings[0].code == "evidence_prefix_omitted"
    assert evidence_set.warnings[0].subject == "step 1: 1 results omitted"
    assert evidence_set.trajectory.budget_used.breach is None
    assert step.context_bytes == evidence_set.request.budget.max_context_bytes
    assert evidence_set.trajectory.budget_used.context_bytes == step.context_bytes
    assert (
        len(canonical_json_bytes(prefix_run.original_search.model_dump(mode="json")))
        > step.context_bytes
    )
    referenced_ids = set()
    for candidate in evidence_set.implementation_candidates:
        referenced_ids.update(candidate.candidate.record.evidence_ids)
    assert set(step.evidence_ids) == referenced_ids
    assert (
        evidence_set.implementation_candidates[0].candidate
        == prefix_run.original_search.candidates[0]
    )
    assert (
        evidence_set.implementation_candidates[1].candidate
        == prefix_run.original_search.candidates[1]
    )


def test_true_prefix_passes_validation_audit_and_replay(prefix_run: PrefixRun) -> None:
    # Arrange
    evidence_set, deployment = prefix_run.evidence_set, prefix_run.deployment

    # Act
    validate_knowledge_evidence_set(
        evidence_set,
        deployment.pinned_fight_snapshot,
        deployment.evidence_catalog,
        evidence_set.source_capabilities,
    )
    audit_decision_path(evidence_set, deployment.topic_registry, deployment.evidence_catalog)
    replay = replay_evidence_set(evidence_set, deployment)

    # Assert
    assert replay == ReplayCompleted(())


@pytest.mark.parametrize(
    "forgery",
    [
        "too_short",
        "too_long",
        "partial_record",
        "wrong_counts",
        "missing_warning",
        "wrong_bytes",
        "wrong_next_bytes",
        "coordinated_bytes",
    ],
)
@pytest.mark.parametrize("check", ["validator", "audit", "replay"])
def test_forged_prefix_is_rejected_by_each_check(
    prefix_run: PrefixRun, forgery: Forgery, check: str
) -> None:
    # Arrange
    evidence_set = forge_prefix(prefix_run, forgery)
    deployment = prefix_run.deployment

    # Act / Assert
    if check == "validator":
        with pytest.raises(EvidenceValidationError, match="prefix"):
            validate_knowledge_evidence_set(
                evidence_set,
                deployment.pinned_fight_snapshot,
                deployment.evidence_catalog,
                evidence_set.source_capabilities,
            )
    elif check == "audit":
        with pytest.raises(EvidenceValidationError, match="prefix"):
            audit_decision_path(
                evidence_set, deployment.topic_registry, deployment.evidence_catalog
            )
    else:
        replay = replay_evidence_set(evidence_set, deployment)
        assert isinstance(replay, ReplayCompleted)
        assert replay.differences


@pytest.mark.parametrize(
    ("query", "scope", "tool"),
    [
        ("democorp", "implementation_only", "cve_search"),
        ("5gaka", "mixed", "topic_context"),
        ("5gaka", "protocol_context_only", "topic_context"),
        (FIGHT_FREE_TEXT_QUERY, "protocol_context_only", "fight_direct_search"),
    ],
)
def test_each_tool_admits_a_replayable_prefix(
    fixture_bundle: FixtureBundle, query: str, scope: str, tool: str
) -> None:
    # Arrange
    deployment = build_test_deployment(fixture_bundle)
    service = InvestigationService(deployment, DeterministicPlanning(), ignore_checkpoint)
    request = build_investigation_request(query, scope)
    whole = service.investigate(request)
    whole_step = whole.trajectory.steps[0]
    request = request.model_copy(
        update={
            "budget": request.budget.model_copy(
                update={"max_context_bytes": whole_step.context_bytes - 1}
            )
        }
    )

    # Act
    evidence_set = service.investigate(request)
    replay = replay_evidence_set(evidence_set, deployment)

    # Assert
    step = evidence_set.trajectory.steps[0]
    assert step.call.tool == tool
    assert step.admission is StepAdmission.ADMITTED_PREFIX
    assert step.prefix_admission is not None
    assert sum(count.omitted for count in step.prefix_admission.counts) > 0
    assert evidence_set.trajectory.budget_used.breach is None
    assert replay == ReplayCompleted(())


def test_topic_prefix_keeps_both_heads_before_either_tail(fixture_bundle: FixtureBundle) -> None:
    # Arrange
    deployment = build_test_deployment(fixture_bundle)
    request = build_investigation_request("5gaka", "mixed")
    execution = deployment.tool_executor.execute(build_topic_call(), request)
    original_response = execution.topic_response
    assert isinstance(original_response, TopicContextResponse)
    heads = slice_response(
        original_response,
        {
            "implementation_candidates": 1,
            "protocol_context": 1,
            "excluded_implementation_candidates": 0,
        },
    )
    cap = len(canonical_json_bytes(heads.model_dump(mode="json")))
    request = request.model_copy(
        update={"budget": request.budget.model_copy(update={"max_context_bytes": cap})}
    )

    # Act
    evidence_set = InvestigationService(
        deployment, DeterministicPlanning(), ignore_checkpoint
    ).investigate(request)

    # Assert
    step = evidence_set.trajectory.steps[0]
    assert step.admission is StepAdmission.ADMITTED_PREFIX
    assert step.prefix_admission is not None
    extended = slice_response(
        original_response,
        {
            "implementation_candidates": 2,
            "protocol_context": 1,
            "excluded_implementation_candidates": 0,
        },
    )
    assert step.prefix_admission.charged_bytes == cap
    assert step.prefix_admission.next_result_bytes == measure_response_bytes(extended) - cap
    counts = []
    for count in step.prefix_admission.counts:
        counts.append((count.kept, count.omitted))
    assert counts == [
        (1, len(original_response.implementation_candidates) - 1),
        (1, len(original_response.protocol_context) - 1),
        (0, 0),
    ]
    assert (
        evidence_set.implementation_candidates[0].candidate
        == original_response.implementation_candidates[0].candidate
    )
    assert evidence_set.protocol_context == original_response.protocol_context[:1]
    warning_subjects = {}
    for warning in step.topic_warnings:
        warning_subjects[warning.code] = warning.subject
    assert warning_subjects["protocol_context_truncated"] == str(
        len(original_response.protocol_context) - 1
    )
    assert warning_subjects["candidates_truncated"] == str(
        len(original_response.implementation_candidates) - 1
    )


def test_prefix_uses_the_budget_left_by_an_earlier_step(fixture_bundle: FixtureBundle) -> None:
    # Arrange
    deployment = build_test_deployment(fixture_bundle)
    first_call = build_exact_lookup_call("CVE-9999-0003")
    second_call = build_search_call("democorp")
    request = build_investigation_request("CVE-9999-0003 democorp", "implementation_only")
    first = deployment.tool_executor.execute(first_call, request)
    second = deployment.tool_executor.execute(second_call, request)
    assert second.search_response is not None
    head = slice_response(second.search_response, {"candidates": 1})
    head_bytes = len(canonical_json_bytes(head.model_dump(mode="json")))
    request = request.model_copy(
        update={
            "budget": request.budget.model_copy(
                update={"max_context_bytes": first.context_bytes + head_bytes}
            )
        }
    )
    planner = ScriptedModelPort(
        [build_plan_reply(first_call.model_dump(mode="json"), second_call.model_dump(mode="json"))]
    )
    service = InvestigationService(deployment, plan_with(planner), ignore_checkpoint)

    # Act
    evidence_set = service.investigate(request)

    # Assert
    admissions = []
    for step in evidence_set.trajectory.steps:
        admissions.append(step.admission)
    assert admissions == [StepAdmission.ADMITTED, StepAdmission.ADMITTED_PREFIX]
    assert evidence_set.trajectory.steps[1].answer_ids == (
        second.search_response.candidates[0].record.cve_id,
    )
    prefix = evidence_set.trajectory.steps[1].prefix_admission
    assert prefix is not None
    assert prefix.counts[0].kept == 1
    assert prefix.counts[0].omitted == len(second.search_response.candidates) - 1
    assert evidence_set.trajectory.steps[1].context_bytes == head_bytes
    assert evidence_set.trajectory.budget_used.context_bytes == first.context_bytes + head_bytes
    assert evidence_set.trajectory.budget_used.breach is None


def test_prefix_serialization_agrees_with_the_published_contract(prefix_run: PrefixRun) -> None:
    # Arrange
    evidence_set = prefix_run.evidence_set
    schema = json.loads((REPOSITORY_SCHEMA_DIR / "knowledge_evidence_set.schema.json").read_text())

    # Act
    contract_errors = list(
        Draft202012Validator(schema).iter_errors(evidence_set.model_dump(mode="json"))
    )
    parsed_set = KnowledgeEvidenceSet.model_validate_json(evidence_set.model_dump_json())

    # Assert
    assert contract_errors == []
    assert parsed_set == evidence_set


@pytest.mark.parametrize("forgery", ["missing_prefix", "prefix_on_full_admission"])
def test_prefix_metadata_is_required_exactly_for_prefix_admission(
    prefix_run: PrefixRun, forgery: str
) -> None:
    # Arrange
    serialized_set = prefix_run.evidence_set.model_dump(mode="json")
    step = serialized_set["trajectory"]["steps"][0]
    if forgery == "missing_prefix":
        step["prefix_admission"] = None
    else:
        step["admission"] = "admitted"
    schema = json.loads((REPOSITORY_SCHEMA_DIR / "knowledge_evidence_set.schema.json").read_text())

    # Act
    is_schema_valid = Draft202012Validator(schema).is_valid(serialized_set)

    # Assert
    assert is_schema_valid is False
    with pytest.raises(ValidationError, match="exactly an admitted_prefix"):
        KnowledgeEvidenceSet.model_validate(serialized_set)


@pytest.mark.parametrize("forgery", ["plausible_next_bytes", "wrong_digest"])
def test_replay_rejects_a_witness_that_passes_the_visible_arithmetic(
    prefix_run: PrefixRun, forgery: Forgery
) -> None:
    # Arrange
    evidence_set = forge_prefix(prefix_run, forgery)
    deployment = prefix_run.deployment

    # Act
    validate_knowledge_evidence_set(
        evidence_set,
        deployment.pinned_fight_snapshot,
        deployment.evidence_catalog,
        evidence_set.source_capabilities,
    )
    audit_decision_path(evidence_set, deployment.topic_registry, deployment.evidence_catalog)
    replay = replay_evidence_set(evidence_set, deployment)

    # Assert
    assert isinstance(replay, ReplayCompleted)
    assert ReplayDifference(1, "prefix_admission") in replay.differences


def build_bundle_with_large_omitted_record(
    fixture_bundle: FixtureBundle, description_chars: int
) -> FixtureBundle:
    records = []
    for record in fixture_bundle.records:
        if record.cve_id == "CVE-9999-0003":
            description = record.descriptions[0].model_copy(
                update={"value": "[SYNTHETIC] " + "x" * description_chars}
            )
            record = record.model_copy(update={"descriptions": (description,)})
        records.append(record)
    return FixtureBundle(fixture_bundle.manifest, tuple(records), fixture_bundle.evidence)


def test_serialized_prefix_stays_within_cap_plus_existing_fixed_set_overhead(
    fixture_bundle: FixtureBundle,
) -> None:
    # Arrange: measure the existing envelope on a fully admitted run, excluding its
    # variable record/anchor bodies and prefix-only metadata.
    request = build_investigation_request(EXACT_QUERY, "implementation_only")
    whole_set = InvestigationService(
        build_test_deployment(fixture_bundle), DeterministicPlanning(), ignore_checkpoint
    ).investigate(request)
    envelope = whole_set.model_dump(mode="json")
    for name in (
        "implementation_candidates",
        "excluded_implementation_candidates",
        "protocol_context",
        "evidence",
    ):
        envelope[name] = []
    for step in envelope["trajectory"]["steps"]:
        del step["prefix_admission"]
    fixed_overhead = len(canonical_json_bytes(envelope))
    original_sizes = []
    serialized_sizes = []
    admitted_sizes = []

    # Act: only an omitted body's size grows; every run uses the same tight cap.
    for description_chars in (20_000, 358_000, 1_000_000):
        bundle = build_bundle_with_large_omitted_record(fixture_bundle, description_chars)
        deployment = build_test_deployment(bundle)
        execution = deployment.tool_executor.execute(
            build_exact_lookup_call("CVE-9999-0001", "CVE-9999-0002", "CVE-9999-0003"), request
        )
        assert execution.search_response is not None
        prefix = slice_response(execution.search_response, {"candidates": 2})
        cap = measure_response_bytes(prefix)
        bounded_request = request.model_copy(
            update={"budget": request.budget.model_copy(update={"max_context_bytes": cap})}
        )
        evidence_set = InvestigationService(
            deployment, DeterministicPlanning(), ignore_checkpoint
        ).investigate(bounded_request)
        original_sizes.append(execution.context_bytes)
        serialized_sizes.append(len(evidence_set.model_dump_json().encode("utf-8")))
        admitted_sizes.append(evidence_set.trajectory.steps[0].context_bytes)

    # Assert: the envelope allowance is fixed independently of the original bodies.
    assert original_sizes[-1] - original_sizes[0] == 980_000
    assert admitted_sizes == [cap, cap, cap]
    assert max(serialized_sizes) <= cap + fixed_overhead
    assert max(serialized_sizes) - min(serialized_sizes) <= 2
    assert "original_response" not in evidence_set.model_dump_json()


def test_replay_recomputes_the_digest_from_the_complete_response(
    prefix_run: PrefixRun, fixture_bundle: FixtureBundle
) -> None:
    # Arrange: the changed omitted record is never included in the admitted prefix.
    bundle = build_bundle_with_large_omitted_record(fixture_bundle, 358_000)
    deployment = build_test_deployment(bundle)
    original_step = prefix_run.evidence_set.trajectory.steps[0]

    # Act
    replay = replay_evidence_set(prefix_run.evidence_set, deployment)
    rebuilt_set = InvestigationService(
        deployment, DeterministicPlanning(), ignore_checkpoint
    ).investigate(prefix_run.evidence_set.request)
    rebuilt_step = rebuilt_set.trajectory.steps[0]

    # Assert: the retained prefix hash is identical, but its complete-source witness differs.
    assert rebuilt_step.result_sha256 == original_step.result_sha256
    assert rebuilt_step.answer_ids == original_step.answer_ids
    assert (
        rebuilt_step.prefix_admission.original_result_sha256
        != original_step.prefix_admission.original_result_sha256
    )
    assert isinstance(replay, ReplayCompleted)
    assert replay.differences == (ReplayDifference(1, "prefix_admission"),)


@pytest.mark.parametrize("scope", ["mixed", "protocol_context_only"])
def test_topic_prefix_can_omit_an_entire_later_list(
    fixture_bundle: FixtureBundle, scope: str
) -> None:
    # Arrange
    deployment = build_test_deployment(fixture_bundle, review_status=ReviewStatus.REVIEWED)
    request = build_investigation_request("5gaka", scope)
    execution = deployment.tool_executor.execute(build_topic_call(), request)
    assert execution.topic_response is not None
    prefix = slice_response(
        execution.topic_response,
        {
            "implementation_candidates": int(scope == "mixed"),
            "protocol_context": int(scope == "protocol_context_only"),
            "excluded_implementation_candidates": 0,
        },
    )
    request = request.model_copy(
        update={
            "budget": request.budget.model_copy(
                update={"max_context_bytes": measure_response_bytes(prefix)}
            )
        }
    )

    # Act
    evidence_set = InvestigationService(
        deployment, DeterministicPlanning(), ignore_checkpoint
    ).investigate(request)
    replay = replay_evidence_set(evidence_set, deployment)

    # Assert
    step = evidence_set.trajectory.steps[0]
    assert step.admission is StepAdmission.ADMITTED_PREFIX
    assert len(step.answer_ids) == 1
    assert evidence_set.trajectory.budget_used.breach is None
    assert replay == ReplayCompleted(())


def test_contract_rejects_original_response_bodies_in_a_prefix_witness(
    prefix_run: PrefixRun,
) -> None:
    # Arrange
    serialized_set = prefix_run.evidence_set.model_dump(mode="json")
    serialized_set["trajectory"]["steps"][0]["prefix_admission"]["original_response"] = (
        prefix_run.original_search.model_dump(mode="json")
    )
    schema = json.loads((REPOSITORY_SCHEMA_DIR / "knowledge_evidence_set.schema.json").read_text())

    # Act
    is_schema_valid = Draft202012Validator(schema).is_valid(serialized_set)

    # Assert
    assert is_schema_valid is False
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        KnowledgeEvidenceSet.model_validate(serialized_set)


def test_replay_rejects_a_consistent_byte_forgery_after_merging_loses_call_metadata(
    fixture_bundle: FixtureBundle,
) -> None:
    # Arrange: the search sees a CVE already returned by the lookup; answer assembly
    # keeps the lookup's candidate, including its channel hits, rather than the search's.
    deployment = build_test_deployment(fixture_bundle)
    request = build_investigation_request("CVE-9999-0001 democorp", "implementation_only")
    first_call = build_exact_lookup_call("CVE-9999-0001")
    second_call = build_search_call("democorp")
    first_execution = deployment.tool_executor.execute(first_call, request)
    second_execution = deployment.tool_executor.execute(second_call, request)
    assert second_execution.search_response is not None
    prefix = slice_response(second_execution.search_response, {"candidates": 1})
    request = request.model_copy(
        update={
            "budget": request.budget.model_copy(
                update={
                    "max_context_bytes": first_execution.context_bytes
                    + measure_response_bytes(prefix)
                }
            )
        }
    )
    planner = ScriptedModelPort(
        [build_plan_reply(first_call.model_dump(mode="json"), second_call.model_dump(mode="json"))]
    )
    evidence_set = InvestigationService(
        deployment, plan_with(planner), ignore_checkpoint
    ).investigate(request)
    forged_set = forge_consistent_charge(evidence_set, 2)

    # Act
    validate_knowledge_evidence_set(
        forged_set,
        deployment.pinned_fight_snapshot,
        deployment.evidence_catalog,
        forged_set.source_capabilities,
    )
    audit_decision_path(forged_set, deployment.topic_registry, deployment.evidence_catalog)
    replay = replay_evidence_set(forged_set, deployment)

    # Assert
    assert evidence_set.trajectory.steps[1].admission is StepAdmission.ADMITTED_PREFIX
    assert evidence_set.implementation_candidates[0].found_by_steps == (1, 2)
    assert isinstance(replay, ReplayCompleted)
    assert ReplayDifference(2, "context_bytes") in replay.differences
    assert ReplayDifference(2, "prefix_admission") in replay.differences
