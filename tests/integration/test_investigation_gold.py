"""Investigations over the packaged card, FiGHT excerpt and CVE fixture follow the
hand-labelled gold trajectories."""

from typing import Any

import pytest

from tests.support.collect import list_technique_ids
from tests.support.investigation import (
    build_test_investigation_service,
    label_row,
    list_excluded_ids,
    list_transitions,
    list_warning_codes,
    load_gold_rows,
)
from vulnwitness.adapters.fixture.synthetic_fixture import FixtureBundle
from vulnwitness.application.topic_context import PROTOCOL_EXCLUSION_REASON
from vulnwitness.domain.investigation import InvestigationRequest, KnowledgeEvidenceSet
from vulnwitness.domain.taxonomy import KnowledgeScope

GOLD_ROWS = load_gold_rows()


def list_rows_with_cves_or_claims() -> list[dict[str, Any]]:
    """The rows whose labelled answer holds a CVE, an excluded CVE or a claim."""
    rows_with_cves_or_claims: list[dict[str, Any]] = []
    for row in GOLD_ROWS:
        expected = row["expected"]
        if (
            expected["implementation_candidates"]
            or expected["excluded_implementation_candidates"]
            or expected["claims"]
        ):
            rows_with_cves_or_claims.append(row)
    return rows_with_cves_or_claims


def investigate_row(fixture_bundle: FixtureBundle, row: dict[str, Any]) -> KnowledgeEvidenceSet:
    service = build_test_investigation_service(fixture_bundle, fight=row["sources"]["mitre_fight"])
    return service.investigate(InvestigationRequest.model_validate(row["request"]))


def describe_steps(evidence_set: KnowledgeEvidenceSet, gold_steps: list[Any]) -> list[Any]:
    """Each step in the gold row's shape; ``channels`` only where the row labels them."""
    labelled_channel_positions: set[int] = set()
    for position, gold_step in enumerate(gold_steps):
        if "channels" in gold_step:
            labelled_channel_positions.add(position)
    described_steps: list[dict[str, Any]] = []
    for position, step in enumerate(evidence_set.trajectory.steps):
        described_step: dict[str, Any] = {
            "round": step.round_number,
            "tool": step.call.tool.value,
            "reason": step.reason.value,
            "charged_tool_calls": step.charged_tool_calls,
            "admission": step.admission.value,
            "status": None if step.status is None else step.status.value,
        }
        if position in labelled_channel_positions:
            channels: list[str] = []
            for channel in step.channels_executed:
                channels.append(channel.value)
            described_step["channels"] = channels
        described_steps.append(described_step)
    return described_steps


def describe_implementation_candidates(
    evidence_set: KnowledgeEvidenceSet,
) -> list[dict[str, str | None]]:
    labels: list[dict[str, str | None]] = []
    for investigation_candidate in evidence_set.implementation_candidates:
        relevance = investigation_candidate.relevance
        labels.append(
            {
                "cve_id": investigation_candidate.candidate.record.cve_id,
                "tier": None if relevance is None else relevance.tier.value,
            }
        )
    return labels


def describe_applicability(evidence_set: KnowledgeEvidenceSet) -> list[dict[str, str]]:
    labels: list[dict[str, str]] = []
    for applicability in evidence_set.product_applicability:
        labels.append({"product": applicability.product, "status": applicability.status.value})
    return labels


def list_claim_ids(evidence_set: KnowledgeEvidenceSet) -> list[str]:
    claim_ids: list[str] = []
    for claim in evidence_set.claims:
        claim_ids.append(claim.claim_id)
    return claim_ids


@pytest.mark.parametrize("row", GOLD_ROWS, ids=label_row)
def test_trajectory_matches_the_labelled_decisions(
    fixture_bundle: FixtureBundle, row: dict[str, Any]
) -> None:
    expected = row["expected"]

    evidence_set = investigate_row(fixture_bundle, row)

    assert evidence_set.interpretation.intent.value == expected["intent"]
    assert list_transitions(evidence_set) == expected["transitions"]
    assert describe_steps(evidence_set, expected["steps"]) == expected["steps"]
    assert evidence_set.stop_reason.value == expected["stop_reason"]
    assert evidence_set.status.value == expected["status"]
    assert evidence_set.trajectory.budget_used.tool_calls == expected["tool_calls"]
    assert evidence_set.trajectory.budget_used.rounds == expected["rounds"]


@pytest.mark.parametrize("row", GOLD_ROWS, ids=label_row)
def test_answer_matches_the_labelled_sections(
    fixture_bundle: FixtureBundle, row: dict[str, Any]
) -> None:
    expected = row["expected"]

    evidence_set = investigate_row(fixture_bundle, row)

    assert (
        describe_implementation_candidates(evidence_set) == (expected["implementation_candidates"])
    )
    assert list_excluded_ids(evidence_set) == expected["excluded_implementation_candidates"]
    for excluded_candidate in evidence_set.excluded_implementation_candidates:
        assert excluded_candidate.reason == PROTOCOL_EXCLUSION_REASON
    assert list_technique_ids(evidence_set.protocol_context) == expected["protocol_context"]
    assert list_claim_ids(evidence_set) == expected["claims"]
    assert describe_applicability(evidence_set) == expected["applicability"]
    assert list_warning_codes(evidence_set) == expected["warning_codes"]


@pytest.mark.parametrize("row", list_rows_with_cves_or_claims(), ids=label_row)
def test_every_cve_stays_implementation_evidence_that_establishes_no_protocol_flaw(
    fixture_bundle: FixtureBundle, row: dict[str, Any]
) -> None:
    evidence_set = investigate_row(fixture_bundle, row)

    cve_records = []
    for investigation_candidate in evidence_set.implementation_candidates:
        cve_records.append(investigation_candidate.candidate.record)
    for excluded_candidate in evidence_set.excluded_implementation_candidates:
        cve_records.append(excluded_candidate.candidate.candidate.record)
    assert cve_records or evidence_set.claims
    for record in cve_records:
        assert record.protocol_design_claim == "not_established"
        assert record.formal_seed_eligible is False
    for claim in evidence_set.claims:
        assert claim.scope is not KnowledgeScope.FORMAL_PROTOCOL_FINDING
        assert "IGNORE" not in claim.statement
