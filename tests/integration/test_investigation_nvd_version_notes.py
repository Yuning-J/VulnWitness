"""Version notes annotate admitted fixture candidates without serving affectedness."""

import json

import pytest

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.domain.evidence_catalog import EvidenceCatalog
from cve_kgrag.domain.investigation import KnowledgeEvidenceSet
from cve_kgrag.domain.investigation_validation import validate_knowledge_evidence_set
from cve_kgrag.domain.nvd_version_note import NvdVersionHit, build_nvd_version_note
from cve_kgrag.domain.threat_context import KnownFightSnapshot
from cve_kgrag.domain.validation import EvidenceValidationError
from tests.support.investigation import reseal_evidence_set
from tests.support.investigation_runs import (
    investigate,
    run_exact_id,
    run_gateway_version_question,
)


def test_version_question_keeps_named_retrieval_needs_and_stop_with_three_note_outcomes(
    fixture_bundle: FixtureBundle,
) -> None:
    # Arrange
    expected_cve_ids = ["CVE-9999-0001", "CVE-9999-0002", "CVE-9999-0003"]

    # Act
    evidence_set = run_gateway_version_question(fixture_bundle)

    # Assert
    assert evidence_set.interpretation.affectedness_mentions == ("democorp 2.0",)
    candidate_ids = []
    note_outcomes = []
    for candidate in evidence_set.implementation_candidates:
        candidate_ids.append(candidate.candidate.record.cve_id)
        assert candidate.nvd_version_notes is not None
        assert len(candidate.nvd_version_notes) == 1
        note_outcomes.append(candidate.nvd_version_notes[0].outcome)
    assert candidate_ids == expected_cve_ids
    assert note_outcomes == ["hit", "no_hit", "unknown"]
    assert len(evidence_set.trajectory.steps) == 1
    step = evidence_set.trajectory.steps[0]
    assert step.call.tool == "cve_exact_lookup"
    assert step.answer_ids == tuple(expected_cve_ids)
    assert evidence_set.trajectory.budget_used.tool_calls == 1
    assert evidence_set.trajectory.budget_used.rounds == 1
    assert evidence_set.stop_reason == "source_unavailable"
    assert evidence_set.status == "partial"
    needs = []
    for need in evidence_set.coverage.needs:
        needs.append((need.kind, need.subject, need.outcome))
    assert needs == [
        ("named_cve", "CVE-9999-0001", "found"),
        ("named_cve", "CVE-9999-0002", "found"),
        ("named_cve", "CVE-9999-0003", "found"),
        ("affectedness", "democorp 2.0", "source_unavailable"),
    ]
    assert len(evidence_set.product_applicability) == 1
    assert evidence_set.product_applicability[0].status == "unknown"


def test_note_field_is_absent_from_serialized_candidates_without_mentions(
    fixture_bundle: FixtureBundle,
) -> None:
    # Arrange
    evidence_set = run_exact_id(fixture_bundle)

    # Act
    evidence_json = json.loads(evidence_set.model_dump_json())

    # Assert
    assert evidence_set.interpretation.affectedness_mentions == ()
    assert set(evidence_json["implementation_candidates"][0]) == {
        "rank",
        "candidate",
        "relevance",
        "found_by_steps",
    }


def test_multiple_mentions_keep_one_note_each_in_interpretation_order(
    fixture_bundle: FixtureBundle,
) -> None:
    # Arrange
    query = "Are democorp 2.0 and f5gc 3.2 affected by CVE-9999-0001 and CVE-9999-0003?"

    # Act
    evidence_set = investigate(fixture_bundle, query, "implementation_only")

    # Assert
    assert evidence_set.interpretation.affectedness_mentions == ("democorp 2.0", "f5gc 3.2")
    for candidate in evidence_set.implementation_candidates:
        assert candidate.nvd_version_notes is not None
        mentions = []
        for note in candidate.nvd_version_notes:
            mentions.append(note.mention)
        assert mentions == ["democorp 2.0", "f5gc 3.2"]
    assert KnowledgeEvidenceSet.model_validate_json(evidence_set.model_dump_json()) == evidence_set


@pytest.mark.parametrize(
    "forgery", ["false_hit", "wrong_wording", "missing_notes", "extra_note", "malformed_mention"]
)
def test_validator_rejects_forged_version_annotations_even_when_resealed(
    fixture_bundle: FixtureBundle,
    pinned_fight_snapshot: KnownFightSnapshot,
    packaged_evidence_catalog: EvidenceCatalog,
    forgery: str,
) -> None:
    # Arrange
    evidence_set = run_gateway_version_question(fixture_bundle)
    candidates = list(evidence_set.implementation_candidates)
    candidate_index = 1 if forgery == "false_hit" else 0
    candidate = candidates[candidate_index]
    assert candidate.nvd_version_notes is not None
    notes = candidate.nvd_version_notes
    if forgery == "false_hit":
        entry = candidate.candidate.record.affected[0]
        notes = (
            NvdVersionHit(
                mention="democorp 2.0",
                wording=(
                    "Version 2.0 matches an NVD CPE version condition for democorp:demo_gateway; "
                    "the full configuration and environment conditions were not evaluated."
                ),
                matched_entry=entry,
                matched_condition=entry.version_ranges[0],
            ),
        )
    elif forgery == "wrong_wording":
        notes = (notes[0].model_copy(update={"wording": "This version is affected."}),)
    elif forgery == "extra_note":
        notes = (*notes, build_nvd_version_note(candidate.candidate.record, "democorp 1.0"))
    elif forgery == "malformed_mention":
        interpretation = evidence_set.interpretation.model_copy(
            update={"affectedness_mentions": ("democorp",)}
        )
        evidence_set = evidence_set.model_copy(update={"interpretation": interpretation})
    candidates[candidate_index] = candidate.model_copy(
        update={"nvd_version_notes": None if forgery == "missing_notes" else notes}
    )
    forged_set = reseal_evidence_set(
        evidence_set,
        implementation_candidates=tuple(candidates),
    )

    # Act
    with pytest.raises(EvidenceValidationError) as rejected_note:
        validate_knowledge_evidence_set(
            forged_set,
            pinned_fight_snapshot,
            packaged_evidence_catalog,
            evidence_set.source_capabilities,
        )

    # Assert
    assert any("NVD version notes" in violation for violation in rejected_note.value.violations)
