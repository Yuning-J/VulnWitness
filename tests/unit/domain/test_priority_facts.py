"""Fact provenance distinguishes unavailable evidence from a negative snapshot result."""

import pytest
from pydantic import ValidationError

from tests.support.priority import REFERENCE_DATE, build_priority_inputs
from vulnwitness.domain.priority_facts import HighGradeFact, KevFact


@pytest.mark.parametrize(
    ("status", "retrieved_at"),
    [("not_listed_in_snapshot", None), ("listed", REFERENCE_DATE), ("unknown", REFERENCE_DATE)],
    ids=["negative-needs-date", "listed-no-negative-date", "unknown-no-negative-date"],
)
def test_kev_snapshot_date_is_required_exactly_for_negative_snapshot_facts(
    status: str, retrieved_at: object
) -> None:
    with pytest.raises(ValidationError, match="snapshot retrieval date"):
        KevFact(value=status, evidence_ids=(), snapshot_retrieved_at=retrieved_at)


def test_negative_kev_fact_keeps_snapshot_date_and_evidence() -> None:
    _, _, facts = build_priority_inputs()

    assert facts.kev.value == "not_listed_in_snapshot"
    assert facts.kev.snapshot_retrieved_at == REFERENCE_DATE
    assert facts.kev.evidence_ids


@pytest.mark.parametrize(
    ("grade", "authorities"),
    [
        ("present", ()),
        ("absent", ("CNVD",)),
        ("none_available", ("NVD",)),
        ("present", ("CNA",)),
        ("present", ("CNVD", "CNVD")),
    ],
    ids=[
        "present-needs-authority",
        "absent-no-trigger",
        "no-grade-no-trigger",
        "cna-never-substitutes-for-nvd",
        "duplicate-authority",
    ],
)
def test_high_grade_fact_rejects_missing_or_unsupported_triggering_authorities(
    grade: str, authorities: tuple[str, ...]
) -> None:
    with pytest.raises(ValidationError):
        HighGradeFact(value=grade, evidence_ids=(), triggering_authorities=authorities)


def test_all_unknowns_are_listed_in_fact_order() -> None:
    _, _, facts = build_priority_inputs("unknown", "unknown", "unknown", "none_available")

    assert facts.list_unknown_facts() == ("applicability", "system_category", "kev", "high_grade")
