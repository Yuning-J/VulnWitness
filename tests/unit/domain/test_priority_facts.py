"""Fact provenance distinguishes unavailable evidence from a negative snapshot result."""

import pytest
from pydantic import ValidationError

from tests.support.priority import REFERENCE_DATE, build_priority_inputs
from vulnwitness.domain.priority_facts import (
    MAX_EXPLOIT_REFERENCE_URLS,
    HighGradeFact,
    KevFact,
    PublicExploitFact,
)


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


@pytest.mark.parametrize(
    ("status", "urls", "evidence", "message"),
    [
        ("referenced", (), ("ev:1234567890abcdef12345678",), "reference URLs"),
        (
            "not_referenced_in_record",
            ("https://x.example/1",),
            ("ev:1234567890abcdef12345678",),
            "reference URLs",
        ),
        ("unknown", ("https://x.example/1",), (), "reference URLs"),
        (
            "referenced",
            ("https://x.example/1", "https://x.example/1"),
            ("ev:1234567890abcdef12345678",),
            "unique",
        ),
        ("not_referenced_in_record", (), (), "record's evidence"),
    ],
    ids=[
        "referenced-needs-urls",
        "negative-has-no-urls",
        "unknown-has-no-urls",
        "urls-unique",
        "known-needs-evidence",
    ],
)
def test_public_exploit_fact_keeps_urls_and_evidence_consistent(
    status: str, urls: tuple[str, ...], evidence: tuple[str, ...], message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        PublicExploitFact(value=status, evidence_ids=evidence, reference_urls=urls)


def test_public_exploit_fact_caps_reference_urls() -> None:
    urls = tuple(f"https://x.example/{index}" for index in range(MAX_EXPLOIT_REFERENCE_URLS + 1))

    with pytest.raises(ValidationError):
        PublicExploitFact(
            value="referenced", evidence_ids=("ev:1234567890abcdef12345678",), reference_urls=urls
        )
