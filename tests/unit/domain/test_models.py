"""Contract-model invariants enforced at construction."""

import re
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from tests.support.builders import build_anchor, build_cve_record
from vulnwitness.domain.evidence import EVIDENCE_ID_PATTERN, EvidenceAnchor, derive_evidence_id
from vulnwitness.domain.search import RetrievalMatch, RetrievalOutcome
from vulnwitness.domain.taxonomy import (
    AssertionKind,
    BackendFailure,
    BackendStatus,
    KnowledgeScope,
    SourceType,
    TrustLevel,
)


def test_inferred_anchor_without_inference_method_is_rejected() -> None:
    with pytest.raises(ValidationError, match="inference_method"):
        build_anchor(assertion_kind=AssertionKind.INFERRED)


def test_asserted_anchor_with_inference_method_is_rejected() -> None:
    with pytest.raises(ValidationError, match="inference_method"):
        build_anchor(inference_method="cwe-capec-mapping")


def test_inferred_anchor_with_inference_method_is_accepted() -> None:
    anchor = build_anchor(
        assertion_kind=AssertionKind.INFERRED, inference_method="cwe-capec-mapping"
    )

    assert anchor.inference_method == "cwe-capec-mapping"


def test_derive_evidence_id_is_stable_for_the_same_anchor() -> None:
    first = derive_evidence_id(build_anchor())
    again = derive_evidence_id(build_anchor())

    assert first == again
    assert re.fullmatch(EVIDENCE_ID_PATTERN, first)


# One changed value for every anchor field the evidence ID binds, from an inferred base
# anchor so ``assertion_kind`` and ``inference_method`` can each change on their own.
PROVENANCE_CHANGES: list[tuple[str, Any]] = [
    ("source_name", "other-source"),
    ("source_type", SourceType.NVD_API_2),
    ("authoritative_record_id", "CVE-9999-0002"),
    ("source_uri", "https://attacker.invalid/forged"),
    ("source_version", "2"),
    ("retrieved_at", datetime(2026, 10, 14, tzinfo=UTC)),
    ("content_sha256", "1" * 64),
    ("locator", "records#/1"),
    ("excerpt", "FORGED SOURCE EXCERPT"),
    ("scope", KnowledgeScope.PROTOCOL_THREAT_CONTEXT),
    ("assertion_kind", AssertionKind.ASSERTED),
    ("inference_method", "other-method"),
    ("license_or_terms_ref", "proprietary"),
    ("trust_level", TrustLevel.AUTHORITATIVE),
]


def list_changed_field_names() -> list[str]:
    changed_field_names: list[str] = []
    for field_name, _ in PROVENANCE_CHANGES:
        changed_field_names.append(field_name)
    return changed_field_names


def build_inferred_anchor() -> EvidenceAnchor:
    return build_anchor(
        source_version="1",
        excerpt="[SYNTHETIC] test record",
        assertion_kind=AssertionKind.INFERRED,
        inference_method="cwe-capec-mapping",
    )


def test_provenance_changes_cover_every_field_but_the_evidence_id() -> None:
    changed_field_names = list_changed_field_names()

    assert sorted(changed_field_names) == sorted(set(EvidenceAnchor.model_fields) - {"evidence_id"})


@pytest.mark.parametrize(
    ("field_name", "changed_value"),
    PROVENANCE_CHANGES,
    ids=list_changed_field_names(),
)
def test_changing_any_provenance_field_changes_the_evidence_id(
    field_name: str, changed_value: Any
) -> None:
    anchor = build_inferred_anchor()

    changed_anchor = anchor.model_copy(update={field_name: changed_value})

    assert derive_evidence_id(changed_anchor) != derive_evidence_id(anchor)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("formal_seed_eligible", True),
        ("protocol_design_claim", "established"),
        ("record_kind", "fight_technique"),
        ("cve_id", "CVE-99-1"),
        ("cwe_ids", ["CWE-abc"]),
        ("evidence_ids", []),
        ("severity", "CRITICAL"),
    ],
    ids=[
        "formal_seed_eligible",
        "protocol_design_claim",
        "record_kind",
        "malformed_cve_id",
        "malformed_cwe_id",
        "no_evidence",
        "unknown_field",
    ],
)
def test_cve_record_rejects_value_breaking_invariant(field_name: str, value: object) -> None:
    with pytest.raises(ValidationError):
        build_cve_record(**{field_name: value})


def test_cve_record_defaults_to_not_established_and_not_seed_eligible() -> None:
    record = build_cve_record()

    assert record.record_kind == "cve"
    assert record.protocol_design_claim == "not_established"
    assert record.formal_seed_eligible is False


def test_cve_record_lists_fields_no_source_supplied() -> None:
    record = build_cve_record()

    assert record.find_missing_fields() == ("cvss", "cwe_ids", "affected", "published")


@pytest.mark.parametrize(
    "version_range",
    [{}, {"exact": "1.0", "end_excluding": "2.0"}],
    ids=["no_bound", "exact_with_bound"],
)
def test_version_range_without_single_consistent_bound_is_rejected(
    version_range: dict[str, str],
) -> None:
    affected = [
        {
            "vendor": "democorp",
            "product": "demo",
            "status": "affected",
            "version_ranges": [version_range],
        }
    ]

    with pytest.raises(ValidationError, match="version"):
        build_cve_record(affected=affected)


def test_cve_record_keeps_multiple_cvss_versions_and_scorers() -> None:
    cvss = [
        {"version": "3.1", "vector_string": "CVSS:3.1/AV:N", "base_score": 5.4, "scorer": "a"},
        {"version": "4.0", "vector_string": "CVSS:4.0/AV:N", "base_score": 5.1, "scorer": "b"},
    ]

    record = build_cve_record(cvss=cvss)

    assert record.cvss[0].version == "3.1"
    assert record.cvss[0].scorer == "a"
    assert record.cvss[1].version == "4.0"
    assert record.cvss[1].scorer == "b"


def build_retrieval_match(cve_id: str = "CVE-9999-0001", score: float = 1.0) -> RetrievalMatch:
    return RetrievalMatch(
        cve_id=cve_id, score=score, matched_fields=("description",), matched_terms=("x",)
    )


@pytest.mark.parametrize(
    ("outcome_fields", "violation"),
    [
        (
            {"status": BackendStatus.OK, "failure": BackendFailure.INDEX_INCOMPLETE},
            "cannot carry a failure",
        ),
        (
            {
                "status": BackendStatus.ERROR,
                "failure": BackendFailure.SEARCH_FAILED,
                "matches": [build_retrieval_match()],
            },
            "cannot carry matches",
        ),
        ({"status": BackendStatus.UNAVAILABLE}, "must carry its failure"),
        (
            {
                "status": BackendStatus.OK,
                "matches": [build_retrieval_match(), build_retrieval_match()],
            },
            "more than once",
        ),
        (
            {
                "status": BackendStatus.ERROR,
                "failure": BackendFailure.SEARCH_FAILED,
                "unindexed_terms": ["srsran"],
            },
            "cannot name unindexed terms",
        ),
        ({"status": BackendStatus.OK, "unindexed_terms": ["zz", "aa"]}, "once each, sorted"),
        ({"status": BackendStatus.OK, "unindexed_terms": ["aa", "aa"]}, "once each, sorted"),
    ],
    ids=[
        "ok_with_failure",
        "failure_with_matches",
        "failure_without_reason",
        "duplicate_match",
        "failure_with_unindexed_terms",
        "unsorted_unindexed_terms",
        "repeated_unindexed_term",
    ],
)
def test_inconsistent_backend_outcome_is_rejected(
    outcome_fields: dict[str, object], violation: str
) -> None:
    with pytest.raises(ValidationError, match=violation):
        RetrievalOutcome.model_validate(outcome_fields)


@pytest.mark.parametrize("score", [float("inf"), float("nan")], ids=["infinite", "nan"])
def test_non_finite_match_score_is_rejected(score: float) -> None:
    with pytest.raises(ValidationError):
        build_retrieval_match(score=score)


def test_cve_id_with_non_ascii_digits_is_rejected() -> None:
    with pytest.raises(ValidationError):
        build_cve_record(cve_id="CVE-٢٠٢٤-١٢٣٤")
