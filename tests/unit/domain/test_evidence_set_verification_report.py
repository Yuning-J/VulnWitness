"""A verification report carries exactly the findings its verdict names."""

import pytest
from pydantic import ValidationError

from cve_kgrag.domain.evidence_set_verification_report import (
    MAX_REPORTED_VIOLATIONS,
    ReportedDifference,
    VerificationReport,
    VerificationVerdict,
)

A_VIOLATION = ("schema_version: Field required",)
A_DIFFERENCE = (ReportedDifference(step_index=1, part="answer_ids"),)


@pytest.mark.parametrize(
    ("verdict", "violations", "differences"),
    [
        (VerificationVerdict.VERIFIED, (), ()),
        (VerificationVerdict.MALFORMED, A_VIOLATION, ()),
        (VerificationVerdict.INVALID, A_VIOLATION, ()),
        (VerificationVerdict.REPLAY_DIFFERS, (), A_DIFFERENCE),
        (VerificationVerdict.REPLAY_TIMED_OUT, (), ()),
    ],
    ids=["verified", "malformed", "invalid", "replay_differs", "replay_timed_out"],
)
def test_report_with_the_findings_its_verdict_names_is_accepted(
    verdict: VerificationVerdict,
    violations: tuple[str, ...],
    differences: tuple[ReportedDifference, ...],
) -> None:
    report = VerificationReport(verdict=verdict, violations=violations, differences=differences)

    assert report.verdict is verdict


@pytest.mark.parametrize(
    ("verdict", "violations", "differences"),
    [
        (VerificationVerdict.VERIFIED, A_VIOLATION, ()),
        (VerificationVerdict.VERIFIED, (), A_DIFFERENCE),
        (VerificationVerdict.MALFORMED, (), ()),
        (VerificationVerdict.INVALID, A_VIOLATION, A_DIFFERENCE),
        (VerificationVerdict.REPLAY_DIFFERS, (), ()),
        (VerificationVerdict.REPLAY_DIFFERS, A_VIOLATION, A_DIFFERENCE),
        (VerificationVerdict.REPLAY_TIMED_OUT, A_VIOLATION, ()),
    ],
    ids=[
        "verified_with_a_violation",
        "verified_with_a_difference",
        "malformed_without_a_violation",
        "invalid_with_a_difference",
        "replay_differs_without_a_difference",
        "replay_differs_with_a_violation",
        "timed_out_with_a_violation",
    ],
)
def test_report_whose_findings_contradict_its_verdict_is_rejected(
    verdict: VerificationVerdict,
    violations: tuple[str, ...],
    differences: tuple[ReportedDifference, ...],
) -> None:
    with pytest.raises(ValidationError):
        VerificationReport(verdict=verdict, violations=violations, differences=differences)


def test_report_with_more_than_the_capped_violations_is_rejected() -> None:
    too_many_violations = A_VIOLATION * (MAX_REPORTED_VIOLATIONS + 1)

    with pytest.raises(ValidationError):
        VerificationReport(verdict=VerificationVerdict.INVALID, violations=too_many_violations)


def test_difference_with_step_index_zero_is_rejected() -> None:
    with pytest.raises(ValidationError):
        ReportedDifference(step_index=0, part="answer_ids")
