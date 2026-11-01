"""A verification report carries exactly the findings its verdict names."""

import pytest
from pydantic import ValidationError

from vulnwitness.domain.evidence_set_verification_report import (
    MAX_REPORTED_VIOLATIONS,
    MAX_VIOLATION_CHARS,
    TRUNCATION_MARK,
    ReportedDifference,
    VerificationReport,
    VerificationVerdict,
    bound_violations,
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


@pytest.mark.parametrize(
    "violation", ["", "x" * (MAX_VIOLATION_CHARS + 1)], ids=["empty", "overlong"]
)
def test_report_with_an_empty_or_overlong_violation_is_rejected(violation: str) -> None:
    with pytest.raises(ValidationError):
        VerificationReport(verdict=VerificationVerdict.INVALID, violations=(violation,))


def test_bound_violations_keeps_the_capped_number_of_violations_in_order() -> None:
    violations: list[str] = []
    for violation_number in range(MAX_REPORTED_VIOLATIONS + 50):
        violations.append(f"violation {violation_number}")

    bounded_violations = bound_violations(violations)

    assert bounded_violations == tuple(violations[:MAX_REPORTED_VIOLATIONS])


def test_bound_violations_cuts_an_overlong_violation_to_the_cap_with_a_mark() -> None:
    overlong_violation = "x" * (MAX_VIOLATION_CHARS * 3)

    (bounded_violation,) = bound_violations([overlong_violation])

    assert len(bounded_violation) == MAX_VIOLATION_CHARS
    assert bounded_violation.endswith(TRUNCATION_MARK)
    VerificationReport(verdict=VerificationVerdict.INVALID, violations=(bounded_violation,))


def test_bound_violations_keeps_a_violation_at_the_cap_whole() -> None:
    violation_at_the_cap = "x" * MAX_VIOLATION_CHARS

    assert bound_violations([violation_at_the_cap]) == (violation_at_the_cap,)


def test_difference_with_step_index_zero_is_rejected() -> None:
    with pytest.raises(ValidationError):
        ReportedDifference(step_index=0, part="answer_ids")
