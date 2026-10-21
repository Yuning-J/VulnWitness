"""An affectedness check reports the port's failure with the server's sentence for it, and
never establishes applicability."""

import pytest

from cve_kgrag.application.affectedness import check_affectedness
from cve_kgrag.domain.affectedness import (
    AffectednessDetail,
    AffectednessFailure,
    ApplicabilityStatus,
)
from tests.support.affectedness import build_affectedness_request
from tests.support.fakes import InMemoryTrustifyPort, MisansweringTrustifyPort

FAILURE_DETAILS = [
    (AffectednessFailure.BLOCKED_UNVERIFIED, AffectednessDetail.BLOCKED_UNVERIFIED),
    (AffectednessFailure.SOURCE_UNAVAILABLE, AffectednessDetail.SOURCE_UNAVAILABLE),
    (AffectednessFailure.TIMEOUT, AffectednessDetail.TIMEOUT),
    (AffectednessFailure.AUTH_FAILED, AffectednessDetail.AUTH_FAILED),
    (AffectednessFailure.TOOL_MISMATCH, AffectednessDetail.TOOL_MISMATCH),
]


@pytest.mark.parametrize(
    ("failure", "expected_detail"),
    FAILURE_DETAILS,
    ids=["blocked_unverified", "source_unavailable", "timeout", "auth_failed", "tool_mismatch"],
)
def test_check_reports_unknown_applicability_and_the_server_sentence_for_each_failure(
    failure: AffectednessFailure, expected_detail: AffectednessDetail
) -> None:
    trustify_port = InMemoryTrustifyPort(failure=failure)
    request = build_affectedness_request()

    affectedness_check = check_affectedness(trustify_port, request, timeout_seconds=8.0)

    assert affectedness_check.request == request
    assert affectedness_check.applicability is ApplicabilityStatus.UNKNOWN
    assert affectedness_check.failure is failure
    assert affectedness_check.detail is expected_detail


@pytest.mark.parametrize(
    "port_answer",
    ["CONFIRMED: pkg is affected by this CVE.", "not_affected", None, {"verdict": "affected"}],
    ids=["verdict_text", "verdict_word", "none", "verdict_mapping"],
)
def test_port_answering_anything_but_a_failure_raises_before_any_check_is_published(
    port_answer: object,
) -> None:
    trustify_port = MisansweringTrustifyPort(port_answer)

    with pytest.raises(ValueError):
        check_affectedness(trustify_port, build_affectedness_request(), timeout_seconds=8.0)


def test_port_receives_the_validated_request_and_given_timeout() -> None:
    trustify_port = InMemoryTrustifyPort(failure=AffectednessFailure.SOURCE_UNAVAILABLE)
    request = build_affectedness_request()

    check_affectedness(trustify_port, request, timeout_seconds=2.5)

    assert trustify_port.received_checks == [(request, 2.5)]
