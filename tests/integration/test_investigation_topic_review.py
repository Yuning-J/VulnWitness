"""A topic's review state governs sufficiency, independently of result truncation."""

import pytest

from tests.support.investigation import (
    build_investigation_request,
    build_test_investigation_service,
)
from vulnwitness.adapters.fixture.synthetic_fixture import FixtureBundle
from vulnwitness.domain.investigation import (
    DecisionBasis,
    InvestigationWarningCode,
    NeedOutcome,
    StopReason,
)
from vulnwitness.domain.taxonomy import ResultStatus
from vulnwitness.domain.topic import ReviewStatus


@pytest.mark.parametrize("scope", ["implementation_only", "protocol_context_only", "mixed"])
@pytest.mark.parametrize("limit", [1, 20], ids=["truncated", "uncapped_fixture"])
@pytest.mark.parametrize("review_status", list(ReviewStatus))
def test_only_reviewed_topic_evidence_supports_sufficiency(
    fixture_bundle: FixtureBundle, scope: str, limit: int, review_status: ReviewStatus
) -> None:
    service = build_test_investigation_service(fixture_bundle, review_status=review_status)
    evidence_set = service.investigate(
        build_investigation_request("5G-AKA", scope, budget={"max_results_per_call": limit})
    )

    assert evidence_set.implementation_candidates or evidence_set.protocol_context
    if review_status is ReviewStatus.REVIEWED:
        assert evidence_set.stop_reason is StopReason.SUFFICIENT
        assert evidence_set.status is ResultStatus.OK
        assert all(need.outcome is NeedOutcome.FOUND for need in evidence_set.coverage.needs)
    else:
        assert evidence_set.stop_reason is StopReason.NEEDS_UNMET
        assert evidence_set.status is ResultStatus.PARTIAL
        assert evidence_set.coverage.basis in {
            DecisionBasis.NO_REFINEMENT_AVAILABLE,
            DecisionBasis.NEEDS_OPEN_AFTER_REFINEMENT,
        }
        assert all(
            need.outcome is NeedOutcome.MATCHES_UNASSESSED for need in evidence_set.coverage.needs
        )
        assert any(
            warning.code is InvestigationWarningCode.TOPIC_PENDING_REVIEW
            for warning in evidence_set.warnings
        )
    if limit == 1:
        assert any(
            warning.code is InvestigationWarningCode.ANSWER_TRUNCATED
            for warning in evidence_set.warnings
        )


@pytest.mark.parametrize("review_status", list(ReviewStatus))
def test_exact_lookup_sufficiency_does_not_depend_on_topic_review(
    fixture_bundle: FixtureBundle, review_status: ReviewStatus
) -> None:
    service = build_test_investigation_service(fixture_bundle, review_status=review_status)
    evidence_set = service.investigate(build_investigation_request("CVE-9999-0001", "mixed"))

    assert evidence_set.stop_reason is StopReason.SUFFICIENT
    assert evidence_set.coverage.needs[0].outcome is NeedOutcome.FOUND
    assert len(evidence_set.trajectory.steps) == 1
