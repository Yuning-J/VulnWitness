"""Several source calls combine into one honest status."""

import pytest

from vulnwitness.domain.taxonomy import ResultStatus
from vulnwitness.domain.topic_context import (
    KnowledgeSource,
    QueryScope,
    SourceOutcome,
    decide_topic_status,
    summarize_statuses,
)


@pytest.mark.parametrize(
    ("statuses", "has_results", "expected"),
    [
        ([ResultStatus.OK, ResultStatus.NO_MATCH], True, ResultStatus.OK),
        ([ResultStatus.NO_MATCH, ResultStatus.NO_MATCH], False, ResultStatus.NO_MATCH),
        ([ResultStatus.NO_MATCH, ResultStatus.BACKEND_ERROR], False, ResultStatus.PARTIAL),
        ([ResultStatus.BACKEND_ERROR, ResultStatus.SOURCE_UNAVAILABLE], True, ResultStatus.PARTIAL),
        (
            [ResultStatus.SOURCE_UNAVAILABLE, ResultStatus.INCOMPLETE_INDEX],
            False,
            ResultStatus.INCOMPLETE_INDEX,
        ),
        (
            [ResultStatus.SOURCE_UNAVAILABLE, ResultStatus.BACKEND_ERROR],
            False,
            ResultStatus.BACKEND_ERROR,
        ),
        ([ResultStatus.SOURCE_UNAVAILABLE], False, ResultStatus.SOURCE_UNAVAILABLE),
    ],
    ids=[
        "all_succeeded",
        "nothing_found",
        "failure_beside_success",
        "failures_with_results",
        "incomplete_over_unavailable",
        "error_over_unavailable",
        "sole_unavailable",
    ],
)
def test_statuses_combine_by_success_then_failure_precedence(
    statuses: list[ResultStatus], has_results: bool, expected: ResultStatus
) -> None:
    assert summarize_statuses(statuses, has_results) is expected


def test_status_ignores_sources_outside_the_answer() -> None:
    outcomes = [
        SourceOutcome(source=KnowledgeSource.MITRE_FIGHT, status=ResultStatus.OK),
        SourceOutcome(source=KnowledgeSource.CVE_SEARCH, status=ResultStatus.BACKEND_ERROR),
    ]

    status = decide_topic_status(QueryScope.PROTOCOL_CONTEXT_ONLY, True, outcomes)

    assert status is ResultStatus.OK
