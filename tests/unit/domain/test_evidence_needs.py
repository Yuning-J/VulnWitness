"""Need outcomes judged from recorded steps: protocol context through the direct FiGHT
search, implementation CVEs through a search of the question's own words, and
``not_evaluated`` for a need no admitted serving step has a result for."""

from typing import Any

import pytest

from cve_kgrag.application.investigation_policy import interpret_request
from cve_kgrag.domain.evidence_needs import is_need_open, judge_needs
from cve_kgrag.domain.investigation import (
    EvidenceNeed,
    EvidenceNeedKind,
    NeedOutcome,
    ToolStep,
)
from cve_kgrag.domain.taxonomy import BackendFailureDetail
from cve_kgrag.domain.threat_context import ThreatContextItem
from cve_kgrag.topics.registry import TopicRegistry
from tests.support.builders import build_recorded_step
from tests.support.investigation import (
    build_investigation_request,
    build_productless_catalog,
    choose_fight_source,
)

DIRECT_SEARCH_REQUEST = [{"source": "mitre_fight", "terms": ["gtp", "threats"], "limit": 20}]


def build_direct_fight_step(**overrides: Any) -> ToolStep:
    """An admitted round-1 ``fight_direct_search`` step of ``gtp threats`` that found nothing."""
    fields: dict[str, Any] = {
        "call": {"tool": "fight_direct_search"},
        "reason": "query_terms_fight",
        "backend_requests": DIRECT_SEARCH_REQUEST,
        "sources": ["mitre_fight"],
        "channels_executed": [],
    }
    fields.update(overrides)
    return build_recorded_step(**fields)


def find_packaged_technique() -> ThreatContextItem:
    """The first technique of the packaged FiGHT excerpt."""
    return choose_fight_source("packaged")[0].list_techniques()[0]


def judge_protocol_need(
    topic_registry: TopicRegistry,
    query: str,
    steps: list[ToolStep],
    protocol_context: tuple[ThreatContextItem, ...] = (),
) -> NeedOutcome:
    request = build_investigation_request(query, "protocol_context_only")
    interpretation = interpret_request(request, topic_registry, build_productless_catalog())
    needs = judge_needs(request, interpretation, steps, (), protocol_context)
    assert len(needs) == 1
    assert needs[0].kind is EvidenceNeedKind.PROTOCOL_CONTEXT
    return needs[0].outcome


def test_protocol_need_is_unsupported_only_when_a_block_bars_the_direct_search(
    topic_registry: TopicRegistry,
) -> None:
    outcome = judge_protocol_need(topic_registry, "EPS AKA crash", [])

    assert outcome is NeedOutcome.UNSUPPORTED


@pytest.mark.parametrize(
    "steps",
    [
        [],
        [build_direct_fight_step(admission="timed_out", status=None, result_sha256=None)],
        [build_direct_fight_step(admission="discarded_after_deadline")],
        [build_direct_fight_step(admission="discarded_over_context_budget")],
        [
            build_direct_fight_step(
                admission="rejected_invalid_evidence", status=None, result_sha256=None
            )
        ],
    ],
    ids=[
        "no_step",
        "timed_out",
        "discarded_after_deadline",
        "discarded_over_context_budget",
        "rejected_invalid_evidence",
    ],
)
def test_protocol_need_without_an_admitted_direct_search_is_not_evaluated(
    topic_registry: TopicRegistry, steps: list[ToolStep]
) -> None:
    outcome = judge_protocol_need(topic_registry, "gtp threats", steps)

    assert outcome is NeedOutcome.NOT_EVALUATED


def test_protocol_need_is_matches_unassessed_when_the_answer_lists_a_direct_search_technique(
    topic_registry: TopicRegistry,
) -> None:
    technique = find_packaged_technique()
    step = build_direct_fight_step(status="ok", answer_ids=[technique.technique_id])

    outcome = judge_protocol_need(topic_registry, "gtp threats", [step], (technique,))

    assert outcome is NeedOutcome.MATCHES_UNASSESSED


def test_protocol_need_is_not_found_when_the_direct_search_warned_a_word_no_technique_holds(
    topic_registry: TopicRegistry,
) -> None:
    technique = find_packaged_technique()
    step = build_direct_fight_step(
        status="ok",
        answer_ids=[technique.technique_id],
        topic_warnings=[{"code": "term_not_indexed", "subject": "threats"}],
    )

    outcome = judge_protocol_need(topic_registry, "gtp threats", [step], (technique,))

    assert outcome is NeedOutcome.NOT_FOUND


def test_protocol_need_ignores_a_word_only_the_cve_search_warned_no_record_holds(
    topic_registry: TopicRegistry,
) -> None:
    technique = find_packaged_technique()
    cve_step = build_recorded_step(
        call={"tool": "cve_search", "query": "gtp threats"},
        backend_requests=[{"source": "cve_search", "query": "gtp threats", "limit": 20}],
        search_warnings=[{"code": "term_not_indexed", "subject": "threats"}],
    )
    fight_step = build_direct_fight_step(
        step_index=2, status="ok", answer_ids=[technique.technique_id]
    )

    outcome = judge_protocol_need(
        topic_registry, "gtp threats", [cve_step, fight_step], (technique,)
    )

    assert outcome is NeedOutcome.MATCHES_UNASSESSED


def test_protocol_need_is_not_found_when_the_allowed_direct_search_ran_and_found_nothing(
    topic_registry: TopicRegistry,
) -> None:
    outcome = judge_protocol_need(topic_registry, "gtp threats", [build_direct_fight_step()])

    assert outcome is NeedOutcome.NOT_FOUND


def test_protocol_need_is_source_unavailable_when_the_admitted_direct_search_failed(
    topic_registry: TopicRegistry,
) -> None:
    failed_step = build_direct_fight_step(
        status="source_unavailable",
        source_outcomes=[
            {
                "source": "mitre_fight",
                "status": "source_unavailable",
                "detail": BackendFailureDetail.NOT_CONFIGURED.value,
            }
        ],
    )

    outcome = judge_protocol_need(topic_registry, "gtp threats", [failed_step])

    assert outcome is NeedOutcome.SOURCE_UNAVAILABLE


def test_protocol_need_of_a_resolved_topic_is_not_served_by_a_direct_search(
    topic_registry: TopicRegistry,
) -> None:
    technique = find_packaged_technique()
    step = build_direct_fight_step(status="ok", answer_ids=[technique.technique_id])

    outcome = judge_protocol_need(topic_registry, "5G-AKA", [step], (technique,))

    assert outcome is NeedOutcome.NOT_EVALUATED


def test_named_cve_and_implementation_needs_without_a_serving_step_are_not_evaluated(
    topic_registry: TopicRegistry,
) -> None:
    request = build_investigation_request("CVE-9999-0003 5gaka", "implementation_only")
    interpretation = interpret_request(request, topic_registry, build_productless_catalog())

    needs = judge_needs(request, interpretation, [], (), ())

    assert needs == (
        EvidenceNeed(
            kind=EvidenceNeedKind.NAMED_CVE,
            subject="CVE-9999-0003",
            outcome=NeedOutcome.NOT_EVALUATED,
        ),
        EvidenceNeed(
            kind=EvidenceNeedKind.IMPLEMENTATION_CVES,
            subject=None,
            outcome=NeedOutcome.NOT_EVALUATED,
        ),
    )


def judge_implementation_need(
    topic_registry: TopicRegistry, query: str, steps: list[ToolStep]
) -> NeedOutcome:
    request = build_investigation_request(query, "implementation_only")
    interpretation = interpret_request(request, topic_registry, build_productless_catalog())
    needs = judge_needs(request, interpretation, steps, (), ())
    assert len(needs) == 1
    assert needs[0].kind is EvidenceNeedKind.IMPLEMENTATION_CVES
    return needs[0].outcome


def test_implementation_need_is_matches_unassessed_when_a_search_of_every_word_returned_a_cve(
    topic_registry: TopicRegistry,
) -> None:
    step = build_recorded_step(
        call={"tool": "cve_search", "query": "gtp threats"},
        backend_requests=[{"source": "cve_search", "query": "gtp threats", "limit": 20}],
        status="ok",
        answer_ids=["CVE-9999-0003"],
    )

    outcome = judge_implementation_need(topic_registry, "gtp threats", [step])

    assert outcome is NeedOutcome.MATCHES_UNASSESSED


def test_implementation_need_is_not_found_when_a_search_warned_a_word_no_record_holds(
    topic_registry: TopicRegistry,
) -> None:
    step = build_recorded_step(
        call={"tool": "cve_search", "query": "gtp threats"},
        backend_requests=[{"source": "cve_search", "query": "gtp threats", "limit": 20}],
        status="ok",
        answer_ids=["CVE-9999-0003"],
        search_warnings=[{"code": "term_not_indexed", "subject": "threats"}],
    )

    outcome = judge_implementation_need(topic_registry, "gtp threats", [step])

    assert outcome is NeedOutcome.NOT_FOUND


@pytest.mark.parametrize(
    ("outcome", "expected_open"),
    [
        (NeedOutcome.NOT_EVALUATED, True),
        (NeedOutcome.NOT_FOUND, True),
        (NeedOutcome.MATCHES_UNASSESSED, True),
        (NeedOutcome.UNSUPPORTED, False),
        (NeedOutcome.SOURCE_UNAVAILABLE, False),
        (NeedOutcome.FOUND, False),
    ],
    ids=[
        "not_evaluated",
        "not_found",
        "matches_unassessed",
        "unsupported",
        "source_unavailable",
        "found",
    ],
)
def test_need_is_open_while_a_tool_could_still_meet_it(
    outcome: NeedOutcome, expected_open: bool
) -> None:
    needs = [EvidenceNeed(kind=EvidenceNeedKind.PROTOCOL_CONTEXT, subject=None, outcome=outcome)]

    assert is_need_open(needs, EvidenceNeedKind.PROTOCOL_CONTEXT) is expected_open
