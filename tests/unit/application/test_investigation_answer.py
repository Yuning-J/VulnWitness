"""Answer assembly: merge order, deduplication, truncation, outcomes and templated claims."""

import pytest

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.application.investigation_answer import (
    AssembledAnswer,
    aggregate_source_outcomes,
    assemble_answer,
    build_claims,
    list_product_applicability,
)
from cve_kgrag.application.investigation_tools import (
    IssuedStep,
    ToolExecution,
    build_search_execution,
    build_tool_step,
)
from cve_kgrag.application.search import SearchService
from cve_kgrag.composition import build_topic_context_service
from cve_kgrag.domain.affectedness import AffectednessDetail
from cve_kgrag.domain.investigation import (
    CveBackendRequest,
    InvestigationCandidate,
    StepAdmission,
    StepReason,
    ToolStep,
)
from cve_kgrag.domain.planning import (
    CveExactLookupCall,
    CveSearchCall,
    PlannerKind,
    ToolCall,
    ToolName,
    TopicContextCall,
    compute_call_key,
)
from cve_kgrag.domain.result_prefix import measure_response_bytes
from cve_kgrag.domain.search import SearchFilters, SearchRequest
from cve_kgrag.domain.taxonomy import KnowledgeScope, ResultStatus
from cve_kgrag.domain.topic import ProtocolTopic
from cve_kgrag.domain.topic_context import KnowledgeSource, QueryScope, TopicContextRequest
from cve_kgrag.topics.registry import TopicRegistry
from tests.support.collect import list_technique_ids

AdmittedStep = tuple[ToolStep, ToolExecution]
# Answer assembly never reads a step's charge or backend requests.
PLACEHOLDER_BACKEND_REQUEST = CveBackendRequest(
    source=KnowledgeSource.CVE_SEARCH, query="placeholder", limit=20
)


@pytest.fixture
def five_g_aka_topic(topic_registry: TopicRegistry) -> ProtocolTopic:
    registered_topic = topic_registry.get_topic("3gpp:5g-aka")
    assert registered_topic is not None
    return registered_topic.topic


def record_admitted_step(
    step_index: int, call: ToolCall, reason: StepReason, execution: ToolExecution
) -> AdmittedStep:
    """The step record the controller would keep for ``execution``, admitted."""
    issued_step = IssuedStep(
        step_index=step_index,
        round_number=1,
        call=call,
        reason=reason,
        planned_by=PlannerKind.DETERMINISTIC,
        call_key=compute_call_key(call),
        backend_requests=(PLACEHOLDER_BACKEND_REQUEST,),
        charged_tool_calls=1,
        sources=(KnowledgeSource.CVE_SEARCH,),
    )
    return build_tool_step(issued_step, StepAdmission.ADMITTED, execution), execution


def build_admitted_search_step(
    search_service: SearchService, step_index: int, query: str
) -> AdmittedStep:
    """An admitted ``cve_search`` step over the real search service."""
    search_response = search_service.search(SearchRequest(query=query, limit=20))
    return record_admitted_step(
        step_index,
        CveSearchCall(tool=ToolName.CVE_SEARCH, query=query),
        StepReason.QUERY_TERMS,
        build_search_execution(search_response),
    )


def build_admitted_exact_lookup_step(
    search_service: SearchService, step_index: int, *cve_ids: str
) -> AdmittedStep:
    """An admitted ``cve_exact_lookup`` step over the real search service."""
    search_response = search_service.search(SearchRequest(query=" ".join(cve_ids), limit=20))
    return record_admitted_step(
        step_index,
        CveExactLookupCall(tool=ToolName.CVE_EXACT_LOOKUP, cve_ids=cve_ids),
        StepReason.QUERY_CVE_IDS,
        build_search_execution(search_response),
    )


def build_admitted_topic_step(
    fixture_bundle: FixtureBundle, step_index: int, scope: QueryScope, limit: int = 20
) -> AdmittedStep:
    """An admitted ``topic_context`` step for 5G-AKA over the packaged sources, with the
    CVE IDs its limit left out handed over as the executor hands them."""
    topic_exploration = build_topic_context_service(fixture_bundle).explore_with_omissions(
        TopicContextRequest(query="5gaka", scope=scope, limit=limit)
    )
    topic_response = topic_exploration.response
    return record_admitted_step(
        step_index,
        TopicContextCall(tool=ToolName.TOPIC_CONTEXT, topic_id="3gpp:5g-aka"),
        StepReason.REVIEWED_TOPIC,
        ToolExecution(
            None,
            topic_response,
            (),
            measure_response_bytes(topic_response),
            topic_exploration.omitted_cve_ids,
        ),
    )


def describe_candidates(
    investigation_candidates: tuple[InvestigationCandidate, ...],
) -> list[tuple[int, str, tuple[int, ...]]]:
    """Each candidate as (rank, CVE ID, steps that found it)."""
    described_candidates: list[tuple[int, str, tuple[int, ...]]] = []
    for investigation_candidate in investigation_candidates:
        described_candidates.append(
            (
                investigation_candidate.rank,
                investigation_candidate.candidate.record.cve_id,
                investigation_candidate.found_by_steps,
            )
        )
    return described_candidates


def list_claim_ids(answer: AssembledAnswer) -> list[str]:
    claim_ids: list[str] = []
    for claim in build_claims(answer):
        claim_ids.append(claim.claim_id)
    return claim_ids


def test_without_a_topic_the_first_step_to_find_a_candidate_ranks_it_first(
    search_service: SearchService,
) -> None:
    admitted_executions = [
        build_admitted_search_step(search_service, 1, "stored cross-site scripting"),
        build_admitted_search_step(search_service, 2, "sql injection login"),
    ]

    answer = assemble_answer(
        QueryScope.IMPLEMENTATION_ONLY, None, admitted_executions, max_results=20
    )

    assert describe_candidates(answer.implementation_candidates)[:2] == [
        (1, "CVE-9999-0002", (1,)),
        (2, "CVE-9999-0001", (2,)),
    ]


def test_relevance_tier_outranks_the_step_that_found_a_candidate(
    search_service: SearchService, five_g_aka_topic: ProtocolTopic
) -> None:
    admitted_executions = [
        build_admitted_search_step(search_service, 1, "suci"),
        build_admitted_search_step(search_service, 2, "5g aka"),
    ]

    answer = assemble_answer(
        QueryScope.IMPLEMENTATION_ONLY, five_g_aka_topic, admitted_executions, max_results=20
    )

    assert describe_candidates(answer.implementation_candidates) == [
        (1, "CVE-9999-0003", (2,)),
        (2, "CVE-9999-0004", (1, 2)),
    ]


def test_candidate_found_by_two_steps_is_kept_once_with_both_steps(
    search_service: SearchService,
) -> None:
    admitted_executions = [
        build_admitted_search_step(search_service, 1, "demo_gateway"),
        build_admitted_search_step(search_service, 2, "sql injection"),
    ]

    answer = assemble_answer(QueryScope.MIXED, None, admitted_executions, max_results=20)

    cve_ids: list[str] = []
    found_by_steps: dict[str, tuple[int, ...]] = {}
    for investigation_candidate in answer.implementation_candidates:
        cve_id = investigation_candidate.candidate.record.cve_id
        cve_ids.append(cve_id)
        found_by_steps[cve_id] = investigation_candidate.found_by_steps
    assert len(cve_ids) == len(set(cve_ids))
    assert found_by_steps["CVE-9999-0001"] == (1, 2)


def test_answer_beyond_the_result_cap_is_cut_and_counted(search_service: SearchService) -> None:
    admitted_executions = [build_admitted_search_step(search_service, 1, "democorp")]

    answer = assemble_answer(
        QueryScope.IMPLEMENTATION_ONLY, None, admitted_executions, max_results=1
    )

    assert describe_candidates(answer.implementation_candidates) == [(1, "CVE-9999-0001", (1,))]
    assert answer.truncated_count == 2


def test_topic_step_cuts_count_toward_the_truncated_answer(
    fixture_bundle: FixtureBundle, five_g_aka_topic: ProtocolTopic
) -> None:
    """|K| - |L| + F: two CVEs known, the topic step's one listed and one cut, one listed,
    and four techniques the topic step matched and did not list (ADR 0009 §11a)."""
    admitted_executions = [build_admitted_topic_step(fixture_bundle, 1, QueryScope.MIXED, 1)]

    answer = assemble_answer(QueryScope.MIXED, five_g_aka_topic, admitted_executions, max_results=1)

    assert len(answer.implementation_candidates) == 1
    assert len(answer.protocol_context) == 1
    assert answer.truncated_count == 2 - 1 + 4


@pytest.mark.parametrize(("max_results", "truncated_count"), [(1, 2 - 1 + 4), (2, 2 - 2 + 4)])
def test_cve_the_topic_step_cut_and_a_lookup_found_again_counts_once_or_not_at_all(
    fixture_bundle: FixtureBundle,
    search_service: SearchService,
    five_g_aka_topic: ProtocolTopic,
    max_results: int,
    truncated_count: int,
) -> None:
    topic_step = build_admitted_topic_step(fixture_bundle, 1, QueryScope.MIXED, 1)
    (omitted_cve_id,) = topic_step[1].omitted_topic_cve_ids
    admitted_executions = [
        topic_step,
        build_admitted_exact_lookup_step(search_service, 2, omitted_cve_id),
    ]

    answer = assemble_answer(
        QueryScope.MIXED, five_g_aka_topic, admitted_executions, max_results=max_results
    )

    assert answer.truncated_count == truncated_count


def test_search_candidates_unrelated_to_the_resolved_topic_are_dropped_and_counted(
    search_service: SearchService, five_g_aka_topic: ProtocolTopic
) -> None:
    admitted_executions = [build_admitted_search_step(search_service, 1, "democorp")]

    answer = assemble_answer(
        QueryScope.IMPLEMENTATION_ONLY, five_g_aka_topic, admitted_executions, max_results=20
    )

    assert answer.implementation_candidates == ()
    assert answer.dropped_count == 3
    assert answer.has_answer() is False


def test_protocol_scope_lists_topic_cves_only_as_excluded_candidates(
    fixture_bundle: FixtureBundle, five_g_aka_topic: ProtocolTopic
) -> None:
    admitted_executions = [
        build_admitted_topic_step(fixture_bundle, 1, QueryScope.PROTOCOL_CONTEXT_ONLY)
    ]

    answer = assemble_answer(
        QueryScope.PROTOCOL_CONTEXT_ONLY, five_g_aka_topic, admitted_executions, max_results=20
    )

    excluded_cve_ids: list[str] = []
    for excluded_candidate in answer.excluded_candidates:
        excluded_cve_ids.append(excluded_candidate.candidate.candidate.record.cve_id)
    assert answer.implementation_candidates == ()
    assert excluded_cve_ids == ["CVE-9999-0003", "CVE-9999-0004"]
    assert len(answer.protocol_context) == 5


def test_evidence_is_exactly_what_the_kept_items_cite(
    fixture_bundle: FixtureBundle,
    search_service: SearchService,
    five_g_aka_topic: ProtocolTopic,
) -> None:
    # The democorp search returns three records unrelated to 5G-AKA, with their anchors.
    admitted_executions = [
        build_admitted_topic_step(fixture_bundle, 1, QueryScope.MIXED),
        build_admitted_search_step(search_service, 2, "democorp"),
    ]
    dropped_evidence_ids = set(admitted_executions[1][0].evidence_ids)

    answer = assemble_answer(
        QueryScope.MIXED, five_g_aka_topic, admitted_executions, max_results=20
    )

    evidence_ids: list[str] = []
    record_ids: list[str] = []
    for anchor in answer.evidence:
        evidence_ids.append(anchor.evidence_id)
        record_ids.append(anchor.authoritative_record_id)
    assert answer.dropped_count == 3
    assert evidence_ids == sorted(evidence_ids)
    assert sorted(record_ids) == [
        "CVE-9999-0003",
        "CVE-9999-0004",
        "FGT1499.503",
        "FGT5019",
        "FGT5019.005",
        "FGT5040",
        "FGT5044",
    ]
    assert dropped_evidence_ids.isdisjoint(evidence_ids)


def test_cve_named_by_id_is_kept_even_when_unrelated_to_the_resolved_topic(
    search_service: SearchService, five_g_aka_topic: ProtocolTopic
) -> None:
    admitted_executions = [
        build_admitted_exact_lookup_step(search_service, 1, "CVE-9999-0007", "CVE-9999-0003")
    ]

    answer = assemble_answer(
        QueryScope.IMPLEMENTATION_ONLY, five_g_aka_topic, admitted_executions, max_results=20
    )

    described_relevance: list[tuple[str, str | None]] = []
    for investigation_candidate in answer.implementation_candidates:
        relevance = investigation_candidate.relevance
        described_relevance.append(
            (
                investigation_candidate.candidate.record.cve_id,
                None if relevance is None else relevance.tier.value,
            )
        )
    assert described_relevance == [
        ("CVE-9999-0007", None),
        ("CVE-9999-0003", "explicit_protocol_mention"),
    ]
    assert answer.dropped_count == 0


def test_claims_cover_each_answer_item_once_and_no_excluded_candidate(
    fixture_bundle: FixtureBundle, five_g_aka_topic: ProtocolTopic
) -> None:
    protocol_answer = assemble_answer(
        QueryScope.PROTOCOL_CONTEXT_ONLY,
        five_g_aka_topic,
        [build_admitted_topic_step(fixture_bundle, 1, QueryScope.PROTOCOL_CONTEXT_ONLY)],
        max_results=20,
    )
    mixed_answer = assemble_answer(
        QueryScope.MIXED,
        five_g_aka_topic,
        [build_admitted_topic_step(fixture_bundle, 1, QueryScope.MIXED)],
        max_results=20,
    )

    expected_fight_claims: list[str] = []
    for technique_id in sorted(list_technique_ids(protocol_answer.protocol_context)):
        expected_fight_claims.append(f"fight:{technique_id}")
    assert list_claim_ids(protocol_answer) == expected_fight_claims
    assert list_claim_ids(mixed_answer) == sorted(
        ["cve:CVE-9999-0003", "cve:CVE-9999-0004", *expected_fight_claims]
    )


def test_claims_are_templates_that_never_repeat_record_text(
    search_service: SearchService,
) -> None:
    answer = assemble_answer(
        QueryScope.IMPLEMENTATION_ONLY,
        None,
        [build_admitted_search_step(search_service, 1, "ignore previous instructions")],
        max_results=20,
    )

    claims = build_claims(answer)

    assert claims[0].subject_id == "CVE-9999-0007"
    assert claims[0].scope is KnowledgeScope.IMPLEMENTATION_VULNERABILITY
    assert claims[0].statement == (
        "CVE-9999-0007 is a CVE record of an implementation vulnerability; "
        "it does not establish a protocol-design flaw."
    )
    for claim in claims:
        assert "IGNORE" not in claim.statement
        assert "demo_reporter" not in claim.statement


def test_required_affectedness_is_reported_unavailable_with_its_detail_once_a_step_ran(
    search_service: SearchService,
) -> None:
    admitted_step = build_admitted_search_step(search_service, 1, "crash")
    answer = assemble_answer(QueryScope.IMPLEMENTATION_ONLY, None, [admitted_step], 20)
    answer_sources = (KnowledgeSource.CVE_SEARCH, KnowledgeSource.AFFECTEDNESS)

    source_outcomes = aggregate_source_outcomes(
        answer_sources,
        [admitted_step[0]],
        answer.implementation_candidates,
        answer.protocol_context,
        ran_any_step=True,
        affectedness_detail=AffectednessDetail.SOURCE_UNAVAILABLE,
    )
    outcomes_without_steps = aggregate_source_outcomes(
        answer_sources,
        [],
        answer.implementation_candidates,
        answer.protocol_context,
        ran_any_step=False,
        affectedness_detail=AffectednessDetail.SOURCE_UNAVAILABLE,
    )

    described_outcomes: list[tuple[KnowledgeSource, ResultStatus, str | None]] = []
    for source_outcome in source_outcomes:
        described_outcomes.append(
            (source_outcome.source, source_outcome.status, source_outcome.detail)
        )
    assert described_outcomes == [
        (KnowledgeSource.CVE_SEARCH, ResultStatus.OK, None),
        (
            KnowledgeSource.AFFECTEDNESS,
            ResultStatus.SOURCE_UNAVAILABLE,
            AffectednessDetail.SOURCE_UNAVAILABLE,
        ),
    ]
    assert outcomes_without_steps == ()


def test_each_named_product_is_unknown_in_vendor_product_purl_order() -> None:
    filters = SearchFilters(
        purls=["pkg:generic/fictional5g/f5gc"], products=["f5gc"], vendors=["fictional5g"]
    )

    applicability = list_product_applicability(filters, ())

    described_products: list[tuple[str, str, str]] = []
    for product_applicability in applicability:
        described_products.append(
            (
                product_applicability.product_kind,
                product_applicability.product,
                product_applicability.status.value,
            )
        )
    assert described_products == [
        ("vendor", "fictional5g", "unknown"),
        ("product", "f5gc", "unknown"),
        ("purl", "pkg:generic/fictional5g/f5gc", "unknown"),
    ]
