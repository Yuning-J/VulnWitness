"""Opaque assessor inputs and the single sourced refinement proposal's gate."""

from collections.abc import Sequence
from dataclasses import replace

from cve_kgrag.application.plan_gate import (
    build_plan_context,
    canonicalize_call,
    find_plan_rejections,
)
from cve_kgrag.domain.cve import CveRecord
from cve_kgrag.domain.hashing import canonical_sha256
from cve_kgrag.domain.investigation import Interpretation, InvestigationRequest, ToolStep
from cve_kgrag.domain.planning import CveSearchCall, ModelReply
from cve_kgrag.domain.relevance import (
    AssessorQuestion,
    RelevanceAssessmentRecord,
    RelevanceInput,
    TermSource,
)
from cve_kgrag.domain.relevance_input import build_assessor_candidate
from cve_kgrag.domain.relevance_reply import parse_relevance_reply
from cve_kgrag.domain.relevance_terms import list_term_sources
from cve_kgrag.domain.text import list_query_terms
from cve_kgrag.topics.registry import TopicRegistry


def build_relevance_input(
    request: InvestigationRequest, records: Sequence[CveRecord]
) -> tuple[RelevanceInput, dict[str, str]]:
    """Keys and input order depend on content, never candidate rank or CVE numbering."""
    records_by_key: dict[str, CveRecord] = {}
    for record in records:
        key = "c" + canonical_sha256({"question": request.query, "cve": record.cve_id})[:24]
        records_by_key[key] = record
    candidates = []
    cve_ids_by_key: dict[str, str] = {}
    for key in sorted(records_by_key):
        record = records_by_key[key]
        candidates.append(build_assessor_candidate(key, record))
        cve_ids_by_key[key] = record.cve_id
    return RelevanceInput(
        question=AssessorQuestion(query=request.query, scope=request.scope),
        candidates=tuple(candidates),
    ), cve_ids_by_key


def gate_relevance_reply(
    request: InvestigationRequest,
    interpretation: Interpretation,
    issued_steps: Sequence[ToolStep],
    records: Sequence[CveRecord],
    cve_ids_by_key: dict[str, str],
    reply: ModelReply | None,
    topic_registry: TopicRegistry,
    allow_refinement: bool = True,
) -> RelevanceAssessmentRecord:
    """Keep valid labels; a search requires a valid gap and a source for every term."""
    proposal = parse_relevance_reply(reply, cve_ids_by_key, request.query)
    issues = list(proposal.issues)
    sources = list_term_sources(interpretation.search_terms, records)
    term_sources: list[TermSource] = []
    rejections = []
    accepted_search: CveSearchCall | None = None
    if proposal.search is not None:
        proposed_terms: set[str] = set()
        for term in list_query_terms(proposal.search.query):
            if term in proposed_terms:
                continue
            proposed_terms.add(term)
            if term in sources:
                term_sources.append(sources[term])
            else:
                issues.append("unsourced_term:" + term)
        context = build_plan_context(request, interpretation, None, issued_steps, None)
        context = replace(context, allowed_terms=frozenset(sources))
        rejections = find_plan_rejections((proposal.search,), context, topic_registry)
        if proposal.gap is None:
            issues.append("search_without_gap")
        if request.budget.max_rounds < 2:
            issues.append("round_cap")
        if not allow_refinement:
            issues.append("refinement_not_allowed")
        if not issues and not rejections:
            canonical_search = canonicalize_call(proposal.search)
            assert isinstance(canonical_search, CveSearchCall)
            accepted_search = canonical_search
    return RelevanceAssessmentRecord(
        cve_ids_by_key=cve_ids_by_key,
        reply=reply,
        labels=proposal.labels,
        gap=proposal.gap,
        search=proposal.search,
        term_sources=tuple(term_sources),
        issues=tuple(issues),
        rejections=tuple(rejections),
        accepted_search=accepted_search,
    )
