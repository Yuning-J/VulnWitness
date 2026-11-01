"""Shared wording for recorded investigation evidence and uncertainty."""

from vulnwitness.domain.cve import CveRecord
from vulnwitness.domain.cvss_ranking import rank_cvss_metric
from vulnwitness.domain.investigation import (
    EvidenceNeed,
    EvidenceNeedKind,
    InvestigationCandidate,
    InvestigationWarning,
    KnowledgeEvidenceSet,
    NeedOutcome,
)
from vulnwitness.domain.search import SearchWarning
from vulnwitness.domain.topic_context import TopicContextWarning

STATUS_SENTENCES = {
    "ok": "Every evidence need was met; that does not show the list is complete.",
    "no_match": "No matches were returned.",
    "partial": "The investigation returned a partial answer.",
    "incomplete_index": "The search index was incomplete.",
    "source_unavailable": "A required source was unavailable.",
    "backend_error": "An evidence source or validation check failed.",
    "policy_blocked": "The investigation policy blocked the request.",
}


STOP_SENTENCES = {
    "sufficient": "Each need was met through an exact lookup or the reviewed topic.",
    "no_evidence": "The investigation stopped without finding evidence.",
    "budget_exhausted": "The investigation reached a budget limit.",
    "source_unavailable": "A required source could not serve the investigation.",
    "policy_blocked": "The request could not proceed under the investigation policy.",
    "invalid_evidence": "The evidence failed validation.",
    "needs_unmet": "Matches were found but not every need was met.",
}


NEED_LABELS = {
    "named_cve": "Named CVE",
    "implementation_cves": "Implementation CVEs",
    "protocol_context": "Protocol context",
    "affectedness": "Affectedness",
}


NEED_OUTCOMES = {
    "matches_unassessed": "matches found; their relevance was not assessed",
    "not_found": "the lookup or search did not meet this need",
    "source_unavailable": "the required source was unavailable",
    "unsupported": "no tool could serve this need for the interpreted query",
    "not_evaluated": "this need was not evaluated",
}


TOOL_LABELS = {
    "cve_exact_lookup": "exact lookup",
    "topic_context": "topic card",
    "cve_search": "word match",
    "product_query": "product match",
}


WARNING_SENTENCES = {
    "product_name_ambiguous": "The product name is ambiguous; lexical retrieval was retained.",
    "excluded_term": "The query contains a term excluded from topic resolution.",
    "topic_not_resolved": "The query did not resolve to a reviewed topic.",
    "topic_pending_review": "The topic card used for retrieval is pending review.",
    "topic_family_scope": "The topic card returns results for the whole protocol family.",
    "no_searchable_terms": "The query contained no searchable terms.",
    "applicability_unknown": "Version affectedness was not assessed.",
    "model_plan_rejected": "The proposed plan was rejected by the investigation policy.",
    "evidence_discarded": "A step's evidence was discarded because of a budget limit.",
    "unrelated_candidates_dropped": "Candidates unrelated to the topic were omitted.",
    "answer_truncated": "The evidence set omits additional CVEs or techniques because of a limit.",
    "result_limit_reached": "A search reached its result limit; more CVE matches may exist.",
    "evidence_prefix_omitted": "A step's context budget omitted returned evidence.",
    "protocol_context_truncated": "The FiGHT context omits matched techniques because of a limit.",
    "candidates_truncated": "The topic context omits additional implementation candidates.",
    "source_snapshot_is_excerpt": "The served FiGHT snapshot is an excerpt.",
    "additional_topic_not_explored": "An additional topic was not explored.",
    "unknown_cve_id": "The exact lookup did not find the named CVE.",
    "excluded_by_filters": "The search filters excluded the CVE.",
    "backend_unavailable": "A search source was unavailable.",
    "backend_incomplete": "A search source's index was incomplete.",
    "backend_error": "A search source failed.",
    "term_not_indexed": "A search term was absent from the searched index.",
}


def format_need(need: EvidenceNeed, has_relevance_labels: bool = False) -> str:
    label = NEED_LABELS[need.kind]
    if need.subject is not None:
        label += f" ({need.subject})"
    if need.outcome is NeedOutcome.FOUND:
        if need.kind is EvidenceNeedKind.NAMED_CVE:
            outcome = "found through an exact lookup"
        else:
            outcome = "found through the reviewed topic"
    elif need.outcome is NeedOutcome.MATCHES_UNASSESSED and has_relevance_labels:
        outcome = "matches found; the system has not confirmed that this need is met"
    else:
        outcome = NEED_OUTCOMES[need.outcome]
    return f"{label}: {outcome}."


def format_severity(record: CveRecord) -> str:
    if not record.cvss:
        return "unknown"
    metric = max(record.cvss, key=rank_cvss_metric)
    severity = metric.base_severity or "unknown"
    return f"{severity} {metric.base_score:.1f} v{metric.version}"


def format_found_by(candidate: InvestigationCandidate, evidence_set: KnowledgeEvidenceSet) -> str:
    tool_labels: list[str] = []
    for step in evidence_set.trajectory.steps:
        if step.step_index in candidate.found_by_steps:
            label = TOOL_LABELS[step.call.tool]
            if label not in tool_labels:
                tool_labels.append(label)
    return ", ".join(tool_labels)


def format_warning(warning: InvestigationWarning | TopicContextWarning | SearchWarning) -> str:
    sentence = WARNING_SENTENCES.get(warning.code)
    if sentence is None:
        return str(warning.code)
    return f"[{warning.code}] {sentence} Subject: {warning.subject}"


def has_candidate_labels(evidence_set: KnowledgeEvidenceSet) -> bool:
    return any(
        round_record.relevance_assessment is not None and round_record.relevance_assessment.labels
        for round_record in evidence_set.trajectory.rounds
    )
