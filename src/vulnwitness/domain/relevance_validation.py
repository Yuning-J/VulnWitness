"""Relevance labels bind to admitted candidates, their replies and the final capped order."""

from vulnwitness.domain.evidence_catalog import EvidenceCatalog
from vulnwitness.domain.investigation import (
    ADMITTED_ADMISSIONS,
    KnowledgeEvidenceSet,
    StopReason,
)
from vulnwitness.domain.planning import CveSearchCall, PlannerKind, QueryIntent
from vulnwitness.domain.relevance import LABEL_ORDER, RelevanceLabel
from vulnwitness.domain.relevance_reply import parse_relevance_reply
from vulnwitness.domain.relevance_terms import list_term_sources
from vulnwitness.domain.text import list_query_terms
from vulnwitness.domain.topic_context import QueryScope


def find_relevance_violations(
    evidence_set: KnowledgeEvidenceSet, evidence_catalog: EvidenceCatalog
) -> list[str]:
    has_recorded_assessment = any(
        round_record.relevance_assessment is not None
        for round_record in evidence_set.trajectory.rounds
    )
    if not has_recorded_assessment:
        if any(
            candidate.relevance_label is not None
            for candidate in evidence_set.implementation_candidates
        ):
            return ["a candidate's relevance label has no assessment"]
        return []
    violations: list[str] = []
    labels: dict[str, RelevanceLabel] = {}
    admitted_ids: list[str] = []
    assessed_ids: set[str] = set()
    records = []
    has_assessment = False
    for round_record in evidence_set.trajectory.rounds:
        new_ids: set[str] = set()
        for step in evidence_set.trajectory.steps:
            if step.round_number != round_record.round_number:
                continue
            if step.admission not in ADMITTED_ADMISSIONS or not isinstance(
                step.call, CveSearchCall
            ):
                continue
            for cve_id in step.answer_ids:
                if cve_id not in admitted_ids:
                    admitted_ids.append(cve_id)
                    new_ids.add(cve_id)
                    record = evidence_catalog.get_cve(cve_id)
                    if record is not None:
                        records.append(record)
        assessment = round_record.relevance_assessment
        if assessment is None:
            if new_ids and round_record.round_number == 2:
                violations.append("new round-2 CVEs require one relevance assessment")
            continue
        has_assessment = True
        if (
            evidence_set.interpretation.intent is not QueryIntent.FREE_TEXT
            or evidence_set.trajectory.planner.kind is not PlannerKind.MODEL
            or evidence_set.request.scope is QueryScope.PROTOCOL_CONTEXT_ONLY
        ):
            violations.append("relevance assessments require a model-planned free-text CVE run")
        assessed_cves = list(assessment.cve_ids_by_key.values())
        if set(assessed_cves) != new_ids or len(assessed_cves) != len(new_ids):
            violations.append("the assessor must receive exactly the round's new admitted CVEs")
        if assessed_ids.intersection(assessed_cves):
            violations.append("a CVE may be assessed only once")
        assessed_ids.update(assessed_cves)
        if assessment.deadline is None:
            parsed = parse_relevance_reply(
                assessment.reply, assessment.cve_ids_by_key, evidence_set.request.query
            )
            if (assessment.labels, assessment.gap, assessment.search) != (
                parsed.labels,
                parsed.gap,
                parsed.search,
            ):
                violations.append("relevance labels, gap or search do not follow from the reply")
        elif (
            assessment.labels
            or assessment.gap
            or assessment.search
            or assessment.accepted_search
            or assessment.term_sources
            or assessment.rejections
            or assessment.issues != ("assessor_deadline",)
        ):
            violations.append("an assessor reply at the deadline cannot label or refine")
        for key, label in assessment.labels.items():
            labelled_cve = assessment.cve_ids_by_key.get(key)
            if labelled_cve is None:
                violations.append("a relevance label has no admitted candidate key")
            else:
                labels[labelled_cve] = label
        if assessment.accepted_search is not None:
            if round_record.round_number != 1 or assessment.gap is None or assessment.rejections:
                violations.append("only a gated round-1 gap may refine")
            sources = list_term_sources(evidence_set.interpretation.search_terms, records)
            expected_sources = []
            for term in list_query_terms(assessment.accepted_search.query):
                if term not in sources:
                    violations.append("the executed relevance search has an unsourced term")
                else:
                    expected_sources.append(sources[term])
            if tuple(expected_sources) != assessment.term_sources:
                violations.append("the relevance search's recorded term sources are incorrect")
    returned_ids: list[str] = []
    for candidate in evidence_set.implementation_candidates:
        cve_id = candidate.candidate.record.cve_id
        returned_ids.append(cve_id)
        if candidate.relevance_label != labels.get(cve_id):
            violations.append("a candidate's relevance label differs from its assessment")
    if not has_assessment:
        return violations
    expected_ids: list[str] = []
    for group_label in (*LABEL_ORDER, None):
        for cve_id in admitted_ids:
            if labels.get(cve_id) == group_label:
                expected_ids.append(cve_id)
    if evidence_set.stop_reason is StopReason.INVALID_EVIDENCE:
        expected_ids = []
    if returned_ids != expected_ids[: evidence_set.request.budget.max_results_per_call]:
        violations.append("the answer does not follow the relevance label order and cap")
    round_one = evidence_set.trajectory.rounds[0].relevance_assessment
    for step in evidence_set.trajectory.steps:
        if (
            step.round_number == 2
            and isinstance(step.call, CveSearchCall)
            and (round_one is None or step.call != round_one.accepted_search)
        ):
            violations.append("the executed search is not the gated relevance proposal")
    return violations
