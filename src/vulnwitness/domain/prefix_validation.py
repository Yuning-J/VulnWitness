"""Check compact prefix witnesses against the content and arithmetic a set exposes."""

from vulnwitness.domain.evidence_catalog import EvidenceCatalog
from vulnwitness.domain.investigation import (
    ADMITTED_ADMISSIONS,
    InvestigationWarningCode,
    KnowledgeEvidenceSet,
    StepAdmission,
    StopReason,
    ToolStep,
    build_prefix_omitted_warning,
)
from vulnwitness.domain.planning import (
    CveExactLookupCall,
    CveSearchCall,
    FightDirectSearchCall,
    ProductQueryCall,
    format_cve_tool_query,
)
from vulnwitness.domain.result_prefix import ResultListCount, measure_response_bytes
from vulnwitness.domain.search import ChannelOutcome, SearchResponse
from vulnwitness.domain.taxonomy import BackendStatus
from vulnwitness.domain.text import normalize_query
from vulnwitness.domain.topic_context import TopicContextWarningCode
from vulnwitness.domain.validation import find_uncatalogued_technique_violations, read_count_subject


def find_prefix_count_violations(step: ToolStep, max_results: int) -> list[str]:
    """Counts describe a nonempty proper prefix in the documented interleaved order."""
    admission = step.prefix_admission
    assert admission is not None
    violations: list[str] = []
    names = []
    for count in admission.counts:
        names.append(count.name)
    is_cve_call = isinstance(step.call, CveExactLookupCall | CveSearchCall | ProductQueryCall)
    expected_names = (
        ["candidates"]
        if is_cve_call
        else ["implementation_candidates", "protocol_context", "excluded_implementation_candidates"]
    )
    if names != expected_names:
        return [f"step {step.step_index}: prefix lists differ from the tool's lists"]
    for count in admission.counts:
        if count.kept + count.omitted > max_results:
            violations.append(f"step {step.step_index}: prefix list exceeds the per-call limit")
    if isinstance(step.call, CveExactLookupCall) and (
        admission.counts[0].kept + admission.counts[0].omitted > len(step.call.cve_ids)
    ):
        violations.append(f"step {step.step_index}: prefix counts exceed the IDs looked up")
    kept_total = sum(count.kept for count in admission.counts)
    omitted_total = sum(count.omitted for count in admission.counts)
    if kept_total != len(step.answer_ids) or not kept_total or not omitted_total:
        violations.append(f"step {step.step_index}: prefix counts need a nonempty proper cut")
    expected_kept = [0] * len(admission.counts)
    for _ in range(kept_total):
        for position, count in enumerate(admission.counts):
            if expected_kept[position] < count.kept + count.omitted:
                expected_kept[position] += 1
                if sum(expected_kept) == kept_total:
                    break
        if sum(expected_kept) == kept_total:
            break
    for position, count in enumerate(admission.counts):
        if count.kept != expected_kept[position]:
            violations.append(f"step {step.step_index}: prefix counts skip an earlier list entry")
    if isinstance(step.call, FightDirectSearchCall) and (
        admission.counts[0].kept
        or admission.counts[0].omitted
        or admission.counts[2].kept
        or admission.counts[2].omitted
    ):
        violations.append(f"step {step.step_index}: direct FiGHT prefix contains CVEs")
    offset = 0
    # ToolStep lists CVEs, excluded CVEs, then techniques, independently of trimming order.
    counts_by_name: dict[str, ResultListCount] = {}
    for count in admission.counts:
        counts_by_name[count.name] = count
    for name in (
        "candidates",
        "implementation_candidates",
        "excluded_implementation_candidates",
        "protocol_context",
    ):
        list_count = counts_by_name.get(name)
        if list_count is None:
            continue
        for answer_id in step.answer_ids[offset : offset + list_count.kept]:
            if answer_id.startswith("FGT") != (name == "protocol_context"):
                violations.append(f"step {step.step_index}: prefix IDs differ from per-list counts")
        offset += list_count.kept
    for code, list_names in (
        (TopicContextWarningCode.PROTOCOL_CONTEXT_TRUNCATED, ("protocol_context",)),
        (
            TopicContextWarningCode.CANDIDATES_TRUNCATED,
            ("implementation_candidates", "excluded_implementation_candidates"),
        ),
    ):
        omitted = 0
        for name in list_names:
            if name in counts_by_name:
                omitted += counts_by_name[name].omitted
        warned_count = 0
        for warning in step.topic_warnings:
            if warning.code is code:
                warned_count = read_count_subject(warning.subject) or 0
        if warned_count < omitted:
            violations.append(f"step {step.step_index}: prefix omissions exceed {code} warning")
    return violations


def find_prefix_content_violations(
    evidence_set: KnowledgeEvidenceSet, step: ToolStep, evidence_catalog: EvidenceCatalog
) -> list[str]:
    """Visible records and anchors are whole; visible first-sighting search ranks agree."""
    violations: list[str] = []
    referenced_ids: set[str] = set()
    for answer_id in step.answer_ids:
        record = evidence_catalog.get_cve(answer_id)
        technique = evidence_catalog.get_technique(answer_id)
        if record is not None:
            referenced_ids.update(record.evidence_ids)
        elif technique is not None:
            referenced_ids.update(technique.evidence_ids)
    if tuple(sorted(referenced_ids)) != step.evidence_ids:
        violations.append(f"step {step.step_index}: prefix anchors differ from whole records")
    candidates = list(evidence_set.implementation_candidates)
    for excluded in evidence_set.excluded_implementation_candidates:
        candidates.append(excluded.candidate)
    for candidate in candidates:
        if step.step_index not in candidate.found_by_steps:
            continue
        record = candidate.candidate.record
        if record.cve_id not in step.answer_ids or record != evidence_catalog.get_cve(
            record.cve_id
        ):
            violations.append(f"step {step.step_index}: prefix record is partial or absent")
        if (
            isinstance(step.call, CveExactLookupCall | CveSearchCall | ProductQueryCall)
            and candidate.found_by_steps[0] == step.step_index
            and record.cve_id in step.answer_ids
            and candidate.candidate.rank != step.answer_ids.index(record.cve_id) + 1
        ):
            violations.append(f"step {step.step_index}: prefix candidate rank differs")
    for anchor in evidence_set.evidence:
        if anchor.evidence_id in step.evidence_ids and anchor != evidence_catalog.get_evidence(
            anchor.evidence_id
        ):
            violations.append(f"step {step.step_index}: prefix anchor is partial")
    techniques = []
    for technique in evidence_set.protocol_context:
        if technique.technique_id in step.answer_ids:
            techniques.append(technique)
            if find_uncatalogued_technique_violations((technique,), evidence_catalog):
                violations.append(f"step {step.step_index}: prefix technique is partial")
    technique_ids = []
    for technique in techniques:
        technique_ids.append(technique.technique_id)
    expected_technique_ids = []
    for answer_id in step.answer_ids:
        if answer_id.startswith("FGT"):
            expected_technique_ids.append(answer_id)
    if (
        evidence_set.stop_reason is not StopReason.INVALID_EVIDENCE
        and technique_ids != expected_technique_ids
    ):
        violations.append(f"step {step.step_index}: prefix technique order differs")
    return violations


def reconstruct_visible_search_prefix(
    evidence_set: KnowledgeEvidenceSet, step: ToolStep, evidence_catalog: EvidenceCatalog
) -> SearchResponse | None:
    """Rebuild a search when every per-call candidate survives as a first sighting.

    Merged or dropped candidates lose their per-call metadata, so those responses
    cannot be rebuilt from a set. No tool is re-run and no omitted record is needed.
    """
    if not isinstance(step.call, CveExactLookupCall | CveSearchCall | ProductQueryCall):
        return None
    if step.status is None or step.result_sha256 is None:
        return None
    candidates_by_id = {}
    answer_candidates = list(evidence_set.implementation_candidates)
    for excluded in evidence_set.excluded_implementation_candidates:
        answer_candidates.append(excluded.candidate)
    for answer_candidate in answer_candidates:
        if answer_candidate.found_by_steps[0] == step.step_index:
            candidate = answer_candidate.candidate
            candidates_by_id[candidate.record.cve_id] = candidate
    candidates = []
    for answer_id in step.answer_ids:
        if answer_id not in candidates_by_id:
            return None
        candidates.append(candidates_by_id[answer_id])
    anchors = []
    for evidence_id in step.evidence_ids:
        anchor = evidence_catalog.get_evidence(evidence_id)
        if anchor is None:
            return None
        anchors.append(anchor)
    channel_failures = {}
    for outcome in step.source_outcomes:
        for failure in outcome.channel_failures:
            channel_failures[failure.channel] = failure
    channel_outcomes = []
    for channel in step.channels_executed:
        channel_outcomes.append(
            channel_failures.get(channel, ChannelOutcome(channel=channel, status=BackendStatus.OK))
        )
    query = (
        step.call.recognition.name
        if isinstance(step.call, ProductQueryCall)
        else format_cve_tool_query(step.call)
    )
    return SearchResponse(
        query=query,
        normalized_query=normalize_query(query),
        status=step.status,
        channels_executed=step.channels_executed,
        channel_outcomes=tuple(channel_outcomes),
        candidates=tuple(candidates),
        evidence=tuple(anchors),
        warnings=step.search_warnings,
        result_sha256=step.result_sha256,
    )


def find_prefix_violations(
    evidence_set: KnowledgeEvidenceSet, evidence_catalog: EvidenceCatalog
) -> list[str]:
    """Check counts, whole visible content, charge agreement, fit and remaining arithmetic.

    A search whose per-call candidates survive is reconstructed to check its canonical
    charge and prefix digest. Replay verifies every original hash, canonical charge and
    next-result increment from complete source responses, including when merging or
    filtering removed the per-call metadata needed for reconstruction.
    """
    violations: list[str] = []
    expected_warnings = []
    admitted_bytes = 0
    for step in evidence_set.trajectory.steps:
        admission = step.prefix_admission
        if (step.admission is StepAdmission.ADMITTED_PREFIX) != (admission is not None):
            violations.append(f"step {step.step_index}: exactly admitted_prefix records a prefix")
        if admission is not None:
            violations.extend(
                find_prefix_count_violations(step, evidence_set.request.budget.max_results_per_call)
            )
            violations.extend(find_prefix_content_violations(evidence_set, step, evidence_catalog))
            visible_prefix = reconstruct_visible_search_prefix(evidence_set, step, evidence_catalog)
            if visible_prefix is not None:
                if measure_response_bytes(visible_prefix) != admission.charged_bytes:
                    violations.append(
                        f"step {step.step_index}: prefix canonical byte charge differs"
                    )
                if visible_prefix.compute_result_sha256() != step.result_sha256:
                    violations.append(f"step {step.step_index}: prefix content digest differs")
            remaining_bytes = evidence_set.request.budget.max_context_bytes - admitted_bytes
            if admission.charged_bytes != step.context_bytes:
                violations.append(f"step {step.step_index}: prefix charged bytes differ")
            if (
                not 0
                < admission.charged_bytes
                <= remaining_bytes
                < admission.charged_bytes + admission.next_result_bytes
            ):
                violations.append(
                    f"step {step.step_index}: prefix does not meet the next-result byte bound"
                )
            expected_warnings.append(build_prefix_omitted_warning(step.step_index, admission))
        if step.admission in ADMITTED_ADMISSIONS:
            admitted_bytes += step.context_bytes
    if admitted_bytes != evidence_set.trajectory.budget_used.context_bytes:
        violations.append("prefix budget arithmetic differs from admitted step bytes")
    recorded_warnings = []
    for warning in evidence_set.warnings:
        if warning.code is InvestigationWarningCode.EVIDENCE_PREFIX_OMITTED:
            recorded_warnings.append(warning)
    if recorded_warnings != expected_warnings:
        violations.append("prefix omission warnings do not match the steps and omitted counts")
    return violations
