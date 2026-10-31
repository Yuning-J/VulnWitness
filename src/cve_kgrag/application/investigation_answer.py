"""The answer an investigation returns, assembled from its admitted steps only.

CVE candidates from every admitted step are merged: each CVE is kept once, at its
first sight, and records every step that found it. When a topic resolved, a
candidate from a free-text CVE search is kept only if its record relates to the
topic (``assess_relevance``); topic steps have already assessed theirs. A CVE the
caller named by ID is never dropped: an exact lookup's candidate keeps its
assessment when it relates to the topic and is kept unassessed otherwise. Candidates an
exact lookup found come first, then the rest; each group is ordered by relevance tier,
then by a match to the recognized product when a product step was admitted.
Within that group, non-product retrieval candidates precede product-only candidates;
each group keeps first step, tool rank and CVE ID order. Product identity supplies
no component relevance and does not reorder matching lexical candidates,
and the whole list is cut to the per-call result cap. A run names at most that many IDs
(``exceeds_lookup_cap``), so the cut never reaches a named CVE, whatever the order of
the plan's steps. Under
``protocol_context_only`` the candidates form the separately labelled excluded
section, never the answer.

Claims are fixed templates over IDs, names and statuses; they carry no source
prose and no planner text.

``assemble_returned_answer`` is everything a sealed set returns from its steps'
responses; the controller seals every set with it, replayed runs included.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from functools import partial

from cve_kgrag.application.fusion import RRF_K
from cve_kgrag.application.investigation_tools import ToolExecution
from cve_kgrag.application.product_investigation import matches_product_name
from cve_kgrag.application.topic_context import PROTOCOL_EXCLUSION_REASON, TIER_ORDER
from cve_kgrag.domain.affectedness import AffectednessDetail, ApplicabilityStatus
from cve_kgrag.domain.evidence import Claim, EvidenceAnchor
from cve_kgrag.domain.evidence_needs import judge_needs
from cve_kgrag.domain.investigation import (
    ADMITTED_ADMISSIONS,
    ApplicabilityBasis,
    CoverageAssessment,
    DecisionBasis,
    ExcludedInvestigationCandidate,
    Interpretation,
    InvestigationCandidate,
    InvestigationRequest,
    InvestigationWarning,
    InvestigationWarningCode,
    ProductApplicability,
    RankingConfiguration,
    StopReason,
    ToolStep,
    decide_investigation_status,
    format_implementation_claim_id,
    format_implementation_statement,
    format_threat_context_claim_id,
    format_threat_context_statement,
    list_answer_sources,
    list_named_products,
    list_record_evidence_ids,
    list_step_notices,
    list_version_mentions,
)
from cve_kgrag.domain.nvd_version_note import list_nvd_version_notes
from cve_kgrag.domain.planning import CveExactLookupCall, ProductQueryCall
from cve_kgrag.domain.relevance import LABEL_ORDER, RelevanceLabel
from cve_kgrag.domain.search import Candidate, ChannelOutcome, SearchFilters
from cve_kgrag.domain.taxonomy import (
    AssertionKind,
    BackendFailureDetail,
    KnowledgeScope,
    ResultStatus,
    RetrievalChannel,
)
from cve_kgrag.domain.threat_context import ThreatContextItem
from cve_kgrag.domain.topic import ProtocolTopic, RelevanceAssessment
from cve_kgrag.domain.topic_context import (
    SERVED_STATUSES,
    KnowledgeSource,
    QueryScope,
    SourceOutcome,
    TopicContextWarningCode,
    summarize_statuses,
)
from cve_kgrag.domain.validation import index_anchors, read_count_subject
from cve_kgrag.topics.relevance import assess_relevance

# The warnings assembling the answer raises, always after the run's other warnings.
ANSWER_WARNING_CODES = frozenset(
    {
        InvestigationWarningCode.UNRELATED_CANDIDATES_DROPPED,
        InvestigationWarningCode.ANSWER_TRUNCATED,
        InvestigationWarningCode.RESULT_LIMIT_REACHED,
        InvestigationWarningCode.TERM_NOT_INDEXED,
        InvestigationWarningCode.APPLICABILITY_UNKNOWN,
    }
)


def list_decision_warnings(
    warnings: Sequence[InvestigationWarning],
) -> list[InvestigationWarning]:
    """The warnings the interpretation and the decisions raise, in recorded order: every
    warning but the answer's own (``ANSWER_WARNING_CODES``)."""
    decision_warnings: list[InvestigationWarning] = []
    for warning in warnings:
        if warning.code not in ANSWER_WARNING_CODES:
            decision_warnings.append(warning)
    return decision_warnings


def describe_ranking() -> RankingConfiguration:
    """The ranking this code applies: the search service's RRF constant, the relevance
    tier order, and ``CandidateSighting.sort_key``'s merge by named ID, tier, product
    match, non-product retrieval, first step and tool rank. A trajectory records it;
    the decision-path audit requires exactly it."""
    return RankingConfiguration(
        rrf_k=RRF_K,
        relevance_tier_order=TIER_ORDER,
        merge_rule="named_then_tier_then_product_match_then_lexical_then_step_then_tool_rank",
    )


@dataclass
class CandidateSighting:
    """A CVE as first seen, plus every step that found it and whether an exact lookup of
    a named ID was one of them."""

    candidate: Candidate
    relevance: RelevanceAssessment | None
    tool_rank: int
    found_by_steps: list[int] = field(default_factory=list)
    is_named: bool = False
    matches_product: bool = False
    is_product_only: bool = True

    def sort_key(self) -> tuple[bool, int, bool, bool, int, int, str]:
        tier_position = 0 if self.relevance is None else TIER_ORDER.index(self.relevance.tier)
        return (
            not self.is_named,
            tier_position,
            not self.matches_product,
            self.is_product_only,
            self.found_by_steps[0],
            self.tool_rank,
            self.candidate.record.cve_id,
        )


@dataclass(frozen=True)
class AssembledAnswer:
    implementation_candidates: tuple[InvestigationCandidate, ...]
    excluded_candidates: tuple[ExcludedInvestigationCandidate, ...]
    protocol_context: tuple[ThreatContextItem, ...]
    evidence: tuple[EvidenceAnchor, ...]
    dropped_count: int
    truncated_count: int

    def has_answer(self) -> bool:
        """Excluded candidates are context for a protocol answer, never the answer itself."""
        return bool(self.implementation_candidates or self.protocol_context)


@dataclass(frozen=True)
class ReturnedAnswer:
    """What a set returns from its admitted responses: the answer, product applicability,
    claims, coverage and status, and the answer's warnings (``ANSWER_WARNING_CODES``) in
    the order the set records them."""

    answer: AssembledAnswer
    product_applicability: tuple[ProductApplicability, ...]
    claims: tuple[Claim, ...]
    coverage: CoverageAssessment
    status: ResultStatus
    warnings: tuple[InvestigationWarning, ...]


def record_sighting(
    sightings: dict[str, CandidateSighting],
    step_index: int,
    candidate: Candidate,
    relevance: RelevanceAssessment | None,
    tool_rank: int,
    is_exact_lookup: bool,
    is_product_step: bool,
) -> None:
    cve_id = candidate.record.cve_id
    sighting = sightings.get(cve_id)
    if sighting is None:
        sighting = CandidateSighting(candidate, relevance, tool_rank)
        sightings[cve_id] = sighting
    if is_exact_lookup:
        sighting.is_named = True
    if not is_product_step:
        sighting.is_product_only = False
    if step_index not in sighting.found_by_steps:
        sighting.found_by_steps.append(step_index)


def list_hit_channels(candidate: Candidate) -> set[RetrievalChannel]:
    hit_channels: set[RetrievalChannel] = set()
    for channel_hit in candidate.channel_hits:
        hit_channels.add(channel_hit.channel)
    return hit_channels


@dataclass(frozen=True)
class CollectedSightings:
    """Every kept CVE in first-sight order, and the CVE IDs search-step relevance dropped
    as unrelated to the topic."""

    sightings: list[CandidateSighting]
    dropped_cve_ids: set[str]


def collect_sightings(
    topic: ProtocolTopic | None, admitted_executions: Sequence[tuple[ToolStep, ToolExecution]]
) -> CollectedSightings:
    """The sightings of the admitted steps' candidates, each CVE once."""
    sightings: dict[str, CandidateSighting] = {}
    dropped_cve_ids: set[str] = set()
    product_name = None
    for step, _ in admitted_executions:
        if isinstance(step.call, ProductQueryCall):
            product_name = step.call.recognition.name
            break
    for step, execution in admitted_executions:
        search_response = execution.search_response
        topic_response = execution.topic_response
        if search_response is not None:
            # The caller named these IDs: an exact match is the answer, related or not.
            is_exact_lookup = isinstance(step.call, CveExactLookupCall)
            for candidate in search_response.candidates:
                relevance: RelevanceAssessment | None = None
                if topic is not None:
                    relevance = assess_relevance(
                        candidate.record, topic, list_hit_channels(candidate)
                    )
                    if relevance is None and not is_exact_lookup:
                        dropped_cve_ids.add(candidate.record.cve_id)
                        continue
                record_sighting(
                    sightings,
                    step.step_index,
                    candidate,
                    relevance,
                    candidate.rank,
                    is_exact_lookup,
                    isinstance(step.call, ProductQueryCall),
                )
        elif topic_response is not None:
            topic_candidates = list(topic_response.implementation_candidates)
            for excluded_candidate in topic_response.excluded_implementation_candidates:
                topic_candidates.append(excluded_candidate.candidate)
            for topic_candidate in topic_candidates:
                record_sighting(
                    sightings,
                    step.step_index,
                    topic_candidate.candidate,
                    topic_candidate.relevance,
                    topic_candidate.topic_rank,
                    False,
                    False,
                )
    if product_name is not None:
        for sighting in sightings.values():
            sighting.matches_product = matches_product_name(sighting.candidate.record, product_name)
    return CollectedSightings(list(sightings.values()), dropped_cve_ids)


def count_topic_cuts(
    admitted_executions: Sequence[tuple[ToolStep, ToolExecution]],
) -> tuple[set[str], int]:
    """What the adopted topic or direct FiGHT step left out at its limit: the CVE IDs a
    topic step kept and did not list, and the techniques the step matched and did not
    list. Context-budget omissions have their own step warning and are counted separately.
    A run issues at most one topic step and at most one step that searches FiGHT,
    and its limit is the per-call cap the answer uses, so these are exact."""
    omitted_cve_ids: set[str] = set()
    unlisted_technique_count = 0
    for _, execution in admitted_executions:
        if execution.topic_response is None:
            continue
        omitted_cve_ids.update(execution.omitted_topic_cve_ids)
        topic_response = execution.topic_response
        for warning in topic_response.warnings:
            if warning.code is TopicContextWarningCode.PROTOCOL_CONTEXT_TRUNCATED:
                cut_count = read_count_subject(warning.subject) or 0
                if execution.prefix_admission is not None:
                    for count in execution.prefix_admission.counts:
                        if count.name == "protocol_context":
                            cut_count -= count.omitted
                unlisted_technique_count += cut_count
    return omitted_cve_ids, unlisted_technique_count


def collect_protocol_context(
    admitted_executions: Sequence[tuple[ToolStep, ToolExecution]],
) -> list[ThreatContextItem]:
    """Threat-context items in first-seen order, each technique once: those of the one
    step that searches FiGHT, a topic step or a direct FiGHT search."""
    items_by_technique: dict[str, ThreatContextItem] = {}
    for _, execution in admitted_executions:
        if execution.topic_response is None:
            continue
        for item in execution.topic_response.protocol_context:
            items_by_technique.setdefault(item.technique_id, item)
    return list(items_by_technique.values())


def collect_evidence(
    admitted_executions: Sequence[tuple[ToolStep, ToolExecution]],
    candidates: Sequence[InvestigationCandidate],
    protocol_context: Sequence[ThreatContextItem],
) -> tuple[EvidenceAnchor, ...]:
    """Exactly the anchors the kept candidates and items cite, ordered by evidence_id."""
    anchors_by_id: dict[str, EvidenceAnchor] = {}
    for _, execution in admitted_executions:
        response_evidence: tuple[EvidenceAnchor, ...] = ()
        if execution.search_response is not None:
            response_evidence = execution.search_response.evidence
        elif execution.topic_response is not None:
            response_evidence = execution.topic_response.evidence
        for anchor in response_evidence:
            anchors_by_id[anchor.evidence_id] = anchor
    cited_ids: set[str] = set()
    for investigation_candidate in candidates:
        cited_ids.update(investigation_candidate.candidate.record.evidence_ids)
    for item in protocol_context:
        cited_ids.update(item.evidence_ids)
    cited_anchors: list[EvidenceAnchor] = []
    for evidence_id in sorted(cited_ids):
        cited_anchors.append(anchors_by_id[evidence_id])
    return tuple(cited_anchors)


def read_label_position(sighting: CandidateSighting, labels: dict[str, RelevanceLabel]) -> int:
    label = labels.get(sighting.candidate.record.cve_id)
    return len(LABEL_ORDER) if label is None else LABEL_ORDER.index(label)


def assemble_answer(
    scope: QueryScope,
    topic: ProtocolTopic | None,
    admitted_executions: Sequence[tuple[ToolStep, ToolExecution]],
    max_results: int,
    affectedness_mentions: Sequence[str] = (),
    relevance_labels: dict[str, RelevanceLabel] | None = None,
) -> AssembledAnswer:
    collected_sightings = collect_sightings(topic, admitted_executions)
    sightings = collected_sightings.sightings
    sightings.sort(key=CandidateSighting.sort_key)
    if relevance_labels:
        sightings.sort(key=partial(read_label_position, labels=relevance_labels))
    ranked_candidates: list[InvestigationCandidate] = []
    for rank, sighting in enumerate(sightings[:max_results], start=1):
        ranked_candidates.append(
            InvestigationCandidate(
                rank=rank,
                relevance_label=(relevance_labels or {}).get(sighting.candidate.record.cve_id),
                candidate=sighting.candidate,
                relevance=sighting.relevance,
                found_by_steps=tuple(sighting.found_by_steps),
                nvd_version_notes=list_nvd_version_notes(
                    sighting.candidate.record, affectedness_mentions
                ),
            )
        )
    protocol_context = tuple(collect_protocol_context(admitted_executions))
    # |K| - |L| + F (ADR 0009 §11a): K the CVEs the adopted steps kept, the topic step's
    # cuts included; L those the answer lists; F the techniques the step that searched
    # FiGHT (a topic step or a direct FiGHT search) matched and did not list.
    omitted_topic_cve_ids, unlisted_technique_count = count_topic_cuts(admitted_executions)
    known_cve_ids: set[str] = set(omitted_topic_cve_ids)
    for sighting in sightings:
        known_cve_ids.add(sighting.candidate.record.cve_id)
    truncated_count = len(known_cve_ids) - len(ranked_candidates) + unlisted_technique_count
    dropped_count = len(collected_sightings.dropped_cve_ids - known_cve_ids)

    implementation_candidates: tuple[InvestigationCandidate, ...] = tuple(ranked_candidates)
    excluded_candidates: list[ExcludedInvestigationCandidate] = []
    if scope is QueryScope.PROTOCOL_CONTEXT_ONLY:
        implementation_candidates = ()
        for investigation_candidate in ranked_candidates:
            excluded_candidates.append(
                ExcludedInvestigationCandidate(
                    candidate=investigation_candidate, reason=PROTOCOL_EXCLUSION_REASON
                )
            )
    return AssembledAnswer(
        implementation_candidates=implementation_candidates,
        excluded_candidates=tuple(excluded_candidates),
        protocol_context=protocol_context,
        evidence=collect_evidence(admitted_executions, ranked_candidates, protocol_context),
        dropped_count=dropped_count,
        truncated_count=truncated_count,
    )


def summarize_source(
    source: KnowledgeSource, step_outcomes: Sequence[SourceOutcome], has_results: bool
) -> SourceOutcome:
    """One outcome over a source's per-step outcomes: the first step's failure sentence,
    every channel failure once, and a served outcome keeps its snapshot."""
    statuses: list[ResultStatus] = []
    detail: AffectednessDetail | BackendFailureDetail | None = None
    channel_failures: list[ChannelOutcome] = []
    snapshot_outcome: SourceOutcome | None = None
    for step_outcome in step_outcomes:
        statuses.append(step_outcome.status)
        if detail is None:
            detail = step_outcome.detail
        for channel_failure in step_outcome.channel_failures:
            if channel_failure not in channel_failures:
                channel_failures.append(channel_failure)
        if snapshot_outcome is None and step_outcome.source_version is not None:
            snapshot_outcome = step_outcome
    status = summarize_statuses(statuses, has_results)
    if status not in SERVED_STATUSES or snapshot_outcome is None:
        return SourceOutcome(
            source=source,
            status=status,
            detail=detail,
            channel_failures=tuple(channel_failures),
        )
    return SourceOutcome(
        source=source,
        status=status,
        detail=detail,
        channel_failures=tuple(channel_failures),
        source_version=snapshot_outcome.source_version,
        coverage=snapshot_outcome.coverage,
    )


def aggregate_source_outcomes(
    answer_sources: Sequence[KnowledgeSource],
    admitted_steps: Sequence[ToolStep],
    implementation_candidates: Sequence[InvestigationCandidate],
    protocol_context: Sequence[ThreatContextItem],
    ran_any_step: bool,
    affectedness_detail: AffectednessDetail,
) -> tuple[SourceOutcome, ...]:
    """One outcome per answer source an admitted step consulted, in answer-source order,
    given the answer's implementation candidates and threat context.

    Affectedness is unavailable and no step consults it: once any step ran, a required
    affectedness source is reported unavailable with ``affectedness_detail``, the
    ``affectedness`` capability's detail, rather than omitted.
    """
    source_outcomes: list[SourceOutcome] = []
    for source in answer_sources:
        if source is KnowledgeSource.AFFECTEDNESS:
            continue
        step_outcomes: list[SourceOutcome] = []
        for step in admitted_steps:
            for step_outcome in step.source_outcomes:
                if step_outcome.source is source:
                    step_outcomes.append(step_outcome)
        if not step_outcomes:
            continue
        if source is KnowledgeSource.MITRE_FIGHT:
            has_results = bool(protocol_context)
        else:
            has_results = bool(implementation_candidates)
        source_outcomes.append(summarize_source(source, step_outcomes, has_results))
    if KnowledgeSource.AFFECTEDNESS in answer_sources and ran_any_step:
        source_outcomes.append(
            SourceOutcome(
                source=KnowledgeSource.AFFECTEDNESS,
                status=ResultStatus.SOURCE_UNAVAILABLE,
                detail=affectedness_detail,
            )
        )
    return tuple(source_outcomes)


def list_product_applicability(
    filters: SearchFilters, affectedness_mentions: Sequence[str]
) -> tuple[ProductApplicability, ...]:
    """One ``unknown`` entry per named vendor, product and purl, in that order, then per
    product version the query asks affectedness of."""
    applicability: list[ProductApplicability] = []
    for product_kind, product in list_named_products(filters, affectedness_mentions):
        applicability.append(
            ProductApplicability(
                product_kind=product_kind,
                product=product,
                status=ApplicabilityStatus.UNKNOWN,
                basis=ApplicabilityBasis.NO_VERIFIED_AFFECTEDNESS_SOURCE,
            )
        )
    return tuple(applicability)


def build_implementation_claim(
    investigation_candidate: InvestigationCandidate, anchors_by_id: dict[str, EvidenceAnchor]
) -> Claim:
    record = investigation_candidate.candidate.record
    return Claim(
        claim_id=format_implementation_claim_id(record.cve_id),
        subject_id=record.cve_id,
        statement=format_implementation_statement(record.cve_id),
        scope=KnowledgeScope.IMPLEMENTATION_VULNERABILITY,
        assertion_kind=AssertionKind.ASSERTED,
        evidence_ids=list_record_evidence_ids(record, anchors_by_id),
    )


def build_threat_context_claim(item: ThreatContextItem) -> Claim:
    return Claim(
        claim_id=format_threat_context_claim_id(item.technique_id),
        subject_id=item.technique_id,
        statement=format_threat_context_statement(item),
        scope=KnowledgeScope.PROTOCOL_THREAT_CONTEXT,
        assertion_kind=AssertionKind.ASSERTED,
        evidence_ids=item.evidence_ids,
    )


def build_claims(answer: AssembledAnswer) -> tuple[Claim, ...]:
    """One templated claim per answer item, ordered by claim_id; excluded CVEs get none."""
    anchors_by_id = index_anchors(answer.evidence)
    claims: list[Claim] = []
    for investigation_candidate in answer.implementation_candidates:
        claims.append(build_implementation_claim(investigation_candidate, anchors_by_id))
    for item in answer.protocol_context:
        claims.append(build_threat_context_claim(item))
    claims.sort(key=lambda claim: claim.claim_id)
    return tuple(claims)


def list_admitted_executions(
    steps: Sequence[ToolStep], executions: Sequence[ToolExecution]
) -> list[tuple[ToolStep, ToolExecution]]:
    """Each admitted step with its execution; ``executions`` holds one per step, in order."""
    admitted_executions: list[tuple[ToolStep, ToolExecution]] = []
    for step, execution in zip(steps, executions, strict=True):
        if step.admission in ADMITTED_ADMISSIONS:
            admitted_executions.append((step, execution))
    return admitted_executions


def list_answer_warnings(
    answer: AssembledAnswer,
    step_notices: Sequence[InvestigationWarning],
    product_applicability: Sequence[ProductApplicability],
) -> tuple[InvestigationWarning, ...]:
    """The dropped and truncated counts, then the ``step_notices`` the adopted steps raise
    (``list_step_notices``), then one warning per product of unknown applicability."""
    warnings: list[InvestigationWarning] = []
    if answer.dropped_count:
        warnings.append(
            InvestigationWarning(
                code=InvestigationWarningCode.UNRELATED_CANDIDATES_DROPPED,
                subject=str(answer.dropped_count),
            )
        )
    if answer.truncated_count:
        warnings.append(
            InvestigationWarning(
                code=InvestigationWarningCode.ANSWER_TRUNCATED,
                subject=str(answer.truncated_count),
            )
        )
    warnings.extend(step_notices)
    for applicability in product_applicability:
        warnings.append(
            InvestigationWarning(
                code=InvestigationWarningCode.APPLICABILITY_UNKNOWN,
                subject=applicability.product,
            )
        )
    return tuple(warnings)


def assemble_returned_answer(
    request: InvestigationRequest,
    interpretation: Interpretation,
    topic: ProtocolTopic | None,
    steps: Sequence[ToolStep],
    executions: Sequence[ToolExecution],
    stop_reason: StopReason,
    basis: DecisionBasis,
    affectedness_detail: AffectednessDetail,
    relevance_labels: dict[str, RelevanceLabel] | None = None,
) -> ReturnedAnswer:
    """What a run that stopped for ``stop_reason`` on ``basis`` returns from its steps and
    their executions (one per step, in order). An ``invalid_evidence`` run returns nothing
    any step retrieved, and its needs are judged as if no step ran. ``affectedness_detail``
    is the deployment's reason affectedness is unavailable (``aggregate_source_outcomes``)."""
    is_invalid = stop_reason is StopReason.INVALID_EVIDENCE
    admitted_executions: list[tuple[ToolStep, ToolExecution]] = []
    if not is_invalid:
        admitted_executions = list_admitted_executions(steps, executions)
    answer = assemble_answer(
        request.scope,
        topic,
        admitted_executions,
        request.budget.max_results_per_call,
        list_version_mentions(
            interpretation.affectedness_mentions, interpretation.product_recognition
        ),
        relevance_labels,
    )
    admitted_steps: list[ToolStep] = []
    for step, _ in admitted_executions:
        admitted_steps.append(step)
    answer_sources = list_answer_sources(
        request.scope, request.filters, interpretation.affectedness_mentions
    )
    source_outcomes = aggregate_source_outcomes(
        answer_sources,
        admitted_steps,
        answer.implementation_candidates,
        answer.protocol_context,
        ran_any_step=bool(steps),
        affectedness_detail=affectedness_detail,
    )
    outcome_statuses: list[ResultStatus] = []
    for source_outcome in source_outcomes:
        outcome_statuses.append(source_outcome.status)
    product_applicability: tuple[ProductApplicability, ...] = ()
    if request.scope is not QueryScope.PROTOCOL_CONTEXT_ONLY and not is_invalid:
        product_applicability = list_product_applicability(
            request.filters, interpretation.affectedness_mentions
        )
    return ReturnedAnswer(
        answer=answer,
        product_applicability=product_applicability,
        claims=build_claims(answer),
        coverage=CoverageAssessment(
            answer_sources=answer_sources,
            source_outcomes=source_outcomes,
            refinement_applied=any(step.round_number == 2 for step in steps),
            basis=basis,
            needs=judge_needs(
                request,
                interpretation,
                admitted_steps,
                answer.implementation_candidates,
                answer.protocol_context,
            ),
        ),
        status=decide_investigation_status(stop_reason, answer.has_answer(), outcome_statuses),
        warnings=list_answer_warnings(
            answer,
            list_step_notices(admitted_steps, request),
            product_applicability,
        ),
    )
