"""Invariants every knowledge evidence set must satisfy before it is returned.

Beyond the anchor, record, threat-context and claim rules of ``validation``:

- ``schema_version`` is the ``SCHEMA_VERSION`` this code serves;
- scopes stay apart: a ``protocol_context_only`` answer holds no CVE candidate,
  implementation claim or product applicability, and an ``implementation_only``
  answer holds no threat context;
- every answer item has exactly one claim, equal to its template (subject, scope,
  statement, assertion kind and cited anchors), the evidence is exactly the anchors
  the answer cites, and every answer ID and anchor was returned by an admitted step;
- every evidence ID a step records is held by the evidence catalog, and every
  answer ID it records has an anchor among them;
- a step that got a response records one outcome per source it consulted; a lookup
  warns ``unknown_cve_id`` for exactly the IDs it looked up that the catalog lacks
  and ``excluded_by_filters`` only for ones it holds and did not return; a search warns
  ``term_not_indexed`` only for a search term its lexical channel was sent; and only a
  CVE search under a semantic request runs the semantic channel, always beside the
  lexical one;
- relevance is assessed for every candidate once a topic resolved, except a CVE the
  caller named by ID, which is kept whether or not it relates to the topic;
- each named product has an ``unknown`` applicability entry and its warning;
- the status follows from the stop reason and the answer sources' outcomes;
- the trajectory is a legal walk of the state machine with at most one refinement,
  and no step runs after one that was not admitted;
- each step's ``call_key`` is recomputed from its call, and its sources are those
  the call consults under the scope;
- rounds and steps describe one run: each round lists exactly its own steps, which
  run the leading calls of its accepted plan in order, planned by the planner its
  outcome names, with a reason the policy gives that tool in that round (or
  ``model_proposal``); a round leaves planned calls unrun only when a step was not
  admitted or the deadline was reached; no call is planned twice, and none the
  scope does not permit; the outcomes are ones the trajectory's planner records, a
  rejection is recorded exactly when the outcome says a plan was rejected, the
  model's reply exactly when the model replied (every consulted outcome but
  ``model_timed_out``) with the hash recomputed from it, and the rounds, planner
  calls, planner durations and ``plan_accepted`` transitions are counted from them;
- rounds follow the state machine: round 1 is recorded exactly when the run moved
  interpret -> plan, and round 2 only after assess -> refine, which under a model
  planner allowed two rounds always records round 2; a deterministic round that
  runs no plan was rejected (stopping ``policy_blocked`` or ``budget_exhausted``)
  or reached the deadline;
- the budget usage matches the steps and never exceeds the request's caps, and
  each step is charged one tool call per backend request it records, every one
  within ``max_results_per_call``; a CVE tool's one request is its call's query;
  a step is discarded over ``max_context_bytes`` exactly when its bytes would push
  the admitted bytes past the cap, and only before the deadline;
- ``coverage.refinement_applied`` says whether a round-2 step ran;
- a step that ran into the deadline (timed out, or returned at or after it)
  finished at or after the deadline, and it, a planner that ran into the deadline
  or a model planner skipped at it makes ``wall_time`` the breach and leaves
  nothing to run after it;
- every anchor, CVE record and FiGHT technique equals the one the service's
  evidence catalog holds under its ID;
- FiGHT evidence comes from the pinned snapshot;
- ``source_capabilities`` equals the capabilities the composition root found the
  deployment serves, describes each subject of ``CAPABILITY_SUBJECTS`` once and in
  that order, in a state that subject can report, with a version and a coverage
  exactly where that state names one and a detail exactly when it is unavailable; and
  it agrees with the run: ``model_planner`` with the trajectory's planner (available
  for a model, not configured or unavailable for the deterministic policy),
  ``mitre_fight`` with the pin and with whether FiGHT served anything,
  ``semantic_channel`` with every semantic search and hit (without
  it, every step that searched text under a semantic request reports its CVE outcome
  unserved), and the unavailable ``affectedness`` with the coverage's affectedness
  outcome, which carries the capability's detail;
- ``result_sha256`` matches.

A holder can reseal ``result_sha256`` and recompute evidence IDs (integrity
hashes, not signatures). The catalog re-check binds the anchors, records and
techniques a set serves, and the evidence its steps record, to the sources this
deployment serves; the FiGHT pin binds the snapshot, and the capability check binds
what the set says the deployment serves. The rest of the trajectory is
re-derived from its own parts; the decision-path audit re-derives its decisions
(each round's from the model reply it records), a topic step's card searches and
the coverage, and binds its ranking and deterministic policy version to this code,
and replay runs the controller again for the request against the sources and
compares every recorded part but the timings with the set it seals.
"""

import re

from cve_kgrag.domain.affectedness import ApplicabilityStatus
from cve_kgrag.domain.budget import BudgetBreach
from cve_kgrag.domain.evidence import Claim, EvidenceAnchor
from cve_kgrag.domain.evidence_catalog import EvidenceCatalog
from cve_kgrag.domain.investigation import (
    ALLOWED_TRANSITIONS,
    CAPABILITY_STATES_BY_SUBJECT,
    CAPABILITY_SUBJECTS,
    CONSULTED_MODEL_OUTCOMES,
    FIRST_REJECTION_BY_OUTCOME,
    FIXED_FIRST_REJECTION_CODES,
    MODEL_REPLY_REJECTION_CODES,
    PLANNER_OUTCOMES_BY_KIND,
    POLICY_STEP_TOOL_AND_ROUND,
    REJECTED_MODEL_OUTCOMES,
    REPLIED_MODEL_OUTCOMES,
    RESPONSELESS_ADMISSIONS,
    STATUSES_BY_STOP_REASON,
    UNAVAILABLE_DETAILS_BY_SUBJECT,
    VERSIONED_CAPABILITY_SUBJECTS,
    CapabilitySubject,
    CveBackendRequest,
    DecisionBasis,
    InvestigationCandidate,
    InvestigationRequest,
    InvestigationState,
    InvestigationWarningCode,
    KnowledgeEvidenceSet,
    PlannerOutcome,
    RoundRecord,
    SourceCapability,
    SourceCapabilityState,
    StepAdmission,
    StepReason,
    StopReason,
    ToolStep,
    decide_investigation_status,
    derive_investigation_id,
    describe_planner_capability,
    format_implementation_claim_id,
    format_implementation_statement,
    format_threat_context_claim_id,
    format_threat_context_statement,
    list_answer_sources,
    list_named_products,
    list_record_evidence_ids,
)
from cve_kgrag.domain.planning import (
    CveExactLookupCall,
    CveSearchCall,
    ModelPlannerUnavailableDetail,
    PlannerKind,
    PlanRejectionCode,
    ToolCall,
    compute_call_key,
    compute_model_reply_sha256,
    format_cve_tool_query,
    is_tool_permitted,
    list_tool_sources,
)
from cve_kgrag.domain.search import (
    SEMANTIC_UNAVAILABLE_FAILURES,
    Candidate,
    SearchWarning,
    SearchWarningCode,
    SemanticUnavailableDetail,
)
from cve_kgrag.domain.taxonomy import (
    BACKEND_FAILURE_DETAILS,
    AssertionKind,
    BackendFailureDetail,
    KnowledgeScope,
    ResultStatus,
    RetrievalChannel,
    SourceType,
)
from cve_kgrag.domain.text import find_cve_ids, list_query_terms, normalize_query
from cve_kgrag.domain.threat_context import FIGHT_TECHNIQUE_ID_PATTERN, KnownFightSnapshot
from cve_kgrag.domain.topic_context import (
    SERVED_STATUSES,
    KnowledgeSource,
    QueryScope,
    SourceOutcome,
    TopicContextWarningCode,
)
from cve_kgrag.domain.validation import (
    EvidenceValidationError,
    find_claim_violations,
    find_pinned_fight_violations,
    find_record_violations,
    find_schema_version_violations,
    find_served_violations,
    find_source_status,
    find_status_violations,
    find_threat_context_violations,
    find_topic_warning_violations,
    index_anchors,
    read_count_subject,
)

# The warning a search records for a semantic channel it ran without an adapter.
UNCONFIGURED_SEMANTIC_WARNING = SearchWarning(
    code=SearchWarningCode.BACKEND_UNAVAILABLE, subject=RetrievalChannel.SEMANTIC.value
)
DEADLINE_ADMISSIONS = frozenset({StepAdmission.DISCARDED_AFTER_DEADLINE, StepAdmission.TIMED_OUT})
# The stops of a run whose policy plan the gate rejected.
REJECTED_POLICY_PLAN_STOPS = frozenset({StopReason.POLICY_BLOCKED, StopReason.BUDGET_EXHAUSTED})
DEADLINE_PLANNER_OUTCOMES = frozenset(
    {
        PlannerOutcome.MODEL_REPLY_AFTER_DEADLINE,
        PlannerOutcome.MODEL_TIMED_OUT,
        PlannerOutcome.MODEL_SKIPPED_AT_DEADLINE,
    }
)
# A claim's content: (subject_id, scope, assertion_kind, statement, evidence_ids).
ClaimContent = tuple[str, KnowledgeScope, AssertionKind, str, tuple[str, ...]]


def list_investigation_candidates(
    evidence_set: KnowledgeEvidenceSet,
) -> list[InvestigationCandidate]:
    """Candidates of both sections: the answer's, then the excluded ones."""
    investigation_candidates = list(evidence_set.implementation_candidates)
    for excluded_candidate in evidence_set.excluded_implementation_candidates:
        investigation_candidates.append(excluded_candidate.candidate)
    return investigation_candidates


def list_cve_candidates(evidence_set: KnowledgeEvidenceSet) -> list[Candidate]:
    cve_candidates: list[Candidate] = []
    for investigation_candidate in list_investigation_candidates(evidence_set):
        cve_candidates.append(investigation_candidate.candidate)
    return cve_candidates


def list_admitted_answer_ids(evidence_set: KnowledgeEvidenceSet) -> set[str]:
    admitted_answer_ids: set[str] = set()
    for step in evidence_set.trajectory.steps:
        if step.admission is StepAdmission.ADMITTED:
            admitted_answer_ids.update(step.answer_ids)
    return admitted_answer_ids


def find_record_and_claim_violations(
    evidence_set: KnowledgeEvidenceSet, evidence_catalog: EvidenceCatalog
) -> list[str]:
    anchors_by_id = index_anchors(evidence_set.evidence)
    violations = find_served_violations(
        evidence_set.evidence,
        list_cve_candidates(evidence_set),
        evidence_set.protocol_context,
        evidence_catalog,
    )
    for cve_candidate in list_cve_candidates(evidence_set):
        violations.extend(find_record_violations(cve_candidate, anchors_by_id))
    violations.extend(find_threat_context_violations(evidence_set.protocol_context, anchors_by_id))
    violations.extend(find_claim_violations(evidence_set.claims, anchors_by_id))
    return violations


def find_identity_violations(evidence_set: KnowledgeEvidenceSet) -> list[str]:
    """The set is in the schema version this code serves, and the ID, normalized query
    and scopes all derive from the echoed request."""
    violations = find_schema_version_violations(evidence_set.schema_version)
    request = evidence_set.request
    if evidence_set.investigation_id != derive_investigation_id(request):
        violations.append("investigation_id is not derived from the request")
    normalized_query = normalize_query(request.query)
    if (
        evidence_set.normalized_query != normalized_query
        or evidence_set.interpretation.normalized_query != normalized_query
    ):
        violations.append("normalized_query does not match the request's query")
    if not (evidence_set.requested_scope is evidence_set.applied_scope is request.scope):
        violations.append("requested and applied scope must both be the request's scope")
    return violations


def find_rank_violations(section_name: str, ranks: list[int]) -> list[str]:
    expected_ranks = list(range(1, len(ranks) + 1))
    if ranks != expected_ranks:
        return [f"{section_name} ranks are {ranks}, expected {expected_ranks}"]
    return []


def find_investigation_scope_violations(evidence_set: KnowledgeEvidenceSet) -> list[str]:
    violations: list[str] = []
    scope = evidence_set.request.scope
    claim_scopes: set[KnowledgeScope] = set()
    for claim in evidence_set.claims:
        claim_scopes.add(claim.scope)
    if scope is QueryScope.PROTOCOL_CONTEXT_ONLY:
        if evidence_set.implementation_candidates:
            violations.append("a protocol_context_only answer cannot contain CVE candidates")
        if KnowledgeScope.IMPLEMENTATION_VULNERABILITY in claim_scopes:
            violations.append("a protocol_context_only answer cannot make implementation claims")
        if evidence_set.product_applicability:
            violations.append("a protocol_context_only answer cannot assess product applicability")
    elif evidence_set.excluded_implementation_candidates:
        violations.append("only a protocol_context_only answer excludes CVE candidates")
    if scope is QueryScope.IMPLEMENTATION_ONLY:
        if evidence_set.protocol_context:
            violations.append("an implementation_only answer cannot contain threat context")
        if KnowledgeScope.PROTOCOL_THREAT_CONTEXT in claim_scopes:
            violations.append("an implementation_only answer cannot make threat-context claims")

    implementation_ranks: list[int] = []
    for investigation_candidate in evidence_set.implementation_candidates:
        implementation_ranks.append(investigation_candidate.rank)
    violations.extend(find_rank_violations("implementation candidate", implementation_ranks))
    excluded_ranks: list[int] = []
    for excluded_candidate in evidence_set.excluded_implementation_candidates:
        excluded_ranks.append(excluded_candidate.candidate.rank)
    violations.extend(find_rank_violations("excluded candidate", excluded_ranks))

    interpretation = evidence_set.interpretation
    is_topic_resolved = bool(interpretation.resolution.matches)
    for investigation_candidate in list_investigation_candidates(evidence_set):
        cve_id = investigation_candidate.candidate.record.cve_id
        is_assessed = investigation_candidate.relevance is not None
        if is_assessed and not is_topic_resolved:
            violations.append(f"{cve_id}: relevance is assessed only when a topic resolved")
        if not is_assessed and is_topic_resolved and cve_id not in interpretation.cve_ids:
            violations.append(
                f"{cve_id}: relevance is assessed for every candidate the caller did not name"
            )
    return violations


def describe_claim_content(claim: Claim) -> ClaimContent:
    return (
        claim.subject_id,
        claim.scope,
        claim.assertion_kind,
        claim.statement,
        tuple(claim.evidence_ids),
    )


def list_expected_claims(evidence_set: KnowledgeEvidenceSet) -> dict[str, ClaimContent]:
    """The templated claim of every answer item, by claim_id."""
    anchors_by_id = index_anchors(evidence_set.evidence)
    expected_claims: dict[str, ClaimContent] = {}
    for investigation_candidate in evidence_set.implementation_candidates:
        record = investigation_candidate.candidate.record
        expected_claims[format_implementation_claim_id(record.cve_id)] = (
            record.cve_id,
            KnowledgeScope.IMPLEMENTATION_VULNERABILITY,
            AssertionKind.ASSERTED,
            format_implementation_statement(record.cve_id),
            list_record_evidence_ids(record, anchors_by_id),
        )
    for item in evidence_set.protocol_context:
        expected_claims[format_threat_context_claim_id(item.technique_id)] = (
            item.technique_id,
            KnowledgeScope.PROTOCOL_THREAT_CONTEXT,
            AssertionKind.ASSERTED,
            format_threat_context_statement(item),
            tuple(item.evidence_ids),
        )
    return expected_claims


def find_citation_violations(evidence_set: KnowledgeEvidenceSet) -> list[str]:
    """One templated claim per answer item, and evidence exactly as cited."""
    violations: list[str] = []
    expected_claims = list_expected_claims(evidence_set)
    claim_ids: list[str] = []
    # A claim is named by its position: its ID is text the set's author chose.
    for claim_index, claim in enumerate(evidence_set.claims):
        claim_ids.append(claim.claim_id)
        expected_claim = expected_claims.get(claim.claim_id)
        if expected_claim is None:
            violations.append(f"claims[{claim_index}]: no answer item for this claim")
        elif describe_claim_content(claim) != expected_claim:
            violations.append(
                f"claims[{claim_index}]: differs from the templated claim of its item"
            )
    if claim_ids != sorted(expected_claims):
        violations.append("claims must be exactly one per answer item, ordered by claim_id")

    cited_ids: set[str] = set()
    for cve_candidate in list_cve_candidates(evidence_set):
        cited_ids.update(cve_candidate.record.evidence_ids)
    for item in evidence_set.protocol_context:
        cited_ids.update(item.evidence_ids)
    for claim in evidence_set.claims:
        cited_ids.update(claim.evidence_ids)
    evidence_ids: list[str] = []
    for anchor in evidence_set.evidence:
        evidence_ids.append(anchor.evidence_id)
    if evidence_ids != sorted(cited_ids):
        violations.append("evidence must be exactly the cited anchors, ordered by evidence_id")
    if evidence_set.trajectory.evidence_ids != tuple(evidence_ids):
        violations.append("trajectory.evidence_ids must list the evidence IDs in order")

    admitted_answer_ids = list_admitted_answer_ids(evidence_set)
    answer_ids: list[str] = []
    for cve_candidate in list_cve_candidates(evidence_set):
        answer_ids.append(cve_candidate.record.cve_id)
    for item in evidence_set.protocol_context:
        answer_ids.append(item.technique_id)
    for answer_id in answer_ids:
        if answer_id not in admitted_answer_ids:
            violations.append(f"{answer_id}: not returned by any admitted step")

    admitted_step_indices: set[int] = set()
    for step in evidence_set.trajectory.steps:
        if step.admission is StepAdmission.ADMITTED:
            admitted_step_indices.add(step.step_index)
    for investigation_candidate in list_investigation_candidates(evidence_set):
        for step_index in investigation_candidate.found_by_steps:
            if step_index not in admitted_step_indices:
                violations.append(
                    f"{investigation_candidate.candidate.record.cve_id}: found by step "
                    f"{step_index}, which is not an admitted step"
                )
    return violations


def find_step_evidence_violations(
    evidence_set: KnowledgeEvidenceSet, evidence_catalog: EvidenceCatalog
) -> list[str]:
    """Every evidence ID a step records is held by the catalog, every answer ID it records
    has an anchor among them, and every anchor of the answer was returned by an admitted
    step."""
    violations: list[str] = []
    admitted_evidence_ids: set[str] = set()
    for step in evidence_set.trajectory.steps:
        anchored_record_ids: set[str] = set()
        for evidence_id in step.evidence_ids:
            catalogued_anchor = evidence_catalog.get_evidence(evidence_id)
            if catalogued_anchor is None:
                violations.append(
                    f"step {step.step_index} returns evidence {evidence_id}, which this "
                    "service's sources do not hold"
                )
            else:
                anchored_record_ids.add(catalogued_anchor.authoritative_record_id)
        for answer_index, answer_id in enumerate(step.answer_ids):
            if answer_id not in anchored_record_ids:
                violations.append(
                    f"step {step.step_index} answer_ids[{answer_index}]: returned without a "
                    "catalogued anchor for it"
                )
        if step.admission is StepAdmission.ADMITTED:
            admitted_evidence_ids.update(step.evidence_ids)
    for anchor in evidence_set.evidence:
        if anchor.evidence_id not in admitted_evidence_ids:
            violations.append(f"{anchor.evidence_id}: not returned by any admitted step")
    return violations


def find_step_outcome_violations(step: ToolStep) -> list[str]:
    """A step that got a response records one outcome per source it consulted, in the
    order it names them; a step without one records none."""
    outcome_sources: list[KnowledgeSource] = []
    for outcome in step.source_outcomes:
        outcome_sources.append(outcome.source)
    expected_sources: list[KnowledgeSource] = []
    if step.admission not in RESPONSELESS_ADMISSIONS:
        expected_sources.extend(step.sources)
    if outcome_sources != expected_sources:
        return [f"step {step.step_index} records an outcome for other sources than it consulted"]
    return []


def find_search_warning_violations(step: ToolStep, evidence_catalog: EvidenceCatalog) -> list[str]:
    """Once its exact-ID channel ran, a search warns ``unknown_cve_id`` for exactly the IDs
    it looked up that the catalog does not hold, in lookup order; it warns
    ``excluded_by_filters`` only for an ID it looked up that the catalog holds and it did
    not return, and ``term_not_indexed`` only for one of the search terms its lexical
    channel was sent. A term the warning leaves out, or one a record does hold, shows only on
    replay."""
    looked_up_ids: list[str] = []
    if isinstance(step.call, CveExactLookupCall | CveSearchCall):
        looked_up_ids = find_cve_ids(format_cve_tool_query(step.call))
    search_terms: list[str] = []
    if isinstance(step.call, CveSearchCall):
        search_terms = list_query_terms(step.call.query)
    ran_lexical = RetrievalChannel.LEXICAL in step.channels_executed
    unknown_ids: list[str] = []
    for looked_up_id in looked_up_ids:
        if evidence_catalog.get_cve(looked_up_id) is None:
            unknown_ids.append(looked_up_id)
    violations: list[str] = []
    warned_unknown_ids: list[str] = []
    # A warning is named by its position: its subject is text the set's author chose.
    for warning_index, search_warning in enumerate(step.search_warnings):
        warning_label = f"step {step.step_index} search_warnings[{warning_index}]"
        subject = search_warning.subject
        if search_warning.code is SearchWarningCode.UNKNOWN_CVE_ID:
            warned_unknown_ids.append(subject)
            if subject not in unknown_ids:
                violations.append(
                    f"{warning_label}: warns of an unknown ID that is not one the step looked "
                    "up that the catalog lacks"
                )
        if search_warning.code is SearchWarningCode.EXCLUDED_BY_FILTERS:
            is_held_and_unreturned = (
                subject in looked_up_ids
                and subject not in unknown_ids
                and subject not in step.answer_ids
            )
            if not is_held_and_unreturned:
                violations.append(
                    f"{warning_label}: warns of an ID excluded by the filters that is not one "
                    "the step looked up, the catalog holds and the step did not return"
                )
        is_unindexed_warning = search_warning.code is SearchWarningCode.TERM_NOT_INDEXED
        if is_unindexed_warning and (subject not in search_terms or not ran_lexical):
            violations.append(
                f"{warning_label}: warns of an unindexed term that is not one of the search "
                "terms its lexical channel was sent"
            )
    ran_exact_id = RetrievalChannel.EXACT_ID in step.channels_executed
    if ran_exact_id and warned_unknown_ids != unknown_ids:
        violations.append(
            f"step {step.step_index} does not warn unknown_cve_id for exactly the IDs it looked "
            "up that the catalog lacks"
        )
    return violations


def find_semantic_channel_violations(step: ToolStep, request: InvestigationRequest) -> list[str]:
    """A CVE search under a semantic request runs the semantic channel beside the lexical
    one (both need searchable terms), and no other search runs it."""
    runs_semantic = (
        request.semantic
        and isinstance(step.call, CveSearchCall)
        and RetrievalChannel.LEXICAL in step.channels_executed
    )
    if (RetrievalChannel.SEMANTIC in step.channels_executed) != runs_semantic:
        return [
            f"step {step.step_index} records the semantic channel where the request does not "
            "run it, or omits it where it does"
        ]
    return []


def find_step_observation_violations(
    evidence_set: KnowledgeEvidenceSet, evidence_catalog: EvidenceCatalog
) -> list[str]:
    """What each step observed agrees with its call, the request and the catalog."""
    violations: list[str] = []
    for step in evidence_set.trajectory.steps:
        violations.extend(find_step_outcome_violations(step))
        violations.extend(find_search_warning_violations(step, evidence_catalog))
        violations.extend(find_semantic_channel_violations(step, evidence_set.request))
    return violations


def find_applicability_violations(evidence_set: KnowledgeEvidenceSet) -> list[str]:
    """One ``unknown`` entry and one warning per named vendor, product and purl, in order."""
    violations: list[str] = []
    filters = evidence_set.request.filters
    is_assessed = (
        evidence_set.request.scope is not QueryScope.PROTOCOL_CONTEXT_ONLY
        and evidence_set.stop_reason is not StopReason.INVALID_EVIDENCE
    )
    expected_products: list[tuple[str, str]] = []
    if is_assessed:
        expected_products.extend(list_named_products(filters))
    assessed_products: list[tuple[str, str]] = []
    for applicability_index, applicability in enumerate(evidence_set.product_applicability):
        assessed_products.append((applicability.product_kind, applicability.product))
        if applicability.status is not ApplicabilityStatus.UNKNOWN:
            violations.append(
                f"product_applicability[{applicability_index}]: applicability must be unknown "
                "without an affectedness source"
            )
    if assessed_products != expected_products:
        violations.append("product_applicability must list each named product once, in order")
    unknown_subjects: list[str] = []
    for warning in evidence_set.warnings:
        if warning.code is InvestigationWarningCode.APPLICABILITY_UNKNOWN:
            unknown_subjects.append(warning.subject)
    expected_subjects: list[str] = []
    for _, product in expected_products:
        expected_subjects.append(product)
    if unknown_subjects != expected_subjects:
        violations.append("each assessed product needs one applicability_unknown warning")
    return violations


def find_stop_violations(evidence_set: KnowledgeEvidenceSet) -> list[str]:
    violations: list[str] = []
    stop_reason = evidence_set.stop_reason
    status = evidence_set.status
    has_answer = evidence_set.has_answer()
    coverage = evidence_set.coverage
    answer_sources = list_answer_sources(evidence_set.request.scope, evidence_set.request.filters)
    if coverage.answer_sources != answer_sources:
        violations.append("coverage.answer_sources do not match the request")
    outcome_statuses: list[ResultStatus] = []
    outcome_sources: list[KnowledgeSource] = []
    for outcome in coverage.source_outcomes:
        outcome_statuses.append(outcome.status)
        outcome_sources.append(outcome.source)
        if outcome.source not in answer_sources:
            violations.append(f"coverage names {outcome.source}, which is not an answer source")
    if len(set(outcome_sources)) != len(outcome_sources):
        violations.append("coverage names a source more than once")
    has_failure = any(outcome_status not in SERVED_STATUSES for outcome_status in outcome_statuses)

    if status not in STATUSES_BY_STOP_REASON[stop_reason]:
        violations.append(f"status {status} cannot report stop reason {stop_reason}")
    expected_status = decide_investigation_status(stop_reason, has_answer, outcome_statuses)
    if status is not expected_status:
        violations.append(f"status {status} should be {expected_status}")
    violations.extend(find_status_violations(status, has_answer, has_failure))

    if stop_reason is StopReason.INVALID_EVIDENCE:
        has_rejected_step = any(
            step.admission is StepAdmission.REJECTED_INVALID_EVIDENCE
            for step in evidence_set.trajectory.steps
        )
        if (
            has_answer
            or evidence_set.excluded_implementation_candidates
            or evidence_set.claims
            or evidence_set.evidence
            or evidence_set.product_applicability
            or not has_rejected_step
        ):
            violations.append(
                "invalid_evidence returns nothing and needs a step rejected for invalid evidence"
            )
    if stop_reason is StopReason.NO_EVIDENCE and (has_answer or has_failure):
        violations.append("no_evidence holds no answer and no failed source")
    is_breached = evidence_set.trajectory.budget_used.breach is not None
    if (stop_reason is StopReason.BUDGET_EXHAUSTED) != is_breached:
        violations.append("budget_exhausted is the stop reason exactly when a cap was breached")
    return violations


def find_trajectory_violations(evidence_set: KnowledgeEvidenceSet) -> list[str]:
    """A legal walk from interpret to return, then well-formed, bounded steps."""
    violations: list[str] = []
    trajectory = evidence_set.trajectory
    budget = evidence_set.request.budget
    transitions = trajectory.transitions
    if not transitions or transitions[0].from_state is not InvestigationState.INTERPRET:
        violations.append("transitions must start at interpret")
    last_transition = transitions[-1] if transitions else None
    if last_transition is None or (
        last_transition.from_state is not InvestigationState.VALIDATE
        or last_transition.to_state is not InvestigationState.RETURN
    ):
        violations.append("transitions must end validate -> return")
    previous_state: InvestigationState | None = None
    stop_basis: DecisionBasis | None = None
    refine_count = 0
    has_assess_refine = False
    for transition in transitions:
        edge = (transition.from_state, transition.to_state)
        if edge not in ALLOWED_TRANSITIONS:
            violations.append(f"illegal transition {edge[0]} -> {edge[1]}")
        if previous_state is not None and transition.from_state is not previous_state:
            violations.append(f"transition from {transition.from_state} does not follow on")
        previous_state = transition.to_state
        if transition.to_state is InvestigationState.REFINE:
            refine_count += 1
            has_assess_refine = transition.from_state is InvestigationState.ASSESS
        if transition.to_state is InvestigationState.VALIDATE:
            stop_basis = transition.basis
    if refine_count > 1:
        violations.append("refine may be entered at most once")
    if stop_basis is not evidence_set.coverage.basis:
        violations.append("coverage.basis must be the basis of the transition into validate")

    round_numbers: list[int] = []
    for round_record in trajectory.rounds:
        round_numbers.append(round_record.round_number)
    if round_numbers != list(range(1, len(round_numbers) + 1)):
        violations.append(f"rounds are numbered {round_numbers}, expected 1..n")
    if len(round_numbers) > budget.max_rounds:
        violations.append(f"{len(round_numbers)} rounds exceed max_rounds {budget.max_rounds}")

    previous_round = 1
    call_keys: set[str] = set()
    ending_step_index: int | None = None
    for expected_index, step in enumerate(trajectory.steps, start=1):
        if step.step_index != expected_index:
            violations.append(f"step {step.step_index} should be numbered {expected_index}")
        # A step that is not admitted stops the run, so nothing runs after it.
        if ending_step_index is not None:
            violations.append(
                f"step {step.step_index} runs after step {ending_step_index}, which was not "
                "admitted"
            )
        if ending_step_index is None and step.admission is not StepAdmission.ADMITTED:
            ending_step_index = step.step_index
        if step.round_number < previous_round:
            violations.append(f"step {step.step_index} goes back to round {step.round_number}")
        previous_round = step.round_number
        if step.round_number > budget.max_rounds:
            violations.append(f"step {step.step_index} runs beyond max_rounds")
        if step.round_number == 2 and not has_assess_refine:
            violations.append(f"step {step.step_index} runs round 2 without an assess -> refine")
        if step.call_key != compute_call_key(step.call):
            violations.append(f"step {step.step_index}'s call_key is not derived from its call")
        if step.call_key in call_keys:
            violations.append(f"step {step.step_index} repeats an issued call")
        call_keys.add(step.call_key)
    runs_round_two = any(step.round_number == 2 for step in trajectory.steps)
    if evidence_set.coverage.refinement_applied != runs_round_two:
        violations.append("coverage.refinement_applied must say whether a round-2 step ran")
    return violations


def find_round_step_violations(
    round_record: RoundRecord, round_steps: list[ToolStep], is_wall_time_breach: bool
) -> list[str]:
    """The round lists exactly its steps, which run the leading calls of its accepted plan
    in order, each planned by the planner the round's outcome names with a reason that
    planner gives its tool in this round. Calls are left unrun only when a step was not
    admitted or the deadline was reached."""
    violations: list[str] = []
    round_number = round_record.round_number
    planner_outcome = round_record.planner_outcome
    step_indices: list[int] = []
    step_calls: list[ToolCall] = []
    for step in round_steps:
        step_indices.append(step.step_index)
        step_calls.append(step.call)
    if tuple(step_indices) != round_record.executed_step_indices:
        violations.append(
            f"round {round_number} lists steps {list(round_record.executed_step_indices)}, "
            f"but its steps are {step_indices}"
        )
    accepted_plan = round_record.accepted_plan
    if step_calls and not accepted_plan:
        violations.append(f"round {round_number} runs steps without an accepted plan")
    elif tuple(step_calls) != accepted_plan[: len(step_calls)]:
        violations.append(
            f"round {round_number}'s steps do not run the leading calls of its accepted plan "
            "in order"
        )
    if len(step_calls) < len(accepted_plan):
        stopped_on_step = bool(round_steps) and (
            round_steps[-1].admission is not StepAdmission.ADMITTED
        )
        if not stopped_on_step and not is_wall_time_breach:
            violations.append(
                f"round {round_number} leaves calls of its accepted plan unrun, though every "
                "step was admitted and the deadline was not reached"
            )
    expected_planner = PlannerKind.DETERMINISTIC
    if planner_outcome is PlannerOutcome.MODEL_ACCEPTED:
        expected_planner = PlannerKind.MODEL
    for step in round_steps:
        if step.planned_by is not expected_planner:
            violations.append(
                f"step {step.step_index} is planned by {step.planned_by}, but round "
                f"{round_number}'s planner outcome is {planner_outcome}"
            )
        is_model_reason = step.reason is StepReason.MODEL_PROPOSAL
        if is_model_reason != (step.planned_by is PlannerKind.MODEL):
            violations.append(
                f"step {step.step_index}'s reason {step.reason} does not match its planner "
                f"{step.planned_by}"
            )
        policy_tool_and_round = POLICY_STEP_TOOL_AND_ROUND.get(step.reason)
        step_tool_and_round = (step.call.tool, step.round_number)
        if policy_tool_and_round is not None and step_tool_and_round != policy_tool_and_round:
            policy_tool, policy_round = policy_tool_and_round
            violations.append(
                f"step {step.step_index}'s reason {step.reason} is given to {policy_tool} in "
                f"round {policy_round}, not to {step.call.tool} in round {step.round_number}"
            )
    return violations


def find_rejection_violations(round_record: RoundRecord) -> list[str]:
    """A rejection is recorded exactly when the outcome says a plan was rejected: a rejected
    model reply records why, first; an accepted, skipped or deterministic plan records
    none, unless the policy's own plan was rejected and the round runs nothing."""
    violations: list[str] = []
    round_number = round_record.round_number
    planner_outcome = round_record.planner_outcome
    rejection_codes: list[PlanRejectionCode] = []
    for rejection in round_record.rejections:
        rejection_codes.append(rejection.code)
    if planner_outcome in REJECTED_MODEL_OUTCOMES:
        expected_first_code = FIRST_REJECTION_BY_OUTCOME.get(planner_outcome)
        if not rejection_codes:
            violations.append(f"round {round_number} is {planner_outcome} but records no rejection")
        elif expected_first_code is not None and rejection_codes[0] is not expected_first_code:
            violations.append(
                f"round {round_number} is {planner_outcome}, so its first rejection is "
                f"{expected_first_code}"
            )
        elif expected_first_code is None and rejection_codes[0] in FIXED_FIRST_REJECTION_CODES:
            violations.append(
                f"round {round_number} is {planner_outcome}, but its first rejection is "
                f"{rejection_codes[0]}"
            )
        return violations
    for rejection_code in rejection_codes:
        if rejection_code in MODEL_REPLY_REJECTION_CODES:
            violations.append(
                f"round {round_number} records {rejection_code}, but its outcome "
                f"{planner_outcome} rejected no model reply"
            )
    runs_no_plan = not round_record.accepted_plan
    is_policy_plan_rejected = planner_outcome is PlannerOutcome.DETERMINISTIC and runs_no_plan
    if rejection_codes and not is_policy_plan_rejected:
        violations.append(
            f"round {round_number} is {planner_outcome} and runs its plan, but records rejections"
        )
    return violations


def find_model_reply_violations(round_record: RoundRecord) -> list[str]:
    """A round records the model's reply exactly when the model gave one, in time or not,
    with the reply's own hash. Violations name the round, never the reply's text."""
    violations: list[str] = []
    round_number = round_record.round_number
    planner_outcome = round_record.planner_outcome
    model_reply = round_record.model_reply
    if model_reply is not None and planner_outcome not in REPLIED_MODEL_OUTCOMES:
        violations.append(
            f"round {round_number} records a reply its {planner_outcome} planner never gave"
        )
    if model_reply is None and planner_outcome in REPLIED_MODEL_OUTCOMES:
        violations.append(
            f"round {round_number} is {planner_outcome} but does not record the model's reply"
        )
    if model_reply is None:
        if round_record.model_reply_sha256 is not None:
            violations.append(f"round {round_number} hashes a reply it does not record")
    elif round_record.model_reply_sha256 != compute_model_reply_sha256(model_reply):
        violations.append(
            f"round {round_number}'s model_reply_sha256 is not the hash of its recorded reply"
        )
    return violations


def find_round_violations(evidence_set: KnowledgeEvidenceSet) -> list[str]:
    """Rounds and steps record one run: every step belongs to a recorded round, each
    round's outcome is one the trajectory's planner records, and the rounds, planner
    calls and ``plan_accepted`` transitions are counted from the rounds."""
    violations: list[str] = []
    trajectory = evidence_set.trajectory
    planner_kind = trajectory.planner.kind
    is_wall_time_breach = trajectory.budget_used.breach is BudgetBreach.WALL_TIME
    round_steps_by_number: dict[int, list[ToolStep]] = {}
    for step in trajectory.steps:
        round_steps_by_number.setdefault(step.round_number, []).append(step)
    consulted_rounds = 0
    planned_rounds = 0
    for round_record in trajectory.rounds:
        planner_outcome = round_record.planner_outcome
        if planner_outcome not in PLANNER_OUTCOMES_BY_KIND[planner_kind]:
            violations.append(
                f"round {round_record.round_number}'s planner outcome {planner_outcome} is not "
                f"one a {planner_kind} planner records"
            )
        if planner_outcome in CONSULTED_MODEL_OUTCOMES:
            consulted_rounds += 1
        if round_record.accepted_plan:
            planned_rounds += 1
        round_steps = round_steps_by_number.pop(round_record.round_number, [])
        violations.extend(
            find_round_step_violations(round_record, round_steps, is_wall_time_breach)
        )
        violations.extend(find_rejection_violations(round_record))
        violations.extend(find_model_reply_violations(round_record))
    for round_number, unrecorded_steps in round_steps_by_number.items():
        for step in unrecorded_steps:
            violations.append(
                f"step {step.step_index} runs in round {round_number}, which has no round record"
            )

    usage = trajectory.budget_used
    if usage.rounds != len(trajectory.rounds):
        violations.append(
            f"budget_used.rounds {usage.rounds} differs from the {len(trajectory.rounds)} "
            "rounds recorded"
        )
    if usage.planner_calls != consulted_rounds:
        violations.append(
            f"planner_calls {usage.planner_calls} differ from the {consulted_rounds} rounds "
            "that consulted the model"
        )
    plan_accepted_transitions = 0
    for transition in trajectory.transitions:
        if transition.basis is DecisionBasis.PLAN_ACCEPTED:
            plan_accepted_transitions += 1
    if plan_accepted_transitions != planned_rounds:
        violations.append(
            f"{plan_accepted_transitions} plan_accepted transitions for {planned_rounds} rounds "
            "with an accepted plan"
        )
    return violations


def find_round_transition_violations(evidence_set: KnowledgeEvidenceSet) -> list[str]:
    """Rounds follow the state machine: round 1 is planned on interpret -> plan, round 2 on
    assess -> refine. A model planner allowed two rounds is consulted again whenever the
    run refines, so that refinement records round 2."""
    violations: list[str] = []
    trajectory = evidence_set.trajectory
    has_interpret_plan = False
    has_assess_refine = False
    for transition in trajectory.transitions:
        edge = (transition.from_state, transition.to_state)
        if edge == (InvestigationState.INTERPRET, InvestigationState.PLAN):
            has_interpret_plan = True
        if edge == (InvestigationState.ASSESS, InvestigationState.REFINE):
            has_assess_refine = True
    recorded_round_numbers: set[int] = set()
    for round_record in trajectory.rounds:
        recorded_round_numbers.add(round_record.round_number)
    if (1 in recorded_round_numbers) != has_interpret_plan:
        violations.append("round 1 is recorded exactly when the run moves interpret -> plan")
    if 2 in recorded_round_numbers and not has_assess_refine:
        violations.append("round 2 is recorded without an assess -> refine")
    consults_model_on_refine = (
        trajectory.planner.kind is PlannerKind.MODEL and evidence_set.request.budget.max_rounds >= 2
    )
    if consults_model_on_refine and has_assess_refine and 2 not in recorded_round_numbers:
        violations.append(
            "the run refines under a model planner allowed two rounds, but records no round 2"
        )
    return violations


def find_policy_round_violations(evidence_set: KnowledgeEvidenceSet) -> list[str]:
    """A round the policy planned runs its plan, unless the gate rejected that plan (and the
    run stopped ``policy_blocked`` or ``budget_exhausted``) or the deadline was reached."""
    violations: list[str] = []
    trajectory = evidence_set.trajectory
    is_wall_time_breach = trajectory.budget_used.breach is BudgetBreach.WALL_TIME
    for round_record in trajectory.rounds:
        if round_record.planner_outcome is not PlannerOutcome.DETERMINISTIC:
            continue
        round_number = round_record.round_number
        if round_record.rejections and evidence_set.stop_reason not in REJECTED_POLICY_PLAN_STOPS:
            violations.append(
                f"round {round_number} records the policy plan's rejection, but the run stops "
                f"{evidence_set.stop_reason}"
            )
        runs_no_plan = not round_record.accepted_plan
        if runs_no_plan and not round_record.rejections and not is_wall_time_breach:
            violations.append(
                f"round {round_number} runs no plan, though its plan was not rejected and the "
                "deadline was not reached"
            )
    return violations


def find_accepted_plan_violations(evidence_set: KnowledgeEvidenceSet) -> list[str]:
    """No call is accepted twice across the run's plans, and none the scope does not permit."""
    violations: list[str] = []
    scope = evidence_set.request.scope
    accepted_call_keys: set[str] = set()
    for round_record in evidence_set.trajectory.rounds:
        round_number = round_record.round_number
        for call in round_record.accepted_plan:
            call_key = compute_call_key(call)
            if call_key in accepted_call_keys:
                violations.append(f"round {round_number} accepts a {call.tool} call twice")
            accepted_call_keys.add(call_key)
            if not is_tool_permitted(call, scope):
                violations.append(f"round {round_number} accepts {call.tool}, which {scope} bars")
    return violations


def find_backend_request_violations(step: ToolStep, request: InvestigationRequest) -> list[str]:
    """One charged tool call per backend request, each within the result cap; the
    requests' sources, in first-sent order, are the step's sources, which are those its
    call consults under the scope; and a CVE tool sends one search, its call's query at
    the result cap. A topic step's searches come from its card, which the set does not
    carry; the decision-path audit rebuilds them from the registry."""
    violations: list[str] = []
    max_results_per_call = request.budget.max_results_per_call
    request_sources: list[KnowledgeSource] = []
    for backend_request in step.backend_requests:
        if backend_request.limit > max_results_per_call:
            violations.append(
                f"step {step.step_index} asks {backend_request.source} for "
                f"{backend_request.limit} results, more than max_results_per_call"
            )
        if backend_request.source not in request_sources:
            request_sources.append(backend_request.source)
    if len(step.backend_requests) != step.charged_tool_calls:
        violations.append(
            f"step {step.step_index} is charged {step.charged_tool_calls} tool calls for "
            f"{len(step.backend_requests)} backend requests"
        )
    if tuple(request_sources) != step.sources:
        violations.append(f"step {step.step_index} sends requests to other sources than it names")
    if step.sources != list_tool_sources(step.call, request.scope):
        violations.append(
            f"step {step.step_index} names other sources than its call consults under the scope"
        )
    if isinstance(step.call, CveExactLookupCall | CveSearchCall):
        sent_request = CveBackendRequest(
            source=KnowledgeSource.CVE_SEARCH,
            query=format_cve_tool_query(step.call),
            limit=max_results_per_call,
        )
        if step.backend_requests != (sent_request,):
            violations.append(
                f"step {step.step_index} records other backend requests than its call sends"
            )
    return violations


def find_deadline_violations(evidence_set: KnowledgeEvidenceSet) -> list[str]:
    """A step or planner call that ran into the deadline, or a model planner skipped at it,
    makes ``wall_time`` the breach, and such a round runs no plan."""
    violations: list[str] = []
    trajectory = evidence_set.trajectory
    is_wall_time_breach = trajectory.budget_used.breach is BudgetBreach.WALL_TIME
    for step in trajectory.steps:
        if step.admission in DEADLINE_ADMISSIONS and not is_wall_time_breach:
            violations.append(
                f"step {step.step_index} ran into the deadline, but the breach is not wall_time"
            )
    for round_record in trajectory.rounds:
        planner_outcome = round_record.planner_outcome
        if planner_outcome not in DEADLINE_PLANNER_OUTCOMES:
            continue
        round_number = round_record.round_number
        if not is_wall_time_breach:
            violations.append(
                f"round {round_number}'s planner ran into the deadline, but the breach is not "
                "wall_time"
            )
        if round_record.accepted_plan or round_record.executed_step_indices:
            violations.append(
                f"round {round_number} runs a plan after its planner ran into the deadline"
            )
    return violations


def find_budget_violations(evidence_set: KnowledgeEvidenceSet) -> list[str]:
    violations: list[str] = []
    budget = evidence_set.request.budget
    usage = evidence_set.trajectory.budget_used
    steps = evidence_set.trajectory.steps
    if usage.rounds > budget.max_rounds or usage.planner_calls > budget.max_rounds:
        violations.append("rounds or planner calls exceed max_rounds")
    if usage.tool_calls > budget.max_tool_calls:
        violations.append("tool calls exceed max_tool_calls")
    if len(usage.sources) > budget.max_sources:
        violations.append("sources exceed max_sources")
    if usage.context_bytes > budget.max_context_bytes:
        violations.append("context bytes exceed max_context_bytes")

    charged_tool_calls = 0
    consulted_sources: list[KnowledgeSource] = []
    admitted_context_bytes = 0
    for step in steps:
        violations.extend(find_backend_request_violations(step, evidence_set.request))
        charged_tool_calls += step.charged_tool_calls
        for source in step.sources:
            if source not in consulted_sources:
                consulted_sources.append(source)
        # A step is discarded over the byte cap exactly when it would push the admitted
        # bytes past it; an admitted step that would is caught by the usage checks.
        fits_byte_cap = admitted_context_bytes + step.context_bytes <= budget.max_context_bytes
        if step.admission is StepAdmission.DISCARDED_OVER_CONTEXT_BUDGET and fits_byte_cap:
            violations.append(
                f"step {step.step_index} was discarded over max_context_bytes, but its "
                f"{step.context_bytes} bytes fit beside the {admitted_context_bytes} admitted"
            )
        if step.admission is StepAdmission.ADMITTED:
            admitted_context_bytes += step.context_bytes
    if usage.tool_calls != charged_tool_calls:
        violations.append(
            f"tool_calls {usage.tool_calls} differ from the {charged_tool_calls} charged"
        )
    if usage.sources != tuple(consulted_sources):
        violations.append("sources must be the steps' sources in first-consulted order")
    if usage.context_bytes != admitted_context_bytes:
        violations.append("context_bytes must be the sum over admitted steps")

    planner_duration_count = len(evidence_set.timings.planner_durations_ms)
    if planner_duration_count != usage.planner_calls:
        violations.append(
            f"timings hold {planner_duration_count} planner durations for "
            f"{usage.planner_calls} planner calls"
        )
    deadline_ms = budget.max_wall_time_seconds * 1000
    # The seal reads the elapsed time after the run found the deadline, so a wall_time
    # breach, wherever it was found (planner, step start, call or finish), ends a run that
    # took at least the cap.
    if usage.breach is BudgetBreach.WALL_TIME and evidence_set.timings.wall_time_ms < deadline_ms:
        violations.append("the run found the deadline, but its wall time is under the cap")

    timed_step_indices: list[int] = []
    for step_timing in evidence_set.timings.steps:
        timed_step_indices.append(step_timing.step_index)
    if timed_step_indices != list(range(1, len(steps) + 1)):
        violations.append("timings must hold one entry per step, in step order")
        return violations
    # Both comparisons include the deadline itself, so either rounding of a finish
    # time that falls on it to whole milliseconds passes.
    for step, step_timing in zip(steps, evidence_set.timings.steps, strict=True):
        finished_ms = step_timing.started_offset_ms + step_timing.duration_ms
        if step.admission is StepAdmission.ADMITTED and finished_ms > deadline_ms:
            violations.append(f"step {step.step_index} was admitted after the deadline")
        # The deadline is checked before the byte cap, so a step past it is never weighed.
        if step.admission is StepAdmission.DISCARDED_OVER_CONTEXT_BUDGET and (
            finished_ms > deadline_ms
        ):
            violations.append(
                f"step {step.step_index} was discarded over max_context_bytes after the deadline"
            )
        if step.admission is StepAdmission.DISCARDED_AFTER_DEADLINE and finished_ms < deadline_ms:
            violations.append(f"step {step.step_index} was discarded before the deadline")
        if step.admission is StepAdmission.TIMED_OUT and finished_ms < deadline_ms:
            violations.append(f"step {step.step_index} timed out before the deadline")
    return violations


def list_served_fight_outcomes(evidence_set: KnowledgeEvidenceSet) -> list[SourceOutcome]:
    """Every served FiGHT outcome the set records: the coverage's, then each step's."""
    recorded_outcomes = list(evidence_set.coverage.source_outcomes)
    for step in evidence_set.trajectory.steps:
        recorded_outcomes.extend(step.source_outcomes)
    served_fight_outcomes: list[SourceOutcome] = []
    for outcome in recorded_outcomes:
        if outcome.source is KnowledgeSource.MITRE_FIGHT and outcome.status in SERVED_STATUSES:
            served_fight_outcomes.append(outcome)
    return served_fight_outcomes


def find_investigation_fight_violations(
    evidence_set: KnowledgeEvidenceSet, pinned_fight_snapshot: KnownFightSnapshot | None
) -> list[str]:
    """FiGHT evidence and a served FiGHT outcome require, and match, the deployment's pin."""
    fight_anchors: list[EvidenceAnchor] = []
    for anchor in evidence_set.evidence:
        if anchor.source_type is SourceType.MITRE_FIGHT_YAML:
            fight_anchors.append(anchor)
    served_fight_outcomes = list_served_fight_outcomes(evidence_set)
    if not fight_anchors and not served_fight_outcomes:
        return []
    if pinned_fight_snapshot is None:
        return ["FiGHT evidence was served but no FiGHT snapshot is pinned"]
    violations: list[str] = []
    for outcome in served_fight_outcomes:
        if (
            outcome.source_version != pinned_fight_snapshot.source_version
            or outcome.coverage is not pinned_fight_snapshot.coverage
        ):
            violations.append("the FiGHT outcome names another snapshot than the pinned one")
    violations.extend(
        find_pinned_fight_violations(
            fight_anchors, evidence_set.protocol_context, pinned_fight_snapshot
        )
    )
    return violations


def find_capability_violations(capability: SourceCapability) -> list[str]:
    """The capability is in a state its subject can report, with a version and a coverage
    exactly where that state names one, and a detail, one of the subject's sentences,
    exactly when it is unavailable."""
    subject = capability.source
    state = capability.state
    violations: list[str] = []
    if state not in CAPABILITY_STATES_BY_SUBJECT[subject]:
        violations.append(f"the {subject} capability cannot be {state}")
    is_available = state is SourceCapabilityState.AVAILABLE
    needs_version = is_available and subject in VERSIONED_CAPABILITY_SUBJECTS
    if (capability.version is not None) != needs_version:
        violations.append(
            f"the {subject} capability names a version exactly when it is an available "
            "cve_search, mitre_fight or model_planner"
        )
    needs_coverage = is_available and subject == KnowledgeSource.MITRE_FIGHT
    if (capability.coverage is not None) != needs_coverage:
        violations.append(
            f"the {subject} capability names a coverage exactly when it is an available mitre_fight"
        )
    is_unavailable = state is SourceCapabilityState.UNAVAILABLE
    if (capability.detail is not None) != is_unavailable:
        violations.append(f"the {subject} capability names a detail exactly when it is unavailable")
    if capability.detail is not None and (
        capability.detail not in UNAVAILABLE_DETAILS_BY_SUBJECT[subject]
    ):
        violations.append(f"the {subject} capability's detail is not one of its sentences")
    return violations


def find_capability_shape_violations(capabilities: tuple[SourceCapability, ...]) -> list[str]:
    """One capability per subject, in ``CAPABILITY_SUBJECTS`` order, each well formed
    (``find_capability_violations``)."""
    subjects: list[CapabilitySubject] = []
    for capability in capabilities:
        subjects.append(capability.source)
    violations: list[str] = []
    if tuple(subjects) != CAPABILITY_SUBJECTS:
        violations.append(
            "source_capabilities must describe "
            + ", ".join(CAPABILITY_SUBJECTS)
            + " once each, in that order"
        )
    for capability in capabilities:
        violations.extend(find_capability_violations(capability))
    return violations


def find_planner_capability_violations(
    evidence_set: KnowledgeEvidenceSet, planner_capability: SourceCapability
) -> list[str]:
    """``model_planner`` is available with the trajectory's model; when the deterministic
    policy planned, it is not configured, or unavailable with the sentence for why the
    configured model planner could not plan (the capability's shape check confines that
    detail to the planner's sentences)."""
    planner = evidence_set.trajectory.planner
    unavailable_detail = None
    if isinstance(planner_capability.detail, ModelPlannerUnavailableDetail):
        unavailable_detail = planner_capability.detail
    if planner_capability != describe_planner_capability(planner, unavailable_detail):
        return [
            "the model_planner capability does not describe the trajectory's "
            f"{planner.kind} planner"
        ]
    return []


def find_fight_capability_violations(
    evidence_set: KnowledgeEvidenceSet,
    fight_capability: SourceCapability,
    pinned_fight_snapshot: KnownFightSnapshot | None,
) -> list[str]:
    """An available ``mitre_fight`` names the pinned snapshot; an unavailable one served
    nothing. Served FiGHT outcomes are checked against the pin itself."""
    if fight_capability.state is SourceCapabilityState.AVAILABLE:
        if (
            pinned_fight_snapshot is None
            or fight_capability.version != pinned_fight_snapshot.source_version
            or fight_capability.coverage is not pinned_fight_snapshot.coverage
        ):
            return ["the mitre_fight capability names another snapshot than the pinned one"]
        return []
    if evidence_set.protocol_context or list_served_fight_outcomes(evidence_set):
        return [
            f"FiGHT served this set, but the mitre_fight capability is {fight_capability.state}"
        ]
    return []


def sends_searchable_text(step: ToolStep) -> bool:
    """Whether a CVE search the step sends has search terms (``list_query_terms``: beyond
    CVE IDs, stopwords and low-signal words), which the search service's text channels,
    the semantic one included, need to run."""
    for backend_request in step.backend_requests:
        if not isinstance(backend_request, CveBackendRequest):
            continue
        if list_query_terms(backend_request.query):
            return True
    return False


def find_semantic_failure_detail_violations(
    evidence_set: KnowledgeEvidenceSet, semantic_capability: SourceCapability
) -> list[str]:
    """A semantic channel that cannot search fails every search for the capability's
    reason: ``NOT_CONFIGURED`` when it is not configured, and when it is unavailable the
    failure its detail names (``ADAPTER_UNUSABLE`` or ``COLLECTION_NOT_BOUND``). Every
    CVE-search outcome, in the steps and the coverage, says so."""
    expected_detail = BackendFailureDetail.NOT_CONFIGURED
    # The capability rules let an unavailable semantic channel carry only its own details.
    unavailable_detail = semantic_capability.detail
    if isinstance(unavailable_detail, SemanticUnavailableDetail):
        unavailable_failure = SEMANTIC_UNAVAILABLE_FAILURES[unavailable_detail]
        expected_detail = BACKEND_FAILURE_DETAILS[unavailable_failure]
    cve_search_outcomes: list[tuple[str, SourceOutcome]] = []
    for step in evidence_set.trajectory.steps:
        for outcome in step.source_outcomes:
            cve_search_outcomes.append((f"step {step.step_index}", outcome))
    for outcome in evidence_set.coverage.source_outcomes:
        cve_search_outcomes.append(("the coverage", outcome))
    violations: list[str] = []
    for where, outcome in cve_search_outcomes:
        if outcome.source is not KnowledgeSource.CVE_SEARCH:
            continue
        for channel_failure in outcome.channel_failures:
            if (
                channel_failure.channel is RetrievalChannel.SEMANTIC
                and channel_failure.detail is not expected_detail
            ):
                violations.append(
                    f"{where} reports a semantic channel failure that does not match the "
                    f"{semantic_capability.state} semantic_channel capability"
                )
    return violations


def find_semantic_capability_violations(
    evidence_set: KnowledgeEvidenceSet, semantic_capability: SourceCapability
) -> list[str]:
    """Without a semantic channel that can search (not configured, or unavailable), a
    search that ran it reports it unavailable and no candidate carries a semantic hit. A
    semantic request runs the channel in every CVE search with searchable text, a topic's
    template searches included, and the channel's failure leaves each such step's CVE
    outcome unserved."""
    if semantic_capability.state is SourceCapabilityState.AVAILABLE:
        return []
    violations = find_semantic_failure_detail_violations(evidence_set, semantic_capability)
    is_semantic_request = evidence_set.request.semantic
    for step in evidence_set.trajectory.steps:
        if (
            RetrievalChannel.SEMANTIC in step.channels_executed
            and UNCONFIGURED_SEMANTIC_WARNING not in step.search_warnings
        ):
            violations.append(
                f"step {step.step_index} ran the semantic channel, which cannot search, "
                "without reporting it unavailable"
            )
        if not is_semantic_request or not sends_searchable_text(step):
            continue
        for outcome in step.source_outcomes:
            if outcome.source is KnowledgeSource.CVE_SEARCH and outcome.status in SERVED_STATUSES:
                violations.append(
                    f"step {step.step_index} searched under a semantic request without a "
                    f"semantic channel that can search, but reports cve_search {outcome.status}"
                )
    for investigation_candidate in list_investigation_candidates(evidence_set):
        candidate = investigation_candidate.candidate
        if any(hit.channel is RetrievalChannel.SEMANTIC for hit in candidate.channel_hits):
            violations.append(
                f"{candidate.record.cve_id} has a semantic hit, but the semantic channel "
                "cannot search"
            )
    return violations


def find_affectedness_outcome_violations(
    evidence_set: KnowledgeEvidenceSet, affectedness_capability: SourceCapability
) -> list[str]:
    """Affectedness is unavailable (its capability is always ``unavailable``), so a
    required affectedness source is reported ``source_unavailable`` once any step ran, and
    never otherwise, with the capability's detail."""
    coverage = evidence_set.coverage
    affectedness_statuses: list[ResultStatus] = []
    violations: list[str] = []
    for outcome in coverage.source_outcomes:
        if outcome.source is not KnowledgeSource.AFFECTEDNESS:
            continue
        affectedness_statuses.append(outcome.status)
        if outcome.detail != affectedness_capability.detail:
            violations.append(
                "the affectedness outcome's detail is not the affectedness capability's detail"
            )
    expected_statuses: list[ResultStatus] = []
    if KnowledgeSource.AFFECTEDNESS in coverage.answer_sources and evidence_set.trajectory.steps:
        expected_statuses.append(ResultStatus.SOURCE_UNAVAILABLE)
    if affectedness_statuses != expected_statuses:
        violations.append(
            "affectedness is unavailable: once a step ran, a required affectedness source "
            "is reported source_unavailable, and never otherwise"
        )
    return violations


def find_source_capability_violations(
    evidence_set: KnowledgeEvidenceSet,
    pinned_fight_snapshot: KnownFightSnapshot | None,
    source_capabilities: tuple[SourceCapability, ...],
) -> list[str]:
    """The set's capabilities are the deployment's, well formed, and agree with the run."""
    capabilities = evidence_set.source_capabilities
    violations: list[str] = []
    if capabilities != source_capabilities:
        violations.append("source_capabilities differ from the capabilities this service serves")
    shape_violations = find_capability_shape_violations(capabilities)
    if shape_violations:
        violations.extend(shape_violations)
        return violations
    capabilities_by_subject: dict[CapabilitySubject, SourceCapability] = {}
    for capability in capabilities:
        capabilities_by_subject[capability.source] = capability
    violations.extend(
        find_planner_capability_violations(evidence_set, capabilities_by_subject["model_planner"])
    )
    violations.extend(
        find_fight_capability_violations(
            evidence_set,
            capabilities_by_subject[KnowledgeSource.MITRE_FIGHT],
            pinned_fight_snapshot,
        )
    )
    violations.extend(
        find_semantic_capability_violations(
            evidence_set, capabilities_by_subject["semantic_channel"]
        )
    )
    violations.extend(
        find_affectedness_outcome_violations(
            evidence_set, capabilities_by_subject[KnowledgeSource.AFFECTEDNESS]
        )
    )
    return violations


def find_step_topic_warning_violations(
    step: ToolStep, pinned_fight_snapshot: KnownFightSnapshot | None
) -> list[str]:
    """The topic-response warning rules (``find_topic_warning_violations``) over what a
    topic step records: its FiGHT outcome, and the techniques and CVEs among its answer
    IDs."""
    listed_technique_count = 0
    listed_candidate_count = 0
    for answer_id in step.answer_ids:
        if re.fullmatch(FIGHT_TECHNIQUE_ID_PATTERN, answer_id):
            listed_technique_count += 1
        else:
            listed_candidate_count += 1
    violations: list[str] = []
    for violation in find_topic_warning_violations(
        step.topic_warnings,
        fight_status=find_source_status(step.source_outcomes, KnowledgeSource.MITRE_FIGHT),
        listed_technique_count=listed_technique_count,
        listed_candidate_count=listed_candidate_count,
        pinned_snapshot=pinned_fight_snapshot,
    ):
        violations.append(f"step {step.step_index}: {violation}")
    return violations


def read_topic_warning_count(step: ToolStep, code: TopicContextWarningCode) -> int:
    """The count a step's topic warning states, 0 without one or with a malformed one."""
    for warning in step.topic_warnings:
        if warning.code is code:
            return read_count_subject(warning.subject) or 0
    return 0


def find_truncation_violations(
    evidence_set: KnowledgeEvidenceSet, pinned_fight_snapshot: KnownFightSnapshot | None
) -> list[str]:
    """Truncation as a set can show it (ADR 0009 §11a): each step's topic warnings follow
    the topic-response rules; ``answer_truncated`` appears at most once, with a positive
    count, and never in a run with no adopted step; its count is at least the adopted
    topic step's two counts together; and when the answer lists fewer CVEs than the
    per-call cap, the topic step left no CVE out, so it equals the FiGHT count. Whether a
    count is true is replay's to prove: the set does not carry what derives it."""
    violations: list[str] = []
    # An invalid_evidence run returns nothing any step retrieved, so it adopts no step.
    is_answer_adopted = evidence_set.stop_reason is not StopReason.INVALID_EVIDENCE
    adopted_steps: list[ToolStep] = []
    for step in evidence_set.trajectory.steps:
        if step.topic_warnings:
            violations.extend(find_step_topic_warning_violations(step, pinned_fight_snapshot))
        if is_answer_adopted and step.admission is StepAdmission.ADMITTED:
            adopted_steps.append(step)
    truncation_counts: list[int] = []
    for warning in evidence_set.warnings:
        if warning.code is not InvestigationWarningCode.ANSWER_TRUNCATED:
            continue
        count = read_count_subject(warning.subject)
        if count is None:
            violations.append("the answer_truncated warning's subject is not a positive count")
        else:
            truncation_counts.append(count)
    if len(truncation_counts) > 1:
        violations.append("the answer_truncated warning appears more than once")
    if truncation_counts and not adopted_steps:
        violations.append("answer_truncated needs a step the answer was assembled from")
    unlisted_technique_count = 0
    left_out_candidate_count = 0
    for step in adopted_steps:
        unlisted_technique_count += read_topic_warning_count(
            step, TopicContextWarningCode.PROTOCOL_CONTEXT_TRUNCATED
        )
        left_out_candidate_count += read_topic_warning_count(
            step, TopicContextWarningCode.CANDIDATES_TRUNCATED
        )
    truncated_count = sum(truncation_counts)
    if truncated_count < unlisted_technique_count + left_out_candidate_count:
        violations.append("answer_truncated counts fewer items than the topic step left out")
    listed_cve_count = len(list_investigation_candidates(evidence_set))
    is_under_cap = listed_cve_count < evidence_set.request.budget.max_results_per_call
    if is_under_cap and truncated_count != unlisted_technique_count:
        violations.append(
            "an answer listing fewer CVEs than the cap truncates only the techniques the topic "
            "step left out"
        )
    return violations


def validate_knowledge_evidence_set(
    evidence_set: KnowledgeEvidenceSet,
    pinned_fight_snapshot: KnownFightSnapshot | None,
    evidence_catalog: EvidenceCatalog,
    source_capabilities: tuple[SourceCapability, ...],
) -> None:
    """Raise ``EvidenceValidationError`` if the set breaks any investigation invariant.

    ``pinned_fight_snapshot`` is the catalog entry the deployment pinned, or ``None``
    when no FiGHT snapshot is configured. ``evidence_catalog`` holds what the service's
    sources hold: every anchor, CVE record and FiGHT technique in the set must equal
    the catalog's, and every evidence ID a step records must be one it holds.
    ``source_capabilities`` is what the composition root found the deployment serves
    when it built the service; the set must report exactly that.
    """
    violations = find_record_and_claim_violations(evidence_set, evidence_catalog)
    violations.extend(find_identity_violations(evidence_set))
    violations.extend(find_investigation_scope_violations(evidence_set))
    violations.extend(find_citation_violations(evidence_set))
    violations.extend(find_step_evidence_violations(evidence_set, evidence_catalog))
    violations.extend(find_step_observation_violations(evidence_set, evidence_catalog))
    violations.extend(find_applicability_violations(evidence_set))
    violations.extend(find_stop_violations(evidence_set))
    violations.extend(find_trajectory_violations(evidence_set))
    violations.extend(find_round_violations(evidence_set))
    violations.extend(find_round_transition_violations(evidence_set))
    violations.extend(find_policy_round_violations(evidence_set))
    violations.extend(find_accepted_plan_violations(evidence_set))
    violations.extend(find_budget_violations(evidence_set))
    violations.extend(find_deadline_violations(evidence_set))
    violations.extend(find_investigation_fight_violations(evidence_set, pinned_fight_snapshot))
    violations.extend(find_truncation_violations(evidence_set, pinned_fight_snapshot))
    violations.extend(
        find_source_capability_violations(evidence_set, pinned_fight_snapshot, source_capabilities)
    )
    if evidence_set.result_sha256 != evidence_set.compute_result_sha256():
        violations.append("result_sha256 does not match the evidence set content")
    if violations:
        raise EvidenceValidationError(violations)
