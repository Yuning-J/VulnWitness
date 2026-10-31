"""Referential-integrity and scope invariants for everything this service returns.

The rules, checked on every response before it leaves the application layer:

- ``schema_version`` is the ``SCHEMA_VERSION`` this code serves;
- every evidence ID a claim or candidate cites resolves to an anchor in the same
  response;
- an anchor's evidence ID derives from every other anchor field, so an anchor whose
  provenance was altered no longer matches its ID;
- every anchor, CVE record and FiGHT technique a response serves equals, field for
  field, the one the service's evidence catalog holds under its ID (a technique
  apart from the ``matched_fields`` and ``matched_terms`` of the search that found
  it). Evidence IDs and ``result_sha256`` are integrity checks a holder can
  recompute after altering the content; the catalog re-check is what establishes
  that the content comes from a configured source;
- a claim cites only anchors of its own scope, so implementation evidence (a CVE)
  can never support a protocol-context claim and vice versa;
- a claim cites only anchors about its own subject, so evidence for one record
  never backs a statement about another;
- an asserted claim cites only asserted anchors, so an inference never becomes a
  stated fact;
- ``formal_protocol_finding`` never appears: only an external formal-analysis
  system may originate it;
- an anchor for a CVE record, or from a CVE source (NVD, CISA KEV), is scoped
  ``implementation_vulnerability``, so CVE evidence cannot be relabeled as
  protocol context;
- an anchor for a FiGHT technique, or from a FiGHT snapshot, is scoped
  ``protocol_threat_context``: threat context, never an implementation
  vulnerability and never a formal finding;
- a CVE candidate is scoped ``implementation_vulnerability``, cites only
  ``implementation_vulnerability`` evidence, and has an anchor whose
  authoritative record is that CVE, so no candidate ID is invented;
- a search warns ``result_limit_reached`` at most once, naming the number of candidates
  it lists, and a topic response at most once, beside a resolved topic.
"""

import re
from collections.abc import Collection, Iterable, Mapping, Sequence

from cve_kgrag.domain.cve import CVE_ID_PATTERN, CveRecord
from cve_kgrag.domain.evidence import Claim, EvidenceAnchor, derive_evidence_id
from cve_kgrag.domain.evidence_catalog import EvidenceCatalog
from cve_kgrag.domain.search import (
    SCHEMA_VERSION,
    Candidate,
    SearchResponse,
    SearchWarning,
    SearchWarningCode,
)
from cve_kgrag.domain.taxonomy import (
    AssertionKind,
    BackendStatus,
    KnowledgeScope,
    ResultStatus,
    RetrievalChannel,
    SourceType,
)
from cve_kgrag.domain.threat_context import (
    FIGHT_SOURCE_NAME,
    FIGHT_TECHNIQUE_ID_PATTERN,
    KnownFightSnapshot,
    SnapshotCoverage,
    ThreatContextItem,
    format_fight_locator,
)
from cve_kgrag.domain.topic_context import (
    SERVED_STATUSES,
    TOPIC_COUNT_WARNING_CODES,
    TOPIC_WARNING_ORDER,
    KnowledgeSource,
    QueryScope,
    SourceOutcome,
    TopicContextResponse,
    TopicContextWarning,
    TopicContextWarningCode,
    decide_topic_status,
    format_excerpt_warning_subject,
    list_consulted_sources,
)

# A warning's count: a positive decimal number, as str(int) writes it, of at most nine
# digits, far above any count a response can make; int() refuses very long digit strings.
COUNT_SUBJECT_PATTERN = r"[1-9][0-9]{0,8}"
IMPLEMENTATION = KnowledgeScope.IMPLEMENTATION_VULNERABILITY
THREAT_CONTEXT = KnowledgeScope.PROTOCOL_THREAT_CONTEXT
CVE_SOURCE_TYPES = frozenset({SourceType.NVD_API_2, SourceType.NVD_JSON_11, SourceType.CISA_KEV})


class EvidenceValidationError(ValueError):
    """An output violates an evidence invariant; it must not be returned."""

    def __init__(self, violations: Iterable[str]) -> None:
        self.violations = tuple(violations)
        super().__init__("; ".join(self.violations))


def index_anchors(anchors: Iterable[EvidenceAnchor]) -> dict[str, EvidenceAnchor]:
    anchors_by_id: dict[str, EvidenceAnchor] = {}
    for anchor in anchors:
        anchors_by_id[anchor.evidence_id] = anchor
    return anchors_by_id


def is_cve_anchor(anchor: EvidenceAnchor) -> bool:
    """Whether the anchor points at a CVE record or comes from a CVE source."""
    names_cve = re.fullmatch(CVE_ID_PATTERN, anchor.authoritative_record_id, re.IGNORECASE)
    return names_cve is not None or anchor.source_type in CVE_SOURCE_TYPES


def is_fight_anchor(anchor: EvidenceAnchor) -> bool:
    """Whether the anchor points at a FiGHT technique or comes from a FiGHT snapshot."""
    names_technique = re.fullmatch(
        FIGHT_TECHNIQUE_ID_PATTERN, anchor.authoritative_record_id, re.IGNORECASE
    )
    return names_technique is not None or anchor.source_type is SourceType.MITRE_FIGHT_YAML


def find_anchor_violations(anchors: Iterable[EvidenceAnchor]) -> list[str]:
    """Each anchor's ID derives from its own fields and its scope fits its source."""
    violations: list[str] = []
    for anchor in anchors:
        if anchor.evidence_id != derive_evidence_id(anchor):
            violations.append(
                f"{anchor.evidence_id}: not derived from the anchor's provenance fields"
            )
        if anchor.scope is KnowledgeScope.FORMAL_PROTOCOL_FINDING:
            violations.append(
                f"{anchor.evidence_id}: formal_protocol_finding is reserved for external "
                "formal-analysis artifacts"
            )
        elif is_fight_anchor(anchor) and anchor.scope is not THREAT_CONTEXT:
            violations.append(
                f"{anchor.evidence_id}: FiGHT evidence must be protocol_threat_context, "
                f"not {anchor.scope}"
            )
        elif is_cve_anchor(anchor) and anchor.scope is not IMPLEMENTATION:
            violations.append(
                f"{anchor.evidence_id}: CVE evidence must be implementation_vulnerability, "
                f"not {anchor.scope}"
            )
    return violations


def find_uncatalogued_anchor_violations(
    anchors: Iterable[EvidenceAnchor], evidence_catalog: EvidenceCatalog
) -> list[str]:
    """Each anchor equals, field for field, the one the service's catalog holds under its ID."""
    violations: list[str] = []
    for anchor in anchors:
        catalogued_anchor = evidence_catalog.get_evidence(anchor.evidence_id)
        if catalogued_anchor is None:
            violations.append(f"{anchor.evidence_id}: not an anchor this service's sources hold")
        elif catalogued_anchor != anchor:
            violations.append(
                f"{anchor.evidence_id}: differs from the anchor this service's sources hold"
            )
    return violations


def find_uncatalogued_record_violations(
    records: Iterable[CveRecord], evidence_catalog: EvidenceCatalog
) -> list[str]:
    """Each CVE record equals, field for field, the one the service's catalog holds."""
    violations: list[str] = []
    for record in records:
        catalogued_record = evidence_catalog.get_cve(record.cve_id)
        if catalogued_record is None:
            violations.append(f"{record.cve_id}: not a record this service's sources hold")
        elif catalogued_record != record:
            violations.append(
                f"{record.cve_id}: differs from the record this service's sources hold"
            )
    return violations


def find_uncatalogued_technique_violations(
    items: Iterable[ThreatContextItem], evidence_catalog: EvidenceCatalog
) -> list[str]:
    """Each technique equals the one the service's catalog holds, apart from what the search
    that found it matched, which depends on the search and not on the source."""
    violations: list[str] = []
    for item in items:
        catalogued_item = evidence_catalog.get_technique(item.technique_id)
        indexed_item = item.model_copy(update={"matched_fields": (), "matched_terms": ()})
        if catalogued_item is None:
            violations.append(f"{item.technique_id}: not a technique this service's sources hold")
        elif catalogued_item != indexed_item:
            violations.append(
                f"{item.technique_id}: differs from the technique this service's sources hold"
            )
    return violations


def find_served_violations(
    anchors: Iterable[EvidenceAnchor],
    candidates: Iterable[Candidate],
    items: Iterable[ThreatContextItem],
    evidence_catalog: EvidenceCatalog,
) -> list[str]:
    """The anchor rules, and the catalog re-check of every anchor, CVE record and FiGHT
    technique a response serves, before it is returned."""
    served_anchors = list(anchors)
    served_candidates = tuple(candidates)
    served_records: list[CveRecord] = []
    for candidate in served_candidates:
        served_records.append(candidate.record)
    violations: list[str] = []
    for candidate in served_candidates:
        if (
            candidate.weakness_associations is not None
            and candidate.weakness_associations
            != evidence_catalog.get_weakness_associations(candidate.record.cve_id)
        ):
            violations.append(
                f"{candidate.record.cve_id}: weakness associations differ from the mapping snapshot"
            )
    violations.extend(find_anchor_violations(served_anchors))
    violations.extend(find_uncatalogued_anchor_violations(served_anchors, evidence_catalog))
    violations.extend(find_uncatalogued_record_violations(served_records, evidence_catalog))
    violations.extend(find_uncatalogued_technique_violations(items, evidence_catalog))
    return violations


def find_claim_violations(
    claims: Iterable[Claim], anchors_by_id: Mapping[str, EvidenceAnchor]
) -> list[str]:
    """Each claim's violations, the claim named by its position: a claim's own ID and
    subject are text the set's author chose, so no violation repeats them."""
    violations: list[str] = []
    for claim_index, claim in enumerate(claims):
        claim_label = f"claims[{claim_index}]"
        if claim.scope is KnowledgeScope.FORMAL_PROTOCOL_FINDING:
            violations.append(f"{claim_label}: formal_protocol_finding is never originated here")
        for evidence_id in claim.evidence_ids:
            anchor = anchors_by_id.get(evidence_id)
            if anchor is None:
                violations.append(f"{claim_label}: cites unknown evidence {evidence_id}")
                continue
            if anchor.scope is not claim.scope:
                violations.append(
                    f"{claim_label}: {claim.scope} claim cites {anchor.scope} evidence "
                    f"{evidence_id}"
                )
            if anchor.authoritative_record_id != claim.subject_id:
                violations.append(
                    f"{claim_label}: cites {evidence_id} about another record than its subject"
                )
            is_asserted_claim = claim.assertion_kind is AssertionKind.ASSERTED
            if is_asserted_claim and anchor.assertion_kind is AssertionKind.INFERRED:
                violations.append(
                    f"{claim_label}: asserted claim rests on inferred evidence {evidence_id}"
                )
    return violations


def find_record_violations(
    candidate: Candidate, anchors_by_id: Mapping[str, EvidenceAnchor]
) -> list[str]:
    """A CVE candidate is implementation scoped and cites resolvable, own-record evidence."""
    violations: list[str] = []
    cve_id = candidate.record.cve_id
    if candidate.scope_assessment.scope is not IMPLEMENTATION:
        violations.append(f"{cve_id}: a CVE candidate must be implementation_vulnerability")
    cites_own_record = False
    for evidence_id in candidate.record.evidence_ids:
        anchor = anchors_by_id.get(evidence_id)
        if anchor is None:
            violations.append(f"{cve_id}: cites evidence {evidence_id} missing from response")
            continue
        if anchor.scope is not IMPLEMENTATION:
            violations.append(f"{cve_id}: cites {anchor.scope} evidence {evidence_id}")
        if anchor.authoritative_record_id == cve_id:
            cites_own_record = True
    if not cites_own_record:
        violations.append(f"{cve_id}: no evidence anchor for the record itself")
    return violations


def find_candidate_violations(
    candidates: Iterable[Candidate], anchors_by_id: Mapping[str, EvidenceAnchor]
) -> list[str]:
    violations: list[str] = []
    for expected_rank, candidate in enumerate(candidates, start=1):
        if candidate.rank != expected_rank:
            cve_id = candidate.record.cve_id
            violations.append(f"{cve_id}: rank {candidate.rank}, expected {expected_rank}")
        violations.extend(find_record_violations(candidate, anchors_by_id))
    return violations


def find_threat_context_violations(
    items: Iterable[ThreatContextItem], anchors_by_id: Mapping[str, EvidenceAnchor]
) -> list[str]:
    """Each item cites resolvable FiGHT anchors for its own technique, all threat context."""
    violations: list[str] = []
    for item in items:
        cites_own_technique = False
        for evidence_id in item.evidence_ids:
            anchor = anchors_by_id.get(evidence_id)
            if anchor is None:
                violations.append(f"{item.technique_id}: cites missing evidence {evidence_id}")
                continue
            if anchor.scope is not THREAT_CONTEXT:
                violations.append(f"{item.technique_id}: cites {anchor.scope} evidence")
            if anchor.source_type is not SourceType.MITRE_FIGHT_YAML:
                violations.append(f"{item.technique_id}: cites non-FiGHT evidence {evidence_id}")
            if anchor.assertion_kind is not AssertionKind.ASSERTED:
                violations.append(f"{item.technique_id}: cites inferred evidence {evidence_id}")
            if anchor.authoritative_record_id == item.technique_id:
                cites_own_technique = True
        if not cites_own_technique:
            violations.append(f"{item.technique_id}: no evidence anchor for the technique itself")
    return violations


def find_schema_version_violations(schema_version: str) -> list[str]:
    """Parsing already rejects another version; this catches one set on a built model."""
    if schema_version != SCHEMA_VERSION:
        return [f"schema_version is not {SCHEMA_VERSION}, the version this code serves"]
    return []


def find_status_violations(status: ResultStatus, has_answer: bool, has_failure: bool) -> list[str]:
    violations: list[str] = []
    if has_failure and status in {ResultStatus.OK, ResultStatus.NO_MATCH}:
        violations.append("a source or backend failure cannot be reported as ok or no_match")
    if has_answer and status is ResultStatus.NO_MATCH:
        violations.append("a response with an answer cannot be no_match")
    if not has_answer and status is ResultStatus.OK:
        violations.append("an ok response must contain an answer")
    return violations


def validate_claims(claims: Iterable[Claim], anchors: Iterable[EvidenceAnchor]) -> None:
    """Raise ``EvidenceValidationError`` if any claim breaks an evidence invariant."""
    cited_anchors = list(anchors)
    violations = find_anchor_violations(cited_anchors)
    violations.extend(find_claim_violations(claims, index_anchors(cited_anchors)))
    if violations:
        raise EvidenceValidationError(violations)


def validate_search_response(response: SearchResponse, evidence_catalog: EvidenceCatalog) -> None:
    """Raise ``EvidenceValidationError`` if the response breaks an evidence invariant.

    ``evidence_catalog`` holds what the service's sources hold; every anchor and record
    the response serves must equal the catalog's.
    """
    violations = find_schema_version_violations(response.schema_version)
    violations.extend(
        find_served_violations(response.evidence, response.candidates, (), evidence_catalog)
    )
    violations.extend(
        find_candidate_violations(response.candidates, index_anchors(response.evidence))
    )
    outcome_channels: list[RetrievalChannel] = []
    for outcome in response.channel_outcomes:
        outcome_channels.append(outcome.channel)
    if tuple(outcome_channels) != response.channels_executed:
        violations.append("channel_outcomes do not correspond to channels_executed")
    has_backend_failure = any(
        outcome.status is not BackendStatus.OK for outcome in response.channel_outcomes
    )
    violations.extend(
        find_status_violations(response.status, bool(response.candidates), has_backend_failure)
    )
    violations.extend(find_result_limit_violations(response.warnings, len(response.candidates)))
    if response.result_sha256 != response.compute_result_sha256():
        violations.append("result_sha256 does not match the response content")
    if violations:
        raise EvidenceValidationError(violations)


def find_result_limit_violations(
    warnings: Sequence[SearchWarning], listed_candidate_count: int
) -> list[str]:
    """``result_limit_reached`` appears at most once, naming the number of candidates the
    search lists, which is its limit. Whether the limit was the request's is replay's to
    prove: the response does not carry the request."""
    limit_subjects: list[str] = []
    for warning in warnings:
        if warning.code is SearchWarningCode.RESULT_LIMIT_REACHED:
            limit_subjects.append(warning.subject)
    violations: list[str] = []
    if len(limit_subjects) > 1:
        violations.append("the result_limit_reached warning appears more than once")
    for limit_subject in limit_subjects:
        if limit_subject != str(listed_candidate_count):
            violations.append(
                "the result_limit_reached warning names another limit than the candidates listed"
            )
    return violations


def has_pinned_provenance(anchor: EvidenceAnchor, pinned_snapshot: KnownFightSnapshot) -> bool:
    """Whether the anchor names the pinned snapshot's version, URI, retrieval time and terms,
    the FiGHT source name and the locator its technique ID derives: every text field of a
    FiGHT anchor but its excerpt is the server's or the pin's, never the source's."""
    return (
        anchor.source_name == FIGHT_SOURCE_NAME
        and anchor.locator == format_fight_locator(anchor.authoritative_record_id)
        and anchor.source_version == pinned_snapshot.source_version
        and anchor.source_uri == pinned_snapshot.source_uri
        and anchor.retrieved_at == pinned_snapshot.retrieved_at
        and anchor.license_or_terms_ref == pinned_snapshot.terms_ref
    )


def find_pinned_fight_violations(
    anchors: Iterable[EvidenceAnchor],
    protocol_context: Iterable[ThreatContextItem],
    pinned_snapshot: KnownFightSnapshot,
) -> list[str]:
    """FiGHT anchors carry the pinned snapshot's provenance, and every technique
    served is one the pinned snapshot catalogues."""
    violations: list[str] = []
    for anchor in anchors:
        if anchor.source_type is not SourceType.MITRE_FIGHT_YAML:
            continue
        if not has_pinned_provenance(anchor, pinned_snapshot):
            violations.append(
                f"{anchor.evidence_id}: FiGHT evidence provenance differs from the pinned snapshot"
            )
    if pinned_snapshot.technique_ids is not None:
        for item in protocol_context:
            if item.technique_id not in pinned_snapshot.technique_ids:
                violations.append(
                    f"{item.technique_id} is not in the pinned snapshot's catalogued techniques"
                )
    return violations


def find_served_fight_anchor_violations(
    anchor: EvidenceAnchor, pinned_fight_snapshot: KnownFightSnapshot | None
) -> list[str]:
    """The rules every anchor a served FiGHT technique cites meets, for FiGHT evidence
    served on its own: asserted, from the FiGHT snapshot the deployment pinned, with that
    snapshot's provenance, and about a technique the snapshot catalogues."""
    evidence_id = anchor.evidence_id
    violations: list[str] = []
    if anchor.source_type is not SourceType.MITRE_FIGHT_YAML:
        violations.append(f"{evidence_id}: FiGHT evidence from a non-FiGHT source")
    if anchor.assertion_kind is not AssertionKind.ASSERTED:
        violations.append(f"{evidence_id}: inferred FiGHT evidence")
    names_technique = re.fullmatch(FIGHT_TECHNIQUE_ID_PATTERN, anchor.authoritative_record_id)
    if names_technique is None:
        violations.append(f"{evidence_id}: FiGHT evidence about no FiGHT technique")
    if pinned_fight_snapshot is None:
        violations.append(f"{evidence_id}: FiGHT evidence but no FiGHT snapshot is pinned")
        return violations
    if not has_pinned_provenance(anchor, pinned_fight_snapshot):
        violations.append(
            f"{evidence_id}: FiGHT evidence provenance differs from the pinned snapshot"
        )
    technique_ids = pinned_fight_snapshot.technique_ids
    if technique_ids is not None and anchor.authoritative_record_id not in technique_ids:
        violations.append(f"{evidence_id}: not a technique the pinned snapshot catalogues")
    return violations


def validate_served_anchor(
    anchor: EvidenceAnchor, pinned_fight_snapshot: KnownFightSnapshot | None
) -> None:
    """The rules for an anchor served on its own, as ``get_evidence`` serves one: the anchor
    rules every response applies (its ID derives from its fields, its scope fits its
    source, and it is never ``formal_protocol_finding``), and for FiGHT evidence the
    rules of a served technique's anchors (``find_served_fight_anchor_violations``)
    against ``pinned_fight_snapshot``, ``None`` when the deployment pins none. Raises
    ``EvidenceValidationError`` on any violation."""
    violations = find_anchor_violations([anchor])
    if is_fight_anchor(anchor):
        violations.extend(find_served_fight_anchor_violations(anchor, pinned_fight_snapshot))
    if violations:
        raise EvidenceValidationError(violations)


def find_fight_snapshot_violations(
    response: TopicContextResponse, pinned_snapshot: KnownFightSnapshot | None
) -> list[str]:
    """A served FiGHT outcome comes from the snapshot the deployment pinned.

    ``pinned_snapshot`` is the reviewed catalog entry the composition root pinned, or
    ``None`` when no FiGHT snapshot is configured. Version, coverage, anchor
    provenance and cited techniques must all match it, and the excerpt warning
    appears exactly once, with the pinned technique count, when it is an excerpt.
    A response holder can reseal ``result_sha256`` (an integrity hash, not a
    signature), so these checks bind a response to a deployment, not to a party.
    """
    violations: list[str] = []
    fight_outcome: SourceOutcome | None = None
    for outcome in response.source_outcomes:
        is_fight = outcome.source is KnowledgeSource.MITRE_FIGHT
        if is_fight and outcome.status in {ResultStatus.OK, ResultStatus.NO_MATCH}:
            fight_outcome = outcome
    excerpt_warnings: list[TopicContextWarning] = []
    for warning in response.warnings:
        if warning.code is TopicContextWarningCode.SOURCE_SNAPSHOT_IS_EXCERPT:
            excerpt_warnings.append(warning)
    expected_excerpt_warnings: list[TopicContextWarning] = []
    serves_pinned_excerpt = (
        fight_outcome is not None
        and pinned_snapshot is not None
        and pinned_snapshot.coverage is SnapshotCoverage.EXCERPT
    )
    if serves_pinned_excerpt and pinned_snapshot is not None:
        expected_excerpt_warnings.append(
            TopicContextWarning(
                code=TopicContextWarningCode.SOURCE_SNAPSHOT_IS_EXCERPT,
                subject=format_excerpt_warning_subject(pinned_snapshot.technique_count),
            )
        )
    if excerpt_warnings != expected_excerpt_warnings:
        violations.append(
            "the excerpt warning must appear exactly once, with the pinned technique count, "
            "when the pinned FiGHT excerpt was served, and never otherwise"
        )
    if fight_outcome is None:
        return violations
    if pinned_snapshot is None:
        violations.append("a FiGHT outcome was served but no FiGHT snapshot is pinned")
        return violations
    if fight_outcome.source_version != pinned_snapshot.source_version:
        violations.append("the FiGHT outcome names another snapshot than the pinned one")
    if fight_outcome.coverage is not pinned_snapshot.coverage:
        violations.append(
            f"the FiGHT outcome reports {fight_outcome.coverage} coverage; the pinned snapshot "
            f"is {pinned_snapshot.coverage}"
        )
    violations.extend(
        find_pinned_fight_violations(response.evidence, response.protocol_context, pinned_snapshot)
    )
    return violations


def read_count_subject(subject: str) -> int | None:
    """The count a warning's subject states, ``None`` unless it is a positive decimal."""
    if re.fullmatch(COUNT_SUBJECT_PATTERN, subject) is None:
        return None
    return int(subject)


def find_source_status(
    source_outcomes: Iterable[SourceOutcome], source: KnowledgeSource
) -> ResultStatus | None:
    """The status of ``source``'s outcome, ``None`` when none names it."""
    for outcome in source_outcomes:
        if outcome.source is source:
            return outcome.status
    return None


def find_unindexed_term_violations(
    warnings: Sequence[TopicContextWarning],
    *,
    is_resolved: bool,
    fight_status: ResultStatus | None,
    sent_terms: Sequence[str],
    listed_matched_terms: Collection[str],
) -> list[str]:
    """``term_not_indexed`` appears only on a direct FiGHT search (no topic resolved)
    whose FiGHT outcome is served, each subject once, one of the terms it sent and none a
    listed technique matched."""
    violations: list[str] = []
    named_subjects: list[str] = []
    for warning in warnings:
        if warning.code is not TopicContextWarningCode.TERM_NOT_INDEXED:
            continue
        if is_resolved or fight_status not in SERVED_STATUSES:
            violations.append(
                "term_not_indexed needs a direct FiGHT search whose FiGHT outcome was served"
            )
        if warning.subject in named_subjects:
            violations.append("term_not_indexed names a term more than once")
        named_subjects.append(warning.subject)
        if warning.subject not in sent_terms:
            violations.append("term_not_indexed names a term the FiGHT search did not send")
        if warning.subject in listed_matched_terms:
            violations.append("term_not_indexed names a term a listed technique holds")
    return violations


def find_topic_warning_violations(
    warnings: Sequence[TopicContextWarning],
    *,
    fight_status: ResultStatus | None,
    listed_technique_count: int,
    listed_candidate_count: int,
    pinned_snapshot: KnownFightSnapshot | None,
    is_resolved: bool,
    sent_terms: Sequence[str],
    listed_matched_terms: Collection[str],
) -> list[str]:
    """Topic warnings' structure and their relations to what the response lists (ADR 0009
    §11a): the warnings come in their fixed order; each count warning appears at most
    once, with a positive decimal subject; ``protocol_context_truncated`` only beside an
    ``ok`` FiGHT outcome (``fight_status``), the techniques listed plus its count at most
    the pinned snapshot's technique count; ``candidates_truncated`` only beside a
    non-empty candidate section; ``result_limit_reached`` only beside a resolved topic,
    whose card searched CVEs; ``term_not_indexed`` as
    ``find_unindexed_term_violations`` says, over the ``sent_terms`` of a direct FiGHT
    search and the ``listed_matched_terms`` of the techniques listed. No count can be
    checked against its truth here: a response does not carry the inputs that derive it,
    which replay re-runs."""
    violations = find_unindexed_term_violations(
        warnings,
        is_resolved=is_resolved,
        fight_status=fight_status,
        sent_terms=sent_terms,
        listed_matched_terms=listed_matched_terms,
    )
    previous_position = 0
    for warning in warnings:
        position = TOPIC_WARNING_ORDER[warning.code]
        if position < previous_position:
            violations.append(f"the {warning.code} warning is out of the warnings' order")
        previous_position = max(previous_position, position)
    counts_by_code: dict[TopicContextWarningCode, int] = {}
    for count_code in TOPIC_COUNT_WARNING_CODES:
        count_warnings: list[TopicContextWarning] = []
        for warning in warnings:
            if warning.code is count_code:
                count_warnings.append(warning)
        if len(count_warnings) > 1:
            violations.append(f"the {count_code} warning appears more than once")
        for count_warning in count_warnings:
            count = read_count_subject(count_warning.subject)
            if count is None:
                violations.append(f"the {count_code} warning's subject is not a positive count")
            else:
                counts_by_code[count_code] = count
    unlisted_technique_count = counts_by_code.get(
        TopicContextWarningCode.PROTOCOL_CONTEXT_TRUNCATED
    )
    if unlisted_technique_count is not None:
        if fight_status is not ResultStatus.OK or pinned_snapshot is None:
            violations.append("protocol_context_truncated needs a FiGHT outcome that is ok")
        elif listed_technique_count + unlisted_technique_count > pinned_snapshot.technique_count:
            violations.append(
                "protocol_context_truncated counts more techniques than the pinned snapshot holds"
            )
    has_candidate_cut = TopicContextWarningCode.CANDIDATES_TRUNCATED in counts_by_code
    if has_candidate_cut and listed_candidate_count == 0:
        violations.append("candidates_truncated needs a candidate section that lists some")
    if TopicContextWarningCode.RESULT_LIMIT_REACHED in counts_by_code and not is_resolved:
        violations.append("result_limit_reached needs a resolved topic whose card searched CVEs")
    return violations


def is_direct_fight_search(response: TopicContextResponse) -> bool:
    """Whether the response is a direct FiGHT search's: no topic resolved and no excluded
    term was named, under ``protocol_context_only``, with FiGHT its only source outcome."""
    outcome_sources: list[KnowledgeSource] = []
    for outcome in response.source_outcomes:
        outcome_sources.append(outcome.source)
    return (
        not response.resolution.matches
        and not response.resolution.excluded_terms
        and response.requested_scope is QueryScope.PROTOCOL_CONTEXT_ONLY
        and tuple(outcome_sources) == (KnowledgeSource.MITRE_FIGHT,)
    )


def find_topic_status_violations(
    response: TopicContextResponse, candidates: list[Candidate]
) -> list[str]:
    """Outcomes name exactly the consulted sources (a resolved topic's, or for an
    unresolved query none, or FiGHT alone for a direct search), agree with the sections,
    and the status is the one ``decide_topic_status`` gives for them."""
    violations: list[str] = []
    outcome_sources: list[KnowledgeSource] = []
    outcomes_by_source: dict[KnowledgeSource, SourceOutcome] = {}
    for outcome in response.source_outcomes:
        outcome_sources.append(outcome.source)
        outcomes_by_source[outcome.source] = outcome
    if response.resolution.matches:
        is_expected_sources = tuple(outcome_sources) == list_consulted_sources(
            response.requested_scope
        )
    else:
        is_expected_sources = not outcome_sources or is_direct_fight_search(response)
    if not is_expected_sources:
        violations.append("source_outcomes do not name exactly the consulted sources")
    fight_outcome = outcomes_by_source.get(KnowledgeSource.MITRE_FIGHT)
    if response.protocol_context and (
        fight_outcome is None or fight_outcome.status is not ResultStatus.OK
    ):
        violations.append("threat context needs a successful FiGHT outcome")
    if (
        fight_outcome is not None
        and fight_outcome.status is ResultStatus.OK
        and not response.protocol_context
    ):
        violations.append("a successful FiGHT outcome must contribute threat context")
    cve_outcome = outcomes_by_source.get(KnowledgeSource.CVE_SEARCH)
    if candidates and (cve_outcome is None or cve_outcome.status is ResultStatus.NO_MATCH):
        violations.append("CVE candidates need a CVE search outcome with matches")
    if cve_outcome is not None and cve_outcome.status is ResultStatus.OK and not candidates:
        violations.append("a successful CVE search outcome must contribute a candidate")
    has_answer = bool(response.protocol_context or response.implementation_candidates)
    expected_status = decide_topic_status(
        response.requested_scope, has_answer, response.source_outcomes
    )
    if response.status is not expected_status:
        violations.append(f"status {response.status} should be {expected_status}")
    return violations


def collect_matched_terms(items: Iterable[ThreatContextItem]) -> set[str]:
    """Every term a listed technique matched."""
    listed_matched_terms: set[str] = set()
    for item in items:
        listed_matched_terms.update(item.matched_terms)
    return listed_matched_terms


def validate_topic_context_response(
    response: TopicContextResponse,
    pinned_fight_snapshot: KnownFightSnapshot | None,
    evidence_catalog: EvidenceCatalog,
    *,
    sent_fight_terms: Sequence[str] = (),
) -> None:
    """Raise ``EvidenceValidationError`` if the response mixes scopes or cites bad evidence.

    Beyond the anchor rules: protocol context cites only asserted FiGHT threat
    context, a protocol_context_only answer holds no CVE candidate, an
    implementation_only answer holds no threat context, every anchor in the response
    is cited, and the status follows from the source outcomes. ``evidence_catalog``
    holds what the service's sources hold; every anchor, record and technique the
    response serves must equal the catalog's. ``sent_fight_terms`` are the words a
    direct FiGHT search sent, none for a topic's exploration: a ``term_not_indexed``
    warning names one of them.
    """
    anchors_by_id = index_anchors(response.evidence)
    candidates: list[Candidate] = []
    for topic_candidate in response.implementation_candidates:
        candidates.append(topic_candidate.candidate)
    for excluded_candidate in response.excluded_implementation_candidates:
        candidates.append(excluded_candidate.candidate.candidate)
    violations = find_schema_version_violations(response.schema_version)
    violations.extend(
        find_served_violations(
            response.evidence, candidates, response.protocol_context, evidence_catalog
        )
    )
    violations.extend(find_threat_context_violations(response.protocol_context, anchors_by_id))
    for candidate in candidates:
        violations.extend(find_record_violations(candidate, anchors_by_id))

    scope = response.requested_scope
    if scope is QueryScope.PROTOCOL_CONTEXT_ONLY and response.implementation_candidates:
        violations.append("a protocol_context_only answer cannot contain CVE candidates")
    if (
        scope is not QueryScope.PROTOCOL_CONTEXT_ONLY
        and response.excluded_implementation_candidates
    ):
        violations.append("only a protocol_context_only answer excludes CVE candidates")
    if scope is QueryScope.IMPLEMENTATION_ONLY and response.protocol_context:
        violations.append("an implementation_only answer cannot contain threat context")

    cited_ids: set[str] = set()
    for item in response.protocol_context:
        cited_ids.update(item.evidence_ids)
    for candidate in candidates:
        cited_ids.update(candidate.record.evidence_ids)
    if cited_ids != set(anchors_by_id):
        violations.append("evidence must be exactly the anchors the response cites")

    violations.extend(find_topic_status_violations(response, candidates))
    violations.extend(find_fight_snapshot_violations(response, pinned_fight_snapshot))
    violations.extend(
        find_topic_warning_violations(
            response.warnings,
            fight_status=find_source_status(response.source_outcomes, KnowledgeSource.MITRE_FIGHT),
            listed_technique_count=len(response.protocol_context),
            listed_candidate_count=len(candidates),
            pinned_snapshot=pinned_fight_snapshot,
            is_resolved=bool(response.resolution.matches),
            sent_terms=sent_fight_terms,
            listed_matched_terms=collect_matched_terms(response.protocol_context),
        )
    )
    if response.result_sha256 != response.compute_result_sha256():
        violations.append("result_sha256 does not match the response content")
    if violations:
        raise EvidenceValidationError(violations)
