"""Extract priority facts exclusively from the checker's in-memory session contents."""

from dataclasses import dataclass
from datetime import date

from vulnwitness.application.priority_decision import evaluate_priority
from vulnwitness.domain.asset_register import Asset, AssetAssessment, AssetRegister
from vulnwitness.domain.cve import CveRecord
from vulnwitness.domain.cve_lookup import ComparedCnvdEntry, CveLookupResponse
from vulnwitness.domain.evidence import EvidenceAnchor
from vulnwitness.domain.priority_decision import (
    DecisionResponseDigest,
    PolicyIdentity,
    PriorityArtifact,
)
from vulnwitness.domain.priority_facts import (
    ApplicabilityFact,
    CnvdLinkToReview,
    GradeAuthority,
    HighGradeFact,
    HighGradeStatus,
    KevFact,
    PriorityFacts,
    SystemCategoryFact,
)
from vulnwitness.domain.priority_policy import PriorityPolicy
from vulnwitness.domain.session_record import SessionCall
from vulnwitness.domain.session_report import CheckedSession
from vulnwitness.domain.source_comparison import select_nvd_cvss3
from vulnwitness.domain.taxonomy import SourceType
from vulnwitness.domain.tool_contracts import KnowledgeCapabilities


@dataclass(frozen=True)
class ExtractedPriorityFacts:
    facts: PriorityFacts
    calls: tuple[SessionCall, ...]
    notes: tuple[str, ...]
    used_after_reference_date_information: bool


def find_recorded_call(
    contents: CheckedSession, commands: tuple[str, ...], cve_id: str | None = None
) -> SessionCall | None:
    """Use the last matching call in sequence order, never a search or product hit."""
    for call in sorted(contents.calls, key=lambda call: call.sequence, reverse=True):
        if call.command not in commands:
            continue
        if cve_id is None or (call.request is not None and call.request.get("cve_id") == cve_id):
            return call
    return None


def source_evidence_ids(
    record: CveRecord, anchors: dict[str, EvidenceAnchor], sources: tuple[SourceType, ...]
) -> tuple[str, ...]:
    """Prefer the source's anchor; fixture and NVD-mirrored KEV fields use their record."""
    source_ids: list[str] = []
    for evidence_id in record.evidence_ids:
        anchor = anchors.get(evidence_id)
        if anchor is not None and anchor.source_type in sources:
            source_ids.append(evidence_id)
    if source_ids:
        return tuple(source_ids)
    for evidence_id in record.evidence_ids:
        anchor = anchors.get(evidence_id)
        if (
            anchor is not None
            and anchor.source_type is SourceType.SYNTHETIC_FIXTURE
            and anchor.authoritative_record_id == record.cve_id
        ):
            source_ids.append(evidence_id)
    if not source_ids and SourceType.CISA_KEV in sources:
        return source_evidence_ids(record, anchors, (SourceType.NVD_API_2, SourceType.NVD_JSON_11))
    return tuple(source_ids)


def extract_kev_fact(
    contents: CheckedSession,
    record: CveRecord,
    anchors: dict[str, EvidenceAnchor],
    kev: KevFact,
) -> tuple[KevFact, SessionCall | None]:
    """Use a positive listing or an explicitly imported snapshot, never a missing field alone."""
    if record.kev is not None:
        evidence_ids = source_evidence_ids(record, anchors, (SourceType.CISA_KEV,))
        if not evidence_ids:
            raise ValueError("KEV listing has no recorded source anchor")
        return KevFact(value="listed", evidence_ids=evidence_ids), None
    capability_call = find_recorded_call(contents, ("capabilities", "get_knowledge_capabilities"))
    if capability_call is None:
        return kev, None
    capabilities = contents.responses.get(capability_call.sequence)
    if capability_call.outcome != "ok" or not isinstance(capabilities, KnowledgeCapabilities):
        raise ValueError("recorded capabilities call did not succeed")
    snapshot = capabilities.kev
    if snapshot.imported:
        assert snapshot.retrieved_at is not None
        kev = KevFact(
            value="not_listed_in_snapshot",
            evidence_ids=source_evidence_ids(
                record, anchors, (SourceType.NVD_API_2, SourceType.NVD_JSON_11)
            ),
            snapshot_retrieved_at=snapshot.retrieved_at.date(),
        )
    return kev, capability_call


def extract_high_grade_fact(
    lookup: CveLookupResponse, cve_id: str, anchors: dict[str, EvidenceAnchor]
) -> HighGradeFact:
    """Retain NVD-own and CNVD grade evidence, including unavailable NVD grades."""
    grade_ids: list[str] = []
    authorities: list[GradeAuthority] = []
    entries: list[ComparedCnvdEntry] = []
    links_to_review: dict[str, CnvdLinkToReview] = {}
    has_grade = False
    for candidate in lookup.candidates:
        record = candidate.record
        if record.cve_id != cve_id:
            continue
        nvd_ids = source_evidence_ids(
            record, anchors, (SourceType.NVD_API_2, SourceType.NVD_JSON_11)
        )
        grade_ids.extend(nvd_ids)
        metric = select_nvd_cvss3(record)
        if metric is not None and metric.base_severity not in (None, "NONE"):
            has_grade = True
            if not nvd_ids:
                raise ValueError("NVD grade has no recorded source anchor")
            if metric.base_severity in ("HIGH", "CRITICAL"):
                authorities.append("NVD")
        entries.extend(record.cnvd)
    for pending_entry in lookup.pending_cnvd:
        if pending_entry.cve_id == cve_id:
            entries.append(pending_entry)
    for entry in entries:
        has_grade = True
        grade_ids.append(entry.evidence_id)
        if entry.severity == "high" and "CNVD" not in authorities:
            authorities.append("CNVD")
        if entry.severity == "high" and entry.name_check.result == "no_overlap":
            assert entry.name_check.cnvd_name is not None
            links_to_review[entry.cnvd_id] = CnvdLinkToReview(
                cnvd_id=entry.cnvd_id, cnvd_name=entry.name_check.cnvd_name
            )
    high_grade: HighGradeStatus = "none_available"
    if authorities:
        high_grade = "present"
    elif has_grade:
        high_grade = "absent"
    return HighGradeFact(
        value=high_grade,
        evidence_ids=tuple(sorted(set(grade_ids))),
        triggering_authorities=tuple(authorities),
        cnvd_links_to_review=tuple(sorted(links_to_review.values(), key=lambda link: link.cnvd_id)),
    )


def uses_after_reference_date_information(
    facts: PriorityFacts,
    anchors: dict[str, EvidenceAnchor],
    reference_date: date,
    snapshot_retrieved_at: date | None,
) -> bool:
    """Check every used anchor and the negative-listing snapshot's retrieval date."""
    after_reference_date = (
        snapshot_retrieved_at is not None and snapshot_retrieved_at > reference_date
    )
    for evidence_id in (*facts.kev.evidence_ids, *facts.high_grade.evidence_ids):
        used_anchor = anchors.get(evidence_id)
        if used_anchor is None:
            raise ValueError(f"used evidence {evidence_id} has no recorded anchor")
        if used_anchor.retrieved_at.date() > reference_date:
            after_reference_date = True
    return after_reference_date


def extract_priority_facts(
    contents: CheckedSession, asset: Asset, assessment: AssetAssessment, reference_date: date
) -> ExtractedPriorityFacts:
    """Extract exact-lookup grades and KEV state; missing lookups remain explicit unknowns."""
    calls: list[SessionCall] = []
    notes: list[str] = []
    anchors: dict[str, EvidenceAnchor] = {}
    kev = KevFact(value="unknown", evidence_ids=())
    snapshot_retrieved_at = None
    high_grade = HighGradeFact(value="none_available", evidence_ids=())
    lookup_call = find_recorded_call(contents, ("lookup", "lookup_cve"), assessment.cve_id)
    if lookup_call is None:
        notes.append(f"{assessment.cve_id} has no recorded exact lookup; CVE facts are unknown.")
    else:
        calls.append(lookup_call)
        lookup = contents.responses.get(lookup_call.sequence)
        if lookup_call.outcome != "ok" or not isinstance(lookup, CveLookupResponse):
            raise ValueError(f"recorded lookup call {lookup_call.sequence} did not succeed")
        for anchor in lookup.evidence:
            anchors[anchor.evidence_id] = anchor
        for candidate in lookup.candidates:
            if candidate.record.cve_id != assessment.cve_id:
                continue
            kev, capability_call = extract_kev_fact(contents, candidate.record, anchors, kev)
            if capability_call is not None:
                calls.append(capability_call)
            if kev.snapshot_retrieved_at is not None:
                snapshot_retrieved_at = kev.snapshot_retrieved_at
        high_grade = extract_high_grade_fact(lookup, assessment.cve_id, anchors)
    facts = PriorityFacts(
        applicability=ApplicabilityFact(value=assessment.applicability, evidence_ids=()),
        system_category=SystemCategoryFact(value=asset.system_category, evidence_ids=()),
        kev=kev,
        high_grade=high_grade,
    )
    after_reference_date = uses_after_reference_date_information(
        facts, anchors, reference_date, snapshot_retrieved_at
    )
    return ExtractedPriorityFacts(facts, tuple(calls), tuple(notes), after_reference_date)


def build_session_priority(
    contents: CheckedSession,
    register: AssetRegister,
    policy: PriorityPolicy,
    policy_sha256: str,
    reference_date: date,
    program_version: str,
) -> PriorityArtifact:
    """Refuse failed session checks and use only checker-verified response digests."""
    check = contents.check
    if not (check.record.consistent and check.citations.resolved and check.claims.verified):
        raise ValueError("session checks failed; priority decisions refused")
    if contents.session is None:
        raise ValueError("session metadata is unavailable")
    assets: dict[str, Asset] = {}
    for asset in register.assets:
        assets[asset.name] = asset
    decisions = []
    used_calls: dict[int, DecisionResponseDigest] = {}
    after_reference_date = False
    for assessment in register.assessments:
        asset = assets[assessment.asset]
        extracted = extract_priority_facts(contents, asset, assessment, reference_date)
        decision = evaluate_priority(policy, asset, assessment, extracted.facts)
        decisions.append(decision.model_copy(update={"notes": extracted.notes}))
        after_reference_date |= extracted.used_after_reference_date_information
        for call in extracted.calls:
            response_digest = contents.response_digests.get(call.sequence)
            if response_digest is None:
                raise ValueError(f"used call {call.sequence} has no verified response digest")
            used_calls[call.sequence] = DecisionResponseDigest(
                call=call.sequence, response_sha256=response_digest
            )
    return PriorityArtifact(
        program_version=program_version,
        policy=PolicyIdentity(
            name=policy.name, format_version=policy.format_version, content_sha256=policy_sha256
        ),
        dataset=contents.session.dataset,
        response_digests=tuple(used_calls.values()),
        register_sha256=register.compute_content_sha256(),
        reference_date=reference_date,
        used_after_reference_date_information=after_reference_date,
        decisions=tuple(decisions),
    )
