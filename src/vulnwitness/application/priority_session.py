"""Extract priority facts exclusively from the checker's in-memory session contents."""

from dataclasses import dataclass
from datetime import date

from vulnwitness.application.priority_decision import evaluate_priority
from vulnwitness.domain.asset_register import Asset, AssetAssessment, AssetRegister
from vulnwitness.domain.cve import CveRecord
from vulnwitness.domain.cve_lookup import ComparedCnvdEntry, CveLookupResponse
from vulnwitness.domain.epss import (
    EpssObservation,
    EpssSnapshotIdentity,
    compute_lev,
    latest_observation,
)
from vulnwitness.domain.evidence import EvidenceAnchor
from vulnwitness.domain.exploit_index import ExploitIndex, ExploitIndexIdentity
from vulnwitness.domain.priority_decision import (
    DecisionResponseDigest,
    PolicyIdentity,
    PriorityArtifact,
)
from vulnwitness.domain.priority_facts import (
    CISA_SSVC_ROLE,
    EXPLOIT_REFERENCE_TAG,
    FACT_NAMES,
    MAX_EXPLOIT_REFERENCE_URLS,
    MAX_FACT_MODULES,
    MAX_SOURCE_GRADE_SCORERS,
    ApplicabilityFact,
    AutomatableFact,
    CnvdLinkToReview,
    ExploitationFact,
    ExploitModuleFact,
    ExploitProbabilityFact,
    ForensicTriageFact,
    GradeAuthority,
    HighGradeFact,
    HighGradeStatus,
    KevFact,
    PriorityFacts,
    PublicExploitFact,
    SourceHighGradeFact,
    SystemCategoryFact,
    TechnicalImpactFact,
    unknown_ssvc_facts,
)
from vulnwitness.domain.priority_policy import PriorityPolicy
from vulnwitness.domain.session_record import SessionCall
from vulnwitness.domain.session_report import CheckedSession
from vulnwitness.domain.source_comparison import select_nvd_cvss3
from vulnwitness.domain.taxonomy import SourceType
from vulnwitness.domain.tool_contracts import KnowledgeCapabilities


@dataclass(frozen=True)
class EpssInput:
    """Supplied EPSS files scored on or before the reference date, and their rows for the
    register's CVEs."""

    snapshots: tuple[EpssSnapshotIdentity, ...]
    observations: dict[str, tuple[EpssObservation, ...]]


@dataclass(frozen=True)
class ExploitIndexInput:
    index: ExploitIndex
    identity: ExploitIndexIdentity


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


def extract_public_exploit_fact(
    lookup: CveLookupResponse, cve_id: str, anchors: dict[str, EvidenceAnchor]
) -> PublicExploitFact:
    """Read exploit-tagged references on the exact record; an untagged record is not "none"."""
    evidence_ids: list[str] = []
    urls: list[str] = []
    found_record = False
    for candidate in lookup.candidates:
        record = candidate.record
        if record.cve_id != cve_id:
            continue
        record_ids = source_evidence_ids(
            record, anchors, (SourceType.NVD_API_2, SourceType.NVD_JSON_11)
        )
        if not record_ids:
            continue
        found_record = True
        evidence_ids.extend(record_ids)
        for reference in record.references:
            if EXPLOIT_REFERENCE_TAG in reference.tags and reference.url not in urls:
                urls.append(reference.url)
    if not found_record:
        return PublicExploitFact(value="unknown", evidence_ids=())
    return PublicExploitFact(
        value="referenced" if urls else "not_referenced_in_record",
        evidence_ids=tuple(sorted(set(evidence_ids))),
        reference_urls=tuple(urls[:MAX_EXPLOIT_REFERENCE_URLS]),
    )


def find_exact_record(lookup: CveLookupResponse, cve_id: str) -> CveRecord | None:
    for candidate in lookup.candidates:
        if candidate.record.cve_id == cve_id:
            return candidate.record
    return None


def extract_ssvc_facts(
    record: CveRecord | None, anchors: dict[str, EvidenceAnchor]
) -> tuple[ExploitationFact, AutomatableFact, TechnicalImpactFact]:
    """The first CISA Coordinator SSVC assessment on the exact record (ADR 0021 §1)."""
    if record is None:
        return unknown_ssvc_facts()
    assessment = next((entry for entry in record.ssvc if entry.role == CISA_SSVC_ROLE), None)
    if assessment is None:
        return unknown_ssvc_facts()
    evidence_ids = source_evidence_ids(
        record, anchors, (SourceType.NVD_API_2, SourceType.NVD_JSON_11)
    )
    if not evidence_ids:
        raise ValueError("SSVC assessment has no recorded source anchor")
    points = assessment.decision_points
    assessor = f"{assessment.source} ({assessment.role})"
    exploitation, automatable, technical_impact = unknown_ssvc_facts()
    if points.exploitation is not None:
        exploitation = ExploitationFact(
            value=points.exploitation,
            evidence_ids=evidence_ids,
            assessor=assessor,
            assessed_at=assessment.assessed_at,
        )
    if points.automatable is not None:
        automatable = AutomatableFact(
            value=points.automatable,
            evidence_ids=evidence_ids,
            assessor=assessor,
            assessed_at=assessment.assessed_at,
        )
    if points.technical_impact is not None:
        technical_impact = TechnicalImpactFact(
            value=points.technical_impact,
            evidence_ids=evidence_ids,
            assessor=assessor,
            assessed_at=assessment.assessed_at,
        )
    return exploitation, automatable, technical_impact


def extract_source_high_grade_fact(
    record: CveRecord | None, anchors: dict[str, EvidenceAnchor]
) -> SourceHighGradeFact:
    """CVSS v3.x or v4.0 from scorers other than NVD; NVD's own grade never counts here."""
    if record is None:
        return SourceHighGradeFact(value="none_available", evidence_ids=())
    metrics = [
        metric
        for metric in record.cvss
        if metric.scorer != "nvd@nist.gov"
        and metric.version in ("3.0", "3.1", "4.0")
        and metric.base_severity not in (None, "NONE")
    ]
    if not metrics:
        return SourceHighGradeFact(value="none_available", evidence_ids=())
    evidence_ids = source_evidence_ids(
        record, anchors, (SourceType.NVD_API_2, SourceType.NVD_JSON_11)
    )
    if not evidence_ids:
        raise ValueError("source CVSS metric has no recorded source anchor")
    scorers: list[str] = []
    for metric in metrics:
        label = f"{metric.scorer} CVSS {metric.version}"
        if metric.base_severity in ("HIGH", "CRITICAL") and label not in scorers:
            scorers.append(label)
    return SourceHighGradeFact(
        value="present" if scorers else "absent",
        evidence_ids=evidence_ids,
        triggering_scorers=tuple(scorers[:MAX_SOURCE_GRADE_SCORERS]),
    )


def extract_forensic_triage_fact(
    record: CveRecord | None, anchors: dict[str, EvidenceAnchor]
) -> ForensicTriageFact:
    if record is None or record.kev is None or record.kev.forensic_triage is None:
        return ForensicTriageFact(value="unknown", evidence_ids=())
    evidence_ids = source_evidence_ids(record, anchors, (SourceType.CISA_KEV,))
    if not evidence_ids:
        raise ValueError("KEV forensic triage has no recorded source anchor")
    return ForensicTriageFact(value=record.kev.forensic_triage, evidence_ids=evidence_ids)


def extract_exploit_probability_fact(
    cve_id: str, epss: EpssInput | None, threshold: float | None, reference_date: date
) -> ExploitProbabilityFact:
    """Unknown without supplied snapshots or when none scores the CVE."""
    if epss is None:
        return ExploitProbabilityFact(value="unknown")
    observations = epss.observations.get(cve_id, ())
    latest = latest_observation(observations, reference_date)
    if latest is None:
        return ExploitProbabilityFact(value="unknown")
    if threshold is None:
        raise ValueError("EPSS files need a policy with exploit_probability_threshold")
    lev = compute_lev(observations, reference_date)
    model_version = next(
        snapshot.model_version
        for snapshot in epss.snapshots
        if snapshot.score_date == latest.score_date
    )
    above = max(latest.epss, lev.lev) >= threshold
    return ExploitProbabilityFact(
        value="at_or_above_threshold" if above else "below_threshold",
        epss=latest.epss,
        percentile=latest.percentile,
        score_date=latest.score_date,
        model_version=model_version,
        lev=lev,
        threshold=threshold,
    )


def extract_exploit_module_fact(
    cve_id: str, exploit_index: ExploitIndexInput | None
) -> ExploitModuleFact:
    if exploit_index is None:
        return ExploitModuleFact(value="unknown")
    entry = exploit_index.index.find(cve_id)
    if entry is None:
        return ExploitModuleFact(value="not_in_index")
    return ExploitModuleFact(
        value="present",
        modules=entry.modules[:MAX_FACT_MODULES],
        omitted_modules=max(0, len(entry.modules) - MAX_FACT_MODULES),
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
    used_ids: list[str] = []
    for fact_name in FACT_NAMES:
        used_ids.extend(getattr(facts, fact_name).evidence_ids)
    for evidence_id in used_ids:
        used_anchor = anchors.get(evidence_id)
        if used_anchor is None:
            raise ValueError(f"used evidence {evidence_id} has no recorded anchor")
        if used_anchor.retrieved_at.date() > reference_date:
            after_reference_date = True
    return after_reference_date


def extract_priority_facts(
    contents: CheckedSession,
    asset: Asset,
    assessment: AssetAssessment,
    reference_date: date,
    epss: EpssInput | None = None,
    probability_threshold: float | None = None,
    exploit_index: ExploitIndexInput | None = None,
) -> ExtractedPriorityFacts:
    """Extract exact-lookup grades and KEV state; missing lookups remain explicit unknowns."""
    calls: list[SessionCall] = []
    notes: list[str] = []
    anchors: dict[str, EvidenceAnchor] = {}
    kev = KevFact(value="unknown", evidence_ids=())
    snapshot_retrieved_at = None
    high_grade = HighGradeFact(value="none_available", evidence_ids=())
    public_exploit = PublicExploitFact(value="unknown", evidence_ids=())
    exploitation, automatable, technical_impact = unknown_ssvc_facts()
    source_high_grade = SourceHighGradeFact(value="none_available", evidence_ids=())
    forensic_triage = ForensicTriageFact(value="unknown", evidence_ids=())
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
        public_exploit = extract_public_exploit_fact(lookup, assessment.cve_id, anchors)
        record = find_exact_record(lookup, assessment.cve_id)
        exploitation, automatable, technical_impact = extract_ssvc_facts(record, anchors)
        source_high_grade = extract_source_high_grade_fact(record, anchors)
        forensic_triage = extract_forensic_triage_fact(record, anchors)
    facts = PriorityFacts(
        applicability=ApplicabilityFact(value=assessment.applicability, evidence_ids=()),
        system_category=SystemCategoryFact(value=asset.system_category, evidence_ids=()),
        kev=kev,
        high_grade=high_grade,
        public_exploit=public_exploit,
        exploitation=exploitation,
        automatable=automatable,
        technical_impact=technical_impact,
        source_high_grade=source_high_grade,
        forensic_triage=forensic_triage,
        exploit_probability=extract_exploit_probability_fact(
            assessment.cve_id, epss, probability_threshold, reference_date
        ),
        exploit_module=extract_exploit_module_fact(assessment.cve_id, exploit_index),
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
    epss: EpssInput | None = None,
    exploit_index: ExploitIndexInput | None = None,
) -> PriorityArtifact:
    """Refuse failed session checks and use only checker-verified response digests."""
    check = contents.check
    if not (check.record.consistent and check.citations.resolved and check.claims.verified):
        raise ValueError("session checks failed; priority decisions refused")
    if contents.session is None:
        raise ValueError("session metadata is unavailable")
    if epss is not None and policy.exploit_probability_threshold is None:
        raise ValueError("EPSS files need a policy with exploit_probability_threshold")
    assets: dict[str, Asset] = {}
    for asset in register.assets:
        assets[asset.name] = asset
    decisions = []
    used_calls: dict[int, DecisionResponseDigest] = {}
    after_reference_date = False
    for assessment in register.assessments:
        asset = assets[assessment.asset]
        extracted = extract_priority_facts(
            contents,
            asset,
            assessment,
            reference_date,
            epss,
            policy.exploit_probability_threshold,
            exploit_index,
        )
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
        used_after_reference_date_information=after_reference_date
        or (exploit_index is not None and exploit_index.identity.built_on > reference_date),
        epss_snapshots=() if epss is None else epss.snapshots,
        exploit_index=None if exploit_index is None else exploit_index.identity,
        decisions=tuple(decisions),
    )
