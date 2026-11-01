"""Compose report sections from recorded content and the existing layered check."""

import json

from pydantic import BaseModel

from vulnwitness.domain.cve import CveRecord
from vulnwitness.domain.evidence import EvidenceAnchor
from vulnwitness.domain.investigation import KnowledgeEvidenceSet, NeedOutcome
from vulnwitness.domain.product_query import ProductQueryResponse
from vulnwitness.domain.search import Candidate, SearchResponse
from vulnwitness.domain.served_dataset import ServedDatasetKind
from vulnwitness.domain.session_record import SessionFinding
from vulnwitness.domain.session_report import (
    CheckedSession,
    ReportParagraph,
    ReportSection,
    ReportTable,
    SessionReport,
)
from vulnwitness.domain.topic_context import TopicContextResponse


def collect_anchors(answer: BaseModel) -> dict[str, EvidenceAnchor]:
    """Retain complete anchors, including those nested in MCP response contracts."""
    anchors: dict[str, EvidenceAnchor] = {}
    pending = [answer.model_dump(mode="python")]
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            if "evidence_id" in node:
                try:
                    anchor = EvidenceAnchor.model_validate(node)
                except ValueError:
                    pass
                else:
                    anchors[anchor.evidence_id] = anchor
            pending.extend(node.values())
        elif isinstance(node, list | tuple):
            pending.extend(node)
    return anchors


def build_header(contents: CheckedSession) -> ReportSection:
    session = contents.session
    if session is None:
        raise ValueError("session metadata is unreadable or invalid")
    identity = session.dataset
    paragraphs = (
        ReportParagraph("Question: not separately recorded in session.json."),
        ReportParagraph(f"Goal: {session.goal or 'not recorded'}"),
        ReportParagraph(f"Scope: {session.scope or 'not recorded'}"),
        ReportParagraph(f"Created at: {session.created_at.isoformat()}"),
        ReportParagraph(f"Contract version: {session.contract_version}"),
    )
    rows = (
        ("Served dataset", identity.served.kind.value),
        ("Search version", identity.served.cve_search_version),
        ("Store name", identity.store_name or "none (synthetic fixture)"),
        ("Store manifest identity", identity.store_manifest_sha256),
        ("Corpus content identity", identity.corpus_content_sha256),
        ("FiGHT snapshot identity", identity.fight_snapshot_sha256 or "not served"),
        ("MITRE snapshot identity", identity.mitre_snapshot_sha256 or "not served"),
    )
    return ReportSection("Header", paragraphs, (ReportTable(("Identity", "Recorded value"), rows),))


def build_checks(contents: CheckedSession) -> ReportSection:
    check = contents.check
    layers = (
        (
            "Record consistency",
            "Checks the structure and consistency of recorded files.",
            check.record,
        ),
        (
            "Citation resolution",
            "Checks that citations resolve to anchors in successful calls with the same dataset.",
            check.citations,
        ),
        (
            "Structured claims",
            "Compares claim fields with recorded fields; it does not establish source support.",
            check.claims,
        ),
        (
            "Not checked: narrative",
            "Counts model and analyst narrative; its support is not checked.",
            check.not_checked,
        ),
    )
    sections: list[ReportSection] = []
    for title, meaning, layer in layers:
        sections.append(
            ReportSection(
                title,
                (ReportParagraph(meaning),),
                verbatim=layer.model_dump_json(indent=2),
            )
        )
    return ReportSection(
        "Check results", (ReportParagraph(check.support_limitation),), sections=tuple(sections)
    )


def build_finding(
    contents: CheckedSession,
    finding: SessionFinding,
    anchors_by_call: dict[int, dict[str, EvidenceAnchor]],
) -> ReportSection:
    paragraphs = [
        ReportParagraph(finding.statement or ""),
        ReportParagraph(f"Author: {finding.author} · Status: {finding.status}"),
    ]
    if finding.claim is None:
        paragraphs.append(ReportParagraph("Claim verification: not checked (narrative)."))
    else:
        for check in contents.check.claims.checks:
            if check.finding_id == finding.id:
                warning = check.status != "verified"
                prefix = "WARNING: " if warning else ""
                paragraphs.append(
                    ReportParagraph(f"{prefix}Claim verification: {check.status}.", warning)
                )
                paragraphs.append(ReportParagraph(check.message))
                break
    for citation in finding.citations:
        anchor = anchors_by_call.get(citation.call, {}).get(citation.evidence_id)
        source = (
            "source URI unavailable (unresolved anchor)" if anchor is None else anchor.source_uri
        )
        paragraphs.append(
            ReportParagraph(f"call {citation.call} · evidence {citation.evidence_id} · {source}")
        )
    if not finding.citations:
        paragraphs.append(ReportParagraph("Citations: none recorded."))
    return ReportSection(finding.id, tuple(paragraphs))


def build_findings(contents: CheckedSession) -> ReportSection:
    if contents.findings is None:
        return ReportSection(
            "Findings",
            (ReportParagraph("Findings are unreadable or invalid; see check results.", True),),
        )
    groups: dict[str, list[SessionFinding]] = {}
    narrative: dict[str, list[SessionFinding]] = {}
    anchors_by_call: dict[int, dict[str, EvidenceAnchor]] = {}
    for sequence, answer in contents.responses.items():
        anchors_by_call[sequence] = collect_anchors(answer)
    for finding in contents.findings.findings:
        group = narrative if finding.claim is None else groups
        group.setdefault(finding.kind, []).append(finding)
    sections: list[ReportSection] = []
    for kind, findings in sorted(groups.items()):
        entries: list[ReportSection] = []
        for finding in findings:
            entries.append(build_finding(contents, finding, anchors_by_call))
        sections.append(ReportSection(kind, sections=tuple(entries)))
    narrative_sections: list[ReportSection] = []
    for kind, findings in sorted(narrative.items()):
        entries = []
        for finding in findings:
            entries.append(build_finding(contents, finding, anchors_by_call))
        narrative_sections.append(ReportSection(kind, sections=tuple(entries)))
    sections.append(ReportSection("Not checked: narrative", sections=tuple(narrative_sections)))
    paragraphs = () if contents.findings.findings else (ReportParagraph("None recorded."),)
    return ReportSection("Findings", paragraphs, sections=tuple(sections))


def summarize_record(record: CveRecord) -> tuple[str, str, str, str]:
    published = "unknown" if record.published is None else record.published.date().isoformat()
    severities: list[str] = []
    for metric in record.cvss:
        severities.append(
            f"{metric.base_severity or 'unknown'} {metric.base_score:g} v{metric.version}"
        )
    description = next(
        (entry.value for entry in record.descriptions if entry.lang == "en"),
        record.descriptions[0].value,
    )
    # A single physical table line; renderers wrap the bounded text to their available width.
    description = " ".join(description.split())
    if len(description) > 160:
        description = description[:157] + "…"
    return record.cve_id, published, "; ".join(severities) or "unknown", description


def build_cves(contents: CheckedSession) -> ReportSection:
    cited_calls: set[int] = set()
    if contents.findings is not None:
        for finding in contents.findings.findings:
            for citation in finding.citations:
                cited_calls.add(citation.call)
    rows: list[tuple[str, ...]] = []
    for sequence in sorted(cited_calls):
        answer = contents.responses.get(sequence)
        if isinstance(answer, ProductQueryResponse):
            for item in answer.items:
                cve_id, published, severity, description = summarize_record(item.record)
                note = item.nvd_version_note
                outcome = "not recorded" if note is None else f"{note.mention}: {note.outcome}"
                rows.append(
                    (
                        str(sequence),
                        cve_id,
                        published,
                        severity,
                        item.basis.kind,
                        outcome,
                        "unknown",
                        description,
                    )
                )
        elif isinstance(answer, SearchResponse | TopicContextResponse):
            candidates: list[Candidate] = []
            if isinstance(answer, SearchResponse):
                candidates.extend(answer.candidates)
            else:
                for topic_candidate in answer.implementation_candidates:
                    candidates.append(topic_candidate.candidate)
            for candidate in candidates:
                cve_id, published, severity, description = summarize_record(candidate.record)
                rows.append(
                    (
                        str(sequence),
                        cve_id,
                        published,
                        severity,
                        "not recorded",
                        "not recorded",
                        "not recorded",
                        description,
                    )
                )
        elif isinstance(answer, KnowledgeEvidenceSet):
            for investigation_candidate in answer.implementation_candidates:
                cve_id, published, severity, description = summarize_record(
                    investigation_candidate.candidate.record
                )
                outcomes: list[str] = []
                for note in investigation_candidate.nvd_version_notes or ():
                    outcomes.append(f"{note.mention}: {note.outcome}")
                applicability = "unknown" if answer.product_applicability else "not recorded"
                rows.append(
                    (
                        str(sequence),
                        cve_id,
                        published,
                        severity,
                        "not recorded",
                        "; ".join(outcomes) or "not recorded",
                        applicability,
                        description,
                    )
                )
    table = ReportTable(
        (
            "Call",
            "ID",
            "Published",
            "Severity",
            "Basis kind",
            "Version-note outcome",
            "Applicability",
            "Description",
        ),
        tuple(rows),
    )
    return ReportSection(
        "CVEs",
        (
            ReportParagraph(
                "Only recorded responses cited by findings are included. "
                "Version-note hits do not establish affectedness."
            ),
        ),
        (table,),
    )


def build_weakness_paths(contents: CheckedSession) -> ReportSection:
    sections: list[ReportSection] = []
    for call in contents.calls:
        answer = contents.responses.get(call.sequence)
        if call.command not in {"lookup", "lookup_cve"} or not isinstance(answer, SearchResponse):
            continue
        for candidate in answer.candidates:
            associations = candidate.weakness_associations
            if associations is None:
                continue
            paragraphs = [ReportParagraph(associations.note)]
            paths: list[ReportSection] = []
            for path in associations.paths:
                hops: list[str] = []
                for hop in path.hops:
                    hops.append(
                        f"{hop.from_id} → {hop.to_id} [{hop.relation}] · {hop.source} · "
                        f"version {hop.source_version or 'not recorded'} · "
                        f"identity {hop.source_sha256 or 'not recorded'}"
                    )
                technique = "no ATT&CK mapping"
                if path.technique is not None:
                    technique = f"{path.technique.technique_id} {path.technique.name}"
                paths.append(
                    ReportSection(
                        f"Path: {path.cwe_id} · {path.capec_id} · {technique}", bullets=tuple(hops)
                    )
                )
            paragraphs.append(ReportParagraph(f"Omitted paths: {associations.omitted_count}"))
            for missing in associations.missing_links:
                paragraphs.append(
                    ReportParagraph(f"Missing link: {missing.subject}: {missing.reason}")
                )
            if not associations.paths:
                paragraphs.append(ReportParagraph("No paths recorded."))
            sections.append(
                ReportSection(
                    f"call {call.sequence} · {candidate.record.cve_id}",
                    tuple(paragraphs),
                    sections=tuple(paths),
                )
            )
    empty_paths = () if sections else (ReportParagraph("No recorded lookup paths."),)
    return ReportSection("Weakness paths", empty_paths, sections=tuple(sections))


def build_unknowns(contents: CheckedSession, triage_scope: str | None) -> ReportSection:
    paragraphs = [
        ReportParagraph(
            "Affectedness: unknown. Matches and version notes do not "
            "establish whether a deployment is affected."
        )
    ]
    if contents.findings is not None:
        for question in contents.findings.open_questions:
            paragraphs.append(ReportParagraph(f"Open question: {question}"))
        for progress in contents.findings.selections.product_queries:
            if not progress.complete:
                paragraphs.append(
                    ReportParagraph(
                        f"Inventory traversal unfinished: {progress.vendor or '(any vendor)'}/"
                        f"{progress.product or '(any product)'}; more pages remain."
                    )
                )
    for call in contents.calls:
        if call.outcome != "ok":
            paragraphs.append(
                ReportParagraph(
                    f"Failed call {call.sequence}: {call.command} · {call.outcome}", True
                )
            )
        answer = contents.responses.get(call.sequence)
        if isinstance(answer, KnowledgeEvidenceSet):
            for need in answer.coverage.needs:
                if need.outcome != NeedOutcome.FOUND:
                    paragraphs.append(
                        ReportParagraph(
                            f"call {call.sequence} · Need {need.kind}: "
                            f"{need.subject or '(no subject)'}"
                            f" · {need.outcome}"
                        )
                    )
            for applicability in answer.product_applicability:
                paragraphs.append(
                    ReportParagraph(
                        f"call {call.sequence} · {applicability.product}: applicability unknown. "
                        f"{applicability.basis}"
                    )
                )
        elif isinstance(answer, ProductQueryResponse) and answer.next_cursor is not None:
            paragraphs.append(
                ReportParagraph(
                    f"call {call.sequence} · This inventory page has a continuation; "
                    "the page alone does not establish inventory completeness."
                )
            )
    sections: tuple[ReportSection, ...] = ()
    if triage_scope is not None:
        sections = (
            ReportSection(
                "Inventory versus deep-dive scope",
                (
                    ReportParagraph(
                        "Recorded workflow scope only; inventory membership does not "
                        "mean a CVE received a deep dive. This summary is not checked."
                    ),
                ),
                verbatim=triage_scope,
            ),
        )
    return ReportSection("What is not established", tuple(paragraphs), sections=sections)


def build_call_log(contents: CheckedSession) -> ReportSection:
    rows: list[tuple[str, ...]] = []
    for call in contents.calls:
        request = json.dumps(call.request, ensure_ascii=True, sort_keys=True)
        rows.append(
            (str(call.sequence), f"{call.interface}: {call.command}", call.outcome, request)
        )
    return ReportSection(
        "Call log",
        tables=(ReportTable(("Sequence", "Tool", "Outcome", "Request summary"), tuple(rows)),),
    )


def build_session_report(
    contents: CheckedSession, triage_scope: str | None = None
) -> SessionReport:
    """Raise ValueError for unreadable metadata; retain and display every checker failure."""
    header = build_header(contents)
    session = contents.session
    assert session is not None
    return SessionReport(
        title=f"Session report: {session.name}",
        synthetic=session.dataset.served.kind == ServedDatasetKind.SYNTHETIC_FIXTURE,
        check=contents.check,
        sections=(
            header,
            build_checks(contents),
            build_findings(contents),
            build_cves(contents),
            build_weakness_paths(contents),
            build_unknowns(contents, triage_scope),
            build_call_log(contents),
        ),
    )
