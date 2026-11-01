"""Compose report sections from recorded content and the existing layered check."""

import json
from datetime import UTC

from pydantic import BaseModel

from vulnwitness.application.investigation_report import build_investigation_report
from vulnwitness.application.triage_workflow import triage_selection_key
from vulnwitness.domain.cve import CveRecord, CvssMetric
from vulnwitness.domain.cvss_ranking import rank_cvss_metric
from vulnwitness.domain.evidence import EvidenceAnchor
from vulnwitness.domain.investigation import KnowledgeEvidenceSet, NeedOutcome
from vulnwitness.domain.product_query import ProductQueryResponse, ProductVulnerability
from vulnwitness.domain.search import Candidate, SearchResponse
from vulnwitness.domain.served_dataset import ServedDatasetKind
from vulnwitness.domain.session_record import SessionFinding
from vulnwitness.domain.session_report import (
    CheckedSession,
    ReportBadge,
    ReportFact,
    ReportLink,
    ReportParagraph,
    ReportSection,
    ReportStat,
    ReportTable,
    SessionReport,
)
from vulnwitness.domain.triage import TriageSummary
from vulnwitness.domain.weakness_associations import DERIVED_ASSOCIATION_NOTE, WeaknessAssociations


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
    return ReportSection(
        "Dataset identity", paragraphs, (ReportTable(("Identity", "Recorded value"), rows),)
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
    for finding in contents.findings.effective_findings():
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
    paragraphs = (
        () if contents.findings.effective_findings() else (ReportParagraph("None recorded."),)
    )
    return ReportSection("Findings", paragraphs, sections=tuple(sections))


def format_metric(metric: CvssMetric) -> str:
    scorer = "NVD" if metric.scorer == "nvd@nist.gov" else metric.scorer
    label = f"{(metric.base_severity or 'unknown').title()} {metric.base_score:g}"
    return (
        f"{label} · CVSS {metric.version} · {scorer} · {metric.scorer_type or 'type not recorded'}"
    )


def format_severity(record: CveRecord) -> str:
    if not record.cvss:
        return "Severity unknown"
    return format_metric(max(record.cvss, key=rank_cvss_metric))


def published_date(record: CveRecord) -> str:
    return "unknown" if record.published is None else record.published.date().isoformat()


def basis_label(vulnerability: ProductVulnerability) -> str:
    basis = vulnerability.basis
    if basis.kind == "description_mention":
        return f"Description mention · {basis.matched_phrase}"
    identities: list[str] = []
    for identity in basis.matched_products:
        identities.append(f"{identity.vendor}/{identity.product}")
    return "NVD product field · " + ", ".join(identities)


def build_version_fact(vulnerability: ProductVulnerability | None) -> ReportFact:
    if vulnerability is None or vulnerability.nvd_version_note is None:
        return ReportFact("NVD version condition", "not recorded")
    note = vulnerability.nvd_version_note
    comparison = ""
    if note.outcome == "hit":
        condition = note.matched_condition
        bounds: list[str] = []
        for operator, bound in (
            ("=", condition.exact),
            ("≥", condition.start_including),
            (">", condition.start_excluding),
            ("≤", condition.end_including),
            ("<", condition.end_excluding),
        ):
            if bound is not None:
                bounds.append(f"{operator} {bound}")
        comparison = f"{note.mention.rsplit(' ', 1)[-1]} vs {', '.join(bounds)}"
    return ReportFact("NVD version condition", comparison, ReportBadge(note.outcome), note.wording)


def path_counts(associations: WeaknessAssociations) -> tuple[int, set[str]]:
    reaching = 0
    techniques: set[str] = set()
    for path in associations.paths:
        if path.technique is not None:
            reaching += 1
            techniques.add(path.technique.technique_id)
    return reaching, techniques


def build_associations(associations: WeaknessAssociations | None) -> ReportSection:
    note = ReportParagraph(
        "Catalogue associations, not attack paths; “no ATT&CK mapping” "
        "describes this snapshot only."
    )
    if associations is None:
        return ReportSection(
            "Weakness associations", (note, ReportParagraph("No catalogue paths recorded."))
        )
    groups: dict[str, dict[str, set[str]]] = {}
    group_path_counts: dict[str, int] = {}
    group_reaching_counts: dict[str, int] = {}
    paths: list[ReportSection] = []
    for index, path in enumerate(associations.paths, 1):
        group_path_counts[path.cwe_id] = group_path_counts.get(path.cwe_id, 0) + 1
        techniques = groups.setdefault(path.cwe_id, {}).setdefault(path.capec_id, set())
        if path.technique is not None:
            group_reaching_counts[path.cwe_id] = group_reaching_counts.get(path.cwe_id, 0) + 1
            techniques.add(path.technique.technique_id)
        hops: list[str] = []
        for hop in path.hops:
            hops.append(
                f"{hop.from_id} → {hop.to_id} [{hop.relation}] · {hop.source} · "
                f"version {hop.source_version or 'not recorded'} · "
                f"identity {hop.source_sha256 or 'not recorded'}"
            )
        if path.inherited_from is not None:
            hops.append(f"CAPEC-parent inheritance: {path.inherited_from}")
        if path.inherited_from_cwe is not None:
            hops.append(f"CWE-parent inheritance: {path.inherited_from_cwe}")
        if path.technique_source is not None:
            source = path.technique_source
            hops.append(
                f"Terminal catalogue: {source.catalogue} · version {source.version} "
                f"· {source.sha256}"
            )
        hops.append(f"Terminal reason: {path.terminal_reason or 'reaches ATT&CK'}")
        paths.append(
            ReportSection(f"Path {index}: {path.cwe_id} → {path.capec_id}", bullets=tuple(hops))
        )
    overview: list[ReportSection] = []
    for cwe_id, capecs in groups.items():
        chips: list[str] = []
        for capec_id, techniques in capecs.items():
            chips.append(
                f"{capec_id} → {', '.join(sorted(techniques))}" if techniques else capec_id
            )
        hidden: tuple[ReportSection, ...] = ()
        if len(chips) > 4:
            hidden = (
                ReportSection(
                    f"+{len(chips) - 4} more", chips=tuple(chips[4:]), folded=True, layout="inline"
                ),
            )
        reaching = group_reaching_counts.get(cwe_id, 0)
        overview.append(
            ReportSection(
                cwe_id,
                chips=tuple(chips[:4]),
                sections=hidden,
                layout="paths",
                heading_note=f"→ {len(capecs)} CAPEC · {group_path_counts[cwe_id]} paths",
                badges=(
                    ReportBadge(
                        f"{reaching} reach ATT&CK"
                        if reaching
                        else "No ATT&CK mapping in this snapshot",
                        "ok" if reaching else "warn",
                    ),
                ),
            )
        )
    reaching, distinct = path_counts(associations)
    missing: list[str] = []
    for link in associations.missing_links:
        missing.append(f"Missing link: {link.subject}: {link.reason}")
    overview.append(
        ReportSection("Each original path", sections=tuple(paths), folded=True, layout="inline")
    )
    return ReportSection(
        "Weakness associations",
        paragraphs=(
            note,
            ReportParagraph(
                f"Showing {len(associations.paths)} returned paths; {reaching} "
                f"paths reaching ATT&CK; "
                f"{len(distinct)} distinct techniques; {associations.omitted_count} "
                f"paths omitted by the cap."
            ),
        ),
        bullets=tuple(missing),
        sections=tuple(overview),
    )


def build_card(
    candidate: Candidate,
    sequence: int,
    anchors: dict[str, EvidenceAnchor],
    vulnerability: ProductVulnerability | None,
    rank: int | None,
    triage: TriageSummary | None,
) -> ReportSection:
    record = candidate.record
    preferred_metric = max(record.cvss, key=rank_cvss_metric) if record.cvss else None
    description = next(
        (entry.value for entry in record.descriptions if entry.lang == "en"),
        record.descriptions[0].value,
    )
    clipped = description if len(description) <= 480 else description[:477].rsplit(" ", 1)[0] + " …"
    if triage is not None and triage.deep_dive.selection_mode == "user-chosen IDs":
        selection = "selected by the user."
    elif vulnerability is not None and rank is not None and triage is not None:
        outcome = (
            vulnerability.nvd_version_note.outcome
            if vulnerability.nvd_version_note
            else "not recorded"
        )
        selection = (
            f"#{rank} by the stated order: {basis_label(vulnerability)} match, "
            f"version note “{outcome}”, published {published_date(record)}. "
            f"Order, not risk ranking."
        )
    else:
        selection = "Recorded lookup; selection reason not recorded."
    sections = [
        ReportSection(
            "NVD description · untrusted text",
            (ReportParagraph(clipped),),
            layout="desc",
            sections=(
                ReportSection(
                    "Full recorded NVD description · untrusted text",
                    verbatim=description,
                    folded=True,
                    layout="inline",
                ),
            ),
        ),
        ReportSection(
            "Facts",
            facts=(
                ReportFact(
                    "Match basis", basis_label(vulnerability) if vulnerability else "not recorded"
                ),
                build_version_fact(vulnerability),
                ReportFact(
                    "Affectedness",
                    badge=ReportBadge("unknown", "warn"),
                    detail="configuration and environment not evaluated",
                ),
            ),
            chips=record.cwe_ids,
            layout="facts",
        ),
    ]
    if len(record.cvss) > 1:
        metrics: list[str] = []
        for metric in record.cvss:
            if metric is not preferred_metric:
                metrics.append(format_metric(metric))
        sections.append(
            ReportSection(
                "Other severity metrics", bullets=tuple(metrics), folded=True, layout="inline"
            )
        )
    sections.append(build_associations(candidate.weakness_associations))
    sources: list[str] = []
    links: list[ReportLink] = []
    for evidence_id in record.evidence_ids:
        anchor = anchors.get(evidence_id)
        if anchor is None:
            sources.append(f"{evidence_id} · source unavailable · call {sequence}")
        else:
            filename = anchor.source_uri.rsplit("/", 1)[-1]
            sources.append(
                f"{evidence_id} · {anchor.source_name} · feed {filename} · call {sequence}"
            )
    links.append(ReportLink("NVD record", f"https://nvd.nist.gov/vuln/detail/{record.cve_id}"))
    sections.append(ReportSection("Sources", bullets=tuple(sources), links=tuple(links)))
    return ReportSection(
        record.cve_id,
        (
            ReportParagraph(f"Published {published_date(record)}"),
            ReportParagraph(f"Why selected: {selection}"),
        ),
        sections=tuple(sections),
        layout="card",
        anchor=record.cve_id,
        badges=(
            ReportBadge(
                format_severity(record),
                severity=preferred_metric.base_severity if preferred_metric is not None else None,
            ),
        ),
    )


def build_checks(contents: CheckedSession) -> ReportSection:
    check = contents.check
    claim_failures = sum(entry.status != "verified" for entry in check.claims.checks)
    rows: list[tuple[str, ...]] = []
    for name, passed, count, failures, meaning in (
        (
            "Record consistency",
            check.record.consistent,
            f"{check.record.calls_checked} calls",
            len(check.record.violations),
            "Files are complete and consistent with one dataset.",
        ),
        (
            "Citation resolution",
            check.citations.resolved,
            f"{check.citations.citations_checked} citations",
            len(check.citations.violations),
            "Each citation points to an anchor in a successful recorded call.",
        ),
        (
            "Structured claims",
            check.claims.verified,
            f"{len(check.claims.checks)} claims",
            claim_failures,
            "Claim fields equal the recorded response fields; this is not source support.",
        ),
    ):
        mark = "✓" if passed else f"✗ · {failures} violations"
        rows.append((mark, name, count, meaning))
    rows.append(
        (
            "\u2013",
            "Narrative",
            f"{check.not_checked.count} not checked",
            "Free text is never checked.",
        )
    )
    return ReportSection(
        "Check layers",
        paragraphs=(ReportParagraph(f"Superseded findings: {check.superseded_count}."),),
        tables=(ReportTable(("Status", "Layer", "Count", "Meaning"), tuple(rows)),),
    )


def build_execution(contents: CheckedSession, triage: TriageSummary | None) -> ReportSection:
    groups: list[ReportSection] = []
    index = 0
    while index < len(contents.calls):
        first = contents.calls[index]
        last = first
        index += 1
        while (
            index < len(contents.calls)
            and contents.calls[index].command == first.command
            and contents.calls[index].interface == first.interface
        ):
            last = contents.calls[index]
            index += 1
        label = (
            f"Call {first.sequence}"
            if first.sequence == last.sequence
            else f"Calls {first.sequence}\u2013{last.sequence}"
        )
        groups.append(
            ReportSection(
                label, (ReportParagraph(f"{first.interface}: {first.command}"),), layout="step"
            )
        )
    stop = triage.stop_reason if triage else "End of recorded calls; stop reason not recorded."
    groups.append(ReportSection("Stopped", (ReportParagraph(stop),), layout="step"))
    return ReportSection(
        "Execution and checks",
        sections=(
            ReportSection("Call timeline", sections=tuple(groups), layout="timeline"),
            build_checks(contents),
        ),
    )


def build_appendix(contents: CheckedSession, triage_scope: str | None) -> ReportSection:
    header = build_header(contents)
    findings = build_findings(contents)
    sections = [ReportSection("Dataset identity", header.paragraphs, header.tables, folded=True)]
    counts: dict[tuple[str, str], int] = {}
    if contents.findings is not None:
        for finding in contents.findings.effective_findings():
            key = (finding.kind, finding.author)
            counts[key] = counts.get(key, 0) + 1
    rows: list[tuple[str, ...]] = []
    for (kind, author), count in sorted(counts.items()):
        rows.append((kind, author, str(count)))
    sections.append(
        ReportSection(
            "Findings by kind and author",
            tables=(ReportTable(("Kind", "Author", "Count"), tuple(rows)),),
            sections=findings.sections,
            paragraphs=findings.paragraphs,
            folded=True,
        )
    )
    claims: list[tuple[str, ...]] = []
    for claim in contents.check.claims.checks:
        claims.append(
            (
                claim.finding_id,
                str(claim.call),
                claim.status,
                claim.field or "—",
                json.dumps(claim.expected, ensure_ascii=True),
                json.dumps(claim.recorded, ensure_ascii=True),
                claim.message,
            )
        )
    sections.append(
        ReportSection(
            "Per-claim check results",
            tables=(
                ReportTable(
                    ("Finding", "Call", "Status", "Field", "Expected", "Recorded", "Meaning"),
                    tuple(claims),
                ),
            ),
            folded=True,
        )
    )
    sections.append(
        ReportSection(
            "Full check JSON", verbatim=contents.check.model_dump_json(indent=2), folded=True
        )
    )
    if triage_scope is not None:
        sections.append(
            ReportSection(
                "Recorded workflow scope (not checked)", verbatim=triage_scope, folded=True
            )
        )
    return ReportSection("Technical appendix", sections=tuple(sections))


def parse_triage_scope(scope: str | None) -> TriageSummary | None:
    if scope is None:
        return None
    try:
        return TriageSummary.model_validate_json(scope)
    except ValueError:
        return None


def build_session_report(
    contents: CheckedSession, triage_scope: str | None = None
) -> SessionReport:
    """Compose only recorded values; optional scope metadata never changes checker verdicts."""
    session = contents.session
    if session is None:
        raise ValueError("session metadata is unreadable or invalid")
    triage = parse_triage_scope(triage_scope)
    pages: list[tuple[int, ProductQueryResponse]] = []
    inventory: list[tuple[int, ProductVulnerability]] = []
    lookups: list[tuple[int, Candidate, dict[str, EvidenceAnchor]]] = []
    investigations: list[tuple[int, KnowledgeEvidenceSet]] = []
    limits = [
        "Affectedness is unknown for every CVE: a version “hit” only "
        "matches an NVD CPE condition; configuration and environment "
        "were not evaluated.",
        DERIVED_ASSOCIATION_NOTE,
    ]
    for call in contents.calls:
        answer = contents.responses.get(call.sequence)
        if call.outcome != "ok":
            limits.append(f"Failed call {call.sequence}: {call.command} · {call.outcome}")
        if isinstance(answer, ProductQueryResponse):
            pages.append((call.sequence, answer))
            for vulnerability in answer.items:
                inventory.append((call.sequence, vulnerability))
        elif isinstance(answer, SearchResponse) and call.command in {"lookup", "lookup_cve"}:
            for candidate in answer.candidates:
                lookups.append((call.sequence, candidate, collect_anchors(answer)))
        elif isinstance(answer, KnowledgeEvidenceSet):
            investigations.append((call.sequence, answer))
            for need in answer.coverage.needs:
                if need.outcome != NeedOutcome.FOUND:
                    limits.append(
                        f"call {call.sequence} · Need {need.kind}: "
                        f"{need.subject or '(no subject)'} "
                        f"· {need.outcome}"
                    )
    if contents.findings is not None:
        for question in contents.findings.open_questions:
            limits.append(f"Open question: {question}")
    title = session.goal or session.name
    if triage_scope is not None:
        query = pages[0][1] if pages else None
        # A deadline can stop before the first page; its request may still be in the call log.
        if query is not None:
            title = (
                f"{query.product or query.vendor} {query.version or ''}".strip()
                + " — product vulnerability triage"
            )
    badges: list[ReportBadge] = []
    stats: list[ReportStat] = []
    if triage is not None:
        complete = bool(pages) and pages[-1][1].next_cursor is None
        total = str(pages[-1][1].total_available) if pages else "unknown"
        unread = str(max(0, pages[-1][1].total_available - len(inventory))) if pages else "unknown"
        if complete:
            badges.append(ReportBadge("Inventory complete", "ok"))
        else:
            reason = {"max_pages": "page cap", "time_limit": "time limit"}.get(
                triage.stop_reason, "failure"
            )
            badges.append(
                ReportBadge(
                    f"Stopped at the {reason} · {unread} of {total} not read",
                    "warn" if reason != "failure" else "bad",
                )
            )
            limits.insert(0, f"Inventory incomplete: {unread} matches were not read ({reason}).")
        if triage.stop_reason not in {"complete", "no_match", "max_pages", "time_limit"}:
            badges.append(ReportBadge(f"Triage failed: {triage.stop_reason}", "bad"))
        elif triage.stop_reason == "time_limit" and complete:
            badges.append(
                ReportBadge("Stopped at the time limit · planned lookups unfinished", "warn")
            )
        mode = (
            "selected by the user"
            if triage.deep_dive.selection_mode == "user-chosen IDs"
            else "first N by the stated order"
        )
        limits.append(
            "Selection is user-selected."
            if mode == "selected by the user"
            else "Selection is an order, not a risk ranking."
        )
        for step in triage.remaining_steps:
            limits.append(f"Remaining step: {step}")
        stats.extend(
            (
                ReportStat("Total matches", total, "reported by the product query"),
                ReportStat("Read", str(len(inventory)), f"{len(pages)} pages"),
                ReportStat("CVE details", str(len(lookups)), mode),
                ReportStat("Applicability", "unknown", "not established for any CVE"),
            )
        )
    elif triage_scope is not None:
        limits.append(
            "triage.json is unreadable or invalid; inventory and CVE detail scope unavailable."
        )
    if triage is None and pages and pages[-1][1].next_cursor is not None:
        limits.insert(0, "Inventory incomplete: the last recorded product page has a continuation.")
    check = contents.check
    if check.record.consistent and check.citations.resolved and check.claims.verified:
        badges.append(
            ReportBadge(
                f"Record, citations and {len(check.claims.checks)} claims "
                f"consistent with the record",
                "ok",
            )
        )
    else:
        for name, passed in (
            ("Record consistency", check.record.consistent),
            ("Citation resolution", check.citations.resolved),
            ("Structured claims", check.claims.verified),
        ):
            if not passed:
                badges.append(ReportBadge(f"{name} failed", "bad"))
    overview = ReportSection(
        "Overview",
        (
            ReportParagraph(
                f"Dataset {session.dataset.store_name or 'packaged demo data'} "
                f"· session “{session.name}” · recorded "
                f"{session.created_at.astimezone(UTC):%Y-%m-%d %H:%M UTC}"
            ),
        ),
        badges=tuple(badges),
        stats=tuple(stats),
    )
    basis_counts: dict[str, int] = {}
    outcomes: dict[str, int] = {}
    vulnerabilities: dict[str, ProductVulnerability] = {}
    for _, vulnerability in inventory:
        vulnerabilities[vulnerability.record.cve_id] = vulnerability
        basis_counts[vulnerability.basis.kind] = basis_counts.get(vulnerability.basis.kind, 0) + 1
        if vulnerability.nvd_version_note is not None:
            outcome = vulnerability.nvd_version_note.outcome
            outcomes[outcome] = outcomes.get(outcome, 0) + 1
    facts: list[str] = []
    if pages:
        facts.append(
            f"{basis_counts.get('product_field', 0)} of {len(inventory)} "
            f"read entries match the NVD product field; "
            f"{basis_counts.get('description_mention', 0)} "
            f"only mention the product in their description."
        )
    if pages and pages[0][1].version is not None:
        facts.append(
            f"Version {pages[0][1].version} against NVD conditions: {outcomes.get('hit', 0)} "
            f"hit, {outcomes.get('unknown', 0)} unknown, {outcomes.get('no_hit', 0)} "
            f"no hit."
        )
    returned = reaching = omitted = 0
    techniques: set[str] = set()
    for _, candidate, _ in lookups:
        associations = candidate.weakness_associations
        if associations is not None:
            count, distinct = path_counts(associations)
            returned += len(associations.paths)
            reaching += count
            techniques.update(distinct)
            omitted += associations.omitted_count
    if lookups:
        facts.append(
            f"The {len(lookups)} CVE details returned {returned} catalogue "
            f"paths; {reaching} paths reaching ATT&CK; {len(techniques)} "
            f"distinct techniques; {omitted} paths omitted by the cap."
        )
    for sequence, investigation in investigations:
        facts.append(
            f"Call {sequence} investigation ({investigation.applied_scope}): "
            f"{len(investigation.implementation_candidates)} implementation candidates, "
            f"{len(investigation.protocol_context)} FiGHT techniques, "
            f"status {investigation.status}"
        )
    ranks: dict[str, int] = {}
    for rank, vulnerability in enumerate(
        sorted(vulnerabilities.values(), key=triage_selection_key), 1
    ):
        ranks[vulnerability.record.cve_id] = rank
    cards: list[ReportSection] = []
    card_links: list[ReportLink] = []
    for sequence, candidate, anchors in lookups:
        cve_id = candidate.record.cve_id
        cards.append(
            build_card(
                candidate, sequence, anchors, vulnerabilities.get(cve_id), ranks.get(cve_id), triage
            )
        )
        card_links.append(ReportLink(cve_id, f"#{cve_id}"))
    rows: list[tuple[str, ...]] = []
    for index, (sequence, vulnerability) in enumerate(inventory, 1):
        record = vulnerability.record
        note = vulnerability.nvd_version_note
        rows.append(
            (
                str(index),
                record.cve_id,
                published_date(record),
                format_severity(record),
                basis_label(vulnerability),
                note.outcome if note else "not recorded",
                str(sequence),
            )
        )
    selection_paragraphs: tuple[ReportParagraph, ...] = ()
    if triage is not None:
        selection_text = f"Selection rule: {triage.deep_dive.selection_rule}"
        if triage.deep_dive.selection_mode == "user-chosen IDs":
            selection_text = "Selection: selected by the user."
        selection_paragraphs = (ReportParagraph(selection_text),)
    inventory_title = f"Read inventory · {len(inventory)} entries"
    if triage is not None:
        total = str(pages[-1][1].total_available) if pages else "unknown"
        inventory_title = f"Read inventory · {len(inventory)} of {total}"
    card_ids: set[str] = set()
    for _, candidate, _ in lookups:
        card_ids.add(candidate.record.cve_id)
    record_sections: list[ReportSection] = []
    if cards:
        record_sections.append(
            ReportSection(
                f"CVE details · {len(cards)} CVEs",
                paragraphs=selection_paragraphs,
                sections=tuple(cards),
            )
        )
    if rows:
        record_sections.append(
            ReportSection(
                inventory_title,
                tables=(
                    ReportTable(
                        (
                            "#",
                            "CVE",
                            "Published",
                            "Severity",
                            "Match basis",
                            "Version note",
                            "Call",
                        ),
                        tuple(rows),
                        tuple(card_links),
                    ),
                ),
            )
        )
    investigation_sections: list[ReportSection] = []
    for sequence, investigation in investigations:
        investigation_sections.append(build_investigation_report(investigation, sequence, card_ids))
    if investigation_sections:
        record_sections.append(
            ReportSection("Investigations", sections=tuple(investigation_sections))
        )
    return SessionReport(
        title,
        session.dataset.served.kind == ServedDatasetKind.SYNTHETIC_FIXTURE,
        check,
        (
            overview,
            ReportSection(
                "Key facts and limits",
                sections=(
                    ReportSection("What the records show", bullets=tuple(facts), layout="panel"),
                    ReportSection(
                        "What is not established", bullets=tuple(limits), layout="limits"
                    ),
                ),
                layout="two",
            ),
            *record_sections,
            build_execution(contents, triage),
            build_appendix(contents, triage_scope),
        ),
    )
