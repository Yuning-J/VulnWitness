"""Plain-text exact lookups, including catalogue paths and their limits."""

from textwrap import fill

from vulnwitness.application.cnvd_presentation import describe_cnvd_comparison
from vulnwitness.application.investigation_presentation import format_severity
from vulnwitness.domain.cve_lookup import ComparedCnvdEntry, CveLookupResponse
from vulnwitness.domain.search import SearchResponse
from vulnwitness.domain.weakness_associations import WeaknessAssociationPath
from vulnwitness.interfaces.record_summary import format_published, summarize_description

MISSING_LINK_REASONS = {
    "no_specific_cwe": "no specific CWE supplied",
    "cwe_not_in_snapshot": "CWE absent from this snapshot",
    "no_related_attack_pattern": "no related attack pattern in this snapshot",
    "capec_not_in_snapshot": "CAPEC absent from this snapshot",
    "capec_parent_unavailable": "CAPEC parent unavailable in this snapshot",
    "attack_technique_unavailable": "ATT&CK technique unavailable in this snapshot",
}


def format_weakness_path(path: WeaknessAssociationPath) -> str:
    """Show every catalogue hop, marking hierarchy inference explicitly."""
    fragments = [path.cwe_id]
    for hop in path.hops:
        if hop.relation == "nvd_cwe":
            continue
        destination = hop.to_id
        if hop.relation == "cwe_child_of":
            destination += " [CWE inheritance inference]"
        elif hop.relation == "capec_child_of":
            destination += " [CAPEC inheritance]"
        fragments.append(destination)
    notation = " → ".join(fragments)
    if path.technique is None:
        return notation + " (no ATT&CK mapping in this snapshot)"
    return notation + " " + path.technique.name


def render_lookup_summary(lookup: SearchResponse, width: int = 100) -> str:
    """Render source fields and all supplied paths; source anchor IDs come last."""
    lines = [f"Lookup: {lookup.query}", f"Status: {lookup.status}"]
    for candidate in lookup.candidates:
        record = candidate.record
        products: list[str] = []
        for product in record.affected:
            name = f"{product.vendor}/{product.product}"
            if name not in products:
                products.append(name)
        kev = "not listed" if record.kev is None else f"yes {record.kev.date_added.isoformat()}"
        lines.extend(
            (
                "",
                record.cve_id,
                f"Published: {format_published(record)}",
                f"CVSS: {format_severity(record)}",
                fill(f"CWEs: {', '.join(record.cwe_ids) or 'unknown'}", width=width),
                fill(f"Products: {', '.join(products) or 'unknown'}", width=width),
                f"KEV: {kev}",
                fill("NVD: " + summarize_description(record), width=width),
                "",
            )
        )
        if record.cnvd:
            for metric in record.cvss:
                lines.append(
                    f"CVSS {metric.version} {metric.base_severity or 'unknown'} "
                    f"{metric.base_score:g} · assessed by {metric.scorer} "
                    f"· {metric.scorer_type or 'type not recorded'} · channel: NVD"
                )
        for entry in record.cnvd:
            if isinstance(entry, ComparedCnvdEntry):
                lines.extend(render_cnvd_comparison(entry, width))
        lines.extend(("", "Weakness paths (catalogue associations):"))
        associations = candidate.weakness_associations
        if associations is None:
            lines.append("Not supplied.")
            continue
        for path in associations.paths:
            lines.append(format_weakness_path(path))
        if not associations.paths:
            lines.append("None recorded.")
        lines.extend((f"Omitted paths: {associations.omitted_count}", "Missing links:"))
        for missing in associations.missing_links:
            lines.append(
                fill(
                    f"{missing.subject}: {MISSING_LINK_REASONS[missing.reason]} [{missing.reason}]",
                    width=width,
                )
            )
        if not associations.missing_links:
            lines.append("None recorded.")
        lines.extend(("", fill(associations.note, width=width)))
    if isinstance(lookup, CveLookupResponse):
        for pending in lookup.pending_cnvd:
            lines.extend(("", pending.cve_id))
            lines.extend(render_cnvd_comparison(pending, width))
        if lookup.cnvd_attribution is not None:
            lines.extend(("", fill(lookup.cnvd_attribution, width=width)))
        if lookup.cnvd_language is not None:
            lines.append(f"CNVD language: {lookup.cnvd_language}")
        if lookup.not_found_statement is not None:
            lines.append(lookup.not_found_statement)
    if not lookup.candidates:
        if isinstance(lookup, CveLookupResponse) and lookup.pending_cnvd:
            lines.append("No servable NVD record; pending CNVD entries shown above.")
        else:
            lines.append("No matching CVE returned.")
    for warning in lookup.warnings:
        lines.append(fill(f"Warning [{warning.code}]: {warning.subject}", width=width))
    lines.extend(("", "Source anchors:"))
    for anchor in lookup.evidence:
        lines.append(anchor.evidence_id)
        if isinstance(lookup, CveLookupResponse) and lookup.cnvd_attribution is not None:
            lines.append(
                f"  {anchor.source_name} · {anchor.authoritative_record_id} "
                f"· {anchor.source_uri} · revision {anchor.source_version or 'not recorded'}"
            )
    if not lookup.evidence:
        lines.append("None recorded.")
    return "\n".join(lines)


def render_cnvd_comparison(entry: ComparedCnvdEntry, width: int) -> list[str]:
    """Keep raw grades, assessing bodies and the recorded comparison explicit."""
    comparison = entry.source_comparison
    nvd_grade = comparison.nvd_raw_severity
    nvd_statement = "no severity from NVD's own CVSS v3 metric"
    if nvd_grade is not None:
        nvd_statement = (
            f"CVSS {nvd_grade.cvss_version} {nvd_grade.base_severity or 'unknown'} "
            f"· assessed by {nvd_grade.scorer} "
            f"· {nvd_grade.scorer_type or 'type not recorded'}"
        )
    lines = [
        f"NVD: {nvd_statement}",
        f"CNVD {entry.cnvd_id}: {comparison.cnvd_raw_severity} "
        "· CNVD three-grade scheme (高 / 中 / 低) · assessed by CNVD",
        f"NVD state: {comparison.nvd_state}",
        fill(f"CNVD title: {entry.title}", width=width),
        fill(f"CNVD description: {entry.description}", width=width),
        describe_cnvd_comparison(comparison),
        render_cnvd_name_check(entry),
        f"Rule: {comparison.rule}",
        fill(comparison.statement, width=width),
        f"Evidence: {entry.evidence_id}",
    ]
    for product in entry.products:
        lines.append(fill(f"CNVD product: {product}", width=width))
    if entry.submit_time is not None:
        lines.append(f"CNVD submitTime: {entry.submit_time.isoformat()}")
    if entry.open_time is not None:
        lines.append(f"CNVD openTime: {entry.open_time.isoformat()}")
    if entry.handling_advice is not None:
        lines.append(fill(f"CNVD handling advice: {entry.handling_advice}", width=width))
    return lines


def render_cnvd_name_check(entry: ComparedCnvdEntry) -> str:
    """One line with the label and the names available for review."""
    check = entry.name_check
    label: str = check.result
    if check.uncheckable_reason is not None:
        label += f" ({check.uncheckable_reason})"
    line = f"Name check: {label} · CNVD name: {check.cnvd_name or 'none extracted'}"
    if check.nvd_pair is not None:
        line += f" · NVD: {check.nvd_pair.vendor}/{check.nvd_pair.product}"
    return line
