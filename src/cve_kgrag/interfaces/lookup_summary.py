"""Plain-text exact lookups, including catalogue paths and their limits."""

from textwrap import fill

from cve_kgrag.domain.search import SearchResponse
from cve_kgrag.domain.weakness_associations import WeaknessAssociationPath
from cve_kgrag.interfaces.investigation_summary import format_severity
from cve_kgrag.interfaces.record_summary import format_published, summarize_description

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
                fill(summarize_description(record), width=width),
                "",
                "Weakness paths (catalogue associations):",
            )
        )
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
    if not lookup.candidates:
        lines.append("No matching CVE returned.")
    for warning in lookup.warnings:
        lines.append(fill(f"Warning [{warning.code}]: {warning.subject}", width=width))
    lines.extend(("", "Source anchors:"))
    for anchor in lookup.evidence:
        lines.append(anchor.evidence_id)
    if not lookup.evidence:
        lines.append("None recorded.")
    return "\n".join(lines)
