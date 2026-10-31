"""Plain-text product vulnerabilities using the same field formatting as investigations."""

from cve_kgrag.domain.product_query import PRODUCT_ORDER_DESCRIPTION, ProductQueryResponse
from cve_kgrag.interfaces.investigation_summary import format_paragraph, format_severity


def render_product_query_summary(vulnerabilities: ProductQueryResponse) -> str:
    """Render a page, its continuation, matching basis and NVD facts, with no ranking."""
    lines = [
        format_paragraph(
            f"Product vulnerabilities: vendor={vulnerabilities.vendor or '(any)'}; "
            f"product={vulnerabilities.product or '(any)'}; "
            f"version={vulnerabilities.version or '(not supplied)'}"
        ),
        f"Showing {len(vulnerabilities.items)} of {vulnerabilities.total_available} "
        f"matching CVEs (page size {vulnerabilities.limit}).",
        format_paragraph(
            "Description mentions left out because the requested vendor was not named: "
            f"{vulnerabilities.description_mentions_vendor_unconfirmed}."
        ),
        format_paragraph(PRODUCT_ORDER_DESCRIPTION),
        "Affectedness: unknown. NVD backlog and mention-only evidence limit coverage.",
        "",
        "Matched products (all pages):",
    ]
    for product in vulnerabilities.matched_products:
        lines.append(format_paragraph(f"{product.vendor}:{product.product}"))
    if not vulnerabilities.matched_products:
        lines.append("None recorded.")
    lines.extend(("", "CVEs:"))
    for vulnerability in vulnerabilities.items:
        record = vulnerability.record
        kev = "not listed" if record.kev is None else f"yes {record.kev.date_added.isoformat()}"
        published = "unknown" if record.published is None else record.published.date().isoformat()
        lines.append(
            format_paragraph(
                f"{record.cve_id} | Severity: {format_severity(record)} | "
                f"KEV: {kev} | Published: {published}"
            )
        )
        basis = vulnerability.basis
        if basis.kind == "product_field":
            matched_names: list[str] = []
            for product in basis.matched_products:
                matched_names.append(f"{product.vendor}:{product.product}")
            basis_text = ", ".join(matched_names)
        else:
            basis_text = basis.matched_phrase
        lines.append(format_paragraph(f"Basis: {basis.kind} ({basis_text})"))
        if vulnerability.nvd_version_note is not None:
            lines.append(format_paragraph(vulnerability.nvd_version_note.wording))
    if not vulnerabilities.items:
        lines.append("None returned.")
    if vulnerabilities.next_cursor is not None:
        lines.extend(
            ("", "Next page: repeat the request with --cursor", vulnerabilities.next_cursor)
        )
    lines.extend(("", "Source records: --format json; anchors: cve-kgrag evidence <evidence_id>."))
    return "\n".join(lines)
