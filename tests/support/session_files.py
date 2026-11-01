"""User-authored session findings for integration tests."""

from pathlib import Path
from typing import Any

import yaml

from vulnwitness.domain.product_query import ProductQueryResponse
from vulnwitness.domain.search import SearchResponse


def write_findings(directory: Path, citations: list[dict[str, Any]]) -> None:
    findings = {
        "findings": [
            {
                "id": "review-1",
                "statement": "An analyst reviewed these returned anchors.",
                "kind": "analyst_note",
                "status": "unconfirmed",
                "citations": citations,
            }
        ],
        "selections": {"cve_ids": [], "product_queries": []},
        "open_questions": ["Does the selected deployment use an affected version?"],
    }
    (directory / "findings.yaml").write_text(yaml.safe_dump(findings), encoding="utf-8")


def populate_product_findings(
    template: Path,
    page: ProductQueryResponse,
    lookup: SearchResponse,
    product_call: int,
    lookup_call: int,
) -> dict[str, Any]:
    """Fill the shipped template from a product page and its selected candidate lookup."""
    findings: dict[str, Any] = yaml.safe_load(template.read_text())
    cve_id = page.items[0].record.cve_id
    findings["findings"][0]["statement"] = (
        f"Synthetic {cve_id} returned a product-field match for vendor {page.vendor}. "
        "This does not establish deployed applicability."
    )
    findings["findings"][0]["status"] = "confirmed"
    findings["findings"][0]["citations"] = [
        {"call": product_call, "evidence_id": page.evidence[0].evidence_id}
    ]
    findings["findings"][1]["statement"] = (
        f"Selected {cve_id} to inspect its product-field match and lookup weakness "
        "associations. Deployment relevance and applicability remain unknown."
    )
    findings["findings"][1]["citations"] = [
        {"call": lookup_call, "evidence_id": lookup.evidence[0].evidence_id}
    ]
    findings["selections"]["cve_ids"] = [cve_id]
    findings["selections"]["product_queries"] = [
        {
            "vendor": page.vendor,
            "product": page.product,
            "version": page.version,
            "calls": [product_call],
            "next_cursor": page.next_cursor,
            "complete": page.next_cursor is None,
        }
    ]
    findings["open_questions"] = [
        "Which deployed component and version should be reviewed?",
        "Unvisited pages remain; this query does not establish vulnerability completeness.",
        "Citation resolution does not establish statement support.",
    ]
    return findings
