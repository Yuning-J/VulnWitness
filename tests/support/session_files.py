"""User-authored session findings for integration tests."""

from pathlib import Path
from typing import Any

import yaml


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
