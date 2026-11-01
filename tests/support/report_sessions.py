"""Real CLI fixture sessions and authored findings for report integration tests."""

import json
from pathlib import Path
from typing import Any

import yaml

from vulnwitness.cli import main


def read_document(directory: Path, sequence: int) -> dict[str, Any]:
    return json.loads((directory / f"responses/{sequence:04d}.json").read_bytes())


def read_findings(directory: Path) -> dict[str, Any]:
    return yaml.safe_load((directory / "findings.yaml").read_text())


def save_findings(directory: Path, findings: dict[str, Any]) -> None:
    (directory / "findings.yaml").write_text(yaml.safe_dump(findings), encoding="utf-8")


def build_report_session(directory: Path) -> None:
    commands = (
        ["product", "--vendor", "democorp"],
        ["lookup", "CVE-9999-0002"],
        ["product", "--vendor", "democorp", "--version", "2.0"],
        ["investigate", "CVE-9999-0001", "--scope", "implementation_only"],
    )
    for command in commands:
        main(
            [
                *command,
                "--session",
                str(directory),
                "--session-goal",
                "Review demonstration product records",
                "--session-scope",
                "Recorded fixture inventory and selected lookups",
            ],
            environment={},
        )
    page = read_document(directory, 1)
    lookup = read_document(directory, 2)
    version_page = read_document(directory, 3)
    investigation = read_document(directory, 4)
    product = page["items"][0]
    identity = product["basis"]["matched_products"][0]
    version_item = version_page["items"][0]
    version_note = version_item["nvd_version_note"]
    path = lookup["candidates"][0]["weakness_associations"]["paths"][0]
    need = investigation["coverage"]["needs"][0]
    declarations: list[dict[str, Any]] = [
        {
            "id": "product-match",
            "kind": "product_field_match",
            "author": "workflow",
            "status": "unconfirmed",
            "claim": {
                "kind": "product_field_match",
                "call": 1,
                "cve_id": product["record"]["cve_id"],
                **identity,
            },
            "citations": [{"call": 1, "evidence_id": page["evidence"][0]["evidence_id"]}],
        },
        {
            "id": "version-note",
            "kind": "version_note",
            "author": "user",
            "status": "confirmed",
            "claim": {
                "kind": "version_note",
                "call": 3,
                "cve_id": version_item["record"]["cve_id"],
                "version": "2.0",
                "mention": version_note["mention"],
                "outcome": version_note["outcome"],
                "applicability": "unknown",
            },
            "citations": [{"call": 3, "evidence_id": version_page["evidence"][0]["evidence_id"]}],
        },
        {
            "id": "catalogue-path",
            "kind": "catalogue_association",
            "author": "user",
            "status": "unconfirmed",
            "claim": {
                "kind": "catalogue_association",
                "call": 2,
                "cve_id": "CVE-9999-0002",
                "cwe_id": path["cwe_id"],
                "capec_id": path["capec_id"],
                "technique_id": path["technique"]["technique_id"],
                "terminal_reason": path["terminal_reason"],
                "inherited_from": path["inherited_from"],
                "inherited_from_cwe": path["inherited_from_cwe"],
                "hops": path["hops"],
            },
            "citations": [{"call": 2, "evidence_id": lookup["evidence"][0]["evidence_id"]}],
        },
        {
            "id": "need-status",
            "kind": "need_status",
            "author": "user",
            "status": "unconfirmed",
            "claim": {
                "kind": "need_status",
                "call": 4,
                "need_kind": need["kind"],
                "subject": need["subject"],
                "outcome": need["outcome"],
            },
            "citations": [{"call": 4, "evidence_id": investigation["evidence"][0]["evidence_id"]}],
        },
        {
            "id": "analyst-review",
            "kind": "analyst_note",
            "author": "user",
            "status": "confirmed",
            "statement": "Review deployment relevance separately.",
            "citations": [],
        },
        {
            "id": "model-review",
            "kind": "model_judgement",
            "author": "agent",
            "status": "unconfirmed",
            "statement": "The model proposes a deployment review.",
            "citations": [],
        },
    ]
    save_findings(
        directory,
        {
            "findings": declarations,
            "selections": {"cve_ids": [], "product_queries": []},
            "open_questions": ["Which deployed version needs review?"],
        },
    )


def read_recorded_files(directory: Path) -> dict[str, bytes]:
    recorded_files: dict[str, bytes] = {}
    for folder in ("calls", "responses"):
        for path in (directory / folder).iterdir():
            recorded_files[str(path.relative_to(directory))] = path.read_bytes()
    return recorded_files
