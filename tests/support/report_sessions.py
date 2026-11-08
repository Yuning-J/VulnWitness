"""Real CLI fixture sessions and authored findings for report integration tests."""

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import yaml

from tests.support.builders import (
    build_anchor,
    build_cnvd_entry,
    build_cve_record,
    build_cvss_metric,
    build_versioned_product,
)
from tests.support.workspaces import build_test_workspace
from vulnwitness.adapters.fixture.synthetic_fixture import FixtureBundle
from vulnwitness.adapters.migration.cnvd_snapshot_catalog import (
    default_cnvd_snapshot_catalog_file,
    load_cnvd_snapshot_catalog,
)
from vulnwitness.cli import main
from vulnwitness.composition import load_packaged_fixture
from vulnwitness.domain.cnvd import PendingCnvdEntry, PendingCnvdOutcome, build_cnvd_index
from vulnwitness.domain.cve import CnvdEntry, CveRecord
from vulnwitness.domain.workspace import StartInvestigationRequest

CNVD_REPORT_CVE_IDS = (
    "CVE-9999-0004",
    "CVE-9999-0001",
    "CVE-9999-0006",
    "CVE-9999-0003",
    "CVE-9999-0002",
    "CVE-9999-0005",
    "CVE-9999-0007",
    "CVE-9999-0008",
    "CVE-9999-0001",
)
CNVD_REPORT_TITLE = 'SYNTHETIC: 中文标题 <img src=x onerror="alert(1)"> & [链接](bad)'
CNVD_REPORT_DESCRIPTION = 'SYNTHETIC: 中文描述 <script>alert("源")</script> & | *文本*\n第二行'


def build_cnvd_report_corpus(*, declares_language: bool = True) -> FixtureBundle:
    """Synthetic source pairs, unusable metrics, NVD states and all pending outcomes."""
    fixture = load_packaged_fixture()
    records: list[CveRecord] = []
    anchors = []
    pending: list[PendingCnvdEntry] = []
    entry_number = 0
    outcomes: tuple[PendingCnvdOutcome, ...] = (
        "cnvd_without_nvd_record",
        "cnvd_for_rejected_nvd_record",
        "cnvd_for_excluded_nvd_record",
    )
    for number in range(1, 9):
        cve_id = f"CVE-9999-{number:04d}"
        entries: list[CnvdEntry] = []
        for severity in ("medium", "low") if number in {1, 6} else ("high",):
            entry_number += 1
            cnvd_id = f"CNVD-9999-{entry_number:05d}"
            anchor = build_anchor(
                source_name="circl-cnvd",
                authoritative_record_id=cnvd_id,
                source_uri=f"urn:synthetic:cnvd:{cnvd_id}",
                locator=f"id={cnvd_id}",
            )
            anchors.append(anchor)
            entry = build_cnvd_entry(
                cnvd_id=cnvd_id,
                title=CNVD_REPORT_TITLE,
                description=CNVD_REPORT_DESCRIPTION,
                severity=severity,
                evidence_id=anchor.evidence_id,
            )
            entries.append(entry)
            if number >= 6:
                pending.append(
                    PendingCnvdEntry(cve_id=cve_id, outcome=outcomes[number - 6], entry=entry)
                )
        if number >= 6:
            continue
        nvd_anchor = build_anchor(authoritative_record_id=cve_id)
        anchors.append(nvd_anchor)
        evidence_ids = [nvd_anchor.evidence_id]
        for entry in entries:
            evidence_ids.append(entry.evidence_id)
        metrics = (build_cvss_metric(),)
        if number == 2:
            metrics = ()
        elif number == 3:
            metrics = (
                build_cvss_metric(
                    base_severity="CRITICAL", base_score=9.8, scorer="cna@example.org"
                ),
                build_cvss_metric(
                    version="3.0", base_severity="HIGH", base_score=8.1, scorer_type="secondary"
                ),
            )
        elif number == 5:
            metrics = (build_cvss_metric(base_severity="NONE", base_score=0),)
        records.append(
            build_cve_record(
                cve_id=cve_id,
                cvss=metrics,
                cnvd=tuple(entries),
                nvd_status={3: "Awaiting Analysis", 4: "Deferred"}.get(number, "Analyzed"),
                affected=(build_versioned_product(),),
                evidence_ids=tuple(evidence_ids),
            )
        )
    catalog = load_cnvd_snapshot_catalog(default_cnvd_snapshot_catalog_file())
    revision = catalog.snapshots[0].revision if declares_language else None
    return replace(
        fixture,
        records=tuple(records),
        evidence=tuple(anchors),
        cnvd_index=build_cnvd_index(records, pending, imported_revision=revision),
    )


def build_cnvd_report_session(
    root: Path,
    cve_ids: tuple[str, ...] = CNVD_REPORT_CVE_IDS,
    *,
    declares_language: bool = True,
) -> Path:
    """Record actual workspace lookups, including a repeat to exercise distinct-CVE counts."""
    _, workspace = build_test_workspace(
        root, corpus=build_cnvd_report_corpus(declares_language=declares_language)
    )
    started = workspace.start(StartInvestigationRequest(goal="Synthetic CNVD source comparison"))
    for cve_id in cve_ids:
        workspace.record(started.session_id, "lookup_cve", {"cve_id": cve_id})
    return root / started.session_id


def set_recorded_cnvd_language(directory: Path, language: str | None) -> None:
    """Edit source metadata at the recording boundary; digest violations remain visible."""
    for path in sorted((directory / "responses").glob("*.json")):
        lookup = json.loads(path.read_bytes())
        if language is None:
            lookup.pop("cnvd_language", None)
        else:
            lookup["cnvd_language"] = language
        path.write_text(json.dumps(lookup), encoding="utf-8")


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
