"""Synthetic explicit inputs shared by priority policy boundary tests."""

from dataclasses import replace
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from tests.support.builders import FIXED_RETRIEVED_AT
from tests.support.report_sessions import build_cnvd_report_corpus
from tests.support.workspaces import build_test_workspace
from vulnwitness.adapters.priority_policy import default_priority_policy_file, load_priority_policy
from vulnwitness.adapters.session.check import SessionChecker
from vulnwitness.application.priority_session import build_session_priority
from vulnwitness.domain.asset_register import (
    Applicability,
    Asset,
    AssetAssessment,
    AssetRegister,
    SystemCategory,
)
from vulnwitness.domain.cve import KevEntry
from vulnwitness.domain.kev import KevCapability
from vulnwitness.domain.priority_decision import PolicyIdentity, PriorityArtifact, PriorityDecision
from vulnwitness.domain.priority_facts import (
    ApplicabilityFact,
    GradeAuthority,
    HighGradeFact,
    HighGradeStatus,
    KevFact,
    KevStatus,
    PriorityFacts,
    SystemCategoryFact,
)
from vulnwitness.domain.served_dataset import ServedDataset, ServedDatasetKind
from vulnwitness.domain.session_record import SessionDatasetIdentity
from vulnwitness.domain.workspace import StartInvestigationRequest

EVIDENCE_ID = "ev:1234567890abcdef12345678"
REFERENCE_DATE = date(2026, 11, 8)


def build_register_document() -> dict[str, Any]:
    return {
        "format_version": 1,
        "assets": [
            {"name": "gateway", "markets": ["CN"], "system_category": "external_connection"}
        ],
        "assessments": [
            {
                "asset": "gateway",
                "cve_id": "CVE-2026-1234",
                "applicability": "affected",
                "justification": "The deployed version is affected.",
                "assessor": "analyst",
                "assessed_at": "2026-11-08",
            }
        ],
    }


def build_priority_inputs(
    applicability: Applicability = "affected",
    system_category: SystemCategory = "external_connection",
    kev: KevStatus = "not_listed_in_snapshot",
    high_grade: HighGradeStatus = "absent",
    authorities: tuple[GradeAuthority, ...] = (),
    markets: tuple[str, ...] = ("CN",),
) -> tuple[Asset, AssetAssessment, PriorityFacts]:
    asset = Asset(name="gateway", markets=markets, system_category=system_category)
    assessment = AssetAssessment(
        asset=asset.name,
        cve_id="CVE-2026-1234",
        applicability=applicability,
        justification="The deployed version was checked.",
        assessor="analyst",
        assessed_at=REFERENCE_DATE,
    )
    facts = PriorityFacts(
        applicability=ApplicabilityFact(value=applicability, evidence_ids=()),
        system_category=SystemCategoryFact(value=system_category, evidence_ids=()),
        kev=KevFact(
            value=kev,
            evidence_ids=(EVIDENCE_ID,),
            snapshot_retrieved_at=REFERENCE_DATE if kev == "not_listed_in_snapshot" else None,
        ),
        high_grade=HighGradeFact(
            value=high_grade, evidence_ids=(EVIDENCE_ID,), triggering_authorities=authorities
        ),
    )
    return asset, assessment, facts


def build_priority_artifact(decisions: tuple[PriorityDecision, ...]) -> PriorityArtifact:
    return PriorityArtifact(
        program_version="2.0.0.dev0",
        policy=PolicyIdentity(name="cn-auto-demo", format_version=1, content_sha256="a" * 64),
        dataset=SessionDatasetIdentity(
            served=ServedDataset(
                kind=ServedDatasetKind.SYNTHETIC_FIXTURE, cve_search_version="synthetic-test"
            ),
            store_name=None,
            store_manifest_sha256="b" * 64,
            corpus_content_sha256="c" * 64,
            fight_snapshot_sha256=None,
            mitre_snapshot_sha256=None,
        ),
        response_digests=(),
        register_sha256="d" * 64,
        reference_date=REFERENCE_DATE,
        used_after_reference_date_information=False,
        decisions=decisions,
    )


def build_priority_session(
    root: Path,
    cve_ids: tuple[str, ...] = ("CVE-9999-0001",),
    *,
    record_capabilities: bool = True,
    kev_imported: bool = True,
    record_overrides: dict[str, Any] | None = None,
    cnvd_overrides: dict[str, Any] | None = None,
) -> Path:
    """Frozen real workspace calls over the shared synthetic CNVD comparison corpus."""
    corpus = build_cnvd_report_corpus()
    records = list(corpus.records)
    if record_overrides is not None:
        records[0] = records[0].model_copy(update=record_overrides)
    if cnvd_overrides is not None:
        entries = []
        for entry in records[0].cnvd:
            entries.append(entry.model_copy(update=cnvd_overrides))
        records[0] = records[0].model_copy(update={"cnvd": tuple(entries)})
    snapshot = KevCapability(imported=False)
    if kev_imported:
        snapshot = KevCapability(
            imported=True,
            retrieved_at=FIXED_RETRIEVED_AT,
            source_version="synthetic-kev-snapshot",
        )
    corpus = replace(corpus, records=tuple(records), kev_snapshot=snapshot)
    _, workspace = build_test_workspace(root, corpus=corpus)
    started = workspace.start(StartInvestigationRequest(goal="Synthetic priority decisions"))
    if record_capabilities:
        workspace.record(started.session_id, "get_knowledge_capabilities", {})
    for cve_id in cve_ids:
        workspace.record(started.session_id, "lookup_cve", {"cve_id": cve_id})
    return root / started.session_id


def write_priority_register(
    path: Path,
    cve_ids: tuple[str, ...] = ("CVE-9999-0001",),
    *,
    category: str = "external_connection",
    applicability: str = "affected",
) -> Path:
    document = build_register_document()
    document["assets"][0]["system_category"] = category
    assessments = []
    for cve_id in cve_ids:
        assessment = dict(document["assessments"][0])
        assessment["cve_id"] = cve_id
        assessment["applicability"] = applicability
        assessments.append(assessment)
    document["assessments"] = assessments
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def priority_arguments(
    directory: Path, assets: Path, reference_date: str = "2026-11-08"
) -> list[str]:
    return [
        "prioritise",
        str(directory),
        "--assets",
        str(assets),
        "--policy",
        "cn-auto-demo",
        "--as-of",
        reference_date,
    ]


def build_priority_report_session(root: Path) -> Path:
    """Record all four recommendation outcomes and a missing-lookup note on frozen data."""
    directory = build_priority_session(
        root,
        ("CVE-9999-0001", "CVE-9999-0002", "CVE-9999-0003", "CVE-9999-0004"),
        record_overrides={"kev": KevEntry(date_added="2026-01-01")},
    )
    assets = []
    assessments = []
    for name, cve_id, category, applicability in (
        ("head <script>alert(1)</script>", "CVE-9999-0001", "external_connection", "affected"),
        ("ota", "CVE-9999-0002", "software_update", "affected"),
        ("body", "CVE-9999-0003", "other", "not_affected"),
        ("unclassified", "CVE-9999-0004", "unknown", "affected"),
        ("missing", "CVE-9999-0099", "external_connection", "unknown"),
    ):
        assets.append({"name": name, "markets": ["CN"], "system_category": category})
        assessments.append(
            {
                "asset": name,
                "cve_id": cve_id,
                "applicability": applicability,
                "justification": "Synthetic inventory assessment <img src=x>.",
                "assessor": "synthetic analyst",
                "assessed_at": "2026-11-08",
            }
        )
    register = AssetRegister.model_validate(
        {"format_version": 1, "assets": assets, "assessments": assessments}
    )
    policy = load_priority_policy(default_priority_policy_file())
    artifact = build_session_priority(
        SessionChecker(directory).check_with_contents(),
        register,
        policy.policy,
        policy.content_sha256,
        date(2026, 10, 12),
        "2.0.0.dev0",
    )
    (directory / "priority.json").write_bytes(artifact.to_json_bytes())
    return directory
