"""Synthetic explicit inputs shared by priority policy boundary tests."""

from datetime import date
from typing import Any

from vulnwitness.domain.asset_register import Applicability, Asset, AssetAssessment, SystemCategory
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
