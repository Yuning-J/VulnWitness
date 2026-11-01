"""Builders for valid domain objects; tests override only the fields they exercise."""

from datetime import UTC, datetime
from typing import Any

import yaml

from vulnwitness.adapters.fixture.synthetic_fixture import FixtureBundle
from vulnwitness.domain.cve import AffectedProduct, CveRecord
from vulnwitness.domain.evidence import (
    UNSEALED_EVIDENCE_ID,
    Claim,
    EvidenceAnchor,
    seal_evidence_anchor,
)
from vulnwitness.domain.hashing import sha256_hex
from vulnwitness.domain.investigation import ToolStep
from vulnwitness.domain.taxonomy import AssertionKind, KnowledgeScope, SourceType, TrustLevel
from vulnwitness.domain.threat_context import (
    FightSnapshotCatalog,
    KnownFightSnapshot,
    SnapshotCoverage,
    ThreatContextItem,
)
from vulnwitness.domain.topic import ProtocolTopic

FIGHT_TEST_COMMIT = "0" * 40

FIXED_RETRIEVED_AT = datetime(2026, 10, 13, tzinfo=UTC)
ZERO_SHA256 = "0" * 64


def build_anchor(**overrides: Any) -> EvidenceAnchor:
    """A sealed anchor: its evidence ID derives from its fields, overrides included,
    unless ``evidence_id`` itself is overridden."""
    fields: dict[str, Any] = {
        "evidence_id": UNSEALED_EVIDENCE_ID,
        "source_name": "test-source",
        "source_type": SourceType.SYNTHETIC_FIXTURE,
        "authoritative_record_id": "CVE-9999-0001",
        "source_uri": "urn:vulnwitness:test",
        "retrieved_at": FIXED_RETRIEVED_AT,
        "content_sha256": ZERO_SHA256,
        "locator": "records#/0",
        "scope": KnowledgeScope.IMPLEMENTATION_VULNERABILITY,
        "assertion_kind": AssertionKind.ASSERTED,
        "license_or_terms_ref": "MIT",
        "trust_level": TrustLevel.SYNTHETIC,
    }
    fields.update(overrides)
    anchor = EvidenceAnchor(**fields)
    if "evidence_id" in overrides:
        return anchor
    return seal_evidence_anchor(anchor)


def build_versioned_product(**overrides: Any) -> AffectedProduct:
    """A synthetic CPE entry; tests supply the conditions they exercise."""
    fields: dict[str, Any] = {
        "vendor": "democorp",
        "product": "demo_gateway",
        "cpe": "cpe:2.3:a:democorp:demo_gateway:*:*:*:*:*:*:*:*",
        "status": "affected",
    }
    fields.update(overrides)
    return AffectedProduct.model_validate(fields)


def build_cve_record(**overrides: Any) -> CveRecord:
    fields: dict[str, Any] = {
        "cve_id": "CVE-9999-0001",
        "descriptions": [{"lang": "en", "value": "[SYNTHETIC] test record", "source": "test"}],
        "evidence_ids": [build_anchor().evidence_id],
    }
    fields.update(overrides)
    return CveRecord.model_validate(fields)


def build_threat_context_item(**overrides: Any) -> ThreatContextItem:
    """A FiGHT technique as its source indexes it: no matched fields or terms."""
    fields: dict[str, Any] = {
        "technique_id": "FGT1234",
        "name": "Test technique",
        "status": "theoretical",
        "source_status": "Theoretical",
        "tactic_ids": ["TA0001"],
        "tactic_names": ["Initial Access"],
        "matched_fields": [],
        "matched_terms": [],
        "evidence_ids": ["ev:" + "a" * 24],
    }
    fields.update(overrides)
    return ThreatContextItem.model_validate(fields)


def build_bundle_with(
    fixture_bundle: FixtureBundle, cve_id: str, description: str, **record_overrides: Any
) -> FixtureBundle:
    """``fixture_bundle`` plus one record anchored to its own evidence; ``record_overrides``
    sets further record fields, such as ``affected``."""
    anchor = build_anchor(authoritative_record_id=cve_id)
    record = build_cve_record(
        cve_id=cve_id,
        descriptions=[{"lang": "en", "value": description, "source": "test"}],
        evidence_ids=[anchor.evidence_id],
        **record_overrides,
    )
    return FixtureBundle(
        manifest=fixture_bundle.manifest,
        records=(*fixture_bundle.records, record),
        evidence=(*fixture_bundle.evidence, anchor),
    )


def build_claim(**overrides: Any) -> Claim:
    fields: dict[str, Any] = {
        "claim_id": "claim-1",
        "subject_id": "CVE-9999-0001",
        "statement": "CVE-9999-0001 is an implementation vulnerability in demo_gateway.",
        "scope": KnowledgeScope.IMPLEMENTATION_VULNERABILITY,
        "assertion_kind": AssertionKind.ASSERTED,
        "evidence_ids": [build_anchor().evidence_id],
    }
    fields.update(overrides)
    return Claim(**fields)


def build_topic(**overrides: Any) -> ProtocolTopic:
    """A pending-review test card for a fictional protocol, ``Demo Key Exchange`` (DKX)."""
    fields: dict[str, Any] = {
        "topic_id": "test:dkx",
        "version": "1.0.0",
        "canonical_name": "Demo Key Exchange",
        "exact_aliases": ["DKX", "D-KX"],
        "contextual_aliases": [{"alias": "KX", "requires_any": ["keyhub"]}],
        "entities": [{"name": "KeyHub", "role": "issues demo keys"}],
        "ecosystem_terms": ["demo network", "demo core"],
        "exclusions": [
            {"term": "dk", "reason": "bare dk names many demo kits"},
            {"term": "EAP-KX", "reason": "a different method"},
        ],
        "query_templates": ["DKX KeyHub"],
        "review": {
            "status": "pending_review",
            "reviewer": None,
            "reviewed_on": None,
            "basis": "test data",
        },
        "references": [{"title": "Demo spec", "uri": "urn:test:demo-spec", "locator": "1"}],
    }
    fields.update(overrides)
    return ProtocolTopic.model_validate(fields)


def build_fight_technique(**overrides: Any) -> dict[str, Any]:
    """A FiGHT-shaped technique entry for a fictional technique; override what a test needs."""
    fields: dict[str, Any] = {
        "id": "FGT9001",
        "name": "Demo Technique",
        "bluf": "A demo adversary abuses the KeyHub.",
        "description": "[SYNTHETIC] The adversary replays DKX messages to the KeyHub.",
        "status": "Theoretical",
        "tactics": ["TA0006"],
        "object-type": "technique",
        "procedureexamples": [{"name": "Replay", "description": "Replays DKX traffic."}],
    }
    fields.update(overrides)
    return fields


def build_fight_document(techniques: list[dict[str, Any]]) -> bytes:
    document = {
        "id": "FiGHT",
        "name": "FiGHT Threat Matrix",
        "tactics": [
            {
                "id": "TA0006",
                "name": "Credential Access",
                "description": "d",
                "object-type": "tactic",
            },
            {"id": "TA0007", "name": "Discovery", "description": "d", "object-type": "tactic"},
        ],
        "techniques": techniques,
    }
    return yaml.safe_dump(document, sort_keys=True, allow_unicode=True).encode()


def build_known_snapshot(snapshot: bytes, **overrides: Any) -> KnownFightSnapshot:
    """A full-coverage catalog entry for ``snapshot`` holding one technique and two tactics."""
    fields: dict[str, Any] = {
        "snapshot_sha256": sha256_hex(snapshot),
        "repository_url": "https://github.com/mitre/FiGHT",
        "commit": FIGHT_TEST_COMMIT,
        "data_version": "0.0.0",
        "upstream_path": "fight.yaml",
        "coverage": SnapshotCoverage.FULL,
        "technique_count": 1,
        "tactic_count": 2,
        "retrieved_at": FIXED_RETRIEVED_AT,
        "terms_ref": "https://fight.mitre.org/resources/terms/",
    }
    fields.update(overrides)
    return KnownFightSnapshot.model_validate(fields)


def build_catalog(*snapshots: KnownFightSnapshot) -> FightSnapshotCatalog:
    return FightSnapshotCatalog(snapshots=snapshots)


def build_recorded_step(**overrides: Any) -> ToolStep:
    """An admitted round-1 ``cve_search`` step that found nothing."""
    fields: dict[str, Any] = {
        "step_index": 1,
        "round_number": 1,
        "call": {"tool": "cve_search", "query": "crash"},
        "reason": "query_terms",
        "planned_by": "deterministic",
        "call_key": ZERO_SHA256,
        "backend_requests": [{"source": "cve_search", "query": "crash", "limit": 20}],
        "charged_tool_calls": 1,
        "sources": ["cve_search"],
        "admission": "admitted",
        "status": "no_match",
        "channels_executed": ["lexical"],
        "source_outcomes": [],
        "search_warnings": [],
        "topic_warnings": [],
        "answer_ids": [],
        "evidence_ids": [],
        "result_sha256": ZERO_SHA256,
        "context_bytes": 0,
    }
    fields.update(overrides)
    return ToolStep.model_validate(fields)
