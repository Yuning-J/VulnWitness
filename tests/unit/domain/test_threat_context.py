"""A threat-context outcome carries the snapshot its results come from."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from cve_kgrag.domain.taxonomy import (
    BackendFailure,
    BackendFailureDetail,
    BackendStatus,
    KnowledgeScope,
    ResultStatus,
    SourceType,
)
from cve_kgrag.domain.threat_context import (
    FightSnapshotInfo,
    SnapshotCoverage,
    ThreatContextOutcome,
)
from cve_kgrag.domain.topic_context import KnowledgeSource, SourceOutcome
from tests.support.builders import build_anchor, build_catalog, build_known_snapshot

SNAPSHOT = FightSnapshotInfo(
    repository_url="https://github.com/mitre/FiGHT",
    commit="0" * 40,
    data_version="0.0.0",
    snapshot_sha256="1" * 64,
    coverage=SnapshotCoverage.FULL,
    technique_count=1,
    tactic_count=1,
    retrieved_at=datetime(2026, 10, 14, tzinfo=UTC),
    ingested_at=datetime(2026, 10, 15, tzinfo=UTC),
    terms_ref="https://fight.mitre.org/resources/terms/",
)


def build_fight_anchor(source_version: str) -> object:
    return build_anchor(
        authoritative_record_id="FGT9001",
        source_type=SourceType.MITRE_FIGHT_YAML,
        scope=KnowledgeScope.PROTOCOL_THREAT_CONTEXT,
        source_version=source_version,
    )


def test_snapshot_version_names_data_version_commit_and_hash() -> None:
    assert SNAPSHOT.source_version == f"0.0.0@{'0' * 40}+sha256:{'1' * 64}"


def test_successful_outcome_without_a_snapshot_is_rejected() -> None:
    with pytest.raises(ValidationError, match="must name its snapshot"):
        ThreatContextOutcome(status=BackendStatus.OK)


def test_outcome_whose_evidence_comes_from_another_snapshot_is_rejected() -> None:
    other_snapshot_anchor = build_fight_anchor("9.9.9@other+sha256:" + "2" * 64)

    with pytest.raises(ValidationError, match="another snapshot"):
        ThreatContextOutcome(
            status=BackendStatus.OK, evidence=(other_snapshot_anchor,), snapshot=SNAPSHOT
        )


def test_failed_outcome_naming_a_snapshot_is_rejected() -> None:
    with pytest.raises(ValidationError, match="cannot carry items, unindexed terms or a snapshot"):
        ThreatContextOutcome(
            status=BackendStatus.ERROR, failure=BackendFailure.SEARCH_FAILED, snapshot=SNAPSHOT
        )


@pytest.mark.parametrize(
    ("entry_fields", "violation"),
    [
        ({"coverage": SnapshotCoverage.EXCERPT}, "names the snapshot it was cut from"),
        ({"derived_from_sha256": "5" * 64}, "names the snapshot it was cut from"),
        (
            {
                "coverage": SnapshotCoverage.EXCERPT,
                "derived_from_sha256": "5" * 64,
            },
            "lists its technique and tactic IDs",
        ),
        ({"technique_ids": ["FGT9001", "FGT9002"]}, "technique_count distinct IDs"),
        ({"tactic_ids": ["TA0006"]}, "tactic_count distinct IDs"),
        (
            {
                "coverage": SnapshotCoverage.EXCERPT,
                "derived_from_sha256": "5" * 64,
                "technique_ids": ["FGT9001"],
            },
            "lists its technique and tactic IDs",
        ),
    ],
    ids=[
        "excerpt_without_source",
        "full_with_source",
        "excerpt_without_ids",
        "id_count",
        "tactic_id_count",
        "excerpt_without_tactic_ids",
    ],
)
def test_inconsistent_catalog_entry_is_rejected(
    entry_fields: dict[str, object], violation: str
) -> None:
    with pytest.raises(ValidationError, match=violation):
        build_known_snapshot(b"snapshot", **entry_fields)


def test_catalog_rejects_an_excerpt_cut_from_an_uncatalogued_snapshot() -> None:
    excerpt = build_known_snapshot(
        b"excerpt",
        coverage=SnapshotCoverage.EXCERPT,
        derived_from_sha256="5" * 64,
        technique_ids=["FGT9001"],
        tactic_ids=["TA0006", "TA0007"],
    )

    with pytest.raises(ValidationError, match="not cut from a catalogued full snapshot"):
        build_catalog(excerpt)


def test_catalog_rejects_a_snapshot_listed_twice() -> None:
    entry = build_known_snapshot(b"snapshot")

    with pytest.raises(ValidationError, match="listed twice"):
        build_catalog(entry, entry)


@pytest.mark.parametrize(
    "provenance_field",
    ["commit", "data_version", "repository_url", "upstream_path", "terms_ref"],
)
def test_catalog_rejects_an_excerpt_whose_provenance_differs_from_its_parent(
    provenance_field: str,
) -> None:
    parent = build_known_snapshot(b"parent")
    differing_values = {
        "commit": "9" * 40,
        "data_version": "9.9.9",
        "repository_url": "https://example.com/fork",
        "upstream_path": "other.yaml",
        "terms_ref": "https://example.com/terms",
    }
    excerpt = build_known_snapshot(
        b"excerpt",
        coverage=SnapshotCoverage.EXCERPT,
        derived_from_sha256=parent.snapshot_sha256,
        technique_ids=["FGT9001"],
        tactic_ids=["TA0006", "TA0007"],
        **{provenance_field: differing_values[provenance_field]},
    )

    with pytest.raises(ValidationError, match=f"{provenance_field} differs"):
        build_catalog(parent, excerpt)


def test_source_uri_names_the_upstream_path_at_the_commit() -> None:
    snapshot = build_known_snapshot(b"snapshot", upstream_path="data/fight.yaml")

    assert snapshot.source_uri == (
        f"https://github.com/mitre/FiGHT/blob/{snapshot.commit}/data/fight.yaml"
    )


@pytest.mark.parametrize("status", [ResultStatus.SOURCE_UNAVAILABLE, ResultStatus.BACKEND_ERROR])
def test_failed_source_outcome_naming_a_snapshot_is_rejected(status: ResultStatus) -> None:
    with pytest.raises(ValidationError, match="cannot name a snapshot"):
        SourceOutcome(
            source=KnowledgeSource.MITRE_FIGHT,
            status=status,
            detail=BackendFailureDetail.SEARCH_FAILED,
            source_version=SNAPSHOT.source_version,
            coverage=SnapshotCoverage.EXCERPT,
        )


def test_catalog_rejects_an_excerpt_cut_from_another_excerpt() -> None:
    full_snapshot = build_known_snapshot(b"full")
    excerpt_fields = {
        "coverage": SnapshotCoverage.EXCERPT,
        "technique_ids": ["FGT9001"],
        "tactic_ids": ["TA0006", "TA0007"],
    }
    first_excerpt = build_known_snapshot(
        b"first", derived_from_sha256=full_snapshot.snapshot_sha256, **excerpt_fields
    )
    second_excerpt = build_known_snapshot(
        b"second", derived_from_sha256=first_excerpt.snapshot_sha256, **excerpt_fields
    )

    with pytest.raises(ValidationError, match="not cut from a catalogued full snapshot"):
        build_catalog(full_snapshot, first_excerpt, second_excerpt)


@pytest.mark.parametrize(
    ("status", "detail"),
    [
        (ResultStatus.SOURCE_UNAVAILABLE, None),
        (ResultStatus.OK, BackendFailureDetail.SEARCH_FAILED),
    ],
    ids=["failed_without_sentence", "answered_with_sentence"],
)
def test_fight_outcome_carries_a_sentence_exactly_when_the_source_did_not_answer(
    status: ResultStatus, detail: BackendFailureDetail | None
) -> None:
    with pytest.raises(ValidationError, match="exactly when the source did not answer"):
        SourceOutcome(source=KnowledgeSource.MITRE_FIGHT, status=status, detail=detail)
