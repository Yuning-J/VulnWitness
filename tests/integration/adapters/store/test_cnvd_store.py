"""CNVD records, pending entries and anchors across import, verification and startup."""

import json
from pathlib import Path

import pytest

from tests.support.cnvd_inputs import TEST_REVISION, CnvdScenario, build_cnvd_scenario
from tests.support.corpus_stores import copy_compatibility_store
from tests.support.legacy_inputs import RETRIEVED_AT, build_cve_id, run_test_migration
from vulnwitness.adapters.store.corpus_store import (
    PENDING_CNVD_FILE,
    CorpusStoreIntegrityError,
    load_corpus_store,
    verify_corpus_store,
)
from vulnwitness.composition import build_store_activation, load_served_corpus
from vulnwitness.domain.hashing import canonical_json_bytes, canonical_sha256, sha256_hex
from vulnwitness.domain.migration_report import CnvdOutcome, MigrationOutcome
from vulnwitness.domain.taxonomy import AssertionKind, KnowledgeScope, SourceType, TrustLevel
from vulnwitness.domain.validation import find_anchor_violations


@pytest.fixture
def cnvd_store(tmp_path: Path) -> CnvdScenario:
    scenario = build_cnvd_scenario(tmp_path)
    report = run_test_migration(
        scenario.manifest, scenario.target, dependencies=scenario.dependencies
    )
    assert report.outcome is MigrationOutcome.IMPORTED, report.failure
    return scenario


def test_merged_entries_are_ordered_and_keep_nvd_fields_and_evidence(
    cnvd_store: CnvdScenario,
) -> None:
    corpus = load_corpus_store(cnvd_store.target)

    assert corpus.manifest.store_format_version == 2
    assert len(corpus.records) == 1
    record = corpus.records[0]
    assert record.nvd_status == "Analyzed"
    assert record.descriptions[0].value == "SYNTHETIC: democorp gateway mishandles input."
    cnvd_ids = []
    severities = []
    for entry in record.cnvd:
        cnvd_ids.append(entry.cnvd_id)
        severities.append(entry.severity)
    assert tuple(cnvd_ids) == ("CNVD-9999-00001", "CNVD-9999-00007")
    assert tuple(severities) == ("medium", "low")
    assert len(record.evidence_ids) == 3
    for entry in record.cnvd:
        assert entry.evidence_id in record.evidence_ids
        assert entry.title == "SYNTHETIC: 示例标题"


def test_every_stored_row_has_its_own_exact_anchor_and_unjoinable_rows_have_none(
    cnvd_store: CnvdScenario,
) -> None:
    corpus = load_corpus_store(cnvd_store.target)
    anchors_by_cnvd_id = {}
    for anchor in corpus.evidence:
        if anchor.source_type is SourceType.CIRCL_CNVD_PARQUET:
            anchors_by_cnvd_id[anchor.authoritative_record_id] = anchor

    assert len(anchors_by_cnvd_id) == 5
    assert not find_anchor_violations(corpus.evidence)
    for index, row in enumerate(cnvd_store.rows[:5]):
        anchor = anchors_by_cnvd_id[row["id"]]
        assert anchor.source_name == "circl-cnvd"
        assert anchor.source_uri == (
            "https://huggingface.co/datasets/CIRCL/Vulnerability-CNVD/resolve/"
            f"{TEST_REVISION}/data/part-{0 if index < 3 else 1}.parquet"
        )
        assert anchor.source_version == TEST_REVISION
        assert anchor.model_dump(mode="json")["retrieved_at"] == RETRIEVED_AT
        assert anchor.content_sha256 == canonical_sha256(row)
        assert anchor.locator == f"id={row['id']}"
        assert anchor.license_or_terms_ref == "https://creativecommons.org/licenses/by/4.0/"
        assert anchor.scope is KnowledgeScope.IMPLEMENTATION_VULNERABILITY
        assert anchor.assertion_kind is AssertionKind.ASSERTED
        assert anchor.trust_level is TrustLevel.SECONDARY
        assert anchor.excerpt is None
    assert "CNVD-9999-00005" not in corpus.cnvd_index.cve_id_by_cnvd_id
    assert "CNVD-9999-00006" not in corpus.cnvd_index.cve_id_by_cnvd_id


@pytest.mark.parametrize(
    ("number", "outcome"),
    [
        (2, CnvdOutcome.FOR_REJECTED_NVD_RECORD),
        (3, CnvdOutcome.FOR_EXCLUDED_NVD_RECORD),
        (4, CnvdOutcome.WITHOUT_NVD_RECORD),
    ],
    ids=["rejected", "excluded", "absent"],
)
def test_pending_outcomes_round_trip_in_file_and_both_loading_indexes(
    cnvd_store: CnvdScenario,
    number: int,
    outcome: CnvdOutcome,
) -> None:
    corpus = load_corpus_store(cnvd_store.target)
    pending = corpus.cnvd_index.pending_by_cve_id[build_cve_id(number)][0]
    pending_lines = (cnvd_store.target / PENDING_CNVD_FILE).read_text().splitlines()

    assert pending.outcome == outcome.value
    assert pending == corpus.cnvd_index.pending_by_cnvd_id[f"CNVD-9999-{number:05d}"]
    assert pending.model_dump(mode="json") == json.loads(pending_lines[number - 2])
    assert len(pending_lines) == 3
    assert verify_corpus_store(cnvd_store.target).manifest.anchor_count == 6


def test_active_dataset_loads_pending_and_merged_identifier_indexes(
    cnvd_store: CnvdScenario,
) -> None:
    activation = build_store_activation(cnvd_store.target.parent)
    activation.activate(cnvd_store.target.name)

    corpus = load_served_corpus(cnvd_store.target.parent)

    assert corpus.cnvd_index.cve_id_by_cnvd_id == {
        "CNVD-9999-00001": build_cve_id(1),
        "CNVD-9999-00007": build_cve_id(1),
        "CNVD-9999-00002": build_cve_id(2),
        "CNVD-9999-00003": build_cve_id(3),
        "CNVD-9999-00004": build_cve_id(4),
    }
    assert len(corpus.cnvd_index.pending_by_cnvd_id) == 3


def test_format_1_active_dataset_serves_null_status_and_empty_cnvd(tmp_path: Path) -> None:
    root = tmp_path / "stores"
    root.mkdir()
    store = copy_compatibility_store(root, "format1")
    build_store_activation(root).activate(store.name)

    corpus = load_served_corpus(root)

    assert corpus.records
    for record in corpus.records:
        assert record.nvd_status is None
        assert record.cnvd == ()
    assert corpus.cnvd_index.pending_by_cve_id == {}
    assert corpus.cnvd_index.pending_by_cnvd_id == {}
    assert corpus.cnvd_index.cve_id_by_cnvd_id == {}


@pytest.mark.parametrize("reader", [load_corpus_store, verify_corpus_store], ids=["load", "verify"])
def test_tampered_pending_line_fails_verification(cnvd_store: CnvdScenario, reader) -> None:
    path = cnvd_store.target / PENDING_CNVD_FILE
    path.write_bytes(path.read_bytes().replace(b"fictional", b"FICTIONAL", 1))

    with pytest.raises(CorpusStoreIntegrityError):
        reader(cnvd_store.target)


def repin_pending_file(store_dir: Path, pending_bytes: bytes) -> None:
    path = store_dir / PENDING_CNVD_FILE
    path.write_bytes(pending_bytes)
    manifest_path = store_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    for pin in manifest["files"]:
        if pin["path"] == PENDING_CNVD_FILE:
            pin["size_bytes"] = len(pending_bytes)
            pin["sha256"] = sha256_hex(pending_bytes)
    manifest_path.write_bytes(canonical_json_bytes(manifest))


def test_pending_content_changes_the_served_dataset_identity(cnvd_store: CnvdScenario) -> None:
    original = verify_corpus_store(cnvd_store.target)
    pending_bytes = (cnvd_store.target / PENDING_CNVD_FILE).read_bytes()
    pending_bytes = pending_bytes.replace(
        b"cnvd_for_rejected_nvd_record", b"cnvd_without_nvd_record"
    )
    repin_pending_file(cnvd_store.target, pending_bytes)

    changed = verify_corpus_store(cnvd_store.target)

    assert changed.corpus_content_sha256 != original.corpus_content_sha256


def test_repinning_edited_pending_text_still_fails_its_row_anchor(cnvd_store: CnvdScenario) -> None:
    pending_bytes = (cnvd_store.target / PENDING_CNVD_FILE).read_bytes()
    repin_pending_file(cnvd_store.target, pending_bytes.replace(b"fictional", b"FICTIONAL", 1))

    with pytest.raises(CorpusStoreIntegrityError, match="differs from its row anchor"):
        verify_corpus_store(cnvd_store.target)
