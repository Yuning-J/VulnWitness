"""Synthetic fixture loading: checksum pinning, determinism and labelling."""

import json
import shutil
from pathlib import Path

import pytest

from vulnwitness.adapters.fixture.synthetic_fixture import (
    FixtureBundle,
    FixtureIntegrityError,
    default_fixture_dir,
    load_fixture_bundle,
)
from vulnwitness.domain.hashing import sha256_hex
from vulnwitness.domain.taxonomy import SourceType, TrustLevel


@pytest.fixture
def fixture_copy(tmp_path: Path) -> Path:
    source_dir = Path(str(default_fixture_dir()))
    copy_dir = tmp_path / "synthetic"
    shutil.copytree(source_dir, copy_dir)
    return copy_dir


def rewrite_records_and_repin(fixture_dir: Path, records_payload: dict[str, object]) -> None:
    records_bytes = json.dumps(records_payload).encode()
    (fixture_dir / "records.json").write_bytes(records_bytes)
    manifest = json.loads((fixture_dir / "manifest.json").read_text())
    manifest["files"][0]["sha256"] = sha256_hex(records_bytes)
    (fixture_dir / "manifest.json").write_text(json.dumps(manifest))


def test_fixture_loads_every_record_with_its_own_anchor(fixture_bundle: FixtureBundle) -> None:
    assert len(fixture_bundle.records) == 8
    assert len(fixture_bundle.evidence) == 8
    for record, anchor in zip(fixture_bundle.records, fixture_bundle.evidence, strict=True):
        assert record.evidence_ids == (anchor.evidence_id,)
        assert anchor.authoritative_record_id == record.cve_id


def test_fixture_is_labelled_synthetic_throughout(fixture_bundle: FixtureBundle) -> None:
    assert fixture_bundle.manifest.synthetic is True
    for record, anchor in zip(fixture_bundle.records, fixture_bundle.evidence, strict=True):
        assert record.cve_id.startswith("CVE-9999-")
        assert record.descriptions[0].value.startswith("[SYNTHETIC]")
        assert anchor.source_type is SourceType.SYNTHETIC_FIXTURE
        assert anchor.trust_level is TrustLevel.SYNTHETIC


def test_loading_twice_yields_identical_records_and_anchors() -> None:
    first = load_fixture_bundle(default_fixture_dir())
    second = load_fixture_bundle(default_fixture_dir())

    assert first == second


def test_tampered_records_file_fails_closed(fixture_copy: Path) -> None:
    records_path = fixture_copy / "records.json"
    records_path.write_bytes(records_path.read_bytes().replace(b"9.8", b"1.0", 1))

    with pytest.raises(FixtureIntegrityError, match="does not match manifest"):
        load_fixture_bundle(fixture_copy)


def test_fixture_entry_authoring_its_own_evidence_ids_is_rejected(fixture_copy: Path) -> None:
    records_payload = json.loads((fixture_copy / "records.json").read_text())
    records_payload["records"][0]["evidence_ids"] = ["ev:" + "0" * 24]
    rewrite_records_and_repin(fixture_copy, records_payload)

    with pytest.raises(FixtureIntegrityError, match="derived by the loader"):
        load_fixture_bundle(fixture_copy)


def test_fixture_entry_claiming_formal_seed_eligibility_is_rejected(fixture_copy: Path) -> None:
    records_payload = json.loads((fixture_copy / "records.json").read_text())
    records_payload["records"][0]["formal_seed_eligible"] = True
    rewrite_records_and_repin(fixture_copy, records_payload)

    with pytest.raises(ValueError, match="formal_seed_eligible"):
        load_fixture_bundle(fixture_copy)


def test_evidence_anchor_hash_changes_when_record_content_changes(fixture_copy: Path) -> None:
    original_anchor = load_fixture_bundle(fixture_copy).evidence[0]
    records_payload = json.loads((fixture_copy / "records.json").read_text())
    records_payload["records"][0]["cwe_ids"] = ["CWE-90"]
    rewrite_records_and_repin(fixture_copy, records_payload)

    changed_anchor = load_fixture_bundle(fixture_copy).evidence[0]

    assert changed_anchor.content_sha256 != original_anchor.content_sha256
    assert changed_anchor.evidence_id != original_anchor.evidence_id
