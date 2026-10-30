"""The packaged FiGHT excerpt loads only when it and its notice match the manifest."""

import json
import re
import shutil
from pathlib import Path

import pytest

from cve_kgrag.adapters.fight.pinned_yaml import FightSnapshotError
from cve_kgrag.adapters.fight.snapshot_catalog import (
    default_fight_snapshot_catalog_file,
    load_fight_snapshot_catalog,
)
from cve_kgrag.adapters.fixture.fight_fixture import default_fight_fixture_dir, load_fight_fixture
from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureIntegrityError
from cve_kgrag.domain.taxonomy import KnowledgeScope
from cve_kgrag.domain.threat_context import FightSnapshotCatalog, SnapshotCoverage
from tests.support.clocks import read_fixed_clock
from tests.support.collect import list_technique_ids

PINNED_COMMIT = "097cd5f73811dc34916ef84d5acc3fe7aba70450"
EXCERPT_SHA256 = "08cd11d579889c819c00888ecbb85d6d4b470b8fdf9fea833324441e28635726"
UPSTREAM_SHA256 = "59a9addbd75d8680091797d66d5b237d9d026512990c61a6f51692ca94d2a7a8"
PACKAGED_CATALOG = load_fight_snapshot_catalog(default_fight_snapshot_catalog_file())


def copy_fixture(tmp_path: Path) -> Path:
    fixture_copy = tmp_path / "fight"
    shutil.copytree(str(default_fight_fixture_dir()), fixture_copy)
    return fixture_copy


def test_excerpt_serves_techniques_pinned_to_the_upstream_commit() -> None:
    source = load_fight_fixture(default_fight_fixture_dir(), PACKAGED_CATALOG, read_fixed_clock)

    outcome = source.search(["SUCI"], 20)

    assert list_technique_ids(outcome.items) == ["FGT5040", "FGT5019", "FGT1499.503"]
    for anchor in outcome.evidence:
        assert anchor.source_version == f"3.1.0@{PINNED_COMMIT}+sha256:{EXCERPT_SHA256}"
        assert anchor.scope is KnowledgeScope.PROTOCOL_THREAT_CONTEXT


def test_excerpt_search_orders_by_bm25_score_and_breaks_ties_by_technique_id() -> None:
    # FGT5044 names "obtained" twice, the others once each; FGT5019 is the shortest of
    # those, and FGT5019.005 and FGT5040 have the same word count, so their scores tie.
    source = load_fight_fixture(default_fight_fixture_dir(), PACKAGED_CATALOG, read_fixed_clock)

    outcome = source.search(["obtained"], 20)

    assert list_technique_ids(outcome.items) == ["FGT5044", "FGT5019", "FGT5019.005", "FGT5040"]


def test_excerpt_declares_itself_an_excerpt() -> None:
    snapshot_info = load_fight_fixture(
        default_fight_fixture_dir(), PACKAGED_CATALOG, read_fixed_clock
    ).describe()

    assert snapshot_info.coverage is SnapshotCoverage.EXCERPT
    assert snapshot_info.technique_count == 6
    assert snapshot_info.snapshot_sha256 == EXCERPT_SHA256


@pytest.mark.parametrize("tampered_file", ["fight-excerpt.yaml", "NOTICE.md"])
def test_tampered_excerpt_or_notice_is_refused(tmp_path: Path, tampered_file: str) -> None:
    fixture_copy = copy_fixture(tmp_path)
    with (fixture_copy / tampered_file).open("a", encoding="utf-8") as tampered:
        tampered.write("\n# edited\n")

    with pytest.raises(FixtureIntegrityError, match=re.escape(tampered_file)):
        load_fight_fixture(fixture_copy, PACKAGED_CATALOG, read_fixed_clock)


def test_manifest_that_stops_pinning_the_notice_is_refused(tmp_path: Path) -> None:
    fixture_copy = copy_fixture(tmp_path)
    manifest_file = fixture_copy / "manifest.json"
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    pinned_files = []
    for pinned_file in manifest["files"]:
        if pinned_file["path"] != "NOTICE.md":
            pinned_files.append(pinned_file)
    manifest["files"] = pinned_files
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(FixtureIntegrityError, match=r"NOTICE\.md"):
        load_fight_fixture(fixture_copy, PACKAGED_CATALOG, read_fixed_clock)


def test_excerpt_whose_techniques_differ_from_its_catalog_entry_is_refused() -> None:
    excerpt_entry = PACKAGED_CATALOG.find(EXCERPT_SHA256)
    assert excerpt_entry is not None
    full_entry = PACKAGED_CATALOG.find(UPSTREAM_SHA256)
    assert full_entry is not None
    declared_ids = list(excerpt_entry.technique_ids or ())
    declared_ids[0] = "FGT9999"
    edited_catalog = FightSnapshotCatalog(
        snapshots=(
            full_entry,
            excerpt_entry.model_copy(update={"technique_ids": tuple(declared_ids)}),
        )
    )

    with pytest.raises(FightSnapshotError, match="catalogued technique IDs"):
        load_fight_fixture(default_fight_fixture_dir(), edited_catalog, read_fixed_clock)


def test_packaged_catalog_describes_the_excerpt_as_cut_from_the_full_upstream_file() -> None:
    excerpt_entry = PACKAGED_CATALOG.find(EXCERPT_SHA256)
    full_entry = PACKAGED_CATALOG.find(UPSTREAM_SHA256)

    assert excerpt_entry is not None
    assert full_entry is not None
    assert excerpt_entry.derived_from_sha256 == UPSTREAM_SHA256
    assert full_entry.coverage is SnapshotCoverage.FULL
    assert (full_entry.technique_count, full_entry.tactic_count) == (183, 15)
