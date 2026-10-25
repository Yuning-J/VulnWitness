"""The legacy-data importer end to end (ADR 0008), on synthetic ``CVE-9999-*`` inputs.

Proves that a run writes nothing but its new target, verified and readable, and leaves
every input and every other store as it was (content and modification time); that one
declared input set gives the same records and anchors whatever the manifest's order and
whatever container carries a feed; that a rerun, an occupied target and a corrupted
store are each told apart and never written over; that a dry run reports what a real
run would and leaves nothing behind; that a failure publishes nothing and leaves no
working directory; that NVD duplicates resolve as §5 states and KEV rows as §6 states;
that every file-level fault fails the run with its fixed code, an NVD input that is not
a whole feed among them; that an input rewritten in place while the run reads it never
reaches the store, which imports the inspected bytes or fails as ``input_changed``; that
the store's modes do not depend on the umask; that the store manifest
records each input's hashes and generation time; that anchors cite the registry's terms
and URLs; that ``--legacy-root`` findings are reported; that a report never quotes an input;
and that ``cve-kgrag migrate legacy`` prints the report and exits 0, 1 or 2 as §7
states. The command needs the ``migration`` extra, so its runs live here, beside the
importer's other tests, outside the core-only lane.
"""

import dataclasses
import gc
import gzip
import os
import stat
import tempfile
import warnings
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from cve_kgrag.adapters.migration.input_files import PayloadStream
from cve_kgrag.adapters.migration.legacy_migration import MigrationDependencies
from cve_kgrag.adapters.migration.migration_limits import MigrationLimits
from cve_kgrag.adapters.migration.parser_types import EntryHandler, FeedHeader
from cve_kgrag.adapters.nvd.normalizer import (
    KevSource,
    NormalizedCve,
    NvdNormalizer,
    SourceSnapshot,
    SourceTerms,
)
from cve_kgrag.adapters.store.corpus_store import (
    ANCHORS_FILE,
    RECORDS_FILE,
    STORE_MANIFEST_FILE,
    CorpusStore,
    load_corpus_store,
)
from cve_kgrag.cli import main
from cve_kgrag.composition import load_packaged_source_registry
from cve_kgrag.domain.corpus_store_manifest import (
    ROLLBACK_INSTRUCTION,
    InputContainer,
    StoreInput,
    StoreSource,
)
from cve_kgrag.domain.cve import CveRecord, KevEntry
from cve_kgrag.domain.evidence import EvidenceAnchor
from cve_kgrag.domain.hashing import sha256_hex
from cve_kgrag.domain.migration_report import (
    KEV_REMEDY,
    KEV_WITHOUT_NVD_RECORD_ADVICE,
    MAX_REPORTED_LOCATORS,
    CandidateOutcome,
    CveOutcome,
    EntryLocator,
    KevOutcome,
    LegacyFileKind,
    MigrationFailureCode,
    MigrationOutcome,
    MigrationReport,
)
from cve_kgrag.domain.normalization import NormalizationFailureCode
from cve_kgrag.domain.taxonomy import SourceType
from tests.support.legacy_inputs import (
    KEV_COLUMNS,
    RETRIEVED_AT,
    build_cve_id,
    build_declaration,
    build_kev_row,
    build_migration_dependencies,
    build_v1_feed,
    build_v1_item,
    build_v2_entry,
    build_v2_feed,
    encode_feed,
    encode_kev_csv,
    list_names,
    run_test_migration,
    snapshot_tree,
    write_gzip_feed,
    write_inputs_manifest,
    write_kev_csv,
    write_plain_feed,
    write_zip_feed,
)

V2_YEAR_FEED = "nvdcve-2.0-2099.json.gz"
V2_MODIFIED_FEED = "nvdcve-2.0-modified.json.gz"
V1_YEAR_FEED = "nvdcve-1.1-2099.json.gz"
KEV_FILE = "known_exploited_vulnerabilities.csv"
LATER_RETRIEVED_AT = "2026-10-24T09:00:00Z"
LATER_MODIFIED = "2099-02-01T00:00:00.000"
V2_YEAR_FEED_URI = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2099.json.gz"
V2_MODIFIED_FEED_URI = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz"
V2_2098_FEED_URI = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2098.json.gz"
KEV_URI = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
MALFORMED_ENTRY_MARKER = "malformed-entry-marker-5e2b"
INPUT_PATH_MARKER = "input-path-marker-91c4"
DERIVED_FILE_NAME = "nvdcve-2.0-2099.json"
V2_PLAIN_YEAR_FEED = "nvdcve-2.0-2099.json"
ORIGINAL_DESCRIPTION = "SYNTHETIC: democorp gateway mishandles input."
# As long as the original, so a file rewritten with it keeps its size.
REWRITTEN_DESCRIPTION = ORIGINAL_DESCRIPTION.upper()


@dataclass(frozen=True)
class ImportLayout:
    """Where a test's inputs and stores live: the target's parent never holds an input."""

    inputs_dir: Path
    stores_dir: Path
    target: Path


@pytest.fixture
def layout(tmp_path: Path) -> ImportLayout:
    inputs_dir = tmp_path / "inputs"
    inputs_dir.mkdir()
    stores_dir = tmp_path / "stores"
    stores_dir.mkdir()
    return ImportLayout(inputs_dir=inputs_dir, stores_dir=stores_dir, target=stores_dir / "store")


@pytest.fixture
def system_temp_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An empty directory standing in for the system's temporary directory, where a dry
    run stages, so what a run leaves there is seen apart from every other process's."""
    system_temp_dir = tmp_path / "system-temp"
    system_temp_dir.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(system_temp_dir))
    return system_temp_dir


def write_feed(path: Path, feed: dict[str, Any]) -> Path:
    """The feed in the container its file name names: gzip, zip or plain JSON."""
    if path.name.endswith(".gz"):
        return write_gzip_feed(path, feed)
    if path.name.endswith(".zip"):
        return write_zip_feed(path, feed)
    return write_plain_feed(path, feed)


def write_import(
    inputs_dir: Path,
    nvd_feeds: dict[str, dict[str, Any]],
    kev_rows: list[dict[str, str]] | None = None,
    retrieved_at: str = RETRIEVED_AT,
) -> Path:
    """Each feed under its standard file name, the KEV catalog if rows are given, and the
    manifest declaring them all; the manifest's path."""
    declarations: list[dict[str, Any]] = []
    for file_name, feed in nvd_feeds.items():
        write_feed(inputs_dir / file_name, feed)
        declarations.append(build_declaration(file_name, retrieved_at=retrieved_at))
    if kev_rows is not None:
        write_kev_csv(inputs_dir / KEV_FILE, kev_rows)
        declarations.append(
            build_declaration(KEV_FILE, source="cisa-kev", retrieved_at=retrieved_at)
        )
    return write_inputs_manifest(inputs_dir, declarations)


def write_standard_import(inputs_dir: Path, retrieved_at: str = RETRIEVED_AT) -> Path:
    """A 2.0 year feed with CVE-9999-0001 and -0002, and a KEV catalog listing -0002."""
    return write_import(
        inputs_dir,
        {V2_YEAR_FEED: build_v2_feed([build_v2_entry(1), build_v2_entry(2)])},
        [build_kev_row(2)],
        retrieved_at,
    )


def write_conflicting_kev_import(inputs_dir: Path) -> Path:
    return write_import(
        inputs_dir,
        {V2_YEAR_FEED: build_v2_feed([build_v2_entry(1)])},
        [build_kev_row(1), build_kev_row(1, notes="a second, different row")],
    )


def write_only_rejected_import(inputs_dir: Path) -> Path:
    return write_import(
        inputs_dir, {V2_YEAR_FEED: build_v2_feed([build_v2_entry(1, status="Rejected")])}
    )


def write_two_entry_import(inputs_dir: Path) -> Path:
    return write_import(
        inputs_dir, {V2_YEAR_FEED: build_v2_feed([build_v2_entry(1), build_v2_entry(2)])}
    )


def write_derived_documents_import(inputs_dir: Path) -> Path:
    write_plain_feed(
        inputs_dir / "nvdcve-2.0-2099.json",
        {"documents_by_year": {"2099": 1}, "basic_stats": {"total": 1}},
    )
    return write_inputs_manifest(inputs_dir, [build_declaration("nvdcve-2.0-2099.json")])


def build_api_page(start_index: int) -> dict[str, Any]:
    """Two entries of a 2.0 API result of 250,000, starting at ``start_index``: valid
    JSON in the feed's format, but not a whole feed."""
    page = build_v2_feed([build_v2_entry(1), build_v2_entry(2)])
    page["startIndex"] = start_index
    page["totalResults"] = 250_000
    return page


def write_api_page_import(inputs_dir: Path) -> Path:
    """A 2.0 year feed that is a later page of a larger API result: an incomplete feed."""
    return write_import(inputs_dir, {V2_YEAR_FEED: build_api_page(start_index=2000)})


FAILING_IMPORTS = [
    (write_conflicting_kev_import, MigrationLimits(), MigrationFailureCode.KEV_CONFLICTING_ROWS),
    (write_only_rejected_import, MigrationLimits(), MigrationFailureCode.NO_IMPORTABLE_RECORDS),
    (
        write_two_entry_import,
        MigrationLimits(max_nvd_candidates=1),
        MigrationFailureCode.TOO_MANY_CANDIDATES,
    ),
    (
        write_two_entry_import,
        MigrationLimits(max_entry_bytes=64, parser_buffer_bytes=16),
        MigrationFailureCode.ENTRY_TOO_LARGE,
    ),
    (
        write_derived_documents_import,
        MigrationLimits(),
        MigrationFailureCode.DERIVED_FILE_DECLARED_AS_SOURCE,
    ),
    # Two rows are far below the rows between staging size checks, so only the check
    # after every input is read meets the cap.
    (
        write_two_entry_import,
        MigrationLimits(max_staging_bytes=1),
        MigrationFailureCode.STAGING_TOO_LARGE,
    ),
]
FAILING_IMPORT_IDS = [
    "kev_conflicting_rows",
    "no_importable_records",
    "too_many_candidates",
    "entry_too_large",
    "derived_file",
    "staging_too_large_at_the_final_check",
]


def read_store_files(store_dir: Path) -> tuple[bytes, bytes]:
    """The store's records and anchors files, byte for byte."""
    return (store_dir / RECORDS_FILE).read_bytes(), (store_dir / ANCHORS_FILE).read_bytes()


def list_record_ids(store: CorpusStore) -> list[str]:
    record_ids: list[str] = []
    for record in store.records:
        record_ids.append(record.cve_id)
    return record_ids


def list_evidence_ids(store: CorpusStore) -> list[str]:
    evidence_ids: list[str] = []
    for anchor in store.evidence:
        evidence_ids.append(anchor.evidence_id)
    return evidence_ids


def find_record(store: CorpusStore, cve_id: str) -> CveRecord:
    return next(record for record in store.records if record.cve_id == cve_id)


def find_anchor(store: CorpusStore, source_type: SourceType, cve_id: str) -> EvidenceAnchor:
    return next(
        anchor
        for anchor in store.evidence
        if anchor.source_type is source_type and anchor.authoritative_record_id == cve_id
    )


def find_store_input(store: CorpusStore, source: StoreSource) -> StoreInput:
    return next(
        store_input for store_input in store.manifest.inputs if store_input.source is source
    )


def list_cited_source_types(store: CorpusStore, record: CveRecord) -> list[SourceType]:
    """The source type of every anchor the record cites, in the record's order."""
    anchors_by_id: dict[str, EvidenceAnchor] = {}
    for anchor in store.evidence:
        anchors_by_id[anchor.evidence_id] = anchor
    source_types: list[SourceType] = []
    for evidence_id in record.evidence_ids:
        source_types.append(anchors_by_id[evidence_id].source_type)
    return source_types


def describe_counts(report: MigrationReport) -> dict[str, Any]:
    """Everything a report states except what only a published store gives it."""
    return report.model_dump(
        mode="json",
        exclude={
            "outcome",
            "store_manifest_sha256",
            "rollback_kind",
            "rollback_scope",
            "rollback_instruction",
        },
    )


class AnchorTamperingNormalizer(NvdNormalizer):
    """Normalizes a 2.0 entry as the real normalizer does, then alters the record's own
    anchor after its evidence ID was derived, so the anchor breaks the store's rules
    while the staged state and hashes stay what they were."""

    def normalize_v2(
        self,
        vulnerability: Mapping[str, Any],
        snapshot: SourceSnapshot,
        kev: KevSource | None = None,
    ) -> NormalizedCve:
        normalized = super().normalize_v2(vulnerability, snapshot, kev)
        own_anchor, *other_anchors = normalized.evidence
        tampered_anchor = own_anchor.model_copy(update={"locator": "tampered/locator"})
        return NormalizedCve(record=normalized.record, evidence=(tampered_anchor, *other_anchors))


def build_tampering_dependencies() -> MigrationDependencies:
    source_registry = load_packaged_source_registry()
    terms = SourceTerms(
        nvd=source_registry.require_terms(StoreSource.NVD.value),
        cisa_kev=source_registry.require_terms(StoreSource.CISA_KEV.value),
    )
    return dataclasses.replace(
        build_migration_dependencies(), normalizer=AnchorTamperingNormalizer(terms)
    )


# The store and the write protocol (§9)


def test_import_creates_only_the_target_in_its_parent_directory(layout: ImportLayout) -> None:
    manifest_path = write_standard_import(layout.inputs_dir)

    run_test_migration(manifest_path, layout.target)

    assert list_names(layout.stores_dir) == ["store"]


def test_import_writes_a_store_that_load_corpus_store_reads_in_cve_id_order(
    layout: ImportLayout,
) -> None:
    manifest_path = write_standard_import(layout.inputs_dir)

    report = run_test_migration(manifest_path, layout.target)

    assert report.outcome is MigrationOutcome.IMPORTED
    assert list_record_ids(load_corpus_store(layout.target)) == [build_cve_id(1), build_cve_id(2)]


def test_import_report_names_the_store_by_its_manifest_sha256_and_identity(
    layout: ImportLayout,
) -> None:
    manifest_path = write_standard_import(layout.inputs_dir)

    report = run_test_migration(manifest_path, layout.target)

    store = load_corpus_store(layout.target)
    assert report.store_manifest_sha256 == sha256_hex(
        (layout.target / STORE_MANIFEST_FILE).read_bytes()
    )
    assert report.import_identity_sha256 == store.manifest.import_identity_sha256


def test_import_leaves_every_input_with_its_content_and_modification_time(
    layout: ImportLayout,
) -> None:
    manifest_path = write_standard_import(layout.inputs_dir)
    inputs_before = snapshot_tree(layout.inputs_dir)

    run_test_migration(manifest_path, layout.target)

    assert snapshot_tree(layout.inputs_dir) == inputs_before


def test_import_leaves_an_existing_sibling_store_with_its_content_and_modification_time(
    layout: ImportLayout,
) -> None:
    sibling_store = layout.stores_dir / "previous"
    run_test_migration(write_standard_import(layout.inputs_dir), sibling_store)
    sibling_before = snapshot_tree(sibling_store)
    later_manifest_path = write_standard_import(layout.inputs_dir, LATER_RETRIEVED_AT)

    report = run_test_migration(later_manifest_path, layout.target)

    assert report.outcome is MigrationOutcome.IMPORTED
    assert snapshot_tree(sibling_store) == sibling_before


def test_import_publishes_the_store_directory_with_mode_0755(layout: ImportLayout) -> None:
    manifest_path = write_standard_import(layout.inputs_dir)

    run_test_migration(manifest_path, layout.target)

    assert stat.S_IMODE(layout.target.stat().st_mode) == 0o755


@pytest.fixture
def process_umask(request: pytest.FixtureRequest) -> Iterator[int]:
    """The process umask set to the test's parameter for the test; the previous umask
    comes back afterwards."""
    umask: int = request.param
    previous_umask = os.umask(umask)
    try:
        yield umask
    finally:
        os.umask(previous_umask)


def read_store_modes(store_dir: Path) -> dict[str, int]:
    """The permission bits of the store directory (``.``) and of every file in it."""
    modes = {".": stat.S_IMODE(store_dir.stat().st_mode)}
    for store_file in store_dir.iterdir():
        modes[store_file.name] = stat.S_IMODE(store_file.stat().st_mode)
    return modes


@pytest.mark.parametrize(
    "process_umask", [0o077, 0o000], indirect=True, ids=["umask_077", "umask_000"]
)
def test_import_publishes_its_files_with_mode_0644_and_its_directory_0755_whatever_the_umask(
    layout: ImportLayout, process_umask: int
) -> None:
    manifest_path = write_standard_import(layout.inputs_dir)

    run_test_migration(manifest_path, layout.target)

    assert read_store_modes(layout.target) == {
        ".": 0o755,
        STORE_MANIFEST_FILE: 0o644,
        RECORDS_FILE: 0o644,
        ANCHORS_FILE: 0o644,
    }


def test_import_whose_written_store_fails_verification_fails_as_store_write_failed(
    layout: ImportLayout,
) -> None:
    manifest_path = write_two_entry_import(layout.inputs_dir)

    report = run_test_migration(
        manifest_path, layout.target, dependencies=build_tampering_dependencies()
    )

    assert report.failure is not None
    assert report.failure.code is MigrationFailureCode.STORE_WRITE_FAILED


def test_import_whose_written_store_fails_verification_leaves_no_target_and_no_working_dir(
    layout: ImportLayout,
) -> None:
    manifest_path = write_two_entry_import(layout.inputs_dir)

    run_test_migration(manifest_path, layout.target, dependencies=build_tampering_dependencies())

    # No target, and no .store.partial-* or .store.staging-* directory beside it.
    assert list_names(layout.stores_dir) == []


def write_two_year_feeds_import(inputs_dir: Path, is_2099_declared_first: bool) -> Path:
    """Plain 2098 and 2099 year feeds, declared in the order asked. The 2099 file's SHA-256
    sorts before the 2098 file's, so only the artifact's year puts 2098 first."""
    write_plain_feed(inputs_dir / "nvdcve-2.0-2098.json", build_v2_feed([build_v2_entry(1)]))
    write_plain_feed(inputs_dir / "nvdcve-2.0-2099.json", build_v2_feed([build_v2_entry(2)]))
    declarations = [
        build_declaration("nvdcve-2.0-2098.json"),
        build_declaration("nvdcve-2.0-2099.json"),
    ]
    if is_2099_declared_first:
        declarations.reverse()
    return write_inputs_manifest(inputs_dir, declarations)


@pytest.mark.parametrize(
    "is_2099_declared_first", [False, True], ids=["2098_declared_first", "2099_declared_first"]
)
def test_store_manifest_lists_the_inputs_in_sorted_order_whatever_the_manifest_order(
    layout: ImportLayout, is_2099_declared_first: bool
) -> None:
    manifest_path = write_two_year_feeds_import(layout.inputs_dir, is_2099_declared_first)

    run_test_migration(manifest_path, layout.target)

    source_uris: list[str] = []
    for store_input in load_corpus_store(layout.target).manifest.inputs:
        source_uris.append(store_input.source_uri)
    assert source_uris == [V2_2098_FEED_URI, V2_YEAR_FEED_URI]


def test_import_with_the_manifest_reordered_commented_and_moved_writes_identical_store_files(
    tmp_path: Path, layout: ImportLayout
) -> None:
    run_test_migration(write_standard_import(layout.inputs_dir), layout.target)
    moved_dir = tmp_path / "moved"
    moved_dir.mkdir()
    write_standard_import(moved_dir)
    reordered_manifest = moved_dir / "inputs.yaml"
    manifest_document = yaml.safe_load(reordered_manifest.read_text(encoding="utf-8"))
    manifest_document["inputs"].reverse()
    reordered_manifest.write_text(
        "# the same inputs, listed the other way round\n"
        + yaml.safe_dump(manifest_document, indent=4),
        encoding="utf-8",
    )
    reordered_target = layout.stores_dir / "store-reordered"

    run_test_migration(reordered_manifest, reordered_target)

    assert read_store_files(reordered_target) == read_store_files(layout.target)


def test_import_with_the_manifest_reordered_keeps_its_identity_and_records_the_raw_manifest_hash(
    tmp_path: Path, layout: ImportLayout
) -> None:
    first_report = run_test_migration(write_standard_import(layout.inputs_dir), layout.target)
    moved_dir = tmp_path / "moved"
    moved_dir.mkdir()
    write_standard_import(moved_dir)
    reordered_manifest = moved_dir / "inputs.yaml"
    manifest_document = yaml.safe_load(reordered_manifest.read_text(encoding="utf-8"))
    manifest_document["inputs"].reverse()
    reordered_manifest.write_text(yaml.safe_dump(manifest_document), encoding="utf-8")
    reordered_target = layout.stores_dir / "store-reordered"

    reordered_report = run_test_migration(reordered_manifest, reordered_target)

    reordered_store = load_corpus_store(reordered_target)
    assert reordered_report.import_identity_sha256 == first_report.import_identity_sha256
    assert reordered_store.manifest.inputs_manifest_sha256 == sha256_hex(
        reordered_manifest.read_bytes()
    )
    assert reordered_store.manifest.inputs_manifest_sha256 != sha256_hex(
        (layout.inputs_dir / "inputs.yaml").read_bytes()
    )


@pytest.mark.parametrize(
    "file_name", ["nvdcve-2.0-2099.json.gz", "nvdcve-2.0-2099.json.zip"], ids=["gzip", "zip"]
)
def test_import_of_one_payload_gives_the_same_evidence_ids_in_any_container(
    tmp_path: Path, layout: ImportLayout, file_name: str
) -> None:
    feed = build_v2_feed([build_v2_entry(1), build_v2_entry(2)])
    run_test_migration(
        write_import(layout.inputs_dir, {"nvdcve-2.0-2099.json": feed}), layout.target
    )
    container_dir = tmp_path / "container"
    container_dir.mkdir()
    container_target = layout.stores_dir / "store-container"

    run_test_migration(write_import(container_dir, {file_name: feed}), container_target)

    assert list_evidence_ids(load_corpus_store(container_target)) == list_evidence_ids(
        load_corpus_store(layout.target)
    )


def test_import_of_the_same_bytes_retrieved_at_another_time_is_another_import(
    tmp_path: Path, layout: ImportLayout
) -> None:
    first_report = run_test_migration(write_standard_import(layout.inputs_dir), layout.target)
    later_dir = tmp_path / "later"
    later_dir.mkdir()
    later_target = layout.stores_dir / "store-later"

    later_report = run_test_migration(
        write_standard_import(later_dir, LATER_RETRIEVED_AT), later_target
    )

    assert later_report.import_identity_sha256 != first_report.import_identity_sha256
    assert set(list_evidence_ids(load_corpus_store(later_target))).isdisjoint(
        list_evidence_ids(load_corpus_store(layout.target))
    )


# Idempotence and existing targets (§4)


def test_rerun_of_the_same_import_reports_already_imported_naming_the_same_store(
    layout: ImportLayout,
) -> None:
    manifest_path = write_standard_import(layout.inputs_dir)
    first_report = run_test_migration(manifest_path, layout.target)

    rerun_report = run_test_migration(manifest_path, layout.target)

    assert rerun_report.outcome is MigrationOutcome.ALREADY_IMPORTED
    assert rerun_report.store_manifest_sha256 == first_report.store_manifest_sha256
    assert rerun_report.import_identity_sha256 == first_report.import_identity_sha256


def test_rerun_of_the_same_import_leaves_the_store_untouched(layout: ImportLayout) -> None:
    manifest_path = write_standard_import(layout.inputs_dir)
    run_test_migration(manifest_path, layout.target)
    store_before = snapshot_tree(layout.target)

    run_test_migration(manifest_path, layout.target)

    assert snapshot_tree(layout.target) == store_before


@pytest.mark.parametrize(
    ("run_count", "outcome"),
    [(1, MigrationOutcome.IMPORTED), (2, MigrationOutcome.ALREADY_IMPORTED)],
    ids=["imported", "already_imported"],
)
def test_report_naming_a_store_states_the_fixed_rollback(
    layout: ImportLayout, run_count: int, outcome: MigrationOutcome
) -> None:
    manifest_path = write_standard_import(layout.inputs_dir)
    for _ in range(run_count - 1):
        run_test_migration(manifest_path, layout.target)

    report = run_test_migration(manifest_path, layout.target)

    assert (
        report.outcome,
        report.rollback_kind,
        report.rollback_scope,
        report.rollback_instruction,
    ) == (outcome, "delete_unactivated_target", "before_activation_only", ROLLBACK_INSTRUCTION)


def occupy_with_another_import(layout: ImportLayout) -> None:
    run_test_migration(write_standard_import(layout.inputs_dir, LATER_RETRIEVED_AT), layout.target)


def occupy_with_an_import_of_other_bytes_of_the_same_artifact(layout: ImportLayout) -> None:
    run_test_migration(
        write_import(layout.inputs_dir, {V2_YEAR_FEED: build_v2_feed([build_v2_entry(3)])}),
        layout.target,
    )


def occupy_with_an_empty_directory(layout: ImportLayout) -> None:
    layout.target.mkdir()


def occupy_with_a_directory_holding_a_file(layout: ImportLayout) -> None:
    layout.target.mkdir()
    (layout.target / "notes.txt").write_text("operator notes", encoding="utf-8")


def occupy_with_a_file(layout: ImportLayout) -> None:
    layout.target.write_text("a file where the store would go", encoding="utf-8")


OCCUPIED_TARGETS = [
    occupy_with_another_import,
    occupy_with_an_import_of_other_bytes_of_the_same_artifact,
    occupy_with_an_empty_directory,
    occupy_with_a_directory_holding_a_file,
    occupy_with_a_file,
]
OCCUPIED_TARGET_IDS = [
    "another_import",
    "import_of_other_bytes",
    "empty_directory",
    "directory_with_a_file",
    "file",
]


@pytest.mark.parametrize("occupy_target", OCCUPIED_TARGETS, ids=OCCUPIED_TARGET_IDS)
def test_import_into_an_occupied_target_fails_as_target_exists(
    layout: ImportLayout, occupy_target: Callable[[ImportLayout], None]
) -> None:
    occupy_target(layout)
    manifest_path = write_standard_import(layout.inputs_dir)

    report = run_test_migration(manifest_path, layout.target)

    assert report.outcome is MigrationOutcome.FAILED
    assert report.failure is not None
    assert report.failure.code is MigrationFailureCode.TARGET_EXISTS


@pytest.mark.parametrize("occupy_target", OCCUPIED_TARGETS, ids=OCCUPIED_TARGET_IDS)
def test_import_into_an_occupied_target_leaves_it_and_its_parent_untouched(
    layout: ImportLayout, occupy_target: Callable[[ImportLayout], None]
) -> None:
    occupy_target(layout)
    manifest_path = write_standard_import(layout.inputs_dir)
    stores_before = snapshot_tree(layout.stores_dir)
    names_before = list_names(layout.stores_dir)

    run_test_migration(manifest_path, layout.target)

    assert (snapshot_tree(layout.stores_dir), list_names(layout.stores_dir)) == (
        stores_before,
        names_before,
    )


def alter_records_file(target: Path) -> None:
    records_path = target / RECORDS_FILE
    records_path.write_bytes(records_path.read_bytes().replace(b"democorp", b"democorq", 1))


def add_unpinned_file(target: Path) -> None:
    (target / "extra.jsonl").write_bytes(b"{}\n")


def remove_anchors_file(target: Path) -> None:
    (target / ANCHORS_FILE).unlink()


STORE_CORRUPTIONS = [alter_records_file, add_unpinned_file, remove_anchors_file]
STORE_CORRUPTION_IDS = ["altered_records", "unpinned_file", "missing_anchors"]


@pytest.mark.parametrize("corrupt_store", STORE_CORRUPTIONS, ids=STORE_CORRUPTION_IDS)
def test_rerun_onto_a_corrupted_store_of_the_same_import_fails_as_existing_store_invalid(
    layout: ImportLayout, corrupt_store: Callable[[Path], None]
) -> None:
    manifest_path = write_standard_import(layout.inputs_dir)
    run_test_migration(manifest_path, layout.target)
    corrupt_store(layout.target)

    report = run_test_migration(manifest_path, layout.target)

    assert report.failure is not None
    assert report.failure.code is MigrationFailureCode.EXISTING_STORE_INVALID


@pytest.mark.parametrize("corrupt_store", STORE_CORRUPTIONS, ids=STORE_CORRUPTION_IDS)
def test_rerun_onto_a_corrupted_store_never_repairs_it(
    layout: ImportLayout, corrupt_store: Callable[[Path], None]
) -> None:
    manifest_path = write_standard_import(layout.inputs_dir)
    run_test_migration(manifest_path, layout.target)
    corrupt_store(layout.target)
    store_before = snapshot_tree(layout.target)

    run_test_migration(manifest_path, layout.target)

    assert snapshot_tree(layout.target) == store_before


# Dry run (§7, §9)


def test_dry_run_reports_the_dry_run_outcome_with_the_identity_a_real_run_records(
    layout: ImportLayout,
) -> None:
    manifest_path = write_standard_import(layout.inputs_dir)

    dry_report = run_test_migration(manifest_path, layout.target, is_dry_run=True)

    real_report = run_test_migration(manifest_path, layout.target)
    assert dry_report.outcome is MigrationOutcome.DRY_RUN
    assert dry_report.import_identity_sha256 == real_report.import_identity_sha256


def test_dry_run_reports_every_count_a_real_run_reports(layout: ImportLayout) -> None:
    manifest_path = write_import(
        layout.inputs_dir,
        {
            V2_YEAR_FEED: build_v2_feed(
                [build_v2_entry(1), build_v2_entry(2, status="Rejected"), build_v2_entry(3)]
            ),
            V2_MODIFIED_FEED: build_v2_feed([build_v2_entry(3, last_modified=LATER_MODIFIED)]),
        },
        [build_kev_row(1), build_kev_row(4)],
    )

    dry_report = run_test_migration(manifest_path, layout.target, is_dry_run=True)

    real_report = run_test_migration(manifest_path, layout.target)
    assert describe_counts(dry_report) == describe_counts(real_report)


def test_dry_run_names_no_store_and_states_no_rollback(layout: ImportLayout) -> None:
    manifest_path = write_standard_import(layout.inputs_dir)

    report = run_test_migration(manifest_path, layout.target, is_dry_run=True)

    assert (
        report.store_manifest_sha256,
        report.rollback_kind,
        report.rollback_scope,
        report.rollback_instruction,
    ) == (None, None, None, None)


def test_dry_run_creates_no_target_and_nothing_beside_it(layout: ImportLayout) -> None:
    manifest_path = write_standard_import(layout.inputs_dir)

    run_test_migration(manifest_path, layout.target, is_dry_run=True)

    assert list_names(layout.stores_dir) == []


def test_dry_run_leaves_nothing_in_the_system_temporary_directory(
    layout: ImportLayout, system_temp_dir: Path
) -> None:
    manifest_path = write_standard_import(layout.inputs_dir)

    run_test_migration(manifest_path, layout.target, is_dry_run=True)

    assert list_names(system_temp_dir) == []


@pytest.mark.parametrize(
    ("write_failing_import", "limits", "failure_code"), FAILING_IMPORTS, ids=FAILING_IMPORT_IDS
)
def test_dry_run_of_a_failing_import_fails_with_the_code_a_real_run_gives(
    layout: ImportLayout,
    write_failing_import: Callable[[Path], Path],
    limits: MigrationLimits,
    failure_code: MigrationFailureCode,
) -> None:
    manifest_path = write_failing_import(layout.inputs_dir)

    report = run_test_migration(
        manifest_path,
        layout.target,
        is_dry_run=True,
        dependencies=build_migration_dependencies(limits),
    )

    assert report.outcome is MigrationOutcome.FAILED
    assert report.failure is not None
    assert report.failure.code is failure_code


@pytest.mark.parametrize(
    ("write_failing_import", "limits", "failure_code"), FAILING_IMPORTS, ids=FAILING_IMPORT_IDS
)
def test_dry_run_of_a_failing_import_leaves_nothing_in_the_system_temporary_directory(
    layout: ImportLayout,
    system_temp_dir: Path,
    write_failing_import: Callable[[Path], Path],
    limits: MigrationLimits,
    failure_code: MigrationFailureCode,
) -> None:
    manifest_path = write_failing_import(layout.inputs_dir)

    run_test_migration(
        manifest_path,
        layout.target,
        is_dry_run=True,
        dependencies=build_migration_dependencies(limits),
    )

    assert list_names(system_temp_dir) == []


# Failure (§7, §9)


@pytest.mark.parametrize(
    ("write_failing_import", "limits", "failure_code"), FAILING_IMPORTS, ids=FAILING_IMPORT_IDS
)
def test_failing_import_reports_failed_with_its_fixed_code_and_names_no_store(
    layout: ImportLayout,
    write_failing_import: Callable[[Path], Path],
    limits: MigrationLimits,
    failure_code: MigrationFailureCode,
) -> None:
    manifest_path = write_failing_import(layout.inputs_dir)

    report = run_test_migration(
        manifest_path, layout.target, dependencies=build_migration_dependencies(limits)
    )

    assert report.outcome is MigrationOutcome.FAILED
    assert report.failure is not None
    assert report.failure.code is failure_code
    assert (report.store_manifest_sha256, report.rollback_instruction) == (None, None)


@pytest.mark.parametrize(
    ("write_failing_import", "limits", "failure_code"), FAILING_IMPORTS, ids=FAILING_IMPORT_IDS
)
def test_failing_import_leaves_no_target_and_no_working_directory(
    layout: ImportLayout,
    write_failing_import: Callable[[Path], Path],
    limits: MigrationLimits,
    failure_code: MigrationFailureCode,
) -> None:
    manifest_path = write_failing_import(layout.inputs_dir)

    run_test_migration(
        manifest_path, layout.target, dependencies=build_migration_dependencies(limits)
    )

    assert list_names(layout.stores_dir) == []


@pytest.mark.parametrize(
    ("write_failing_import", "limits", "failure_code"), FAILING_IMPORTS, ids=FAILING_IMPORT_IDS
)
def test_failing_import_leaves_every_input_unchanged(
    layout: ImportLayout,
    write_failing_import: Callable[[Path], Path],
    limits: MigrationLimits,
    failure_code: MigrationFailureCode,
) -> None:
    manifest_path = write_failing_import(layout.inputs_dir)
    inputs_before = snapshot_tree(layout.inputs_dir)

    run_test_migration(
        manifest_path, layout.target, dependencies=build_migration_dependencies(limits)
    )

    assert snapshot_tree(layout.inputs_dir) == inputs_before


def test_failing_import_report_never_quotes_an_input_path(tmp_path: Path) -> None:
    inputs_dir = tmp_path / INPUT_PATH_MARKER
    inputs_dir.mkdir()
    manifest_path = write_conflicting_kev_import(inputs_dir)

    report = run_test_migration(manifest_path, tmp_path / "stores" / "store")

    assert INPUT_PATH_MARKER not in report.model_dump_json()


# NVD entries for the same CVE (§5)


def test_modified_feed_entry_supersedes_the_older_year_feed_entry(layout: ImportLayout) -> None:
    manifest_path = write_import(
        layout.inputs_dir,
        {
            V2_YEAR_FEED: build_v2_feed([build_v2_entry(1, description="SYNTHETIC: year text.")]),
            V2_MODIFIED_FEED: build_v2_feed(
                [
                    build_v2_entry(
                        1, last_modified=LATER_MODIFIED, description="SYNTHETIC: modified text."
                    )
                ]
            ),
        },
    )

    run_test_migration(manifest_path, layout.target)

    store = load_corpus_store(layout.target)
    assert find_record(store, build_cve_id(1)).descriptions[0].value == "SYNTHETIC: modified text."
    assert find_anchor(store, SourceType.NVD_API_2, build_cve_id(1)).source_uri == (
        V2_MODIFIED_FEED_URI
    )


def test_superseded_entry_is_counted_and_gets_no_anchor(layout: ImportLayout) -> None:
    manifest_path = write_import(
        layout.inputs_dir,
        {
            V2_YEAR_FEED: build_v2_feed([build_v2_entry(1)]),
            V2_MODIFIED_FEED: build_v2_feed([build_v2_entry(1, last_modified=LATER_MODIFIED)]),
        },
    )

    report = run_test_migration(manifest_path, layout.target)

    assert report.candidate_outcomes[CandidateOutcome.SUPERSEDED] == 1
    assert len(load_corpus_store(layout.target).evidence) == 1


def test_identical_entries_in_two_feeds_import_one_record_counted_as_an_identical_duplicate(
    layout: ImportLayout,
) -> None:
    manifest_path = write_import(
        layout.inputs_dir,
        {
            V2_YEAR_FEED: build_v2_feed([build_v2_entry(1)]),
            V2_MODIFIED_FEED: build_v2_feed([build_v2_entry(1)], timestamp="2026-10-21T00:00:00"),
        },
    )

    report = run_test_migration(manifest_path, layout.target)

    assert (
        report.cve_outcomes[CveOutcome.IMPORTED],
        report.candidate_outcomes[CandidateOutcome.CHOSEN],
        report.candidate_outcomes[CandidateOutcome.IDENTICAL_DUPLICATE],
    ) == (1, 1, 1)


def test_v2_entry_wins_over_a_differing_v1_entry_modified_at_the_same_instant(
    layout: ImportLayout,
) -> None:
    manifest_path = write_import(
        layout.inputs_dir,
        {
            V1_YEAR_FEED: build_v1_feed([build_v1_item(1, description="SYNTHETIC: 1.1 text.")]),
            V2_YEAR_FEED: build_v2_feed([build_v2_entry(1, description="SYNTHETIC: 2.0 text.")]),
        },
    )

    report = run_test_migration(manifest_path, layout.target)

    record = find_record(load_corpus_store(layout.target), build_cve_id(1))
    assert record.descriptions[0].value == "SYNTHETIC: 2.0 text."
    assert report.candidate_outcomes[CandidateOutcome.DROPPED_FOR_FORMAT] == 1


def test_differing_v2_entries_modified_at_the_same_instant_exclude_the_cve(
    layout: ImportLayout,
) -> None:
    manifest_path = write_import(
        layout.inputs_dir,
        {
            V2_YEAR_FEED: build_v2_feed(
                [build_v2_entry(1, description="SYNTHETIC: one text."), build_v2_entry(2)]
            ),
            V2_MODIFIED_FEED: build_v2_feed([build_v2_entry(1, description="SYNTHETIC: another.")]),
        },
    )

    report = run_test_migration(manifest_path, layout.target)

    assert report.cve_outcomes[CveOutcome.CONFLICTING_DUPLICATE] == 1
    assert list_record_ids(load_corpus_store(layout.target)) == [build_cve_id(2)]


def test_rejected_newer_entry_withdraws_the_cve_an_older_active_entry_described(
    layout: ImportLayout,
) -> None:
    manifest_path = write_import(
        layout.inputs_dir,
        {
            V2_YEAR_FEED: build_v2_feed([build_v2_entry(1), build_v2_entry(2)]),
            V2_MODIFIED_FEED: build_v2_feed(
                [build_v2_entry(1, last_modified=LATER_MODIFIED, status="Rejected")]
            ),
        },
    )

    report = run_test_migration(manifest_path, layout.target)

    assert report.cve_outcomes[CveOutcome.WITHDRAWN_BY_SOURCE] == 1
    assert list_record_ids(load_corpus_store(layout.target)) == [build_cve_id(2)]


def test_rejected_v1_entry_withdraws_the_cve(layout: ImportLayout) -> None:
    manifest_path = write_import(
        layout.inputs_dir,
        {
            V1_YEAR_FEED: build_v1_feed(
                [
                    build_v1_item(1, description="** REJECT ** SYNTHETIC: withdrawn."),
                    build_v1_item(2),
                ]
            )
        },
    )

    report = run_test_migration(manifest_path, layout.target)

    assert report.cve_outcomes[CveOutcome.WITHDRAWN_BY_SOURCE] == 1
    assert list_record_ids(load_corpus_store(layout.target)) == [build_cve_id(2)]


def write_malformed_entry_import(inputs_dir: Path) -> Path:
    """CVE-9999-0002, the feed's second entry, has a publication time that is no time."""
    return write_import(
        inputs_dir,
        {
            V2_YEAR_FEED: build_v2_feed(
                [
                    build_v2_entry(1),
                    build_v2_entry(2, description=MALFORMED_ENTRY_MARKER, published="no time"),
                ]
            )
        },
    )


def test_malformed_entry_is_located_by_input_position_and_entry_index_with_its_code(
    layout: ImportLayout,
) -> None:
    manifest_path = write_malformed_entry_import(layout.inputs_dir)

    report = run_test_migration(manifest_path, layout.target)

    assert report.skipped_entries == (
        EntryLocator(
            input_position=0, entry_index=1, code=NormalizationFailureCode.INVALID_TIMESTAMP
        ),
    )
    assert report.normalization_failures[NormalizationFailureCode.INVALID_TIMESTAMP] == 1


def test_malformed_sole_entry_excludes_its_cve_as_a_malformed_winning_candidate(
    layout: ImportLayout,
) -> None:
    manifest_path = write_malformed_entry_import(layout.inputs_dir)

    report = run_test_migration(manifest_path, layout.target)

    assert report.cve_outcomes[CveOutcome.MALFORMED_WINNING_CANDIDATE] == 1
    assert list_record_ids(load_corpus_store(layout.target)) == [build_cve_id(1)]


def test_malformed_entry_is_never_quoted_in_the_report(layout: ImportLayout) -> None:
    manifest_path = write_malformed_entry_import(layout.inputs_dir)

    report = run_test_migration(manifest_path, layout.target)

    assert MALFORMED_ENTRY_MARKER not in report.model_dump_json()


def test_malformed_entry_older_than_a_valid_winner_is_skipped_and_the_cve_imported(
    layout: ImportLayout,
) -> None:
    manifest_path = write_import(
        layout.inputs_dir,
        {
            V2_YEAR_FEED: build_v2_feed([build_v2_entry(1, published="no time")]),
            V2_MODIFIED_FEED: build_v2_feed([build_v2_entry(1, last_modified=LATER_MODIFIED)]),
        },
    )

    report = run_test_migration(manifest_path, layout.target)

    assert report.candidate_outcomes[CandidateOutcome.MALFORMED] == 1
    assert list_record_ids(load_corpus_store(layout.target)) == [build_cve_id(1)]


def test_duplicate_group_with_an_entry_lacking_a_modification_time_is_unorderable(
    layout: ImportLayout,
) -> None:
    manifest_path = write_import(
        layout.inputs_dir,
        {
            V2_YEAR_FEED: build_v2_feed([build_v2_entry(1, last_modified=None), build_v2_entry(2)]),
            V2_MODIFIED_FEED: build_v2_feed([build_v2_entry(1, last_modified=LATER_MODIFIED)]),
        },
    )

    report = run_test_migration(manifest_path, layout.target)

    assert report.cve_outcomes[CveOutcome.UNORDERABLE_CANDIDATE] == 1
    assert list_record_ids(load_corpus_store(layout.target)) == [build_cve_id(2)]


def test_single_entry_without_a_modification_time_is_imported(layout: ImportLayout) -> None:
    manifest_path = write_import(
        layout.inputs_dir, {V2_YEAR_FEED: build_v2_feed([build_v2_entry(1, last_modified=None)])}
    )

    run_test_migration(manifest_path, layout.target)

    assert list_record_ids(load_corpus_store(layout.target)) == [build_cve_id(1)]


OUT_OF_UTC_RANGE_TIMES = ["9999-12-31T23:59:00.000-01:00", "0001-01-01T00:00:00+01:00"]
OUT_OF_UTC_RANGE_IDS = ["after_year_9999_in_utc", "before_year_1_in_utc"]


@pytest.mark.parametrize("last_modified", OUT_OF_UTC_RANGE_TIMES, ids=OUT_OF_UTC_RANGE_IDS)
def test_duplicate_group_with_a_modification_time_outside_utc_is_unorderable(
    layout: ImportLayout, last_modified: str
) -> None:
    manifest_path = write_import(
        layout.inputs_dir,
        {
            V2_YEAR_FEED: build_v2_feed(
                [build_v2_entry(1, last_modified=last_modified), build_v2_entry(2)]
            ),
            V2_MODIFIED_FEED: build_v2_feed([build_v2_entry(1, last_modified=LATER_MODIFIED)]),
        },
    )

    report = run_test_migration(manifest_path, layout.target)

    assert report.cve_outcomes[CveOutcome.UNORDERABLE_CANDIDATE] == 1
    assert list_record_ids(load_corpus_store(layout.target)) == [build_cve_id(2)]


@pytest.mark.parametrize("last_modified", OUT_OF_UTC_RANGE_TIMES, ids=OUT_OF_UTC_RANGE_IDS)
def test_single_entry_with_a_modification_time_outside_utc_is_imported(
    layout: ImportLayout, last_modified: str
) -> None:
    manifest_path = write_import(
        layout.inputs_dir,
        {V2_YEAR_FEED: build_v2_feed([build_v2_entry(1, last_modified=last_modified)])},
    )

    report = run_test_migration(manifest_path, layout.target)

    assert report.outcome is MigrationOutcome.IMPORTED
    assert list_record_ids(load_corpus_store(layout.target)) == [build_cve_id(1)]


def test_more_malformed_entries_than_the_report_locates_are_all_counted_and_the_first_located(
    layout: ImportLayout,
) -> None:
    entries = [build_v2_entry(1)]
    for number in range(2, MAX_REPORTED_LOCATORS + 3):
        entries.append(build_v2_entry(number, published="no time"))
    manifest_path = write_import(layout.inputs_dir, {V2_YEAR_FEED: build_v2_feed(entries)})

    report = run_test_migration(manifest_path, layout.target)

    assert report.normalization_failures[NormalizationFailureCode.INVALID_TIMESTAMP] == (
        MAX_REPORTED_LOCATORS + 1
    )
    assert len(report.skipped_entries) == MAX_REPORTED_LOCATORS
    assert report.skipped_entries[-1].entry_index == MAX_REPORTED_LOCATORS


def test_identical_rejected_entries_in_two_feeds_withdraw_the_cve_choosing_one(
    layout: ImportLayout,
) -> None:
    manifest_path = write_import(
        layout.inputs_dir,
        {
            V2_YEAR_FEED: build_v2_feed([build_v2_entry(1, status="Rejected"), build_v2_entry(2)]),
            V2_MODIFIED_FEED: build_v2_feed([build_v2_entry(1, status="Rejected")]),
        },
    )

    report = run_test_migration(manifest_path, layout.target)

    # CVE-9999-0002's sole entry is the other chosen candidate.
    assert (
        report.cve_outcomes[CveOutcome.WITHDRAWN_BY_SOURCE],
        report.candidate_outcomes[CandidateOutcome.CHOSEN],
        report.candidate_outcomes[CandidateOutcome.IDENTICAL_DUPLICATE],
    ) == (1, 2, 1)


def build_rejected_v2_entry_without_a_cve_id() -> dict[str, Any]:
    return build_v2_entry(2, status="Rejected", id="NOT-A-CVE-ID")


def build_rejected_v1_item_without_a_cve_id() -> dict[str, Any]:
    rejected_item = build_v1_item(2, description="** REJECT ** SYNTHETIC: withdrawn.")
    rejected_item["cve"]["CVE_data_meta"]["ID"] = "NOT-A-CVE-ID"
    return rejected_item


@pytest.mark.parametrize(
    ("file_name", "build_feed", "build_valid_entry", "build_rejected_entry"),
    [
        (V2_YEAR_FEED, build_v2_feed, build_v2_entry, build_rejected_v2_entry_without_a_cve_id),
        (V1_YEAR_FEED, build_v1_feed, build_v1_item, build_rejected_v1_item_without_a_cve_id),
    ],
    ids=["v2_vuln_status_rejected", "v1_reject_description"],
)
def test_rejected_entry_whose_id_is_no_cve_id_is_a_located_contract_violation(
    layout: ImportLayout,
    file_name: str,
    build_feed: Callable[[list[dict[str, Any]]], dict[str, Any]],
    build_valid_entry: Callable[[int], dict[str, Any]],
    build_rejected_entry: Callable[[], dict[str, Any]],
) -> None:
    manifest_path = write_import(
        layout.inputs_dir, {file_name: build_feed([build_valid_entry(1), build_rejected_entry()])}
    )

    report = run_test_migration(manifest_path, layout.target)

    assert report.normalization_failures[NormalizationFailureCode.CONTRACT_VIOLATION] == 1
    assert report.skipped_entries == (
        EntryLocator(
            input_position=0, entry_index=1, code=NormalizationFailureCode.CONTRACT_VIOLATION
        ),
    )
    assert list_record_ids(load_corpus_store(layout.target)) == [build_cve_id(1)]


# KEV (§6)


def write_kev_outcome_import(inputs_dir: Path) -> Path:
    """KEV rows for CVE-9999-0001 (listed twice, equal) and -0005, imported; -0002,
    rejected; -0003, a conflicting duplicate; and -0004, which no NVD feed holds."""
    return write_import(
        inputs_dir,
        {
            V2_YEAR_FEED: build_v2_feed(
                [
                    build_v2_entry(1),
                    build_v2_entry(2, status="Rejected"),
                    build_v2_entry(3, description="SYNTHETIC: one text."),
                    build_v2_entry(5),
                ]
            ),
            V2_MODIFIED_FEED: build_v2_feed([build_v2_entry(3, description="SYNTHETIC: another.")]),
        },
        [
            build_kev_row(1),
            build_kev_row(1),
            build_kev_row(2),
            build_kev_row(3),
            build_kev_row(4),
            build_kev_row(5),
        ],
    )


@pytest.mark.parametrize(
    ("kev_outcome", "expected_count"),
    [
        (KevOutcome.MERGED, 2),
        (KevOutcome.IDENTICAL_DUPLICATE, 1),
        (KevOutcome.FOR_REJECTED_NVD_RECORD, 1),
        (KevOutcome.FOR_EXCLUDED_NVD_RECORD, 1),
        (KevOutcome.WITHOUT_NVD_RECORD, 1),
    ],
    ids=["merged", "identical_duplicate", "for_rejected", "for_excluded", "without_nvd_record"],
)
def test_kev_rows_are_counted_by_what_became_of_their_nvd_cve(
    layout: ImportLayout, kev_outcome: KevOutcome, expected_count: int
) -> None:
    manifest_path = write_kev_outcome_import(layout.inputs_dir)

    report = run_test_migration(manifest_path, layout.target)

    assert report.kev_outcomes[kev_outcome] == expected_count


@pytest.mark.parametrize(
    ("kev_rows", "kev_advice"),
    [
        ([build_kev_row(2)], None),
        ([build_kev_row(2), build_kev_row(4)], KEV_WITHOUT_NVD_RECORD_ADVICE),
    ],
    ids=["every_kev_cve_in_nvd", "a_kev_cve_in_no_nvd_input"],
)
def test_report_advises_adding_nvd_feeds_exactly_when_a_kev_row_names_a_cve_no_nvd_input_holds(
    layout: ImportLayout, kev_rows: list[dict[str, str]], kev_advice: str | None
) -> None:
    manifest_path = write_import(
        layout.inputs_dir,
        {V2_YEAR_FEED: build_v2_feed([build_v2_entry(1), build_v2_entry(2)])},
        kev_rows,
    )

    report = run_test_migration(manifest_path, layout.target)

    assert report.kev_advice == kev_advice


def test_merged_kev_anchor_and_the_store_manifest_give_the_catalog_file_hash_as_its_version(
    layout: ImportLayout,
) -> None:
    manifest_path = write_standard_import(layout.inputs_dir)

    run_test_migration(manifest_path, layout.target)

    store = load_corpus_store(layout.target)
    kev_anchor = find_anchor(store, SourceType.CISA_KEV, build_cve_id(2))
    kev_input = find_store_input(store, StoreSource.CISA_KEV)
    kev_file_version = "sha256:" + sha256_hex((layout.inputs_dir / KEV_FILE).read_bytes())
    assert (kev_anchor.source_version, kev_input.source_version) == (
        kev_file_version,
        kev_file_version,
    )


def test_kev_rows_without_a_servable_nvd_record_get_no_record_and_no_anchor(
    layout: ImportLayout,
) -> None:
    manifest_path = write_kev_outcome_import(layout.inputs_dir)

    run_test_migration(manifest_path, layout.target)

    store = load_corpus_store(layout.target)
    kev_anchor_cves: list[str] = []
    for anchor in store.evidence:
        if anchor.source_type is SourceType.CISA_KEV:
            kev_anchor_cves.append(anchor.authoritative_record_id)
    assert list_record_ids(store) == [build_cve_id(1), build_cve_id(5)]
    # Anchors are stored in evidence ID order, which says nothing of their CVE's order.
    assert sorted(kev_anchor_cves) == [build_cve_id(1), build_cve_id(5)]


def test_merged_kev_row_gives_its_record_a_kev_anchor_of_its_own(layout: ImportLayout) -> None:
    manifest_path = write_standard_import(layout.inputs_dir)

    run_test_migration(manifest_path, layout.target)

    store = load_corpus_store(layout.target)
    assert list_cited_source_types(store, find_record(store, build_cve_id(2))) == [
        SourceType.NVD_API_2,
        SourceType.CISA_KEV,
    ]


def test_merged_kev_anchor_locates_the_cve_in_the_catalog_at_its_published_url(
    layout: ImportLayout,
) -> None:
    manifest_path = write_standard_import(layout.inputs_dir)

    run_test_migration(manifest_path, layout.target)

    kev_anchor = find_anchor(load_corpus_store(layout.target), SourceType.CISA_KEV, build_cve_id(2))
    assert (kev_anchor.locator, kev_anchor.source_uri) == (
        f"vulnerabilities/{build_cve_id(2)}",
        KEV_URI,
    )


def test_kev_row_supersedes_the_kev_fields_nvd_mirrors(layout: ImportLayout) -> None:
    manifest_path = write_import(
        layout.inputs_dir,
        {
            V2_YEAR_FEED: build_v2_feed(
                [build_v2_entry(1, cisaExploitAdd="2099-01-04", cisaActionDue="2099-01-20")]
            )
        },
        [build_kev_row(1, dateAdded="2099-01-05", dueDate="2099-01-26")],
    )

    run_test_migration(manifest_path, layout.target)

    assert find_record(load_corpus_store(layout.target), build_cve_id(1)).kev == KevEntry(
        date_added=date(2099, 1, 5),
        due_date=date(2099, 1, 26),
        known_ransomware_campaign_use="unknown",
    )


def test_nvd_mirrored_kev_fields_stay_when_the_catalog_lists_no_row_for_the_cve(
    layout: ImportLayout,
) -> None:
    manifest_path = write_import(
        layout.inputs_dir,
        {
            V2_YEAR_FEED: build_v2_feed(
                [build_v2_entry(1, cisaExploitAdd="2099-01-04", cisaActionDue="2099-01-20")]
            )
        },
        [build_kev_row(2)],
    )

    run_test_migration(manifest_path, layout.target)

    assert find_record(load_corpus_store(layout.target), build_cve_id(1)).kev == KevEntry(
        date_added=date(2099, 1, 4), due_date=date(2099, 1, 20)
    )


def test_kev_catalog_without_its_optional_columns_merges_its_rows(layout: ImportLayout) -> None:
    required_columns: list[str] = []
    for column in KEV_COLUMNS:
        if column not in {"notes", "knownRansomwareCampaignUse", "cwes"}:
            required_columns.append(column)
    write_feed(layout.inputs_dir / V2_YEAR_FEED, build_v2_feed([build_v2_entry(1)]))
    write_kev_csv(layout.inputs_dir / KEV_FILE, [build_kev_row(1)], required_columns)
    manifest_path = write_inputs_manifest(
        layout.inputs_dir,
        [build_declaration(V2_YEAR_FEED), build_declaration(KEV_FILE, source="cisa-kev")],
    )

    report = run_test_migration(manifest_path, layout.target)

    assert report.kev_outcomes[KevOutcome.MERGED] == 1


def write_kev_catalog_bytes(inputs_dir: Path, catalog_bytes: bytes) -> Path:
    write_feed(inputs_dir / V2_YEAR_FEED, build_v2_feed([build_v2_entry(1)]))
    (inputs_dir / KEV_FILE).write_bytes(catalog_bytes)
    return write_inputs_manifest(
        inputs_dir,
        [build_declaration(V2_YEAR_FEED), build_declaration(KEV_FILE, source="cisa-kev")],
    )


KEV_HEADER = ",".join(KEV_COLUMNS).encode()
VALID_KEV_LINE = (
    b"CVE-9999-0001,Democorp,Gateway,Democorp Gateway Input Flaw,2099-01-05,"
    b"SYNTHETIC: exploited input flaw.,Apply the vendor update.,2099-01-26,Unknown,,"
)


@pytest.mark.parametrize(
    ("catalog_bytes", "failure_code"),
    [
        (
            KEV_HEADER
            + b"\r\n"
            + VALID_KEV_LINE
            + b"\r\n"
            + VALID_KEV_LINE.replace(b"2099-01-26", b"2099-02-26")
            + b"\r\n",
            MigrationFailureCode.KEV_CONFLICTING_ROWS,
        ),
        (
            KEV_HEADER.replace(b",dueDate", b"") + b"\r\n",
            MigrationFailureCode.KEV_INVALID_HEADER,
        ),
        (KEV_HEADER + b",unknownColumn\r\n", MigrationFailureCode.KEV_INVALID_HEADER),
        (
            KEV_HEADER + b"\r\n" + VALID_KEV_LINE.replace(b"2099-01-05", b"2099-13-05") + b"\r\n",
            MigrationFailureCode.KEV_INVALID_ROW,
        ),
        (
            KEV_HEADER + b"\r\n" + VALID_KEV_LINE.replace(b"Unknown", b"Perhaps") + b"\r\n",
            MigrationFailureCode.KEV_INVALID_ROW,
        ),
        (
            KEV_HEADER + b"\r\n" + VALID_KEV_LINE + b",extra\r\n",
            MigrationFailureCode.KEV_INVALID_ROW,
        ),
        (
            KEV_HEADER + b"\r\n\r\n" + VALID_KEV_LINE + b"\r\n",
            MigrationFailureCode.KEV_INVALID_ROW,
        ),
        (KEV_HEADER + b"\r\n\xff\xfe\r\n", MigrationFailureCode.KEV_INVALID_ENCODING),
    ],
    ids=[
        "conflicting_rows",
        "missing_required_column",
        "unknown_column",
        "invalid_date_added",
        "invalid_ransomware_use",
        "row_wider_than_header",
        "blank_line",
        "not_utf8",
    ],
)
def test_invalid_kev_catalog_fails_the_whole_run_with_its_code(
    layout: ImportLayout, catalog_bytes: bytes, failure_code: MigrationFailureCode
) -> None:
    manifest_path = write_kev_catalog_bytes(layout.inputs_dir, catalog_bytes)

    report = run_test_migration(manifest_path, layout.target)

    assert report.failure is not None
    assert report.failure.code is failure_code


def test_invalid_kev_catalog_publishes_no_target(layout: ImportLayout) -> None:
    manifest_path = write_conflicting_kev_import(layout.inputs_dir)

    run_test_migration(manifest_path, layout.target)

    assert not layout.target.exists()


def test_invalid_kev_catalog_failure_names_the_kev_input_and_offers_both_ways_on(
    layout: ImportLayout,
) -> None:
    manifest_path = write_conflicting_kev_import(layout.inputs_dir)

    report = run_test_migration(manifest_path, layout.target)

    assert report.failure is not None
    # cisa-kev sorts before nvd, so the KEV input is the first in the sorted list.
    assert report.failure.input_position == 0
    assert report.failure.message.endswith(KEV_REMEDY)


# File-level faults (§1-§3, §7)


@pytest.mark.parametrize(
    "derived_document",
    [
        [{"document_type": "cve_summary", "cve_refs": ["CVE-9999-0001"], "content": "x"}],
        [{"content": "SYNTHETIC text", "metadata": {"cve_id": "CVE-9999-0001"}}],
        {"vendors": {"democorp": 1}, "products": {"gateway": 1}},
        {"nodes": [], "relationships": []},
        {"CVE-9999-0001": ["CWE-20"], "CVE-9999-0002": ["CWE-79"]},
        {"basic_stats": {"total": 2}},
    ],
    ids=[
        "enhanced_documents",
        "rag_export",
        "cpe_parsing_results",
        "graph_export",
        "mapping",
        "analytics",
    ],
)
@pytest.mark.parametrize("source", ["nvd", "cisa-kev"], ids=["as_nvd", "as_cisa_kev"])
def test_derived_file_declared_as_a_source_fails_as_derived_file_declared_as_source(
    layout: ImportLayout, derived_document: Any, source: str
) -> None:
    write_plain_feed(layout.inputs_dir / DERIVED_FILE_NAME, derived_document)
    manifest_path = write_inputs_manifest(
        layout.inputs_dir, [build_declaration(DERIVED_FILE_NAME, source=source)]
    )

    report = run_test_migration(manifest_path, layout.target)

    assert report.failure is not None
    assert report.failure.code is MigrationFailureCode.DERIVED_FILE_DECLARED_AS_SOURCE


def test_graph_export_whose_node_list_passes_the_entry_cap_fails_as_derived_file(
    layout: ImportLayout,
) -> None:
    graph_nodes: list[dict[str, Any]] = []
    for number in range(1, 65):
        graph_nodes.append({"id": build_cve_id(number), "labels": ["CVE"]})
    write_plain_feed(
        layout.inputs_dir / DERIVED_FILE_NAME, {"nodes": graph_nodes, "relationships": []}
    )
    manifest_path = write_inputs_manifest(layout.inputs_dir, [build_declaration(DERIVED_FILE_NAME)])
    # The node list is longer than an entry may be, and than the prefix read to tell the
    # file, so its relationships are never seen.
    limits = MigrationLimits(
        max_entry_bytes=64, parser_buffer_bytes=16, max_fingerprint_file_bytes=256
    )

    report = run_test_migration(
        manifest_path, layout.target, dependencies=build_migration_dependencies(limits)
    )

    assert report.failure is not None
    assert report.failure.code is MigrationFailureCode.DERIVED_FILE_DECLARED_AS_SOURCE


def test_unrecognised_json_declared_as_an_nvd_source_fails_as_unrecognised_format(
    layout: ImportLayout,
) -> None:
    write_plain_feed(layout.inputs_dir / "nvdcve-2.0-2099.json", {"greeting": "hello"})
    manifest_path = write_inputs_manifest(
        layout.inputs_dir, [build_declaration("nvdcve-2.0-2099.json")]
    )

    report = run_test_migration(manifest_path, layout.target)

    assert report.failure is not None
    assert report.failure.code is MigrationFailureCode.UNRECOGNISED_FORMAT


def test_import_of_only_rejected_entries_fails_as_no_importable_records(
    layout: ImportLayout,
) -> None:
    manifest_path = write_only_rejected_import(layout.inputs_dir)

    report = run_test_migration(manifest_path, layout.target)

    assert report.failure is not None
    assert report.failure.code is MigrationFailureCode.NO_IMPORTABLE_RECORDS


@pytest.mark.parametrize(
    ("file_name", "feed"),
    [
        (V2_YEAR_FEED, build_v2_feed([build_v2_entry(1)])),
        (V1_YEAR_FEED, build_v1_feed([build_v1_item(1)])),
    ],
    ids=["v2", "v1"],
)
def test_input_retrieved_before_its_feed_was_generated_fails_as_retrieved_before_generated(
    layout: ImportLayout, file_name: str, feed: dict[str, Any]
) -> None:
    manifest_path = write_import(
        layout.inputs_dir, {file_name: feed}, retrieved_at="2026-10-19T23:59:59Z"
    )

    report = run_test_migration(manifest_path, layout.target)

    assert report.failure is not None
    assert report.failure.code is MigrationFailureCode.RETRIEVED_BEFORE_GENERATED


def test_input_retrieved_at_the_instant_its_feed_was_generated_is_imported(
    layout: ImportLayout,
) -> None:
    manifest_path = write_import(
        layout.inputs_dir,
        {V2_YEAR_FEED: build_v2_feed([build_v2_entry(1)])},
        retrieved_at="2026-10-20T00:00:00Z",
    )

    report = run_test_migration(manifest_path, layout.target)

    assert report.outcome is MigrationOutcome.IMPORTED


@pytest.mark.parametrize(
    "feed_timestamp",
    ["yesterday", "2026-13-40T00:00:00", "2026-10-20 00:00:00", "", *OUT_OF_UTC_RANGE_TIMES],
    ids=["words", "impossible_date", "space_separator", "empty", *OUT_OF_UTC_RANGE_IDS],
)
def test_feed_with_an_invalid_generation_time_fails_as_generated_at_invalid(
    layout: ImportLayout, feed_timestamp: str
) -> None:
    manifest_path = write_import(
        layout.inputs_dir, {V2_YEAR_FEED: build_v2_feed([build_v2_entry(1)], feed_timestamp)}
    )

    report = run_test_migration(manifest_path, layout.target)

    assert report.failure is not None
    assert report.failure.code is MigrationFailureCode.GENERATED_AT_INVALID


def write_v1_content_under_a_v2_name(inputs_dir: Path) -> Path:
    write_gzip_feed(inputs_dir / V2_YEAR_FEED, build_v1_feed([build_v1_item(1)]))
    return write_inputs_manifest(inputs_dir, [build_declaration(V2_YEAR_FEED)])


def write_v2_content_under_a_v1_name(inputs_dir: Path) -> Path:
    write_gzip_feed(inputs_dir / V1_YEAR_FEED, build_v2_feed([build_v2_entry(1)]))
    return write_inputs_manifest(inputs_dir, [build_declaration(V1_YEAR_FEED)])


def write_v1_content_declared_as_v2(inputs_dir: Path) -> Path:
    write_gzip_feed(inputs_dir / "renamed-feed.json.gz", build_v1_feed([build_v1_item(1)]))
    return write_inputs_manifest(
        inputs_dir,
        [
            build_declaration(
                "renamed-feed.json.gz", artifact={"format": "2.0", "series": "year", "year": 2099}
            )
        ],
    )


@pytest.mark.parametrize(
    "write_mismatched_import",
    [
        write_v1_content_under_a_v2_name,
        write_v2_content_under_a_v1_name,
        write_v1_content_declared_as_v2,
    ],
    ids=["v1_content_v2_name", "v2_content_v1_name", "v1_content_declared_v2"],
)
def test_feed_whose_content_declares_another_format_than_its_artifact_fails_as_format_mismatch(
    layout: ImportLayout, write_mismatched_import: Callable[[Path], Path]
) -> None:
    manifest_path = write_mismatched_import(layout.inputs_dir)

    report = run_test_migration(manifest_path, layout.target)

    assert report.failure is not None
    assert report.failure.code is MigrationFailureCode.FORMAT_MISMATCH


def test_feed_with_no_entries_whose_content_declares_another_format_fails_naming_its_input(
    layout: ImportLayout,
) -> None:
    # The modified feed sorts before any year feed, so the empty one is the second input.
    manifest_path = write_import(
        layout.inputs_dir,
        {
            V2_MODIFIED_FEED: build_v2_feed([build_v2_entry(1)]),
            "nvdcve-2.0-2097.json.gz": build_v1_feed([]),
        },
    )

    report = run_test_migration(manifest_path, layout.target)

    assert report.failure is not None
    assert (report.failure.code, report.failure.input_position) == (
        MigrationFailureCode.FORMAT_MISMATCH,
        1,
    )


@pytest.mark.parametrize(
    "api_page",
    [build_api_page(start_index=2000), build_api_page(start_index=0)],
    ids=["later_page", "first_page"],
)
@pytest.mark.parametrize("is_dry_run", [False, True], ids=["real_run", "dry_run"])
def test_api_page_saved_as_a_year_feed_fails_as_incomplete_feed_publishing_nothing(
    layout: ImportLayout, api_page: dict[str, Any], is_dry_run: bool
) -> None:
    # The whole modified feed sorts before any year feed, so it is read first and the
    # page, the second input, still fails the run.
    manifest_path = write_import(
        layout.inputs_dir,
        {
            V2_MODIFIED_FEED: build_v2_feed([build_v2_entry(3)]),
            "nvdcve-2.0-2024.json.gz": api_page,
        },
    )

    report = run_test_migration(manifest_path, layout.target, is_dry_run=is_dry_run)

    assert report.failure is not None
    assert (report.failure.code, report.failure.input_position) == (
        MigrationFailureCode.INCOMPLETE_FEED,
        1,
    )
    assert list_names(layout.stores_dir) == []


def write_target_inside_the_inputs(layout: ImportLayout) -> tuple[Path, Path]:
    return write_standard_import(layout.inputs_dir), layout.inputs_dir / "store"


def write_target_at_the_inputs(layout: ImportLayout) -> tuple[Path, Path]:
    return write_standard_import(layout.inputs_dir), layout.inputs_dir


def write_target_at_an_input(layout: ImportLayout) -> tuple[Path, Path]:
    return write_standard_import(layout.inputs_dir), layout.inputs_dir / V2_YEAR_FEED


@pytest.mark.parametrize(
    ("place_target", "failure_code"),
    [
        (write_target_inside_the_inputs, MigrationFailureCode.TARGET_PARENT_HOLDS_INPUT),
        (write_target_at_the_inputs, MigrationFailureCode.TARGET_OVERLAPS_INPUT),
        (write_target_at_an_input, MigrationFailureCode.TARGET_OVERLAPS_INPUT),
    ],
    ids=["beside_an_input", "holding_the_inputs", "at_an_input"],
)
def test_target_overlapping_the_inputs_fails_with_its_code(
    layout: ImportLayout,
    place_target: Callable[[ImportLayout], tuple[Path, Path]],
    failure_code: MigrationFailureCode,
) -> None:
    manifest_path, target = place_target(layout)

    report = run_test_migration(manifest_path, target)

    assert report.failure is not None
    assert report.failure.code is failure_code


@pytest.mark.parametrize("is_dry_run", [False, True], ids=["real_run", "dry_run"])
def test_target_whose_parent_is_missing_fails_as_target_unusable(
    layout: ImportLayout, is_dry_run: bool
) -> None:
    manifest_path = write_standard_import(layout.inputs_dir)

    report = run_test_migration(
        manifest_path, layout.stores_dir / "missing" / "store", is_dry_run=is_dry_run
    )

    assert report.failure is not None
    assert report.failure.code is MigrationFailureCode.TARGET_UNUSABLE


def test_dangling_symbolic_link_at_the_target_fails_as_target_exists(
    layout: ImportLayout,
) -> None:
    layout.target.symlink_to(layout.stores_dir / "link-destination")
    manifest_path = write_standard_import(layout.inputs_dir)

    report = run_test_migration(manifest_path, layout.target)

    assert report.failure is not None
    assert report.failure.code is MigrationFailureCode.TARGET_EXISTS


def test_dangling_symbolic_link_at_the_target_is_never_followed(layout: ImportLayout) -> None:
    link_destination = layout.stores_dir / "link-destination"
    layout.target.symlink_to(link_destination)
    manifest_path = write_standard_import(layout.inputs_dir)

    run_test_migration(manifest_path, layout.target)

    assert not os.path.lexists(link_destination)
    assert list_names(layout.stores_dir) == ["store"]


def place_target_at_a_looping_link(layout: ImportLayout) -> Path:
    layout.target.symlink_to(layout.target)
    return layout.target


def place_target_under_a_looping_link(layout: ImportLayout) -> Path:
    looping_link = layout.stores_dir / "loop"
    looping_link.symlink_to(looping_link)
    return looping_link / "store"


@pytest.mark.parametrize(
    ("place_target", "failure_code"),
    [
        # A link that resolves nowhere is an entry at the target, like a dangling one.
        (place_target_at_a_looping_link, MigrationFailureCode.TARGET_EXISTS),
        (place_target_under_a_looping_link, MigrationFailureCode.TARGET_UNUSABLE),
    ],
    ids=["looping_link_at_target", "target_under_a_looping_link"],
)
def test_target_on_a_symbolic_link_loop_fails_with_its_code(
    layout: ImportLayout,
    place_target: Callable[[ImportLayout], Path],
    failure_code: MigrationFailureCode,
) -> None:
    target = place_target(layout)
    manifest_path = write_standard_import(layout.inputs_dir)

    report = run_test_migration(manifest_path, target)

    assert report.failure is not None
    assert report.failure.code is failure_code


def test_input_under_a_symbolic_link_loop_fails_naming_its_declaration(
    layout: ImportLayout,
) -> None:
    looping_link = layout.inputs_dir / "loop"
    looping_link.symlink_to(looping_link)
    write_feed(layout.inputs_dir / V2_YEAR_FEED, build_v2_feed([build_v2_entry(1)]))
    manifest_path = write_inputs_manifest(
        layout.inputs_dir,
        [build_declaration(V2_YEAR_FEED), build_declaration(f"loop/{V2_YEAR_FEED}")],
    )

    report = run_test_migration(manifest_path, layout.target)

    assert report.failure is not None
    assert (report.failure.code, report.failure.manifest_index) == (
        MigrationFailureCode.INPUT_NOT_A_REGULAR_FILE,
        1,
    )


# Provenance in the store manifest and the anchors (§3)


@pytest.mark.parametrize(
    ("file_name", "feed", "generated_at"),
    [
        (
            V2_YEAR_FEED,
            build_v2_feed([build_v2_entry(1)]),
            datetime(2026, 10, 20, tzinfo=UTC),
        ),
        (
            V1_YEAR_FEED,
            build_v1_feed([build_v1_item(1)]),
            datetime(2026, 10, 20, tzinfo=UTC),
        ),
        (
            V2_YEAR_FEED,
            build_v2_feed([build_v2_entry(1)], timestamp="2026-10-20T01:02:03.1234567"),
            datetime(2026, 10, 20, 1, 2, 3, 123456, tzinfo=UTC),
        ),
        (
            V2_YEAR_FEED,
            build_v2_feed([build_v2_entry(1)], timestamp="2026-10-20T02:00:00+02:00"),
            datetime(2026, 10, 20, tzinfo=UTC),
        ),
    ],
    ids=["v2_without_offset", "v1_with_z", "v2_seven_fraction_digits", "v2_with_offset"],
)
def test_store_manifest_records_the_feed_generation_time_in_utc(
    layout: ImportLayout, file_name: str, feed: dict[str, Any], generated_at: datetime
) -> None:
    manifest_path = write_import(layout.inputs_dir, {file_name: feed})

    run_test_migration(manifest_path, layout.target)

    nvd_input = find_store_input(load_corpus_store(layout.target), StoreSource.NVD)
    assert nvd_input.source_generated_at == generated_at


@pytest.mark.parametrize(
    ("file_name", "container"),
    [
        ("nvdcve-2.0-2099.json", InputContainer.PLAIN),
        ("nvdcve-2.0-2099.json.gz", InputContainer.GZIP),
        ("nvdcve-2.0-2099.json.zip", InputContainer.ZIP),
    ],
    ids=["plain", "gzip", "zip"],
)
def test_store_manifest_records_the_container_and_both_hashes_of_an_nvd_input(
    layout: ImportLayout, file_name: str, container: InputContainer
) -> None:
    feed = build_v2_feed([build_v2_entry(1)])
    manifest_path = write_import(layout.inputs_dir, {file_name: feed})

    run_test_migration(manifest_path, layout.target)

    nvd_input = find_store_input(load_corpus_store(layout.target), StoreSource.NVD)
    payload_sha256 = sha256_hex(encode_feed(feed))
    assert (
        nvd_input.container,
        nvd_input.input_file_sha256,
        nvd_input.payload_sha256,
        nvd_input.source_version,
    ) == (
        container,
        sha256_hex((layout.inputs_dir / file_name).read_bytes()),
        payload_sha256,
        f"sha256:{payload_sha256}",
    )


def test_store_manifest_records_the_kev_input_by_its_file_hash_without_payload_or_time(
    layout: ImportLayout,
) -> None:
    manifest_path = write_standard_import(layout.inputs_dir)

    run_test_migration(manifest_path, layout.target)

    kev_input = find_store_input(load_corpus_store(layout.target), StoreSource.CISA_KEV)
    kev_file_sha256 = sha256_hex((layout.inputs_dir / KEV_FILE).read_bytes())
    assert (
        kev_input.input_file_sha256,
        kev_input.source_version,
        kev_input.payload_sha256,
        kev_input.source_generated_at,
    ) == (kev_file_sha256, f"sha256:{kev_file_sha256}", None, None)


def test_store_manifest_records_the_declared_retrieval_time_of_every_input(
    layout: ImportLayout,
) -> None:
    manifest_path = write_standard_import(layout.inputs_dir)

    run_test_migration(manifest_path, layout.target)

    retrieval_times: set[datetime] = set()
    for store_input in load_corpus_store(layout.target).manifest.inputs:
        retrieval_times.add(store_input.retrieved_at)
    assert retrieval_times == {datetime(2026, 10, 24, 8, 30, tzinfo=UTC)}


def test_anchors_carry_the_declared_retrieval_time(layout: ImportLayout) -> None:
    manifest_path = write_standard_import(layout.inputs_dir)

    run_test_migration(manifest_path, layout.target)

    retrieval_times: set[datetime] = set()
    for anchor in load_corpus_store(layout.target).evidence:
        retrieval_times.add(anchor.retrieved_at)
    assert retrieval_times == {datetime(2026, 10, 24, 8, 30, tzinfo=UTC)}


@pytest.mark.parametrize(
    ("source_type", "registry_name"),
    [(SourceType.NVD_API_2, "nvd"), (SourceType.CISA_KEV, "cisa-kev")],
    ids=["nvd", "cisa_kev"],
)
def test_anchors_cite_the_source_registry_terms_url(
    layout: ImportLayout, source_type: SourceType, registry_name: str
) -> None:
    manifest_path = write_standard_import(layout.inputs_dir)
    terms_url = load_packaged_source_registry().find_source(registry_name).terms_or_license_url

    run_test_migration(manifest_path, layout.target)

    anchor = find_anchor(load_corpus_store(layout.target), source_type, build_cve_id(2))
    assert anchor.license_or_terms_ref == terms_url


@pytest.mark.parametrize(
    "file_name",
    ["nvdcve-2.0-2099.json", "nvdcve-2.0-2099.json.gz", "nvdcve-2.0-2099.json.zip"],
    ids=["plain", "gzip", "zip"],
)
def test_nvd_anchor_cites_the_published_gzip_url_whatever_container_was_supplied(
    layout: ImportLayout, file_name: str
) -> None:
    manifest_path = write_import(layout.inputs_dir, {file_name: build_v2_feed([build_v2_entry(1)])})

    run_test_migration(manifest_path, layout.target)

    anchor = find_anchor(load_corpus_store(layout.target), SourceType.NVD_API_2, build_cve_id(1))
    assert anchor.source_uri == V2_YEAR_FEED_URI


def test_nvd_anchor_of_a_renamed_feed_cites_the_url_of_its_declared_artifact(
    layout: ImportLayout,
) -> None:
    write_gzip_feed(layout.inputs_dir / "renamed-feed.json.gz", build_v2_feed([build_v2_entry(1)]))
    manifest_path = write_inputs_manifest(
        layout.inputs_dir,
        [
            build_declaration(
                "renamed-feed.json.gz", artifact={"format": "2.0", "series": "modified"}
            )
        ],
    )

    run_test_migration(manifest_path, layout.target)

    anchor = find_anchor(load_corpus_store(layout.target), SourceType.NVD_API_2, build_cve_id(1))
    assert anchor.source_uri == V2_MODIFIED_FEED_URI


# The legacy root (§1)


def write_legacy_tree(legacy_root: Path) -> None:
    """Two pickles, an array, a model archive, an enhanced-documents export, a RAG export
    and a plain text file that is none of them."""
    (legacy_root / "models").mkdir(parents=True)
    (legacy_root / "rag_exports").mkdir()
    (legacy_root / "cache.pkl").write_bytes(b"\x80\x04\x95synthetic")
    (legacy_root / "models" / "unnamed").write_bytes(b"\x80\x05\x95synthetic")
    (legacy_root / "models" / "vectors.npy").write_bytes(b"\x93NUMPY\x01\x00synthetic")
    (legacy_root / "models" / "encoder.safetensors").write_bytes(b"synthetic weights")
    write_plain_feed(
        legacy_root / "enhanced_documents_2099.json",
        [{"document_type": "cve_summary", "cve_refs": ["CVE-9999-0001"], "content": "x"}],
    )
    write_plain_feed(
        legacy_root / "rag_exports" / "cve_documents_for_rag.json",
        [{"content": "SYNTHETIC text", "metadata": {"cve_id": "CVE-9999-0001"}}],
    )
    (legacy_root / "README.txt").write_text("synthetic legacy tree", encoding="utf-8")


def test_legacy_root_findings_are_reported_by_kind(tmp_path: Path, layout: ImportLayout) -> None:
    legacy_root = tmp_path / "legacy"
    write_legacy_tree(legacy_root)
    manifest_path = write_standard_import(layout.inputs_dir)
    expected_findings = dict.fromkeys(LegacyFileKind, 0)
    expected_findings[LegacyFileKind.PICKLE] = 2
    expected_findings[LegacyFileKind.NUMPY_ARRAY] = 1
    expected_findings[LegacyFileKind.MODEL_ARCHIVE] = 1
    expected_findings[LegacyFileKind.ENHANCED_DOCUMENTS] = 1
    expected_findings[LegacyFileKind.RAG_EXPORT] = 1

    report = run_test_migration(manifest_path, layout.target, legacy_root=legacy_root)

    assert report.legacy_root_findings == expected_findings


def test_legacy_root_is_left_with_its_content_and_modification_times(
    tmp_path: Path, layout: ImportLayout
) -> None:
    legacy_root = tmp_path / "legacy"
    write_legacy_tree(legacy_root)
    legacy_before = snapshot_tree(legacy_root)
    manifest_path = write_standard_import(layout.inputs_dir)

    run_test_migration(manifest_path, layout.target, legacy_root=legacy_root)

    assert snapshot_tree(legacy_root) == legacy_before


def test_legacy_root_files_are_never_imported(tmp_path: Path, layout: ImportLayout) -> None:
    legacy_root = tmp_path / "legacy"
    write_legacy_tree(legacy_root)
    manifest_path = write_standard_import(layout.inputs_dir)

    run_test_migration(manifest_path, layout.target, legacy_root=legacy_root)

    assert list_record_ids(load_corpus_store(layout.target)) == [build_cve_id(1), build_cve_id(2)]


def test_legacy_root_findings_cite_the_legacy_formats_commit(
    tmp_path: Path, layout: ImportLayout
) -> None:
    legacy_root = tmp_path / "legacy"
    write_legacy_tree(legacy_root)
    manifest_path = write_standard_import(layout.inputs_dir)

    report = run_test_migration(manifest_path, layout.target, legacy_root=legacy_root)

    assert report.legacy_formats_commit == "b64eef3"


def test_import_without_a_legacy_root_reports_no_findings_and_cites_no_commit(
    layout: ImportLayout,
) -> None:
    manifest_path = write_standard_import(layout.inputs_dir)

    report = run_test_migration(manifest_path, layout.target)

    assert (report.legacy_root_findings, report.legacy_formats_commit) == (None, None)


def name_a_missing_legacy_root(legacy_root: Path) -> Path:
    return legacy_root


def name_a_looping_legacy_root(legacy_root: Path) -> Path:
    legacy_root.symlink_to(legacy_root)
    return legacy_root


def name_a_legacy_root_under_a_looping_link(legacy_root: Path) -> Path:
    legacy_root.symlink_to(legacy_root)
    return legacy_root / "tree"


@pytest.mark.parametrize(
    "name_legacy_root",
    [
        name_a_missing_legacy_root,
        name_a_looping_legacy_root,
        name_a_legacy_root_under_a_looping_link,
    ],
    ids=["missing", "looping_link", "under_a_looping_link"],
)
def test_legacy_root_that_cannot_be_walked_fails_as_legacy_root_unreadable(
    tmp_path: Path, layout: ImportLayout, name_legacy_root: Callable[[Path], Path]
) -> None:
    legacy_root = name_legacy_root(tmp_path / "legacy")
    manifest_path = write_standard_import(layout.inputs_dir)

    report = run_test_migration(manifest_path, layout.target, legacy_root=legacy_root)

    assert report.failure is not None
    assert report.failure.code is MigrationFailureCode.LEGACY_ROOT_UNREADABLE


def test_legacy_root_deeper_than_the_walk_fails_a_dry_run_with_no_findings(
    tmp_path: Path, layout: ImportLayout
) -> None:
    legacy_root = tmp_path / "legacy"
    (legacy_root / "one" / "two" / "three").mkdir(parents=True)
    manifest_path = write_standard_import(layout.inputs_dir)

    report = run_test_migration(
        manifest_path,
        layout.target,
        legacy_root=legacy_root,
        is_dry_run=True,
        dependencies=build_migration_dependencies(MigrationLimits(max_walk_depth=2)),
    )

    assert report.failure is not None
    assert report.failure.code is MigrationFailureCode.LEGACY_ROOT_TOO_DEEP
    assert report.legacy_root_findings is None


def test_target_inside_the_legacy_root_fails_as_target_overlaps_input(
    tmp_path: Path, layout: ImportLayout
) -> None:
    legacy_root = tmp_path / "legacy"
    write_legacy_tree(legacy_root)
    manifest_path = write_standard_import(layout.inputs_dir)

    report = run_test_migration(manifest_path, legacy_root / "store", legacy_root=legacy_root)

    assert report.failure is not None
    assert report.failure.code is MigrationFailureCode.TARGET_OVERLAPS_INPUT


# Inputs rewritten while the run reads them (§1, §8)


def encode_feed_in_container(file_name: str, feed: dict[str, Any]) -> bytes:
    """The feed as the container its file name names holds it: gzip of stored blocks,
    whose length depends on the payload's length alone, or plain JSON."""
    payload_bytes = encode_feed(feed)
    if file_name.endswith(".gz"):
        return gzip.compress(payload_bytes, compresslevel=0, mtime=0)
    return payload_bytes


def rewrite_in_place(path: Path, replacement_bytes: bytes) -> None:
    """Overwrite the file through its own inode with bytes of the same length."""
    with path.open("r+b") as input_stream:
        input_stream.write(replacement_bytes)


@dataclass(frozen=True)
class RewritingFeedReader:
    """The real feed reader, which first rewrites the operator's file at ``path`` in
    place: the input changing while the run parses it."""

    read_nvd_feed: Callable[[PayloadStream, EntryHandler], FeedHeader]
    path: Path
    replacement_bytes: bytes

    def read(self, payload: PayloadStream, handle_entry: EntryHandler) -> FeedHeader:
        rewrite_in_place(self.path, self.replacement_bytes)
        return self.read_nvd_feed(payload, handle_entry)


@dataclass(frozen=True)
class RewritingClassifier:
    """The real JSON classifier, which first rewrites the operator's file at ``path`` in
    place. Every call writes the same bytes, so only the first one changes the file."""

    classify_json_prefix: Callable[[bytes], LegacyFileKind | None]
    path: Path
    replacement_bytes: bytes

    def classify(self, prefix: bytes) -> LegacyFileKind | None:
        rewrite_in_place(self.path, self.replacement_bytes)
        return self.classify_json_prefix(prefix)


def build_dependencies_rewriting_during_the_parse(
    path: Path, replacement_bytes: bytes
) -> MigrationDependencies:
    dependencies = build_migration_dependencies()
    feed_reader = RewritingFeedReader(dependencies.parsers.read_nvd_feed, path, replacement_bytes)
    parsers = dataclasses.replace(dependencies.parsers, read_nvd_feed=feed_reader.read)
    return dataclasses.replace(dependencies, parsers=parsers)


def build_dependencies_rewriting_at_each_classification(
    path: Path, replacement_bytes: bytes
) -> MigrationDependencies:
    dependencies = build_migration_dependencies()
    classifier = RewritingClassifier(
        dependencies.parsers.classify_json_prefix, path, replacement_bytes
    )
    parsers = dataclasses.replace(dependencies.parsers, classify_json_prefix=classifier.classify)
    return dataclasses.replace(dependencies, parsers=parsers)


def list_kev_anchor_versions(store: CorpusStore) -> list[tuple[str, str | None]]:
    """Each KEV anchor's CVE and source version, in the store's order."""
    kev_anchor_versions: list[tuple[str, str | None]] = []
    for anchor in store.evidence:
        if anchor.source_type is SourceType.CISA_KEV:
            kev_anchor_versions.append((anchor.authoritative_record_id, anchor.source_version))
    return kev_anchor_versions


@pytest.mark.parametrize("file_name", [V2_PLAIN_YEAR_FEED, V2_YEAR_FEED], ids=["plain", "gzip"])
def test_feed_rewritten_in_place_during_its_parse_is_imported_as_it_was_inspected(
    layout: ImportLayout, file_name: str
) -> None:
    original_feed = build_v2_feed([build_v2_entry(1, description=ORIGINAL_DESCRIPTION)])
    rewritten_feed = build_v2_feed([build_v2_entry(1, description=REWRITTEN_DESCRIPTION)])
    input_path = layout.inputs_dir / file_name
    original_bytes = encode_feed_in_container(file_name, original_feed)
    rewritten_bytes = encode_feed_in_container(file_name, rewritten_feed)
    input_path.write_bytes(original_bytes)
    manifest_path = write_inputs_manifest(layout.inputs_dir, [build_declaration(file_name)])
    dependencies = build_dependencies_rewriting_during_the_parse(input_path, rewritten_bytes)

    report = run_test_migration(manifest_path, layout.target, dependencies=dependencies)

    assert report.outcome is MigrationOutcome.IMPORTED
    # The operator's file did change, and the store never saw it.
    assert input_path.read_bytes() == rewritten_bytes
    store = load_corpus_store(layout.target)
    nvd_input = find_store_input(store, StoreSource.NVD)
    record = find_record(store, build_cve_id(1))
    assert (
        nvd_input.input_file_sha256,
        nvd_input.payload_sha256,
        record.descriptions[0].value,
    ) == (
        sha256_hex(original_bytes),
        sha256_hex(encode_feed(original_feed)),
        ORIGINAL_DESCRIPTION,
    )


def test_feed_rewritten_in_place_after_inspection_before_its_snapshot_fails_as_input_changed(
    tmp_path: Path, layout: ImportLayout
) -> None:
    # The legacy-root walk runs after the inputs are inspected and before any is copied,
    # and classifies the root's one JSON file; that first classification rewrites the feed.
    legacy_root = tmp_path / "legacy"
    legacy_root.mkdir()
    write_plain_feed(legacy_root / "notes.json", {"synthetic": True})
    original_feed = build_v2_feed([build_v2_entry(1, description=ORIGINAL_DESCRIPTION)])
    rewritten_feed = build_v2_feed([build_v2_entry(1, description=REWRITTEN_DESCRIPTION)])
    input_path = write_plain_feed(layout.inputs_dir / V2_PLAIN_YEAR_FEED, original_feed)
    manifest_path = write_inputs_manifest(
        layout.inputs_dir, [build_declaration(V2_PLAIN_YEAR_FEED)]
    )
    dependencies = build_dependencies_rewriting_at_each_classification(
        input_path, encode_feed(rewritten_feed)
    )

    report = run_test_migration(
        manifest_path, layout.target, legacy_root=legacy_root, dependencies=dependencies
    )

    assert report.failure is not None
    assert (report.failure.code, report.failure.input_position) == (
        MigrationFailureCode.INPUT_CHANGED,
        0,
    )
    assert list_names(layout.stores_dir) == []


def test_kev_catalog_over_its_cap_is_refused_before_it_is_copied(
    tmp_path: Path, layout: ImportLayout
) -> None:
    # The legacy-root walk runs before any input is copied and rewrites the catalog, so
    # had the catalog been copied before its cap was checked, the copy would have failed
    # as input_changed instead.
    legacy_root = tmp_path / "legacy"
    legacy_root.mkdir()
    write_plain_feed(legacy_root / "notes.json", {"synthetic": True})
    manifest_path = write_standard_import(layout.inputs_dir)
    kev_path = layout.inputs_dir / KEV_FILE
    kev_bytes = kev_path.read_bytes()
    dependencies = dataclasses.replace(
        build_dependencies_rewriting_at_each_classification(kev_path, kev_bytes[::-1]),
        limits=MigrationLimits(max_kev_bytes=len(kev_bytes) - 1),
    )

    report = run_test_migration(
        manifest_path, layout.target, legacy_root=legacy_root, dependencies=dependencies
    )

    assert report.failure is not None
    assert report.failure.code is MigrationFailureCode.KEV_TOO_LARGE


def test_failed_import_leaves_no_store_file_open(layout: ImportLayout) -> None:
    # The records file is open when the run finds nothing to import; an unclosed file
    # warns when it is collected.
    manifest_path = write_only_rejected_import(layout.inputs_dir)

    with warnings.catch_warnings(record=True) as caught_warnings:
        warnings.simplefilter("always", ResourceWarning)
        report = run_test_migration(manifest_path, layout.target)
        gc.collect()

    unclosed_file_warnings: list[warnings.WarningMessage] = []
    for caught_warning in caught_warnings:
        if issubclass(caught_warning.category, ResourceWarning):
            unclosed_file_warnings.append(caught_warning)
    assert report.failure is not None
    assert report.failure.code is MigrationFailureCode.NO_IMPORTABLE_RECORDS
    assert unclosed_file_warnings == []


def test_kev_catalog_rewritten_in_place_after_its_snapshot_is_imported_as_it_was_inspected(
    layout: ImportLayout,
) -> None:
    # Each input's snapshot is classified as a possible derived file before it is read.
    # The KEV catalog sorts first, so the first classification falls after its snapshot
    # is taken and before its rows are read; it rewrites the catalog to list another CVE.
    manifest_path = write_standard_import(layout.inputs_dir)
    kev_path = layout.inputs_dir / KEV_FILE
    original_kev_bytes = kev_path.read_bytes()
    dependencies = build_dependencies_rewriting_at_each_classification(
        kev_path, encode_kev_csv([build_kev_row(1)])
    )

    report = run_test_migration(manifest_path, layout.target, dependencies=dependencies)

    assert report.outcome is MigrationOutcome.IMPORTED
    assert list_kev_anchor_versions(load_corpus_store(layout.target)) == [
        (build_cve_id(2), "sha256:" + sha256_hex(original_kev_bytes))
    ]


@pytest.mark.parametrize(
    ("write_run_import", "is_dry_run", "expected_store_names"),
    [
        (write_standard_import, False, ["store"]),
        (write_standard_import, True, []),
        (write_api_page_import, False, []),
        (write_api_page_import, True, []),
    ],
    ids=["imported", "dry_run", "failed", "failed_dry_run"],
)
def test_run_leaves_no_copy_of_its_inputs_behind(
    layout: ImportLayout,
    system_temp_dir: Path,
    write_run_import: Callable[[Path], Path],
    is_dry_run: bool,
    expected_store_names: list[str],
) -> None:
    manifest_path = write_run_import(layout.inputs_dir)
    input_names = list_names(layout.inputs_dir)

    run_test_migration(manifest_path, layout.target, is_dry_run=is_dry_run)

    assert (
        list_names(layout.stores_dir),
        list_names(system_temp_dir),
        list_names(layout.inputs_dir),
    ) == (expected_store_names, [], input_names)


# Entries and feed fields as the reader meets them (§1, §7, §8)


def test_entry_without_a_cve_id_is_counted_with_its_locator_and_the_rest_imported(
    layout: ImportLayout,
) -> None:
    entry_without_id = build_v2_entry(2)
    del entry_without_id["cve"]["id"]
    manifest_path = write_import(
        layout.inputs_dir, {V2_YEAR_FEED: build_v2_feed([build_v2_entry(1), entry_without_id])}
    )

    report = run_test_migration(manifest_path, layout.target)

    assert report.skipped_entries == (
        EntryLocator(input_position=0, entry_index=1, code=NormalizationFailureCode.MISSING_FIELD),
    )
    assert list_record_ids(load_corpus_store(layout.target)) == [build_cve_id(1)]


def test_feed_declaring_its_format_after_its_entries_is_imported(layout: ImportLayout) -> None:
    feed_with_entries_first = {
        "vulnerabilities": [build_v2_entry(1)],
        "timestamp": "2026-10-20T00:00:00.000",
        "startIndex": 0,
        "totalResults": 1,
        "version": "2.0",
        "format": "NVD_CVE",
    }
    manifest_path = write_import(layout.inputs_dir, {V2_YEAR_FEED: feed_with_entries_first})

    report = run_test_migration(manifest_path, layout.target)

    assert report.outcome is MigrationOutcome.IMPORTED


# cve-kgrag migrate legacy (§7)

MANIFEST_MARKER = "manifest-marker-3f9a"
NO_SETTINGS: dict[str, str] = {}


def run_migrate_legacy_cli(manifest_path: Path, target: Path, *options: str) -> int:
    """``cve-kgrag migrate legacy`` with no settings from the environment the tests run in."""
    return main(
        ["migrate", "legacy", "--inputs", str(manifest_path), "--target", str(target), *options],
        NO_SETTINGS,
    )


def test_migrate_legacy_command_imports_and_prints_its_report_exiting_zero(
    layout: ImportLayout, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest_path = write_standard_import(layout.inputs_dir)

    exit_code = run_migrate_legacy_cli(manifest_path, layout.target)

    report = MigrationReport.model_validate_json(capsys.readouterr().out)
    assert (exit_code, report.outcome) == (0, MigrationOutcome.IMPORTED)
    assert list_record_ids(load_corpus_store(layout.target)) == [build_cve_id(1), build_cve_id(2)]


def test_migrate_legacy_command_rerun_reports_already_imported_exiting_zero(
    layout: ImportLayout, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest_path = write_standard_import(layout.inputs_dir)
    run_migrate_legacy_cli(manifest_path, layout.target)
    capsys.readouterr()

    exit_code = run_migrate_legacy_cli(manifest_path, layout.target)

    report = MigrationReport.model_validate_json(capsys.readouterr().out)
    assert (exit_code, report.outcome) == (0, MigrationOutcome.ALREADY_IMPORTED)


def test_migrate_legacy_command_dry_run_exits_zero_and_creates_no_target(
    layout: ImportLayout, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest_path = write_standard_import(layout.inputs_dir)

    exit_code = run_migrate_legacy_cli(manifest_path, layout.target, "--dry-run")

    report = MigrationReport.model_validate_json(capsys.readouterr().out)
    assert (exit_code, report.outcome) == (0, MigrationOutcome.DRY_RUN)
    assert list_names(layout.stores_dir) == []


def test_migrate_legacy_command_failed_import_exits_one_and_prints_its_report(
    layout: ImportLayout, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest_path = write_conflicting_kev_import(layout.inputs_dir)

    exit_code = run_migrate_legacy_cli(manifest_path, layout.target)

    report = MigrationReport.model_validate_json(capsys.readouterr().out)
    assert exit_code == 1
    assert report.failure is not None
    assert report.failure.code is MigrationFailureCode.KEV_CONFLICTING_ROWS
    assert list_names(layout.stores_dir) == []


def test_migrate_legacy_command_with_a_legacy_root_reports_its_findings(
    tmp_path: Path, layout: ImportLayout, capsys: pytest.CaptureFixture[str]
) -> None:
    legacy_root = tmp_path / "legacy"
    write_legacy_tree(legacy_root)
    manifest_path = write_standard_import(layout.inputs_dir)

    exit_code = run_migrate_legacy_cli(
        manifest_path, layout.target, "--legacy-root", str(legacy_root), "--dry-run"
    )

    report = MigrationReport.model_validate_json(capsys.readouterr().out)
    assert exit_code == 0
    assert report.legacy_root_findings is not None
    assert report.legacy_root_findings[LegacyFileKind.PICKLE] == 2


@pytest.mark.parametrize(
    "manifest_text",
    [
        f"format_version: 1\ninputs:\n  - {{source: {MANIFEST_MARKER}, path: a.json, "
        "retrieved_at: '2026-10-24T08:30:00Z'}\n",
        "format_version: 1\ninputs:\n  - {source: nvd, path: a.json, "
        f"retrieved_at: '{MANIFEST_MARKER}'}}\n",
        f"format_version: 1\ninputs:\n  - {{source: nvd, path: {MANIFEST_MARKER}.json, "
        "retrieved_at: '2026-10-24T08:30:00'}\n",
        f"format_version: 1\ninputs:\n  - {{source: nvd, path: {MANIFEST_MARKER}.json, "
        "retrieved_at: '2026-10-24T08:30:00Z', artifact: {format: 2.0, series: recent}}\n",
        f"format_version: 1\n{MANIFEST_MARKER}: 1\ninputs:\n  - {{source: nvd, path: a.json, "
        "retrieved_at: '2026-10-24T08:30:00Z'}\n",
        f"format_version: 1\ninputs:\n  - &{MANIFEST_MARKER} {{source: nvd, path: a.json, "
        f"retrieved_at: '2026-10-24T08:30:00Z'}}\n  - *{MANIFEST_MARKER}\n",
        f"format_version: 1\ninputs: [{MANIFEST_MARKER}\n",
        f"format_version: 2\ninputs:\n  - {{source: nvd, path: {MANIFEST_MARKER}.json, "
        "retrieved_at: '2026-10-24T08:30:00Z'}\n",
        f"format_version: 1\ninputs:\n  - {{source: cisa-kev, path: {MANIFEST_MARKER}.csv, "
        "retrieved_at: '2026-10-24T08:30:00Z'}\n  - {source: cisa-kev, path: b.csv, "
        "retrieved_at: '2026-10-24T08:30:00Z'}\n",
    ],
    ids=[
        "unknown_source",
        "retrieved_at_not_a_timestamp",
        "naive_retrieved_at",
        "artifact_format_a_number",
        "unknown_field",
        "yaml_alias",
        "not_yaml",
        "unknown_format_version",
        "two_kev_inputs",
    ],
)
def test_migrate_legacy_command_with_an_invalid_manifest_is_a_usage_error_never_quoting_it(
    layout: ImportLayout, capsys: pytest.CaptureFixture[str], manifest_text: str
) -> None:
    manifest_path = layout.inputs_dir / "inputs.yaml"
    manifest_path.write_text(manifest_text, encoding="utf-8")

    with pytest.raises(SystemExit) as raised:
        run_migrate_legacy_cli(manifest_path, layout.target)

    error_output = capsys.readouterr().err
    assert raised.value.code == 2
    assert "invalid input manifest: " in error_output
    assert MANIFEST_MARKER not in error_output


def test_migrate_legacy_command_with_an_invalid_manifest_creates_nothing(
    layout: ImportLayout,
) -> None:
    manifest_path = layout.inputs_dir / "inputs.yaml"
    manifest_path.write_text("format_version: 1\ninputs: []\n", encoding="utf-8")

    with pytest.raises(SystemExit):
        run_migrate_legacy_cli(manifest_path, layout.target)

    assert list_names(layout.stores_dir) == []


def test_migrate_legacy_command_with_an_unreadable_manifest_is_a_usage_error(
    layout: ImportLayout, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as raised:
        run_migrate_legacy_cli(layout.inputs_dir / "missing.yaml", layout.target)

    assert raised.value.code == 2
    assert "cannot read" in capsys.readouterr().err
