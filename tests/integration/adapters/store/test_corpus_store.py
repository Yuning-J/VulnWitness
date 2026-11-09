"""Proves the corpus store's write and read protocol (ADR 0008 §9): a store the importer
writes from a synthetic feed loads back whole, the writers reproduce it byte for byte
with mode 0644 whatever the umask, and both readers (``verify_corpus_store`` and
``load_corpus_store``) refuse every store that is not exactly what its manifest pins —
tampered or reordered lines, extra, missing or symlinked files, broken record-to-anchor
links, wrong counts and invalid manifests.

Every refused store except the raw-byte cases is written with ``StoreFileWriter`` and
``write_store_manifest``, so its files are correctly pinned and only the defect under
test remains."""

import errno
import functools
import json
import os
import shutil
import stat
import threading
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from operator import attrgetter
from pathlib import Path
from typing import Any, TypeVar

import pytest

from tests.support.builders import build_anchor
from tests.support.legacy_inputs import (
    build_declaration,
    build_kev_row,
    build_v2_entry,
    build_v2_feed,
    run_test_migration,
    write_gzip_feed,
    write_inputs_manifest,
    write_kev_csv,
)
from vulnwitness.adapters.store.corpus_store import (
    ANCHORS_FILE,
    MAX_STORE_MANIFEST_BYTES,
    PENDING_CNVD_FILE,
    RECORDS_FILE,
    STORE_MANIFEST_FILE,
    CorpusStore,
    CorpusStoreIntegrityError,
    StoreFileWriter,
    UnsupportedStoreFormatError,
    VerifiedStore,
    encode_line,
    load_corpus_store,
    verify_corpus_store,
    write_store_manifest,
)
from vulnwitness.domain.cnvd import CnvdIndex
from vulnwitness.domain.corpus_store_manifest import CorpusStoreManifest
from vulnwitness.domain.cve import CveRecord
from vulnwitness.domain.evidence import EvidenceAnchor
from vulnwitness.domain.hashing import sha256_hex
from vulnwitness.domain.migration_report import MigrationOutcome
from vulnwitness.domain.served_dataset import ServedDataset, ServedDatasetKind
from vulnwitness.domain.taxonomy import KnowledgeScope

KEV_SOURCE_NAME = "cisa_kev"
EMPTY_FILE_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
# Long enough for a reader that blocks on a FIFO to be told from one that returns at once.
BLOCKING_READ_TIMEOUT_SECONDS = 5
StoreReader = Callable[[Path], object]
ModelT = TypeVar("ModelT", CveRecord, EvidenceAnchor)


def build_content_identity(store_dir: Path) -> bytes:
    """The canonical JSON the corpus content digest is taken over, written out as ADR 0009
    §2 specifies it, from the bytes of the store's two files."""
    records_bytes = (store_dir / RECORDS_FILE).read_bytes()
    anchors_bytes = (store_dir / ANCHORS_FILE).read_bytes()
    pending_bytes = (store_dir / PENDING_CNVD_FILE).read_bytes()
    return (
        '{"files":['
        f'{{"role":"records","sha256":"{sha256_hex(records_bytes)}","size_bytes":{len(records_bytes)}}},'
        f'{{"role":"anchors","sha256":"{sha256_hex(anchors_bytes)}","size_bytes":{len(anchors_bytes)}}},'
        f'{{"role":"pending_cnvd","sha256":"{sha256_hex(pending_bytes)}","size_bytes":{len(pending_bytes)}}}'
        '],"identity_version":1}'
    ).encode()


@dataclass(frozen=True)
class StoreContents:
    """A store's manifest, records and anchors, parsed line by line from its files."""

    manifest: CorpusStoreManifest
    records: list[CveRecord]
    anchors: list[EvidenceAnchor]


def read_store_contents(store_dir: Path) -> StoreContents:
    manifest = CorpusStoreManifest.model_validate_json(
        (store_dir / STORE_MANIFEST_FILE).read_bytes()
    )
    records: list[CveRecord] = []
    for line in (store_dir / RECORDS_FILE).read_bytes().splitlines():
        records.append(CveRecord.model_validate_json(line))
    anchors: list[EvidenceAnchor] = []
    for line in (store_dir / ANCHORS_FILE).read_bytes().splitlines():
        anchors.append(EvidenceAnchor.model_validate_json(line))
    return StoreContents(manifest, records, anchors)


def write_store_lines(
    store_dir: Path,
    manifest: CorpusStoreManifest,
    record_lines: list[bytes],
    anchor_lines: list[bytes],
    count_offsets: tuple[int, int] = (0, 0),
) -> CorpusStoreManifest:
    """A store in the new ``store_dir`` holding the given lines, each file pinned by the
    writer; ``count_offsets`` are added to the record and anchor counts the manifest
    states. Its manifest."""
    store_dir.mkdir()
    records_writer = StoreFileWriter(store_dir, RECORDS_FILE)
    for line in record_lines:
        records_writer.write_line(line)
    records_file = records_writer.close()
    anchors_writer = StoreFileWriter(store_dir, ANCHORS_FILE)
    for line in anchor_lines:
        anchors_writer.write_line(line)
    anchors_file = anchors_writer.close()
    pending_file = StoreFileWriter(store_dir, PENDING_CNVD_FILE).close()
    record_offset, anchor_offset = count_offsets
    store_manifest = manifest.model_copy(
        update={
            "files": (anchors_file, records_file, pending_file),
            "record_count": records_writer.line_count + record_offset,
            "anchor_count": anchors_writer.line_count + anchor_offset,
        }
    )
    write_store_manifest(store_dir, store_manifest)
    return store_manifest


def write_store(
    store_dir: Path,
    manifest: CorpusStoreManifest,
    records: list[CveRecord],
    anchors: list[EvidenceAnchor],
    count_offsets: tuple[int, int] = (0, 0),
) -> CorpusStoreManifest:
    return write_store_lines(
        store_dir, manifest, encode_lines(records), encode_lines(anchors), count_offsets
    )


def encode_lines(models: Sequence[CveRecord | EvidenceAnchor]) -> list[bytes]:
    lines: list[bytes] = []
    for model in models:
        lines.append(encode_line(model))
    return lines


def select_at(models: list[ModelT], positions: tuple[int, ...]) -> list[ModelT]:
    """The models at ``positions``, in that order, repeats included."""
    selected: list[ModelT] = []
    for position in positions:
        selected.append(models[position])
    return selected


def find_kev_anchor(anchors: list[EvidenceAnchor]) -> EvidenceAnchor:
    for anchor in anchors:
        if anchor.source_name == KEV_SOURCE_NAME:
            return anchor
    raise AssertionError("the imported store holds no KEV anchor")


def list_without(anchors: list[EvidenceAnchor], removed: EvidenceAnchor) -> list[EvidenceAnchor]:
    remaining: list[EvidenceAnchor] = []
    for anchor in anchors:
        if anchor != removed:
            remaining.append(anchor)
    return remaining


def write_manifest_overrides(store_dir: Path, overrides: dict[str, Any]) -> None:
    manifest_path = store_dir / STORE_MANIFEST_FILE
    manifest_fields = json.loads(manifest_path.read_bytes())
    for field_name, value in overrides.items():
        manifest_fields[field_name] = value
    manifest_path.write_text(json.dumps(manifest_fields), encoding="utf-8")


@pytest.fixture
def imported_store(tmp_path: Path) -> Path:
    """A store the importer wrote from one 2.0 feed of two CVEs and a KEV catalog listing
    the first: two records and three anchors."""
    inputs_dir = tmp_path / "inputs"
    inputs_dir.mkdir()
    write_gzip_feed(
        inputs_dir / "nvdcve-2.0-2099.json.gz",
        build_v2_feed([build_v2_entry(1), build_v2_entry(2)]),
    )
    write_kev_csv(inputs_dir / "kev.csv", [build_kev_row(1)])
    manifest_path = write_inputs_manifest(
        inputs_dir,
        [
            build_declaration("nvdcve-2.0-2099.json.gz"),
            build_declaration("kev.csv", source="cisa-kev"),
        ],
    )
    store_dir = tmp_path / "store"
    report = run_test_migration(manifest_path, store_dir)
    assert report.outcome is MigrationOutcome.IMPORTED
    return store_dir


@pytest.fixture
def imported_contents(imported_store: Path) -> StoreContents:
    return read_store_contents(imported_store)


@pytest.fixture
def rewritten_dir(tmp_path: Path) -> Path:
    return tmp_path / "rewritten"


@pytest.fixture(params=[verify_corpus_store, load_corpus_store], ids=["verify", "load"])
def read_store(request: pytest.FixtureRequest) -> StoreReader:
    reader: StoreReader = request.param
    return reader


# --- Loading a valid store -------------------------------------------------------------


def test_imported_store_holds_two_records_and_three_anchors(
    imported_contents: StoreContents,
) -> None:
    # Act
    counts = (len(imported_contents.records), len(imported_contents.anchors))

    # Assert
    assert counts == (2, 3)


def test_load_corpus_store_returns_manifest_records_and_anchors_as_written(
    imported_store: Path, imported_contents: StoreContents
) -> None:
    # Act
    corpus_store = load_corpus_store(imported_store)

    # Assert
    assert corpus_store == CorpusStore(
        store_name=imported_store.name,
        manifest=imported_contents.manifest,
        store_manifest_sha256=sha256_hex((imported_store / STORE_MANIFEST_FILE).read_bytes()),
        corpus_content_sha256=sha256_hex(build_content_identity(imported_store)),
        records=tuple(imported_contents.records),
        evidence=tuple(imported_contents.anchors),
        cnvd_index=CnvdIndex(),
    )


def test_load_corpus_store_returns_records_in_cve_id_order(imported_store: Path) -> None:
    # Act
    corpus_store = load_corpus_store(imported_store)
    cve_ids: list[str] = []
    for record in corpus_store.records:
        cve_ids.append(record.cve_id)

    # Assert
    assert cve_ids == ["CVE-9999-0001", "CVE-9999-0002"]


def test_verify_corpus_store_returns_manifest_and_both_digests(
    imported_store: Path, imported_contents: StoreContents
) -> None:
    # Act
    verified_store = verify_corpus_store(imported_store)

    # Assert
    assert verified_store == VerifiedStore(
        manifest=imported_contents.manifest,
        store_manifest_sha256=sha256_hex((imported_store / STORE_MANIFEST_FILE).read_bytes()),
        corpus_content_sha256=sha256_hex(build_content_identity(imported_store)),
    )


def test_loaded_store_names_its_dataset_by_its_content_digest(imported_store: Path) -> None:
    # Act
    served_dataset = load_corpus_store(imported_store).describe_served_dataset()

    # Assert
    content_sha256 = sha256_hex(build_content_identity(imported_store))
    assert served_dataset == ServedDataset(
        kind=ServedDatasetKind.CORPUS_STORE,
        cve_search_version=f"corpus-store-v1@sha256:{content_sha256}",
    )


def test_stores_with_equal_files_and_other_manifests_serve_one_dataset(
    imported_contents: StoreContents, rewritten_dir: Path, tmp_path: Path
) -> None:
    # Arrange
    write_store(
        rewritten_dir,
        imported_contents.manifest,
        imported_contents.records,
        imported_contents.anchors,
    )
    other_manifest = imported_contents.manifest.model_copy(
        update={"importer_version": "9.9.9", "inputs_manifest_sha256": "f" * 64}
    )
    other_dir = tmp_path / "other"
    write_store(other_dir, other_manifest, imported_contents.records, imported_contents.anchors)

    # Act
    first_store = load_corpus_store(rewritten_dir)
    second_store = load_corpus_store(other_dir)

    # Assert
    assert first_store.store_manifest_sha256 != second_store.store_manifest_sha256
    assert first_store.describe_served_dataset() == second_store.describe_served_dataset()
    assert (first_store.records, first_store.evidence) == (
        second_store.records,
        second_store.evidence,
    )


def test_stores_whose_records_differ_serve_other_datasets(
    imported_contents: StoreContents, rewritten_dir: Path, tmp_path: Path
) -> None:
    # Arrange
    write_store(
        rewritten_dir,
        imported_contents.manifest,
        imported_contents.records,
        imported_contents.anchors,
    )
    first_record = imported_contents.records[0]
    edited_record = first_record.model_copy(update={"cwe_ids": ("CWE-79",)})
    other_dir = tmp_path / "other"
    write_store(
        other_dir,
        imported_contents.manifest,
        [edited_record, *imported_contents.records[1:]],
        imported_contents.anchors,
    )

    # Act
    first_dataset = load_corpus_store(rewritten_dir).describe_served_dataset()
    second_dataset = load_corpus_store(other_dir).describe_served_dataset()

    # Assert
    assert first_dataset != second_dataset


def test_store_written_with_store_writers_loads_back_unchanged(
    imported_contents: StoreContents, rewritten_dir: Path
) -> None:
    # Arrange
    manifest = write_store(
        rewritten_dir,
        imported_contents.manifest,
        imported_contents.records,
        imported_contents.anchors,
    )

    # Act
    corpus_store = load_corpus_store(rewritten_dir)

    # Assert
    assert corpus_store == CorpusStore(
        store_name=rewritten_dir.name,
        manifest=manifest,
        store_manifest_sha256=sha256_hex((rewritten_dir / STORE_MANIFEST_FILE).read_bytes()),
        corpus_content_sha256=sha256_hex(build_content_identity(rewritten_dir)),
        records=tuple(imported_contents.records),
        evidence=tuple(imported_contents.anchors),
        cnvd_index=CnvdIndex(),
    )


@pytest.mark.parametrize(
    "file_name",
    [RECORDS_FILE, ANCHORS_FILE, PENDING_CNVD_FILE, STORE_MANIFEST_FILE],
    ids=["records", "anchors", "pending", "manifest"],
)
def test_store_writers_reproduce_imported_store_byte_for_byte(
    imported_store: Path, imported_contents: StoreContents, rewritten_dir: Path, file_name: str
) -> None:
    # Arrange
    write_store(
        rewritten_dir,
        imported_contents.manifest,
        imported_contents.records,
        imported_contents.anchors,
    )

    # Act
    rewritten_bytes = (rewritten_dir / file_name).read_bytes()

    # Assert
    assert rewritten_bytes == (imported_store / file_name).read_bytes()


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


@pytest.mark.parametrize(
    "process_umask", [0o077, 0o000], indirect=True, ids=["umask_077", "umask_000"]
)
@pytest.mark.parametrize(
    "file_name",
    [RECORDS_FILE, ANCHORS_FILE, PENDING_CNVD_FILE, STORE_MANIFEST_FILE],
    ids=["records", "anchors", "pending", "manifest"],
)
def test_store_writers_create_files_with_mode_0644_whatever_the_umask(
    imported_contents: StoreContents, rewritten_dir: Path, process_umask: int, file_name: str
) -> None:
    # Arrange
    write_store(
        rewritten_dir,
        imported_contents.manifest,
        imported_contents.records,
        imported_contents.anchors,
    )

    # Act
    file_mode = stat.S_IMODE((rewritten_dir / file_name).stat().st_mode)

    # Assert
    assert file_mode == 0o644


def test_store_file_writer_refuses_to_overwrite_existing_file(imported_store: Path) -> None:
    # Arrange
    original_bytes = (imported_store / RECORDS_FILE).read_bytes()

    # Act
    with pytest.raises(FileExistsError):
        StoreFileWriter(imported_store, RECORDS_FILE)

    # Assert
    assert (imported_store / RECORDS_FILE).read_bytes() == original_bytes


# --- Refusals: the files on disk -------------------------------------------------------


@pytest.mark.parametrize(
    ("file_name", "original", "tampered"),
    [
        (
            RECORDS_FILE,
            b"democorp gateway mishandles",
            b"democorp Gateway mishandles",
        ),
        (
            ANCHORS_FILE,
            b'"excerpt":null,"inference_method":null',
            b'"inference_method":null,"excerpt":null',
        ),
    ],
    ids=["records", "anchors"],
)
def test_reading_store_with_tampered_bytes_of_same_size_is_refused(
    imported_store: Path,
    read_store: StoreReader,
    file_name: str,
    original: bytes,
    tampered: bytes,
) -> None:
    # Arrange
    store_file = imported_store / file_name
    store_file.write_bytes(store_file.read_bytes().replace(original, tampered, 1))

    # Act / Assert
    with pytest.raises(CorpusStoreIntegrityError, match="does not match its pinned SHA-256"):
        read_store(imported_store)


@pytest.mark.parametrize(
    "file_name",
    [RECORDS_FILE, ANCHORS_FILE],
    ids=["records", "anchors"],
)
def test_reading_store_with_appended_byte_is_refused(
    imported_store: Path, read_store: StoreReader, file_name: str
) -> None:
    # Arrange
    store_file = imported_store / file_name
    store_file.write_bytes(store_file.read_bytes() + b"\n")

    # Act / Assert
    with pytest.raises(CorpusStoreIntegrityError):
        read_store(imported_store)


@pytest.mark.parametrize(
    "file_name", ["notes.txt", ".hidden", "extra.jsonl"], ids=["text", "hidden", "jsonl"]
)
def test_reading_store_with_unpinned_extra_file_is_refused(
    imported_store: Path, read_store: StoreReader, file_name: str
) -> None:
    # Arrange
    (imported_store / file_name).write_bytes(b"{}\n")

    # Act / Assert
    with pytest.raises(CorpusStoreIntegrityError, match="does not pin"):
        read_store(imported_store)


@pytest.mark.parametrize(
    "file_name",
    [RECORDS_FILE, ANCHORS_FILE, PENDING_CNVD_FILE, STORE_MANIFEST_FILE],
    ids=["records", "anchors", "pending", "manifest"],
)
def test_reading_store_missing_file_is_refused(
    imported_store: Path, read_store: StoreReader, file_name: str
) -> None:
    # Arrange
    (imported_store / file_name).unlink()

    # Act / Assert
    with pytest.raises(CorpusStoreIntegrityError):
        read_store(imported_store)


def test_reading_store_with_subdirectory_is_refused(
    imported_store: Path, read_store: StoreReader
) -> None:
    # Arrange
    (imported_store / "nested").mkdir()

    # Act / Assert
    with pytest.raises(CorpusStoreIntegrityError, match="does not pin"):
        read_store(imported_store)


@pytest.mark.parametrize(
    "file_name",
    [RECORDS_FILE, ANCHORS_FILE, PENDING_CNVD_FILE, STORE_MANIFEST_FILE],
    ids=["records", "anchors", "pending", "manifest"],
)
def test_reading_store_with_directory_in_place_of_store_file_is_refused(
    imported_store: Path, read_store: StoreReader, file_name: str
) -> None:
    # Arrange
    (imported_store / file_name).unlink()
    (imported_store / file_name).mkdir()

    # Act / Assert
    with pytest.raises(CorpusStoreIntegrityError):
        read_store(imported_store)


@pytest.mark.parametrize(
    "file_name",
    [RECORDS_FILE, ANCHORS_FILE, PENDING_CNVD_FILE, STORE_MANIFEST_FILE],
    ids=["records", "anchors", "pending", "manifest"],
)
def test_reading_store_with_symlinked_file_is_refused(
    imported_store: Path, tmp_path: Path, read_store: StoreReader, file_name: str
) -> None:
    # Arrange
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    store_file = imported_store / file_name
    outside_file = outside_dir / file_name
    shutil.copyfile(store_file, outside_file)
    store_file.unlink()
    store_file.symlink_to(outside_file)

    # Act / Assert
    with pytest.raises(CorpusStoreIntegrityError):
        read_store(imported_store)


# --- Refusals: the lines and their links ----------------------------------------------


@pytest.mark.parametrize(
    "record_positions",
    [(1, 0), (0, 0, 1), (0, 1, 1)],
    ids=["reversed", "first_twice", "last_twice"],
)
def test_reading_store_with_records_out_of_order_is_refused(
    imported_contents: StoreContents,
    rewritten_dir: Path,
    read_store: StoreReader,
    record_positions: tuple[int, ...],
) -> None:
    # Arrange
    records = select_at(imported_contents.records, record_positions)
    write_store(rewritten_dir, imported_contents.manifest, records, imported_contents.anchors)

    # Act / Assert
    with pytest.raises(CorpusStoreIntegrityError, match="strict CVE ID order"):
        read_store(rewritten_dir)


@pytest.mark.parametrize(
    "anchor_positions",
    [(2, 1, 0), (0, 2, 1), (0, 0, 1, 2), (0, 1, 2, 2)],
    ids=["reversed", "last_two_swapped", "first_twice", "last_twice"],
)
def test_reading_store_with_anchors_out_of_order_is_refused(
    imported_contents: StoreContents,
    rewritten_dir: Path,
    read_store: StoreReader,
    anchor_positions: tuple[int, ...],
) -> None:
    # Arrange
    anchors = select_at(imported_contents.anchors, anchor_positions)
    write_store(rewritten_dir, imported_contents.manifest, imported_contents.records, anchors)

    # Act / Assert
    with pytest.raises(CorpusStoreIntegrityError, match="strict evidence ID order"):
        read_store(rewritten_dir)


def test_reading_store_with_record_citing_missing_anchor_is_refused(
    imported_contents: StoreContents, rewritten_dir: Path, read_store: StoreReader
) -> None:
    # Arrange
    kev_anchor = find_kev_anchor(imported_contents.anchors)
    anchors = list_without(imported_contents.anchors, kev_anchor)
    write_store(rewritten_dir, imported_contents.manifest, imported_contents.records, anchors)

    # Act / Assert
    with pytest.raises(CorpusStoreIntegrityError, match="cites an anchor the store lacks"):
        read_store(rewritten_dir)


def test_reading_store_with_record_citing_no_anchor_of_its_own_is_refused(
    imported_contents: StoreContents, rewritten_dir: Path, read_store: StoreReader
) -> None:
    # Arrange
    first_record, second_record = imported_contents.records
    borrowing_record = second_record.model_copy(
        update={"evidence_ids": (first_record.evidence_ids[0],)}
    )
    write_store(
        rewritten_dir,
        imported_contents.manifest,
        [first_record, borrowing_record],
        imported_contents.anchors,
    )

    # Act / Assert
    with pytest.raises(CorpusStoreIntegrityError, match="cites no anchor of its own"):
        read_store(rewritten_dir)


def test_reading_store_with_anchor_no_record_cites_is_refused(
    imported_contents: StoreContents, rewritten_dir: Path, read_store: StoreReader
) -> None:
    # Arrange
    first_record = imported_contents.records[0]
    write_store(
        rewritten_dir, imported_contents.manifest, [first_record], imported_contents.anchors
    )

    # Act / Assert
    with pytest.raises(
        CorpusStoreIntegrityError, match="an anchor no record or pending entry cites"
    ):
        read_store(rewritten_dir)


def sort_by_evidence_id(anchors: list[EvidenceAnchor]) -> list[EvidenceAnchor]:
    return sorted(anchors, key=attrgetter("evidence_id"))


@pytest.mark.parametrize(
    "scope",
    [KnowledgeScope.PROTOCOL_THREAT_CONTEXT, KnowledgeScope.UNKNOWN],
    ids=["protocol_threat_context", "unknown"],
)
def test_reading_store_with_record_citing_non_implementation_anchor_is_refused(
    imported_contents: StoreContents,
    rewritten_dir: Path,
    read_store: StoreReader,
    scope: KnowledgeScope,
) -> None:
    # Arrange
    context_anchor = build_anchor(authoritative_record_id="SYNTHETIC-CONTEXT-0001", scope=scope)
    first_record, second_record = imported_contents.records
    citing_record = first_record.model_copy(
        update={"evidence_ids": (*first_record.evidence_ids, context_anchor.evidence_id)}
    )
    anchors = sort_by_evidence_id([*imported_contents.anchors, context_anchor])
    write_store(rewritten_dir, imported_contents.manifest, [citing_record, second_record], anchors)

    # Act / Assert
    with pytest.raises(CorpusStoreIntegrityError, match="cites non-implementation evidence"):
        read_store(rewritten_dir)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("locator", "vulnerabilities/CVE-9999-0042"),
        ("content_sha256", "0" * 64),
        ("retrieved_at", "2026-10-24T09:30:00Z"),
    ],
    ids=["locator", "content_sha256", "retrieved_at"],
)
def test_reading_store_with_anchor_whose_evidence_id_does_not_rederive_is_refused(
    imported_contents: StoreContents,
    rewritten_dir: Path,
    read_store: StoreReader,
    field_name: str,
    value: str,
) -> None:
    # Arrange
    kev_anchor = find_kev_anchor(imported_contents.anchors)
    altered_fields = kev_anchor.model_dump(mode="json")
    altered_fields[field_name] = value
    altered_anchor = EvidenceAnchor.model_validate(altered_fields)
    anchors: list[EvidenceAnchor] = []
    for anchor in imported_contents.anchors:
        anchors.append(altered_anchor if anchor == kev_anchor else anchor)
    write_store(rewritten_dir, imported_contents.manifest, imported_contents.records, anchors)

    # Act / Assert
    with pytest.raises(CorpusStoreIntegrityError, match="breaks the anchor rules"):
        read_store(rewritten_dir)


@pytest.mark.parametrize(
    ("extra_record_lines", "extra_anchor_lines", "refusal"),
    [
        ([b"{}"], [], "a record line is not a CVE record"),
        ([b"not json"], [], "a record line is not a CVE record"),
        ([], [b"{}"], "an anchor line is not an evidence anchor"),
        ([], [b"not json"], "an anchor line is not an evidence anchor"),
    ],
    ids=["record_object", "record_text", "anchor_object", "anchor_text"],
)
def test_reading_store_with_line_that_is_not_its_model_is_refused(
    imported_contents: StoreContents,
    rewritten_dir: Path,
    read_store: StoreReader,
    extra_record_lines: list[bytes],
    extra_anchor_lines: list[bytes],
    refusal: str,
) -> None:
    # Arrange
    record_lines = encode_lines(imported_contents.records) + extra_record_lines
    anchor_lines = encode_lines(imported_contents.anchors) + extra_anchor_lines
    write_store_lines(rewritten_dir, imported_contents.manifest, record_lines, anchor_lines)

    # Act / Assert
    with pytest.raises(CorpusStoreIntegrityError, match=refusal):
        read_store(rewritten_dir)


@pytest.mark.parametrize(
    "count_offsets",
    [(1, 0), (-1, 0), (0, 1), (0, -1)],
    ids=["more_records", "fewer_records", "more_anchors", "fewer_anchors"],
)
def test_reading_store_whose_counts_differ_from_manifest_is_refused(
    imported_contents: StoreContents,
    rewritten_dir: Path,
    read_store: StoreReader,
    count_offsets: tuple[int, int],
) -> None:
    # Arrange
    write_store(
        rewritten_dir,
        imported_contents.manifest,
        imported_contents.records,
        imported_contents.anchors,
        count_offsets,
    )

    # Act / Assert
    with pytest.raises(CorpusStoreIntegrityError, match="counts differ"):
        read_store(rewritten_dir)


# --- Refusals: the manifest ------------------------------------------------------------


@pytest.mark.parametrize(
    "manifest_bytes",
    [b"", b"{", b"[]", b"null", b"[" * 200_000],
    ids=["empty", "truncated", "array", "null", "nested_past_the_recursion_limit"],
)
def test_reading_store_whose_manifest_is_not_json_object_is_refused(
    imported_store: Path, read_store: StoreReader, manifest_bytes: bytes
) -> None:
    # Arrange
    (imported_store / STORE_MANIFEST_FILE).write_bytes(manifest_bytes)

    # Act / Assert
    with pytest.raises(CorpusStoreIntegrityError, match="not a corpus store manifest"):
        read_store(imported_store)


@pytest.mark.parametrize(
    "overrides",
    [
        {"synthetic": True},
        {"unexpected_field": 1},
        {"store_format_version": None},
        {"store_format_version": "1"},
        {"store_format_version": 1.5},
        {"store_format_version": True},
        {"schema_version": "2.0.0-beta"},
        {"schema_version": "2.0.0-dev.26\n"},
        {"schema_version": "1" * 31 + ".0.0"},
        {"schema_version": None},
        {"rollback_instruction": ""},
        {"rollback_instruction": "x" * 513},
        {"rollback_instruction": "Delete the \u202edirectory."},
        {"rollback_instruction": "Delete the directory.\n"},
        {"rollback_kind": "repair_in_place"},
        {"record_count": 0},
        {"files": []},
        {"inputs": []},
        {"import_identity_sha256": "not-a-hash"},
    ],
    ids=[
        "synthetic",
        "unknown_field",
        "store_format_version_null",
        "store_format_version_string",
        "store_format_version_fraction",
        "store_format_version_boolean",
        "schema_version_not_a_contract_version",
        "schema_version_with_a_newline",
        "schema_version_too_long",
        "schema_version_null",
        "rollback_instruction_empty",
        "rollback_instruction_too_long",
        "rollback_instruction_with_a_bidirectional_override",
        "rollback_instruction_with_a_newline",
        "rollback_kind",
        "zero_records",
        "no_files",
        "no_inputs",
        "identity_not_sha256",
    ],
)
def test_reading_store_with_invalid_manifest_field_is_refused(
    imported_store: Path, read_store: StoreReader, overrides: dict[str, Any]
) -> None:
    # Arrange
    write_manifest_overrides(imported_store, overrides)

    # Act / Assert
    with pytest.raises(CorpusStoreIntegrityError, match="not a corpus store manifest"):
        read_store(imported_store)


@pytest.mark.parametrize(
    "overrides",
    [
        {"schema_version": "2.0.0-dev.25"},
        {"schema_version": "3.1.4"},
        {"rollback_instruction": "Delete the directory."},
        {"rollback_instruction": "x" * 512},
    ],
    ids=[
        "earlier_contract_version",
        "later_release_version",
        "other_instruction",
        "longest_instruction",
    ],
)
def test_reading_store_never_compares_its_provenance_with_this_release(
    imported_store: Path, overrides: dict[str, Any]
) -> None:
    # Arrange
    write_manifest_overrides(imported_store, overrides)

    # Act
    manifest = load_corpus_store(imported_store).manifest

    # Assert
    for field_name, value in overrides.items():
        assert getattr(manifest, field_name) == value


def test_reading_store_without_a_format_version_is_refused_as_invalid(
    imported_store: Path, read_store: StoreReader
) -> None:
    # Arrange
    manifest_fields = json.loads((imported_store / STORE_MANIFEST_FILE).read_bytes())
    del manifest_fields["store_format_version"]
    (imported_store / STORE_MANIFEST_FILE).write_text(json.dumps(manifest_fields))

    # Act / Assert
    with pytest.raises(CorpusStoreIntegrityError, match="not a corpus store manifest"):
        read_store(imported_store)


@pytest.mark.parametrize("format_version", [0, 4, 10**30], ids=["zero", "next", "huge"])
def test_reading_store_of_another_format_version_is_refused_as_unsupported(
    imported_store: Path, read_store: StoreReader, format_version: int
) -> None:
    # Arrange: a later format may change any other field, which this reader must not judge.
    write_manifest_overrides(
        imported_store, {"store_format_version": format_version, "records_layout": "v2"}
    )

    # Act / Assert
    with pytest.raises(UnsupportedStoreFormatError):
        read_store(imported_store)


@pytest.mark.parametrize(
    "pinned_path",
    ["../anchors.jsonl", "/tmp/anchors.jsonl", "nested/anchors.jsonl", "Anchors.jsonl"],
    ids=["parent", "absolute", "nested", "uppercase"],
)
def test_reading_store_whose_manifest_pins_path_outside_store_names_is_refused(
    imported_store: Path, read_store: StoreReader, pinned_path: str
) -> None:
    # Arrange
    manifest_fields = json.loads((imported_store / STORE_MANIFEST_FILE).read_bytes())
    pinned_files: list[dict[str, Any]] = []
    for pinned_file in manifest_fields["files"]:
        if pinned_file["path"] == ANCHORS_FILE:
            pinned_file["path"] = pinned_path
        pinned_files.append(pinned_file)
    write_manifest_overrides(imported_store, {"files": pinned_files})

    # Act / Assert
    with pytest.raises(CorpusStoreIntegrityError, match="not a corpus store manifest"):
        read_store(imported_store)


def test_reading_store_whose_manifest_pins_file_other_than_store_files_is_refused(
    imported_store: Path, read_store: StoreReader
) -> None:
    # Arrange
    (imported_store / "extra.jsonl").write_bytes(b"")
    manifest_fields = json.loads((imported_store / STORE_MANIFEST_FILE).read_bytes())
    pinned_files = [
        *manifest_fields["files"],
        {"path": "extra.jsonl", "sha256": EMPTY_FILE_SHA256, "size_bytes": 0},
    ]
    write_manifest_overrides(imported_store, {"files": pinned_files})

    # Act / Assert
    with pytest.raises(CorpusStoreIntegrityError, match="pins other files"):
        read_store(imported_store)


def test_reading_store_whose_manifest_pins_store_file_twice_is_refused(
    imported_store: Path, read_store: StoreReader
) -> None:
    # Arrange
    manifest_fields = json.loads((imported_store / STORE_MANIFEST_FILE).read_bytes())
    conflicting_pin = {"path": RECORDS_FILE, "sha256": "0" * 64, "size_bytes": 1}
    pinned_files = [*manifest_fields["files"], conflicting_pin]
    write_manifest_overrides(imported_store, {"files": pinned_files})

    # Act / Assert
    with pytest.raises(CorpusStoreIntegrityError):
        read_store(imported_store)


class RecordedRead:
    """A store read run on another thread, recording the exception it raised, if any, and
    whether it returned at all."""

    def __init__(self, read: Callable[[], object]) -> None:
        self._read = read
        self.raised: BaseException | None = None
        self.has_finished = False

    def __call__(self) -> None:
        try:
            self._read()
        except BaseException as error:
            # Handed to the test thread, which asserts on it.
            self.raised = error
        self.has_finished = True


def run_on_daemon_thread(read: Callable[[], object]) -> RecordedRead:
    """``read`` run on a daemon thread, waited on for at most the blocking-read timeout, so
    a reader blocked on a FIFO fails the test instead of hanging the run."""
    recorded_read = RecordedRead(read)
    reading_thread = threading.Thread(target=recorded_read, daemon=True)
    reading_thread.start()
    reading_thread.join(timeout=BLOCKING_READ_TIMEOUT_SECONDS)
    return recorded_read


def release_fifo_reader(fifo_path: Path) -> None:
    """Open the FIFO for writing and close it, which releases a reader blocked opening it;
    with no reader waiting there is nothing to release."""
    try:
        writer_descriptor = os.open(fifo_path, os.O_WRONLY | os.O_NONBLOCK)
    except OSError as error:
        if error.errno != errno.ENXIO:
            raise
        return
    os.close(writer_descriptor)


@pytest.fixture(
    params=[RECORDS_FILE, ANCHORS_FILE, PENDING_CNVD_FILE], ids=["records", "anchors", "pending"]
)
def store_with_fifo(imported_store: Path, request: pytest.FixtureRequest) -> Iterator[Path]:
    """The imported store with a FIFO in place of one of its files; a reader left blocked
    on it is released afterwards."""
    fifo_path = imported_store / request.param
    fifo_path.unlink()
    os.mkfifo(fifo_path)
    try:
        yield imported_store
    finally:
        release_fifo_reader(fifo_path)


def test_reading_store_with_fifo_in_place_of_store_file_is_refused_at_once(
    store_with_fifo: Path, read_store: StoreReader
) -> None:
    # Arrange
    read = functools.partial(read_store, store_with_fifo)

    # Act
    recorded_read = run_on_daemon_thread(read)

    # Assert
    assert recorded_read.has_finished
    assert isinstance(recorded_read.raised, CorpusStoreIntegrityError)


# --- Refusals: sizes -----------------------------------------------------------------------


def write_pinned_size(store_dir: Path, file_name: str, size_bytes: int) -> None:
    """Pin ``file_name`` at ``size_bytes`` in the manifest, its SHA-256 left as it is."""
    manifest_fields = json.loads((store_dir / STORE_MANIFEST_FILE).read_bytes())
    pinned_files: list[dict[str, Any]] = []
    for pinned_file in manifest_fields["files"]:
        if pinned_file["path"] == file_name:
            pinned_file["size_bytes"] = size_bytes
        pinned_files.append(pinned_file)
    write_manifest_overrides(store_dir, {"files": pinned_files})


@pytest.mark.parametrize("file_name", [RECORDS_FILE, ANCHORS_FILE], ids=["records", "anchors"])
def test_reading_store_whose_manifest_pins_one_byte_more_than_file_holds_is_refused(
    imported_store: Path, read_store: StoreReader, file_name: str
) -> None:
    # Arrange
    real_size = (imported_store / file_name).stat().st_size
    write_pinned_size(imported_store, file_name, real_size + 1)

    # Act / Assert
    with pytest.raises(CorpusStoreIntegrityError, match="does not match its pinned size"):
        read_store(imported_store)


@pytest.mark.parametrize("file_name", [RECORDS_FILE, ANCHORS_FILE], ids=["records", "anchors"])
def test_reading_store_file_larger_than_pinned_is_refused_before_any_line_is_read(
    imported_store: Path, read_store: StoreReader, file_name: str
) -> None:
    """The appended line is no model: read, it would be refused as such instead."""
    # Arrange
    store_file = imported_store / file_name
    store_file.write_bytes(store_file.read_bytes() + b"not json\n")

    # Act / Assert
    with pytest.raises(CorpusStoreIntegrityError, match="does not match its pinned size"):
        read_store(imported_store)


def pad_manifest(store_dir: Path, padded_size: int) -> None:
    """Pad ``manifest.json`` with trailing whitespace to ``padded_size`` bytes; it stays
    the same JSON document."""
    manifest_path = store_dir / STORE_MANIFEST_FILE
    manifest_bytes = manifest_path.read_bytes()
    manifest_path.write_bytes(manifest_bytes + b" " * (padded_size - len(manifest_bytes)))


def test_reading_store_whose_manifest_is_over_its_cap_is_refused(
    imported_store: Path, read_store: StoreReader
) -> None:
    # Arrange
    pad_manifest(imported_store, MAX_STORE_MANIFEST_BYTES + 1)

    # Act / Assert
    with pytest.raises(CorpusStoreIntegrityError, match="larger than a store manifest"):
        read_store(imported_store)


def test_verify_corpus_store_whose_manifest_is_exactly_at_its_cap_passes(
    imported_store: Path, imported_contents: StoreContents
) -> None:
    # Arrange
    pad_manifest(imported_store, MAX_STORE_MANIFEST_BYTES)

    # Act
    verified_store = verify_corpus_store(imported_store)

    # Assert
    assert verified_store.manifest == imported_contents.manifest
