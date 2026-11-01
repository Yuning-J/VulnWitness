"""Write and read a corpus store: ``manifest.json`` and the JSON Lines files it pins
(ADR 0008 §9).

Every record and anchor is one line of canonical JSON, records in CVE ID order and
anchors in evidence ID order. Reading a store fails closed: the directory holds exactly
the manifest and the files it pins, each matching its SHA-256 and size; every anchor's
ID re-derives from its fields; every record cites its own CVE anchor and only anchors the
store holds; no anchor is left uncited. A store is read as untrusted input, so the
manifest and every line are read within a cap and a file's size is checked before its
lines are. ``verify_corpus_store`` checks a store keeping only an index of anchor IDs in
memory; ``load_corpus_store`` also keeps every record and anchor, for serving.

A store has three identities (ADR 0009 §2): the SHA-256 of the manifest bytes the reader
parsed names the physical store; the manifest's import identity names the import; and the
corpus content digest, derived from the records' and anchors' pins once both files match
them, names the dataset served.
"""

import hashlib
import json
import os
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from pydantic import ValidationError

from cve_kgrag.adapters.regular_files import open_regular_file
from cve_kgrag.domain.corpus_store_manifest import (
    STORE_FORMAT_VERSION,
    CorpusStoreManifest,
    StoreFile,
    derive_corpus_content_sha256,
    name_corpus_store_version,
)
from cve_kgrag.domain.cve import CveRecord
from cve_kgrag.domain.evidence import EvidenceAnchor
from cve_kgrag.domain.hashing import canonical_json_bytes, sha256_hex
from cve_kgrag.domain.served_dataset import ServedDataset, ServedDatasetKind
from cve_kgrag.domain.session_record import SessionCorpusIdentity
from cve_kgrag.domain.taxonomy import KnowledgeScope
from cve_kgrag.domain.validation import find_anchor_violations

STORE_MANIFEST_FILE = "manifest.json"
RECORDS_FILE = "records.jsonl"
ANCHORS_FILE = "anchors.jsonl"
# Every store has the same modes whatever the umask of the run that wrote it: readable by
# every user, so by the server whichever user runs it, and writable only by its owner.
STORE_FILE_MODE = 0o644
STORE_DIR_MODE = 0o755
# A manifest of the most inputs an import takes is far smaller; a record or anchor line,
# built from an entry within the importer's 16 MiB cap, too.
MAX_STORE_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_STORE_LINE_BYTES = 64 * 1024 * 1024


class CorpusStoreIntegrityError(ValueError):
    """The store fails verification; nothing in it may be served."""


class UnsupportedStoreFormatError(CorpusStoreIntegrityError):
    """The manifest declares a store format version this release does not read, such as
    one a later release wrote."""


@dataclass(frozen=True)
class ParsedStoreManifest:
    """A store's manifest and the SHA-256 of the very bytes it was parsed from."""

    manifest: CorpusStoreManifest
    store_manifest_sha256: str


@dataclass(frozen=True)
class VerifiedStore:
    """What one verification of a store found: its manifest, the digest of the manifest
    bytes it read, and the content digest of the records and anchors it checked."""

    manifest: CorpusStoreManifest
    store_manifest_sha256: str
    corpus_content_sha256: str


@dataclass(frozen=True)
class CorpusStore:
    """A verified store's records and evidence, for serving."""

    manifest: CorpusStoreManifest
    store_manifest_sha256: str
    corpus_content_sha256: str
    records: tuple[CveRecord, ...]
    evidence: tuple[EvidenceAnchor, ...]

    store_name: str

    def describe_session_corpus(self) -> SessionCorpusIdentity:
        return SessionCorpusIdentity(
            served=self.describe_served_dataset(),
            store_name=self.store_name,
            store_manifest_sha256=self.store_manifest_sha256,
            corpus_content_sha256=self.corpus_content_sha256,
        )

    def describe_served_dataset(self) -> ServedDataset:
        return ServedDataset(
            kind=ServedDatasetKind.CORPUS_STORE,
            cve_search_version=name_corpus_store_version(self.corpus_content_sha256),
        )


def create_store_file(path: Path) -> IO[bytes]:
    """A new store file at ``path``, open for writing, with ``STORE_FILE_MODE`` set
    explicitly: the mode ``os.open`` takes is narrowed by the umask."""
    file_descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, STORE_FILE_MODE)
    try:
        os.fchmod(file_descriptor, STORE_FILE_MODE)
    except BaseException:
        os.close(file_descriptor)
        raise
    return os.fdopen(file_descriptor, "wb")


class StoreFileWriter:
    """A new store file, written line by line, hashed as written and synced on close."""

    def __init__(self, store_dir: Path, file_name: str) -> None:
        self.store_dir = store_dir
        self._file_name = file_name
        self._stream: IO[bytes] = create_store_file(store_dir / file_name)
        self._digest = hashlib.sha256()
        self._size_bytes = 0
        self.line_count = 0

    def write_line(self, line: bytes) -> None:
        content = line + b"\n"
        self._stream.write(content)
        self._digest.update(content)
        self._size_bytes += len(content)
        self.line_count += 1

    def discard(self) -> None:
        """Close the file without syncing it, for a store that will not be published."""
        self._stream.close()

    def close(self) -> StoreFile:
        """Sync and close the file; what the manifest pins of it."""
        self._stream.flush()
        os.fsync(self._stream.fileno())
        self._stream.close()
        return StoreFile(
            path=self._file_name, sha256=self._digest.hexdigest(), size_bytes=self._size_bytes
        )


def encode_line(model: CveRecord | EvidenceAnchor) -> bytes:
    return canonical_json_bytes(model.model_dump(mode="json"))


def write_store_manifest(store_dir: Path, manifest: CorpusStoreManifest) -> bytes:
    """Write ``manifest.json`` as canonical JSON, synced; its bytes."""
    manifest_bytes = canonical_json_bytes(manifest.model_dump(mode="json"))
    with create_store_file(store_dir / STORE_MANIFEST_FILE) as manifest_stream:
        manifest_stream.write(manifest_bytes)
        manifest_stream.flush()
        os.fsync(manifest_stream.fileno())
    return manifest_bytes


def sync_directory(directory: Path) -> None:
    directory_descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def publish_store_directory(store_dir: Path, target: Path) -> None:
    """Rename the written store to ``target`` and sync the rename. The target's parent is
    opened first, so a parent that cannot be synced fails before the store appears."""
    os.chmod(store_dir, STORE_DIR_MODE)
    parent_descriptor = os.open(target.parent, os.O_RDONLY)
    try:
        os.rename(store_dir, target)
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)


def open_store_file(path: Path) -> IO[bytes]:
    """The store file, which must be a regular file (``open_regular_file``)."""
    try:
        return open_regular_file(path)
    except OSError as error:
        raise CorpusStoreIntegrityError(f"{path.name} is not a readable regular file") from error


def read_manifest_bytes(store_dir: Path) -> bytes:
    """The bytes of the store's ``manifest.json``, refused past its cap."""
    with open_store_file(store_dir / STORE_MANIFEST_FILE) as manifest_stream:
        manifest_bytes = manifest_stream.read(MAX_STORE_MANIFEST_BYTES + 1)
    if len(manifest_bytes) > MAX_STORE_MANIFEST_BYTES:
        raise CorpusStoreIntegrityError("manifest.json is larger than a store manifest")
    return manifest_bytes


def check_store_format(manifest_bytes: bytes) -> None:
    """Refuse a manifest whose ``store_format_version`` is an integer other than the one
    this release reads, before the rest of it is parsed against this release's model, and
    one whose format version is missing or not an integer (``true`` included, which the
    model's literal would take for 1)."""
    try:
        manifest_document = json.loads(manifest_bytes)
    # json.loads recurses per nesting level: a deeply nested manifest within the cap
    # raises RecursionError, which is as much a malformed manifest as a syntax error.
    except (ValueError, RecursionError) as error:
        raise CorpusStoreIntegrityError("manifest.json is not a corpus store manifest") from error
    if not isinstance(manifest_document, dict):
        raise CorpusStoreIntegrityError("manifest.json is not a corpus store manifest")
    format_version = manifest_document.get("store_format_version")
    is_integer = isinstance(format_version, int) and not isinstance(format_version, bool)
    if not is_integer:
        raise CorpusStoreIntegrityError("manifest.json is not a corpus store manifest")
    if format_version != STORE_FORMAT_VERSION:
        raise UnsupportedStoreFormatError(
            "the store's format version is not one this release reads"
        )


def read_store_manifest(store_dir: Path) -> ParsedStoreManifest:
    """The store's ``manifest.json``, parsed, with the SHA-256 of the bytes parsed, without
    checking the store's files. Every reader of a manifest goes through this one read, so
    no digest is taken over bytes other than those parsed."""
    manifest_bytes = read_manifest_bytes(store_dir)
    check_store_format(manifest_bytes)
    try:
        manifest = CorpusStoreManifest.model_validate_json(manifest_bytes)
    except ValidationError as error:
        raise CorpusStoreIntegrityError("manifest.json is not a corpus store manifest") from error
    return ParsedStoreManifest(manifest=manifest, store_manifest_sha256=sha256_hex(manifest_bytes))


def check_store_entries(store_dir: Path, manifest: CorpusStoreManifest) -> None:
    """The directory holds the manifest and the files it pins, and nothing else."""
    expected_names = {STORE_MANIFEST_FILE}
    for store_file in manifest.files:
        expected_names.add(store_file.path)
    found_names: set[str] = set()
    for entry in os.scandir(store_dir):
        found_names.add(entry.name)
    if found_names != expected_names:
        raise CorpusStoreIntegrityError("the store holds files its manifest does not pin")
    if {RECORDS_FILE, ANCHORS_FILE} != expected_names - {STORE_MANIFEST_FILE}:
        raise CorpusStoreIntegrityError("the manifest pins other files than a store's")


def read_pinned_lines(store_dir: Path, store_file: StoreFile) -> Iterator[bytes]:
    """The file's lines, checked against its pinned size before any is read and against
    its pinned SHA-256 and size once all are. A line past ``MAX_STORE_LINE_BYTES`` is
    refused as it is read. The file name is one the manifest pattern allows, so it never
    leaves the store."""
    digest = hashlib.sha256()
    size_bytes = 0
    with open_store_file(store_dir / store_file.path) as file_stream:
        if os.fstat(file_stream.fileno()).st_size != store_file.size_bytes:
            raise CorpusStoreIntegrityError(f"{store_file.path} does not match its pinned size")
        line = file_stream.readline(MAX_STORE_LINE_BYTES + 1)
        while line:
            if len(line) > MAX_STORE_LINE_BYTES:
                raise CorpusStoreIntegrityError(f"{store_file.path} holds an overlong line")
            digest.update(line)
            size_bytes += len(line)
            yield line.rstrip(b"\n")
            line = file_stream.readline(MAX_STORE_LINE_BYTES + 1)
    if size_bytes != store_file.size_bytes or digest.hexdigest() != store_file.sha256:
        raise CorpusStoreIntegrityError(f"{store_file.path} does not match its pinned SHA-256")


def find_store_file(manifest: CorpusStoreManifest, file_name: str) -> StoreFile:
    for store_file in manifest.files:
        if store_file.path == file_name:
            return store_file
    raise CorpusStoreIntegrityError(f"the manifest does not pin {file_name}")


@dataclass(frozen=True)
class IndexedAnchor:
    scope: KnowledgeScope
    authoritative_record_id: str


def verify_store_files(
    store_dir: Path,
    keep_anchor: Callable[[EvidenceAnchor], None],
    keep_record: Callable[[CveRecord], None],
) -> VerifiedStore:
    """Verify the store, handing each anchor and record to the callbacks as it is read."""
    parsed_manifest = read_store_manifest(store_dir)
    manifest = parsed_manifest.manifest
    check_store_entries(store_dir, manifest)
    anchors_file = find_store_file(manifest, ANCHORS_FILE)
    records_file = find_store_file(manifest, RECORDS_FILE)
    anchors_by_id: dict[str, IndexedAnchor] = {}
    previous_evidence_id = ""
    for line in read_pinned_lines(store_dir, anchors_file):
        try:
            anchor = EvidenceAnchor.model_validate_json(line)
        except ValidationError as error:
            raise CorpusStoreIntegrityError("an anchor line is not an evidence anchor") from error
        if anchor.evidence_id <= previous_evidence_id:
            raise CorpusStoreIntegrityError("anchors are not in strict evidence ID order")
        previous_evidence_id = anchor.evidence_id
        if find_anchor_violations((anchor,)):
            raise CorpusStoreIntegrityError(f"{anchor.evidence_id} breaks the anchor rules")
        anchors_by_id[anchor.evidence_id] = IndexedAnchor(
            anchor.scope, anchor.authoritative_record_id
        )
        keep_anchor(anchor)
    cited_evidence_ids: set[str] = set()
    previous_cve_id = ""
    record_count = 0
    for line in read_pinned_lines(store_dir, records_file):
        try:
            record = CveRecord.model_validate_json(line)
        except ValidationError as error:
            raise CorpusStoreIntegrityError("a record line is not a CVE record") from error
        if record.cve_id <= previous_cve_id:
            raise CorpusStoreIntegrityError("records are not in strict CVE ID order")
        previous_cve_id = record.cve_id
        check_record_evidence(record, anchors_by_id)
        cited_evidence_ids.update(record.evidence_ids)
        record_count += 1
        keep_record(record)
    if cited_evidence_ids != set(anchors_by_id):
        raise CorpusStoreIntegrityError("the store holds an anchor no record cites")
    if record_count != manifest.record_count or len(anchors_by_id) != manifest.anchor_count:
        raise CorpusStoreIntegrityError("the store's counts differ from its manifest's")
    return VerifiedStore(
        manifest=manifest,
        store_manifest_sha256=parsed_manifest.store_manifest_sha256,
        corpus_content_sha256=derive_corpus_content_sha256(records_file, anchors_file),
    )


def check_record_evidence(record: CveRecord, anchors_by_id: dict[str, IndexedAnchor]) -> None:
    """The record cites only anchors the store holds, all implementation scoped, one of
    them for the record itself."""
    cites_own_record = False
    for evidence_id in record.evidence_ids:
        indexed_anchor = anchors_by_id.get(evidence_id)
        if indexed_anchor is None:
            raise CorpusStoreIntegrityError(f"{record.cve_id} cites an anchor the store lacks")
        if indexed_anchor.scope is not KnowledgeScope.IMPLEMENTATION_VULNERABILITY:
            raise CorpusStoreIntegrityError(f"{record.cve_id} cites non-implementation evidence")
        if indexed_anchor.authoritative_record_id == record.cve_id:
            cites_own_record = True
    if not cites_own_record:
        raise CorpusStoreIntegrityError(f"{record.cve_id} cites no anchor of its own")


def ignore_model(model: CveRecord | EvidenceAnchor) -> None:
    """Keep nothing: verification needs only the anchor index."""


def verify_corpus_store(store_dir: Path) -> VerifiedStore:
    """Verify the store at ``store_dir``; raises ``CorpusStoreIntegrityError``
    (``UnsupportedStoreFormatError`` for a format this release does not read) and any
    ``OSError`` reading it raises."""
    return verify_store_files(store_dir, ignore_model, ignore_model)


def load_corpus_store(store_dir: Path) -> CorpusStore:
    """The store at ``store_dir``, verified; raises as ``verify_corpus_store`` does."""
    anchors: list[EvidenceAnchor] = []
    records: list[CveRecord] = []
    verified_store = verify_store_files(store_dir, anchors.append, records.append)
    return CorpusStore(
        store_name=store_dir.name,
        manifest=verified_store.manifest,
        store_manifest_sha256=verified_store.store_manifest_sha256,
        corpus_content_sha256=verified_store.corpus_content_sha256,
        records=tuple(records),
        evidence=tuple(anchors),
    )
