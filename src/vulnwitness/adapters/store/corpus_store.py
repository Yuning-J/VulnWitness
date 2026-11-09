"""Write and read a corpus store: ``manifest.json`` and the JSON Lines files it pins
(ADR 0008 §9).

Records, anchors and pending entries are canonical JSON lines, ordered by CVE ID,
evidence ID and (CVE ID, CNVD ID), respectively. Reading a store fails closed: the
directory holds exactly the manifest and its pinned files, each matching its SHA-256
and size. Every anchor's ID re-derives from its fields; every record cites its own CVE
anchor and only anchors the store holds. CNVD entries cite anchors binding their
retained source fields, and no anchor is left uncited. The manifest and every line are read
within a cap, and a file's size is checked before its lines are. Verification keeps an
anchor index with CNVD row provenance; loading also keeps records, anchors and CNVD
indexes for serving.

A store has three identities (ADR 0009 §2): the SHA-256 of the manifest bytes the reader
parsed names the physical store; the manifest's import identity names the import; and the
corpus content digest, derived from all verified content file pins, names the dataset
served. Format 1 holds records and anchors; formats 2 and 3 also hold pending CNVD
entries. Format 3 supports raw CNVD product text, dates and handling advice.
"""

import hashlib
import json
import os
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from pydantic import ValidationError

from vulnwitness.adapters.regular_files import open_regular_file
from vulnwitness.domain.cnvd import (
    CnvdIndex,
    PendingCnvdEntry,
    build_cnvd_index,
    cnvd_source_row,
)
from vulnwitness.domain.corpus_store_manifest import (
    CorpusStoreManifest,
    StoreFile,
    StoreSource,
    derive_corpus_content_sha256,
    name_corpus_store_version,
)
from vulnwitness.domain.cve import CnvdEntry, CveRecord
from vulnwitness.domain.evidence import EvidenceAnchor
from vulnwitness.domain.hashing import canonical_json_bytes, canonical_sha256, sha256_hex
from vulnwitness.domain.kev import KevCapability
from vulnwitness.domain.served_dataset import ServedDataset, ServedDatasetKind
from vulnwitness.domain.session_record import SessionCorpusIdentity
from vulnwitness.domain.taxonomy import AssertionKind, KnowledgeScope, SourceType, TrustLevel
from vulnwitness.domain.validation import find_anchor_violations

STORE_MANIFEST_FILE = "manifest.json"
RECORDS_FILE = "records.jsonl"
ANCHORS_FILE = "anchors.jsonl"
PENDING_CNVD_FILE = "pending_cnvd.jsonl"
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
    cnvd_index: CnvdIndex

    store_name: str

    def describe_kev(self) -> KevCapability:
        for store_input in self.manifest.inputs:
            if store_input.source is StoreSource.CISA_KEV:
                return KevCapability(
                    imported=True,
                    retrieved_at=store_input.retrieved_at,
                    source_version=store_input.source_version,
                )
        return KevCapability(imported=False)

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


def encode_line(model: CveRecord | EvidenceAnchor | PendingCnvdEntry) -> bytes:
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
    """Read the version before parsing the manifest: formats 1, 2 and 3 are supported;
    any other integer is unsupported, and a missing or non-integer version is invalid.
    Booleans are not version integers.
    """
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
    if format_version not in (1, 2, 3):
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
    required_files = {RECORDS_FILE, ANCHORS_FILE}
    if manifest.store_format_version >= 2:
        required_files.add(PENDING_CNVD_FILE)
    if required_files != expected_names - {STORE_MANIFEST_FILE}:
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
    cnvd_anchor: EvidenceAnchor | None


def verify_store_files(
    store_dir: Path,
    keep_anchor: Callable[[EvidenceAnchor], None],
    keep_record: Callable[[CveRecord], None],
    keep_pending: Callable[[PendingCnvdEntry], None] | None = None,
) -> VerifiedStore:
    """Verify every content file, passing its models to the supplied callbacks."""
    parsed_manifest = read_store_manifest(store_dir)
    manifest = parsed_manifest.manifest
    read_cnvd_revision(manifest)
    cnvd_source = read_cnvd_source(manifest)
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
            anchor.scope,
            anchor.authoritative_record_id,
            anchor
            if anchor.source_type
            in {SourceType.CIRCL_CNVD_PARQUET, SourceType.VULNERABILITY_LOOKUP_CNVD_NDJSON}
            else None,
        )
        keep_anchor(anchor)
    cited_evidence_ids: set[str] = set()
    previous_cve_id = ""
    record_count = 0
    record_cve_ids: set[str] = set()
    cnvd_ids: set[tuple[str, str]] = set()
    for line in read_pinned_lines(store_dir, records_file):
        try:
            record = CveRecord.model_validate_json(line)
        except ValidationError as error:
            raise CorpusStoreIntegrityError("a record line is not a CVE record") from error
        if record.cve_id <= previous_cve_id:
            raise CorpusStoreIntegrityError("records are not in strict CVE ID order")
        previous_cve_id = record.cve_id
        if manifest.store_format_version == 1 and (record.nvd_status is not None or record.cnvd):
            raise CorpusStoreIntegrityError("format 1 holds no NVD status or CNVD entries")
        check_record_evidence(record, anchors_by_id)
        for entry in record.cnvd:
            if entry.evidence_id not in record.evidence_ids:
                raise CorpusStoreIntegrityError("a CNVD entry's anchor is not cited by its record")
            check_cnvd_evidence(
                entry, record.cve_id, anchors_by_id, cnvd_ids, manifest, cnvd_source
            )
        record_cve_ids.add(record.cve_id)
        cited_evidence_ids.update(record.evidence_ids)
        record_count += 1
        keep_record(record)
    pending_file = None
    if manifest.store_format_version >= 2:
        pending_file = find_store_file(manifest, PENDING_CNVD_FILE)
        previous_pending_key = ("", "")
        for line in read_pinned_lines(store_dir, pending_file):
            try:
                pending = PendingCnvdEntry.model_validate_json(line)
            except ValidationError as error:
                raise CorpusStoreIntegrityError("a pending line is not a CNVD entry") from error
            pending_key = (pending.cve_id, pending.entry.cnvd_id)
            if pending_key <= previous_pending_key:
                raise CorpusStoreIntegrityError(
                    "pending entries are not in strict CVE/CNVD ID order"
                )
            previous_pending_key = pending_key
            if pending.cve_id in record_cve_ids:
                raise CorpusStoreIntegrityError("a pending entry has a servable NVD record")
            check_cnvd_evidence(
                pending.entry, pending.cve_id, anchors_by_id, cnvd_ids, manifest, cnvd_source
            )
            cited_evidence_ids.add(pending.entry.evidence_id)
            if keep_pending is not None:
                keep_pending(pending)
    if cited_evidence_ids != set(anchors_by_id):
        raise CorpusStoreIntegrityError(
            "the store holds an anchor no record or pending entry cites"
        )
    if record_count != manifest.record_count or len(anchors_by_id) != manifest.anchor_count:
        raise CorpusStoreIntegrityError("the store's counts differ from its manifest's")
    return VerifiedStore(
        manifest=manifest,
        store_manifest_sha256=parsed_manifest.store_manifest_sha256,
        corpus_content_sha256=derive_corpus_content_sha256(
            records_file, anchors_file, pending_file
        ),
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


def check_cnvd_evidence(
    entry: CnvdEntry,
    cve_id: str,
    anchors_by_id: dict[str, IndexedAnchor],
    cnvd_ids: set[tuple[str, str]],
    manifest: CorpusStoreManifest,
    cnvd_source: str | None,
) -> None:
    """Each CNVD/CVE link is unique and binds its retained source fields and input."""
    is_raw = cnvd_source == StoreSource.VULNERABILITY_LOOKUP_CNVD.value
    cnvd_key = (entry.cnvd_id, cve_id if is_raw else "")
    if cnvd_key in cnvd_ids:
        raise CorpusStoreIntegrityError("a CNVD ID is stored more than once for its CVE")
    cnvd_ids.add(cnvd_key)
    if not is_raw and (
        entry.products
        or entry.submit_time is not None
        or entry.open_time is not None
        or entry.handling_advice is not None
    ):
        raise CorpusStoreIntegrityError("Parquet CNVD entries hold no raw source fields")
    indexed_anchor = anchors_by_id.get(entry.evidence_id)
    if indexed_anchor is None or indexed_anchor.cnvd_anchor is None:
        raise CorpusStoreIntegrityError("a CNVD entry cites no CNVD anchor")
    anchor = indexed_anchor.cnvd_anchor
    if (
        anchor.authoritative_record_id != entry.cnvd_id
        or anchor.source_name != cnvd_source
        or anchor.source_type
        != (
            SourceType.VULNERABILITY_LOOKUP_CNVD_NDJSON if is_raw else SourceType.CIRCL_CNVD_PARQUET
        )
        or anchor.locator != f"id={entry.cnvd_id}"
        or anchor.scope is not KnowledgeScope.IMPLEMENTATION_VULNERABILITY
        or anchor.assertion_kind is not AssertionKind.ASSERTED
        or anchor.trust_level is not TrustLevel.SECONDARY
        or anchor.excerpt is not None
        or anchor.content_sha256 != canonical_sha256(cnvd_source_row(entry, cve_id, raw=is_raw))
    ):
        raise CorpusStoreIntegrityError("a CNVD entry differs from its row anchor")
    if is_raw:
        matches_input = False
        for store_input in manifest.inputs:
            if (
                store_input.source.value == cnvd_source
                and anchor.source_uri == store_input.source_uri
                and anchor.source_version == store_input.source_version
                and anchor.retrieved_at == store_input.retrieved_at
            ):
                matches_input = True
                break
        if not matches_input:
            raise CorpusStoreIntegrityError("a raw CNVD anchor names no imported input")


def ignore_model(model: CveRecord | EvidenceAnchor) -> None:
    """Keep nothing: verification needs only the anchor index."""


def verify_corpus_store(store_dir: Path) -> VerifiedStore:
    """Verify the store at ``store_dir``; raises ``CorpusStoreIntegrityError``
    (``UnsupportedStoreFormatError`` for a format this release does not read) and any
    ``OSError`` reading it raises."""
    return verify_store_files(store_dir, ignore_model, ignore_model)


def read_cnvd_source(manifest: CorpusStoreManifest) -> str | None:
    """Require one CNVD source and an unambiguous raw input order at the store boundary."""
    source_name = None
    previous_retrieval = None
    for store_input in manifest.inputs:
        if store_input.source not in {
            StoreSource.CIRCL_CNVD,
            StoreSource.VULNERABILITY_LOOKUP_CNVD,
        }:
            continue
        if source_name is not None and source_name != store_input.source.value:
            raise CorpusStoreIntegrityError("a store accepts only one CNVD source")
        source_name = store_input.source.value
        if store_input.source is StoreSource.VULNERABILITY_LOOKUP_CNVD:
            if manifest.store_format_version < 3:
                raise CorpusStoreIntegrityError("raw CNVD inputs require store format 3")
            if previous_retrieval is not None and store_input.retrieved_at <= previous_retrieval:
                raise CorpusStoreIntegrityError("raw CNVD inputs must be in strict retrieval order")
            previous_retrieval = store_input.retrieved_at
    return source_name


def read_cnvd_revision(manifest: CorpusStoreManifest) -> str | None:
    """Read the import pin from the fixed upstream URL, including an empty CNVD import.

    Reject malformed or mixed revisions at the store boundary; manifest text never
    supplies the attribution or instructions.
    """
    if manifest.store_format_version == 1:
        return None
    revision = None
    for store_input in manifest.inputs:
        if store_input.source is not StoreSource.CIRCL_CNVD:
            continue
        url_match = re.fullmatch(
            r"https://huggingface\.co/datasets/CIRCL/Vulnerability-CNVD/resolve/"
            r"([0-9a-f]{40})/data/[A-Za-z0-9._-]+\.parquet",
            store_input.source_uri,
        )
        if url_match is None or (revision is not None and revision != url_match[1]):
            raise CorpusStoreIntegrityError("CNVD inputs must name one pinned upstream revision")
        revision = url_match[1]
    return revision


def load_corpus_store(store_dir: Path) -> CorpusStore:
    """The store at ``store_dir``, verified; raises as ``verify_corpus_store`` does."""
    anchors: list[EvidenceAnchor] = []
    records: list[CveRecord] = []
    pending_entries: list[PendingCnvdEntry] = []
    verified_store = verify_store_files(
        store_dir, anchors.append, records.append, pending_entries.append
    )
    return CorpusStore(
        store_name=store_dir.name,
        manifest=verified_store.manifest,
        store_manifest_sha256=verified_store.store_manifest_sha256,
        corpus_content_sha256=verified_store.corpus_content_sha256,
        records=tuple(records),
        evidence=tuple(anchors),
        cnvd_index=build_cnvd_index(
            records,
            pending_entries,
            read_cnvd_revision(verified_store.manifest),
            read_cnvd_source(verified_store.manifest),
        ),
    )
