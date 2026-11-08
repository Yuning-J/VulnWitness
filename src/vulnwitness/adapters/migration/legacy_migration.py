"""Run a legacy-data import end to end (ADR 0008).

A run resolves the declared inputs, checks the target, optionally walks the legacy root,
then copies each input in turn into its staging directory and reads only that copy:
it fingerprints every input, stages every NVD entry and reads the KEV catalog and
CNVD rows. It then chooses each CVE's winner, normalizes the winners with their final
provenance and KEV entries, counts the CNVD join outcomes, and writes the store in a
partial directory beside the target. The store is verified there and renamed into
place; a dry run stages in the system's temporary directory and writes no store. Any
failure removes only what the run created, and the report says why in the server's words.
"""

import json
import os
import shutil
import tempfile
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from vulnwitness.adapters.migration.candidate_staging import (
    CandidateStaging,
    StagedCandidate,
    resolve_cve,
)
from vulnwitness.adapters.migration.cnvd_snapshot_catalog import match_cnvd_inputs
from vulnwitness.adapters.migration.cnvd_types import CnvdRow, check_cnvd_input
from vulnwitness.adapters.migration.input_files import (
    DecompressionBudget,
    InputFile,
    open_payload,
    snapshot_input,
)
from vulnwitness.adapters.migration.input_resolution import (
    ResolvedInput,
    check_target,
    check_target_in_store_root,
    check_target_parent,
    compute_import_identity,
    resolve_inputs,
    resolve_path,
)
from vulnwitness.adapters.migration.kev_csv_reader import (
    KevCatalog,
    check_kev_input,
    read_kev_catalog,
)
from vulnwitness.adapters.migration.legacy_root_scan import scan_legacy_root
from vulnwitness.adapters.migration.migration_limits import MigrationLimits
from vulnwitness.adapters.migration.nvd_entry_stager import (
    NvdEntryStager,
    normalize,
    parse_nvd_time,
)
from vulnwitness.adapters.migration.parser_types import MigrationParsers
from vulnwitness.adapters.migration.report_tally import ReportTally
from vulnwitness.adapters.nvd.normalizer import (
    KevSource,
    NormalizedCve,
    NvdNormalizationError,
    NvdNormalizer,
    SourceSnapshot,
)
from vulnwitness.adapters.store.corpus_store import (
    ANCHORS_FILE,
    RECORDS_FILE,
    CorpusStoreIntegrityError,
    StoreFileWriter,
    encode_line,
    publish_store_directory,
    read_store_manifest,
    sync_directory,
    verify_corpus_store,
    write_store_manifest,
)
from vulnwitness.domain.cnvd_snapshot import CnvdSnapshotCatalog, CnvdSnapshotFile
from vulnwitness.domain.corpus_store_manifest import (
    ROLLBACK_INSTRUCTION,
    CorpusStoreManifest,
    StoreFile,
    StoreInput,
    StoreSource,
)
from vulnwitness.domain.hashing import sha256_hex
from vulnwitness.domain.migration_inputs import InputsManifest
from vulnwitness.domain.migration_report import (
    CnvdOutcome,
    CveOutcome,
    KevOutcome,
    MigrationFailed,
    MigrationFailureCode,
    MigrationOutcome,
    MigrationReport,
)
from vulnwitness.domain.provenance import SourceRegistry
from vulnwitness.domain.search import SCHEMA_VERSION

STAGING_DIR_SUFFIX = "staging"
PARTIAL_DIR_SUFFIX = "partial"
# The copy of the input being read, in the staging directory; one at a time.
INPUT_SNAPSHOT_FILE = "input.snapshot"


@dataclass(frozen=True)
class MigrationRequest:
    """What the operator asked: the manifest (already parsed, with its bytes and path),
    the target, an optional legacy root, and whether this is a dry run; and the store root
    the settings configure, if any, which constrains a target inside it."""

    manifest: InputsManifest
    manifest_bytes: bytes
    manifest_path: Path
    target: Path
    legacy_root: Path | None
    is_dry_run: bool
    store_root: Path | None


@dataclass(frozen=True)
class MigrationDependencies:
    parsers: MigrationParsers
    normalizer: NvdNormalizer
    source_registry: SourceRegistry
    clock: Callable[[], datetime]
    importer_version: str
    limits: MigrationLimits
    cnvd_catalog: CnvdSnapshotCatalog


@dataclass(frozen=True)
class WrittenStore:
    """The store files a run wrote in ``store_dir``, with the counts its manifest
    records."""

    store_dir: Path
    files: tuple[StoreFile, ...]
    record_count: int
    anchor_count: int


@dataclass
class InputReading:
    """What reading the inputs gave: each NVD payload's hash and generation time by
    input position, the KEV catalog with its input, if one, and the CNVD rows."""

    payload_hashes: dict[int, str] = field(default_factory=dict)
    generated_at: dict[int, datetime | None] = field(default_factory=dict)
    kev_catalog: KevCatalog | None = None
    kev_input: ResolvedInput | None = None
    cnvd_rows: list[CnvdRow] = field(default_factory=list)


def with_position(failure: MigrationFailed, input_position: int) -> MigrationFailed:
    """``failure`` naming the input at ``input_position``, unless it names one already."""
    if failure.input_position is not None or failure.manifest_index is not None:
        return failure
    return MigrationFailed(failure.code, input_position)


class Migration:
    """One run of the importer for ``request``."""

    def __init__(self, request: MigrationRequest, dependencies: MigrationDependencies) -> None:
        self._request = request
        self._dependencies = dependencies
        self.tally = ReportTally()

    def run(self) -> MigrationReport:
        now = self._dependencies.clock().astimezone(UTC)
        manifest_path = resolve_path(
            self._request.manifest_path, MigrationFailureCode.INPUT_UNREADABLE
        )
        limits = self._dependencies.limits
        inputs = resolve_inputs(
            self._request.manifest,
            manifest_path.parent,
            self._dependencies.source_registry,
            now,
            limits,
        )
        inputs, cnvd_files = match_cnvd_inputs(inputs, self._dependencies.cnvd_catalog)
        target = self._resolve_target()
        legacy_root = None
        if self._request.legacy_root is not None:
            legacy_root = resolve_path(
                self._request.legacy_root, MigrationFailureCode.LEGACY_ROOT_UNREADABLE
            )
        check_target_parent(target)
        check_target_in_store_root(target, self._request.store_root)
        check_target(target, manifest_path, inputs, legacy_root)
        if legacy_root is not None:
            self.tally.legacy_root_findings = scan_legacy_root(
                legacy_root, self._dependencies.parsers.classify_json_prefix, limits
            )
        if os.path.lexists(target):
            return self._check_existing_target(target, inputs)
        with self._working_directories(target) as (staging_dir, partial_dir):
            staging = CandidateStaging(staging_dir, limits)
            try:
                reading = self._read_inputs(inputs, staging, staging_dir, cnvd_files)
                identity = compute_import_identity(
                    inputs,
                    self._map_payload_hashes(inputs, reading),
                    self._dependencies.source_registry,
                    self._dependencies.importer_version,
                )
                self.tally.import_identity_sha256 = identity
                try:
                    written_store = self._resolve_and_write(inputs, reading, staging, partial_dir)
                except OSError:
                    raise MigrationFailed(MigrationFailureCode.STORE_WRITE_FAILED) from None
            finally:
                staging.close()
            if written_store is None:
                return self.tally.build_report(MigrationOutcome.DRY_RUN)
            return self._publish(inputs, reading, written_store, identity, now, staging_dir, target)

    def _resolve_target(self) -> Path:
        """The target, resolved. A dangling symbolic link there is an existing entry, so it
        is refused like any other rather than followed to wherever it points."""
        requested_target = self._request.target
        if os.path.islink(requested_target) and not os.path.exists(requested_target):
            raise MigrationFailed(MigrationFailureCode.TARGET_EXISTS)
        return resolve_path(requested_target, MigrationFailureCode.TARGET_UNUSABLE)

    @contextmanager
    def _working_directories(self, target: Path) -> Iterator[tuple[Path, Path | None]]:
        """The run's staging directory and, for a real run, its partial store directory,
        removed when the run ends unless the store was renamed into place."""
        created_dirs: list[Path] = []
        try:
            if self._request.is_dry_run:
                try:
                    staging_dir = Path(tempfile.mkdtemp(prefix="vulnwitness-dry-run-"))
                except OSError:
                    raise MigrationFailed(MigrationFailureCode.STAGING_FAILED) from None
                created_dirs.append(staging_dir)
                yield staging_dir, None
                return
            try:
                staging_dir = Path(
                    tempfile.mkdtemp(
                        prefix=f".{target.name}.{STAGING_DIR_SUFFIX}-", dir=target.parent
                    )
                )
                created_dirs.append(staging_dir)
                partial_dir = Path(
                    tempfile.mkdtemp(
                        prefix=f".{target.name}.{PARTIAL_DIR_SUFFIX}-", dir=target.parent
                    )
                )
                created_dirs.append(partial_dir)
            except OSError:
                raise MigrationFailed(MigrationFailureCode.STORE_WRITE_FAILED) from None
            yield staging_dir, partial_dir
        finally:
            for created_dir in created_dirs:
                shutil.rmtree(created_dir, ignore_errors=True)

    def _check_existing_target(
        self, target: Path, inputs: Sequence[ResolvedInput]
    ) -> MigrationReport:
        """An existing target whose manifest records this very import is verified and left
        as it is; one that fails verification is refused and never repaired; anything else
        there is refused."""
        try:
            parsed_manifest = read_store_manifest(target)
        except (CorpusStoreIntegrityError, OSError):
            raise MigrationFailed(MigrationFailureCode.TARGET_EXISTS) from None
        existing_manifest = parsed_manifest.manifest
        payload_hashes: dict[str, str | None] = {}
        for store_input in existing_manifest.inputs:
            payload_hashes[store_input.input_file_sha256] = store_input.payload_sha256
        for resolved_input in inputs:
            if resolved_input.input_file.sha256 not in payload_hashes:
                raise MigrationFailed(MigrationFailureCode.TARGET_EXISTS)
        identity = compute_import_identity(
            inputs,
            payload_hashes,
            self._dependencies.source_registry,
            self._dependencies.importer_version,
        )
        if identity != existing_manifest.import_identity_sha256:
            raise MigrationFailed(MigrationFailureCode.TARGET_EXISTS)
        self.tally.import_identity_sha256 = identity
        try:
            verified_store = verify_corpus_store(target)
        except (CorpusStoreIntegrityError, OSError):
            raise MigrationFailed(MigrationFailureCode.EXISTING_STORE_INVALID) from None
        # The report names the store this run checked: one replaced between the two reads
        # is refused rather than reported under either manifest.
        if verified_store.store_manifest_sha256 != parsed_manifest.store_manifest_sha256:
            raise MigrationFailed(MigrationFailureCode.EXISTING_STORE_INVALID)
        return self.tally.build_report(
            MigrationOutcome.ALREADY_IMPORTED, named_store=verified_store
        )

    def _read_inputs(
        self,
        inputs: Sequence[ResolvedInput],
        staging: CandidateStaging,
        staging_dir: Path,
        cnvd_files: dict[int, CnvdSnapshotFile],
    ) -> InputReading:
        reading = InputReading()
        cnvd_ids: set[str] = set()
        limits = self._dependencies.limits
        budget = DecompressionBudget(remaining_bytes=limits.max_total_decompressed_bytes)
        for resolved_input in inputs:
            try:
                if resolved_input.source is StoreSource.CISA_KEV:
                    check_kev_input(resolved_input.input_file, limits)
                elif resolved_input.source is StoreSource.CIRCL_CNVD:
                    check_cnvd_input(resolved_input.input_file, limits)
                # The copy counts against the staging cap from before it is made until it
                # is removed: there must be room for it, and the check after its input is
                # read sees it still there.
                staging.check_size(incoming_bytes=resolved_input.input_file.size_bytes)
                with open_snapshot(resolved_input.input_file, staging_dir) as snapshot:
                    self._refuse_derived_file(snapshot, budget)
                    if resolved_input.source is StoreSource.CISA_KEV:
                        reading.kev_catalog = read_kev_catalog(snapshot, limits)
                        reading.kev_input = resolved_input
                    elif resolved_input.source is StoreSource.CIRCL_CNVD:
                        rows = self._dependencies.parsers.read_cnvd_rows(
                            snapshot, limits, cnvd_ids, len(reading.cnvd_rows)
                        )
                        if len(rows) != cnvd_files[resolved_input.position].row_count:
                            raise MigrationFailed(MigrationFailureCode.CNVD_ROW_COUNT_MISMATCH)
                        reading.cnvd_rows.extend(rows)
                    else:
                        self._read_nvd_input(resolved_input, snapshot, staging, budget, reading)
                    staging.check_size()
            except MigrationFailed as failure:
                raise with_position(failure, resolved_input.position) from None
        return reading

    def _refuse_derived_file(self, snapshot: InputFile, budget: DecompressionBudget) -> None:
        """Raise ``derived_file_declared_as_source`` when the input, whatever source it is
        declared as, is a legacy derived file, told by its first decompressed bytes."""
        limits = self._dependencies.limits
        with open_payload(snapshot, budget, limits) as payload:
            prefix = payload.read(limits.max_fingerprint_file_bytes)
        if self._dependencies.parsers.classify_json_prefix(prefix) is not None:
            raise MigrationFailed(MigrationFailureCode.DERIVED_FILE_DECLARED_AS_SOURCE)

    def _read_nvd_input(
        self,
        resolved_input: ResolvedInput,
        snapshot: InputFile,
        staging: CandidateStaging,
        budget: DecompressionBudget,
        reading: InputReading,
    ) -> None:
        stager = NvdEntryStager(resolved_input, staging, self._dependencies.normalizer, self.tally)
        with open_payload(snapshot, budget, self._dependencies.limits) as payload:
            header = self._dependencies.parsers.read_nvd_feed(payload, stager.stage_entry)
            payload_sha256 = payload.read_payload_sha256()
        # Checked again here for a feed with no entries, which the stager never sees.
        artifact = resolved_input.artifact
        if artifact is None or header.feed_format is not artifact.format:
            raise MigrationFailed(MigrationFailureCode.FORMAT_MISMATCH)
        generated_at = None
        if header.generated_at_text is not None:
            generated_at = parse_nvd_time(header.generated_at_text)
            if generated_at is None:
                raise MigrationFailed(MigrationFailureCode.GENERATED_AT_INVALID)
            if resolved_input.retrieved_at < generated_at:
                raise MigrationFailed(MigrationFailureCode.RETRIEVED_BEFORE_GENERATED)
        reading.payload_hashes[resolved_input.position] = payload_sha256
        reading.generated_at[resolved_input.position] = generated_at

    def _map_payload_hashes(
        self, inputs: Sequence[ResolvedInput], reading: InputReading
    ) -> dict[str, str | None]:
        payload_hashes: dict[str, str | None] = {}
        for resolved_input in inputs:
            payload_hashes[resolved_input.input_file.sha256] = reading.payload_hashes.get(
                resolved_input.position
            )
        return payload_hashes

    def _resolve_and_write(
        self,
        inputs: Sequence[ResolvedInput],
        reading: InputReading,
        staging: CandidateStaging,
        partial_dir: Path | None,
    ) -> WrittenStore | None:
        """Choose each CVE's winner, normalize it with its final provenance and KEV entry,
        and stage its anchors; unless this is a dry run (no ``partial_dir``), write the
        records and anchors.
        Raises ``OSError`` when a store file cannot be written. Each writer is closed on
        every way out, without a sync when the run fails, since the partial store goes."""
        records_writer = None if partial_dir is None else StoreFileWriter(partial_dir, RECORDS_FILE)
        try:
            records_file = self._write_records(inputs, reading, staging, records_writer)
        except BaseException:
            if records_writer is not None:
                records_writer.discard()
            raise
        if records_writer is None or records_file is None:
            return None
        anchors_writer = StoreFileWriter(records_writer.store_dir, ANCHORS_FILE)
        try:
            for anchor_json in staging.list_anchor_lines():
                anchors_writer.write_line(anchor_json.encode())
            anchors_file = anchors_writer.close()
        except BaseException:
            anchors_writer.discard()
            raise
        return WrittenStore(
            store_dir=records_writer.store_dir,
            files=(anchors_file, records_file),
            record_count=records_writer.line_count,
            anchor_count=anchors_writer.line_count,
        )

    def _write_records(
        self,
        inputs: Sequence[ResolvedInput],
        reading: InputReading,
        staging: CandidateStaging,
        records_writer: StoreFileWriter | None,
    ) -> StoreFile | None:
        """Choose and normalize every CVE's winner and stage its anchors; with
        ``records_writer``, write each record and return the records file, closed. A dry
        run, with no writer, returns ``None``."""
        kev_entries = {} if reading.kev_catalog is None else reading.kev_catalog.entries
        kev_cve_outcomes: dict[str, CveOutcome] = {}
        cnvd_cve_ids: set[str] = set()
        for row in reading.cnvd_rows:
            if row.has_cve_id():
                cnvd_cve_ids.add(row.cve_id)
        cnvd_cve_outcomes: dict[str, CveOutcome] = {}
        source_versions: dict[int, str] = {}
        for position, payload_sha256 in reading.payload_hashes.items():
            source_versions[position] = f"sha256:{payload_sha256}"
        imported_records = 0
        for group in staging.list_candidate_groups():
            resolution = resolve_cve(group, source_versions)
            self.tally.cve_outcomes[resolution.outcome] += 1
            for candidate_outcome in resolution.candidate_outcomes:
                self.tally.candidate_outcomes[candidate_outcome] += 1
            if resolution.cve_id in kev_entries:
                kev_cve_outcomes[resolution.cve_id] = resolution.outcome
            if resolution.cve_id in cnvd_cve_ids:
                cnvd_cve_outcomes[resolution.cve_id] = resolution.outcome
            if resolution.winner is None:
                continue
            normalized = self._normalize_winner(
                inputs, reading, resolution.winner, kev_entries.get(resolution.cve_id)
            )
            imported_records += 1
            if records_writer is not None:
                records_writer.write_line(encode_line(normalized.record))
            # Staged in a dry run too, so it meets the staging cap where a real run would.
            for anchor in normalized.evidence:
                staging.add_anchor(anchor.evidence_id, encode_line(anchor).decode())
        # The last anchors may follow the last periodic measurement.
        staging.check_size()
        self._count_kev_outcomes(reading, kev_cve_outcomes)
        self._count_cnvd_outcomes(reading, cnvd_cve_outcomes)
        if imported_records == 0:
            raise MigrationFailed(MigrationFailureCode.NO_IMPORTABLE_RECORDS)
        if records_writer is None:
            return None
        return records_writer.close()

    def _normalize_winner(
        self,
        inputs: Sequence[ResolvedInput],
        reading: InputReading,
        winner: StagedCandidate,
        kev_entry: dict[str, str] | None,
    ) -> NormalizedCve:
        """The winner normalized again with its final snapshot and its KEV entry, if one.
        An entry that normalized when staged normalizes again; a failure here is the KEV
        entry's, which makes the KEV input invalid."""
        winner_input = inputs[winner.input_position]
        snapshot = SourceSnapshot(
            source_uri=winner_input.source_uri,
            retrieved_at=winner_input.retrieved_at,
            source_version=f"sha256:{reading.payload_hashes[winner_input.position]}",
        )
        kev_source = None
        kev_input = reading.kev_input
        if kev_entry is not None and kev_input is not None:
            kev_source = KevSource(
                entry=kev_entry,
                snapshot=SourceSnapshot(
                    source_uri=kev_input.source_uri,
                    retrieved_at=kev_input.retrieved_at,
                    source_version=f"sha256:{kev_input.input_file.sha256}",
                ),
            )
        # A staged active candidate always keeps its raw entry.
        raw_entry = json.loads(cast(str, winner.raw_entry))
        try:
            return normalize(
                self._dependencies.normalizer, winner.feed_format, raw_entry, snapshot, kev_source
            )
        except NvdNormalizationError:
            kev_position = None if kev_input is None else kev_input.position
            raise MigrationFailed(MigrationFailureCode.KEV_INVALID_ROW, kev_position) from None

    def _count_kev_outcomes(
        self, reading: InputReading, kev_cve_outcomes: dict[str, CveOutcome]
    ) -> None:
        if reading.kev_catalog is None:
            return
        self.tally.kev_outcomes[KevOutcome.IDENTICAL_DUPLICATE] = (
            reading.kev_catalog.identical_duplicates
        )
        for cve_id in reading.kev_catalog.entries:
            cve_outcome = kev_cve_outcomes.get(cve_id)
            if cve_outcome is None:
                kev_outcome = KevOutcome.WITHOUT_NVD_RECORD
            elif cve_outcome is CveOutcome.IMPORTED:
                kev_outcome = KevOutcome.MERGED
            elif cve_outcome is CveOutcome.WITHDRAWN_BY_SOURCE:
                kev_outcome = KevOutcome.FOR_REJECTED_NVD_RECORD
            else:
                kev_outcome = KevOutcome.FOR_EXCLUDED_NVD_RECORD
            self.tally.kev_outcomes[kev_outcome] += 1

    def _count_cnvd_outcomes(
        self, reading: InputReading, cve_outcomes: dict[str, CveOutcome]
    ) -> None:
        for row in reading.cnvd_rows:
            cve_outcome = cve_outcomes.get(row.cve_id)
            if row.cve_id == "":
                outcome = CnvdOutcome.WITHOUT_CVE_ID
            elif not row.has_cve_id():
                outcome = CnvdOutcome.UNRECOGNISED_CVE_ID
            elif cve_outcome is None:
                outcome = CnvdOutcome.WITHOUT_NVD_RECORD
            elif cve_outcome is CveOutcome.IMPORTED:
                outcome = CnvdOutcome.MERGED
            elif cve_outcome is CveOutcome.WITHDRAWN_BY_SOURCE:
                outcome = CnvdOutcome.FOR_REJECTED_NVD_RECORD
            else:
                outcome = CnvdOutcome.FOR_EXCLUDED_NVD_RECORD
            self.tally.cnvd_outcomes[outcome] += 1

    def _publish(
        self,
        inputs: Sequence[ResolvedInput],
        reading: InputReading,
        written_store: WrittenStore,
        identity: str,
        now: datetime,
        staging_dir: Path,
        target: Path,
    ) -> MigrationReport:
        """Write the manifest, drop the staging directory, verify the partial store and
        rename it into place."""
        store_inputs: list[StoreInput] = []
        for resolved_input in inputs:
            store_inputs.append(build_store_input(resolved_input, reading))
        manifest = CorpusStoreManifest(
            schema_version=SCHEMA_VERSION,
            created_at=now,
            importer_version=self._dependencies.importer_version,
            import_identity_sha256=identity,
            inputs_manifest_sha256=sha256_hex(self._request.manifest_bytes),
            inputs=tuple(store_inputs),
            files=written_store.files,
            record_count=written_store.record_count,
            anchor_count=written_store.anchor_count,
            rollback_instruction=ROLLBACK_INSTRUCTION,
        )
        store_dir = written_store.store_dir
        try:
            manifest_bytes = write_store_manifest(store_dir, manifest)
            sync_directory(store_dir)
            shutil.rmtree(staging_dir)
            verified_store = verify_corpus_store(store_dir)
            if verified_store.store_manifest_sha256 != sha256_hex(manifest_bytes):
                raise MigrationFailed(MigrationFailureCode.STORE_WRITE_FAILED)
            # Any entry at the target now is refused. One that appears after this check and
            # before the rename fails the rename if it is a file or a directory with
            # entries; an empty directory is replaced, as rename(2) does.
            if os.path.lexists(target):
                raise MigrationFailed(MigrationFailureCode.TARGET_EXISTS)
            publish_store_directory(store_dir, target)
        except (OSError, CorpusStoreIntegrityError):
            raise MigrationFailed(MigrationFailureCode.STORE_WRITE_FAILED) from None
        return self.tally.build_report(MigrationOutcome.IMPORTED, named_store=verified_store)


@contextmanager
def open_snapshot(input_file: InputFile, staging_dir: Path) -> Iterator[InputFile]:
    """The input's snapshot in ``staging_dir`` (``snapshot_input``), removed once it has
    been read, so the staging directory holds one input copy at a time."""
    snapshot_path = staging_dir / INPUT_SNAPSHOT_FILE
    try:
        yield snapshot_input(input_file, snapshot_path)
    finally:
        try:
            snapshot_path.unlink(missing_ok=True)
        except OSError:
            raise MigrationFailed(MigrationFailureCode.STAGING_FAILED) from None


def build_store_input(resolved_input: ResolvedInput, reading: InputReading) -> StoreInput:
    payload_sha256 = reading.payload_hashes.get(resolved_input.position)
    version_sha256 = payload_sha256 or resolved_input.input_file.sha256
    return StoreInput(
        source=resolved_input.source,
        artifact=resolved_input.artifact,
        container=resolved_input.input_file.container,
        source_uri=resolved_input.source_uri,
        source_version=f"sha256:{version_sha256}",
        input_file_sha256=resolved_input.input_file.sha256,
        payload_sha256=payload_sha256,
        retrieved_at=resolved_input.retrieved_at,
        source_generated_at=reading.generated_at.get(resolved_input.position),
        input_bytes=resolved_input.input_file.size_bytes,
    )


def run_migration(
    request: MigrationRequest, dependencies: MigrationDependencies
) -> MigrationReport:
    """Run the import ``request`` asks for; the report says what came of it, a failure
    included. Raises nothing for a failure the report can state."""
    migration = Migration(request, dependencies)
    try:
        return migration.run()
    except MigrationFailed as failure:
        return migration.tally.build_report(MigrationOutcome.FAILED, failure=failure)
