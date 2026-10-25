"""Stage NVD candidates on disk and choose each CVE's winner (ADR 0008 §5, §8).

Every NVD entry whose CVE ID can be read is staged in a SQLite database in the run's
staging directory, with what the choice needs: its modification time, format, state
(active, rejected by the source, or malformed) and semantic hash, its provenance for
the tie-break, and the raw entry for the winner's final normalization. Candidates are
read back grouped by CVE ID through an index, and anchors in evidence ID order through
the table's key, so nothing is sorted in memory or in temporary files. The number of
candidates and the staging directory's size are capped (``MigrationLimits``); the size
is checked every so many rows or bytes added. A database or disk error fails the run as
``staging_failed``.
"""

import json
import os
import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from cve_kgrag.adapters.migration.migration_limits import MIB, MigrationLimits
from cve_kgrag.domain.corpus_store_manifest import NvdFeedFormat
from cve_kgrag.domain.migration_report import (
    CandidateOutcome,
    CveOutcome,
    MigrationFailed,
    MigrationFailureCode,
)

STAGING_FILE_NAME = "candidates.sqlite"
SIZE_CHECK_INTERVAL_ROWS = 1024
SIZE_CHECK_INTERVAL_BYTES = 64 * MIB
CANDIDATE_COLUMNS = (
    "cve_id",
    "last_modified_us",
    "feed_format",
    "state",
    "semantic_sha256",
    "input_position",
    "entry_index",
    "retrieved_at_us",
    "source_uri",
    "content_sha256",
    "raw_entry",
)


class CandidateState(StrEnum):
    ACTIVE = "active"
    REJECTED = "rejected"
    MALFORMED = "malformed"


@dataclass(frozen=True)
class StagedCandidate:
    """One NVD entry for a CVE. ``last_modified_us`` is the entry's modification time in
    microseconds since the epoch, ``None`` when missing or invalid; ``semantic_sha256``
    is set for an active or rejected entry, and ``raw_entry`` for an active one."""

    cve_id: str
    last_modified_us: int | None
    feed_format: NvdFeedFormat
    state: CandidateState
    semantic_sha256: str | None
    input_position: int
    entry_index: int
    retrieved_at_us: int
    source_uri: str
    content_sha256: str | None
    raw_entry: str | None

    def tie_break_key(self, source_versions: Mapping[int, str]) -> tuple[bool, int, str, str, str]:
        """Among equal candidates: 2.0 first, then the latest retrieval, then the
        smallest source URI, source version (its input's, from ``source_versions``) and
        content hash. Only a stable order, claiming no artifact is more authoritative."""
        return (
            self.feed_format is not NvdFeedFormat.V2_0,
            -self.retrieved_at_us,
            self.source_uri,
            source_versions[self.input_position],
            self.content_sha256 or "",
        )


@dataclass(frozen=True)
class CveResolution:
    """What the candidates of one CVE come to: its outcome, the winner when the CVE is
    imported, and each candidate's outcome."""

    cve_id: str
    outcome: CveOutcome
    winner: StagedCandidate | None
    candidate_outcomes: tuple[CandidateOutcome, ...]


class CandidateStaging:
    """The staging database in ``staging_dir``, created empty."""

    def __init__(self, staging_dir: Path, limits: MigrationLimits) -> None:
        self._staging_dir = staging_dir
        self._limits = limits
        with map_staging_errors():
            self._connection = sqlite3.connect(staging_dir / STAGING_FILE_NAME)
            # The database is disposable, so it keeps no journal and is never synced.
            self._connection.execute("PRAGMA journal_mode = OFF")
            self._connection.execute("PRAGMA synchronous = OFF")
            self._connection.execute("PRAGMA temp_store = MEMORY")
            self._connection.execute(
                "CREATE TABLE candidate (cve_id TEXT NOT NULL, last_modified_us INTEGER, "
                "feed_format TEXT NOT NULL, state TEXT NOT NULL, semantic_sha256 TEXT, "
                "input_position INTEGER NOT NULL, entry_index INTEGER NOT NULL, "
                "retrieved_at_us INTEGER NOT NULL, source_uri TEXT NOT NULL, "
                "content_sha256 TEXT, raw_entry TEXT)"
            )
            self._connection.execute("CREATE INDEX candidate_by_cve ON candidate (cve_id)")
            self._connection.execute(
                "CREATE TABLE anchor (evidence_id TEXT PRIMARY KEY, anchor_json TEXT NOT NULL)"
            )
        self.candidate_count = 0
        self._rows_since_size_check = 0
        self._bytes_since_size_check = 0

    def add_candidate(self, candidate: StagedCandidate) -> None:
        self.candidate_count += 1
        if self.candidate_count > self._limits.max_nvd_candidates:
            raise MigrationFailed(MigrationFailureCode.TOO_MANY_CANDIDATES)
        placeholders = ", ".join("?" for _ in CANDIDATE_COLUMNS)
        with map_staging_errors():
            self._connection.execute(
                f"INSERT INTO candidate ({', '.join(CANDIDATE_COLUMNS)}) VALUES ({placeholders})",
                (
                    candidate.cve_id,
                    candidate.last_modified_us,
                    candidate.feed_format.value,
                    candidate.state.value,
                    candidate.semantic_sha256,
                    candidate.input_position,
                    candidate.entry_index,
                    candidate.retrieved_at_us,
                    candidate.source_uri,
                    candidate.content_sha256,
                    candidate.raw_entry,
                ),
            )
        self._count_row(len(candidate.raw_entry or ""))

    def add_anchor(self, evidence_id: str, anchor_json: str) -> None:
        """Stage an anchor once; an anchor two records share is kept once."""
        with map_staging_errors():
            self._connection.execute(
                "INSERT OR IGNORE INTO anchor (evidence_id, anchor_json) VALUES (?, ?)",
                (evidence_id, anchor_json),
            )
        self._count_row(len(anchor_json))

    def list_candidate_groups(self) -> Iterator[list[StagedCandidate]]:
        """Every staged CVE's candidates, by CVE ID in lexical order."""
        group: list[StagedCandidate] = []
        with map_staging_errors():
            for row in self._connection.execute(
                f"SELECT {', '.join(CANDIDATE_COLUMNS)} FROM candidate ORDER BY cve_id"
            ):
                candidate = read_candidate_row(row)
                if group and group[0].cve_id != candidate.cve_id:
                    yield group
                    group = []
                group.append(candidate)
        if group:
            yield group

    def list_anchor_lines(self) -> Iterator[str]:
        """Every staged anchor's JSON, in evidence ID order."""
        with map_staging_errors():
            for (anchor_json,) in self._connection.execute(
                "SELECT anchor_json FROM anchor ORDER BY evidence_id"
            ):
                yield anchor_json

    def close(self) -> None:
        self._connection.close()

    def _count_row(self, row_bytes: int) -> None:
        self._rows_since_size_check += 1
        self._bytes_since_size_check += row_bytes
        is_check_due = (
            self._rows_since_size_check >= SIZE_CHECK_INTERVAL_ROWS
            or self._bytes_since_size_check >= SIZE_CHECK_INTERVAL_BYTES
        )
        if is_check_due:
            self._rows_since_size_check = 0
            self._bytes_since_size_check = 0
            self.check_size()

    def check_size(self) -> None:
        """Raise ``MigrationFailed`` once the staging directory passes its cap."""
        staging_bytes = 0
        with map_staging_errors():
            for entry in os.scandir(self._staging_dir):
                staging_bytes += entry.stat(follow_symlinks=False).st_size
        if staging_bytes > self._limits.max_staging_bytes:
            raise MigrationFailed(MigrationFailureCode.STAGING_TOO_LARGE)


@contextmanager
def map_staging_errors() -> Iterator[None]:
    """Turn a database or disk error, such as a full disk, into ``staging_failed``."""
    try:
        yield
    except (sqlite3.Error, OSError):
        raise MigrationFailed(MigrationFailureCode.STAGING_FAILED) from None


def read_candidate_row(row: tuple[Any, ...]) -> StagedCandidate:
    """A candidate from its row, read in ``CANDIDATE_COLUMNS`` order."""
    (
        cve_id,
        last_modified_us,
        feed_format,
        state,
        semantic_sha256,
        input_position,
        entry_index,
        retrieved_at_us,
        source_uri,
        content_sha256,
        raw_entry,
    ) = row
    return StagedCandidate(
        cve_id=cve_id,
        last_modified_us=last_modified_us,
        feed_format=NvdFeedFormat(feed_format),
        state=CandidateState(state),
        semantic_sha256=semantic_sha256,
        input_position=input_position,
        entry_index=entry_index,
        retrieved_at_us=retrieved_at_us,
        source_uri=source_uri,
        content_sha256=content_sha256,
        raw_entry=raw_entry,
    )


def describe_semantic_state(cve_id: str) -> str:
    """The semantic content of a candidate the source withdrew: the CVE and that state."""
    return json.dumps({"cve_id": cve_id, "state": CandidateState.REJECTED.value}, sort_keys=True)


def exclude_cve(group: list[StagedCandidate], outcome: CveOutcome) -> CveResolution:
    outcomes: list[CandidateOutcome] = []
    for _ in group:
        outcomes.append(CandidateOutcome.IN_EXCLUDED_CVE)
    return CveResolution(group[0].cve_id, outcome, None, tuple(outcomes))


def has_one_semantic_state(candidates: list[StagedCandidate]) -> bool:
    semantic_states: set[str | None] = set()
    for candidate in candidates:
        semantic_states.add(candidate.semantic_sha256)
    return len(semantic_states) == 1


def resolve_cve(group: list[StagedCandidate], source_versions: Mapping[int, str]) -> CveResolution:
    """The CVE's outcome and winner from all its candidates (ADR 0008 §5);
    ``source_versions`` gives each input position's source version, for the tie-break."""
    cve_id = group[0].cve_id
    if len(group) > 1 and any(candidate.last_modified_us is None for candidate in group):
        return exclude_cve(group, CveOutcome.UNORDERABLE_CANDIDATE)
    latest_us = max(candidate.last_modified_us or 0 for candidate in group)
    outcomes: list[CandidateOutcome] = []
    latest_positions: list[int] = []
    for position, candidate in enumerate(group):
        if (candidate.last_modified_us or 0) == latest_us:
            if candidate.state is CandidateState.MALFORMED:
                return exclude_cve(group, CveOutcome.MALFORMED_WINNING_CANDIDATE)
            latest_positions.append(position)
            outcomes.append(CandidateOutcome.IDENTICAL_DUPLICATE)
        elif candidate.state is CandidateState.MALFORMED:
            outcomes.append(CandidateOutcome.MALFORMED)
        else:
            outcomes.append(CandidateOutcome.SUPERSEDED)
    equal_positions = latest_positions
    if not has_one_semantic_state(list_candidates_at(group, latest_positions)):
        equal_positions = []
        for position in latest_positions:
            if group[position].feed_format is NvdFeedFormat.V1_1:
                outcomes[position] = CandidateOutcome.DROPPED_FOR_FORMAT
            else:
                equal_positions.append(position)
        if not has_one_semantic_state(list_candidates_at(group, equal_positions)):
            return exclude_cve(group, CveOutcome.CONFLICTING_DUPLICATE)
    winner_position = equal_positions[0]
    for position in equal_positions[1:]:
        position_key = group[position].tie_break_key(source_versions)
        if position_key < group[winner_position].tie_break_key(source_versions):
            winner_position = position
    outcomes[winner_position] = CandidateOutcome.CHOSEN
    winner = group[winner_position]
    if winner.state is CandidateState.REJECTED:
        return CveResolution(cve_id, CveOutcome.WITHDRAWN_BY_SOURCE, None, tuple(outcomes))
    return CveResolution(cve_id, CveOutcome.IMPORTED, winner, tuple(outcomes))


def list_candidates_at(group: list[StagedCandidate], positions: list[int]) -> list[StagedCandidate]:
    candidates: list[StagedCandidate] = []
    for position in positions:
        candidates.append(group[position])
    return candidates
