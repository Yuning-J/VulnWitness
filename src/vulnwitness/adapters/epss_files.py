"""Read operator-supplied FIRST EPSS daily files for a few CVEs.

Each file is FIRST's daily CSV, gzip-compressed or not: a first line
``#model_version:v2025.03.14,score_date:2025-03-14T00:00:00+0000``, a header
``cve,epss,percentile`` and one row per CVE. Only the regular files directly in the
directory whose names end in ``.csv`` or ``.csv.gz`` are read, at most 4,096 of them, each
decompressing to at most 64 MiB. Eligible files are read whole within these per-file
size caps; only observations for the CVEs asked for are retained. Non-regular entries,
including symbolic links, are skipped. Files after the reference date are ignored after
their score-date header is read.
"""

import gzip
import hashlib
import io
import re
import zlib
from collections.abc import Iterable
from datetime import date
from pathlib import Path
from typing import IO, Final

from vulnwitness.adapters.regular_files import open_regular_file
from vulnwitness.domain.epss import EpssObservation, EpssSnapshotIdentity

MAX_EPSS_FILES: Final = 4096
MAX_EPSS_FILE_BYTES: Final = 64 * 1024 * 1024
HEADER_PATTERN: Final = re.compile(
    r"^#model_version:(?P<model>[A-Za-z0-9._-]{1,64}),score_date:(?P<date>\d{4}-\d{2}-\d{2})"
    r"(T[0-9:]+(\+0000|Z)?)?$"
)
CVE_PATTERN: Final = re.compile(r"^CVE-\d{4}-\d{4,}$")


class EpssFileError(ValueError):
    """An EPSS file is missing, oversized or not in FIRST's daily format."""


def list_epss_files(directory: Path) -> list[Path]:
    if not directory.is_dir() or directory.is_symlink():
        raise EpssFileError(f"{directory} is not a directory")
    files = []
    for path in directory.iterdir():
        if (
            path.name.endswith((".csv", ".csv.gz"))
            and not path.name.startswith(".")
            and not path.is_symlink()
            and path.is_file()
        ):
            files.append(path)
    files.sort()
    if not files:
        raise EpssFileError(f"{directory} holds no .csv or .csv.gz EPSS file")
    if len(files) > MAX_EPSS_FILES:
        raise EpssFileError(f"{directory} holds more than {MAX_EPSS_FILES} EPSS files")
    return files


def read_score_header(stream: IO[bytes] | gzip.GzipFile, name: str) -> tuple[str, date]:
    """Read only the bounded first header line, without decompressing later rows."""
    header_bytes = bytearray()
    while len(header_bytes) <= 1024:
        character = stream.read1(1) if isinstance(stream, gzip.GzipFile) else stream.read(1)
        if not character or character == b"\n":
            break
        header_bytes.extend(character)
    try:
        header = HEADER_PATTERN.fullmatch(header_bytes.decode("ascii").strip())
    except UnicodeDecodeError as error:
        raise EpssFileError(f"{name} lacks FIRST's EPSS score-date header") from error
    if header is None:
        raise EpssFileError(f"{name} lacks FIRST's EPSS score-date header")
    return header["model"], date.fromisoformat(header["date"])


def read_epss_file(
    path: Path, cve_ids: frozenset[str], reference_date: date | None = None
) -> tuple[EpssSnapshotIdentity, dict[str, EpssObservation]] | None:
    """The file's identity and rows, or None for a score date after the reference date."""
    try:
        with open_regular_file(path) as stream:
            compressed = stream.read(2) == b"\x1f\x8b"
            stream.seek(0)
            if compressed:
                try:
                    with gzip.GzipFile(fileobj=stream) as header_stream:
                        model_version, score_date = read_score_header(header_stream, path.name)
                except (OSError, EOFError, zlib.error) as error:
                    raise EpssFileError(f"{path.name} is not a readable gzip file") from error
            else:
                model_version, score_date = read_score_header(stream, path.name)
            if reference_date is not None and score_date > reference_date:
                return None
            stream.seek(0)
            raw = stream.read(MAX_EPSS_FILE_BYTES + 1)
    except (OSError, EOFError, zlib.error) as error:
        raise EpssFileError(f"{path.name} is not a readable EPSS file") from error
    if len(raw) > MAX_EPSS_FILE_BYTES:
        raise EpssFileError(f"{path.name} is larger than {MAX_EPSS_FILE_BYTES} bytes")
    content = raw
    if raw[:2] == b"\x1f\x8b":
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as decompressed:
                content = decompressed.read(MAX_EPSS_FILE_BYTES + 1)
        except (OSError, EOFError, zlib.error) as error:
            raise EpssFileError(f"{path.name} is not a readable gzip file") from error
        if len(content) > MAX_EPSS_FILE_BYTES:
            raise EpssFileError(f"{path.name} decompresses past {MAX_EPSS_FILE_BYTES} bytes")
    try:
        lines = content.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise EpssFileError(f"{path.name} is not ASCII text") from error
    header = HEADER_PATTERN.fullmatch(lines[0].strip()) if lines else None
    if header is None or len(lines) < 2 or lines[1].strip() != "cve,epss,percentile":
        raise EpssFileError(f"{path.name} lacks FIRST's EPSS header lines")
    observations: dict[str, EpssObservation] = {}
    rows = 0
    for number, line in enumerate(lines[2:], 3):
        if not line:
            continue
        rows += 1
        cve_id, separator, rest = line.partition(",")
        if cve_id not in cve_ids:
            continue
        observations[cve_id] = parse_row(path.name, number, cve_id, separator, rest, score_date)
    identity = EpssSnapshotIdentity(
        file_name=path.name,
        sha256=hashlib.sha256(raw).hexdigest(),
        score_date=score_date,
        model_version=model_version,
        rows=rows,
    )
    return identity, observations


def parse_row(
    name: str, number: int, cve_id: str, separator: str, rest: str, score_date: date
) -> EpssObservation:
    epss_text, _, percentile_text = rest.partition(",")
    try:
        if not separator or not CVE_PATTERN.fullmatch(cve_id):
            raise ValueError
        return EpssObservation(
            score_date=score_date, epss=float(epss_text), percentile=float(percentile_text)
        )
    except ValueError as error:
        raise EpssFileError(f"{name} line {number} is not a CVE, EPSS and percentile") from error


def read_epss_directory(
    directory: Path, cve_ids: Iterable[str], reference_date: date | None = None
) -> tuple[tuple[EpssSnapshotIdentity, ...], dict[str, tuple[EpssObservation, ...]]]:
    """Eligible regular files in score-date order and each asked CVE's observations.

    Future files are ignored after their score-date header, before row parsing or
    duplicate-date checks. Malformed eligible files raise ``EpssFileError``.
    """
    wanted = frozenset(cve_ids)
    identities: list[EpssSnapshotIdentity] = []
    found: dict[str, list[EpssObservation]] = {}
    for cve_id in wanted:
        found[cve_id] = []
    dates: set[date] = set()
    for path in list_epss_files(directory):
        snapshot = read_epss_file(path, wanted, reference_date)
        if snapshot is None:
            continue
        identity, observations = snapshot
        if identity.score_date in dates:
            raise EpssFileError(f"two EPSS files are scored on {identity.score_date}")
        dates.add(identity.score_date)
        identities.append(identity)
        for cve_id, observation in observations.items():
            found[cve_id].append(observation)
    identities.sort(key=lambda identity: identity.score_date)
    histories = {}
    for cve_id, observations_for_cve in found.items():
        histories[cve_id] = tuple(
            sorted(observations_for_cve, key=lambda observation: observation.score_date)
        )
    return tuple(identities), histories
