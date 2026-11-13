"""Fetch one raw CNVD base, operator-run increments, or a combined input manifest."""

import argparse
import csv
import hashlib
import http.client
import json
import os
import re
import signal
import tempfile
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import BinaryIO
from urllib.parse import urlsplit

import yaml

from vulnwitness.adapters.migration.inputs_manifest import load_inputs_manifest
from vulnwitness.adapters.migration.migration_limits import MigrationLimits
from vulnwitness.domain.corpus_store_manifest import StoreSource

DUMP_URL = "https://vulnerability.circl.lu/dumps/cnvd.ndjson"
QUERY_URL = (
    "https://vulnerability.circl.lu/api/vulnerability/?source=cnvd&since={since}"
    "&date_sort=updated&sort_order=asc&per_page=100&page={page}"
)
PROVENANCE_FIELDS = (
    "action",
    "file",
    "url",
    "retrieved_at",
    "file_sha256",
    "bytes",
    "last_modified",
    "etag",
    "since",
    "page_count",
    "record_count",
    "high_water",
    "request_count",
    "http_429_count",
    "elapsed_seconds",
)


@dataclass(frozen=True)
class HttpDownload:
    status: int
    headers: Mapping[str, str]
    body: BinaryIO


@contextmanager
def get_http(url: str) -> Iterator[HttpDownload]:
    """Stream a GET without redirects, implicit retries, proxies or authentication."""
    address = urlsplit(url)
    connection = http.client.HTTPSConnection(address.hostname, timeout=120)
    try:
        connection.request(
            "GET",
            address.path + ("?" + address.query if address.query else ""),
            headers={"User-Agent": "VulnWitness raw CNVD research operator"},
        )
        download = connection.getresponse()
        headers = {}
        for name, value in download.getheaders():
            headers[name.lower()] = value
        yield HttpDownload(download.status, headers, download)
    finally:
        connection.close()


def read_provenance(directory: Path) -> list[dict[str, str]]:
    path = directory / "provenance.tsv"
    if not path.exists():
        return []
    with path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        if reader.fieldnames != list(PROVENANCE_FIELDS):
            raise ValueError("unrecognised raw CNVD provenance header")
        rows = list(reader)
    if not rows or rows[0]["action"] != "base":
        raise ValueError("provenance must start with a base")
    previous_retrieval: datetime | None = None
    for index, row in enumerate(rows):
        if None in row or any(value is None for value in row.values()):
            raise ValueError("incomplete provenance row")
        if row["action"] != ("base" if index == 0 else "increment"):
            raise ValueError("provenance must contain one base followed by increments")
        retrieved_at = datetime.fromisoformat(row["retrieved_at"])
        if retrieved_at.tzinfo is None or (
            previous_retrieval is not None and retrieved_at <= previous_retrieval
        ):
            raise ValueError("retrieval times must be distinct and increasing")
        previous_retrieval = retrieved_at
        if row["file"] and (
            Path(row["file"]).name != row["file"] or not (directory / row["file"]).is_file()
        ):
            raise ValueError("provenance names a missing or non-local file")
        if row["high_water"]:
            date.fromisoformat(row["high_water"])
    return rows


@contextmanager
def lock_directory(directory: Path) -> Iterator[None]:
    directory.mkdir(parents=True, exist_ok=True)
    lock_path = directory / ".fetch.lock"
    descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.close(descriptor)
        yield
    finally:
        lock_path.unlink()


def record_open_time(record: object) -> str:
    """Require a dump-line object and return its optional calendar openTime."""
    if not isinstance(record, dict) or not isinstance(record.get("number"), str):
        raise ValueError("expected a dump-line CNVD object with number")
    if re.fullmatch(r"CNVD-[0-9]{4}-[0-9]{4,}", record["number"]) is None:
        raise ValueError("invalid CNVD number")
    open_time = record.get("openTime", "")
    if not isinstance(open_time, str):
        raise ValueError("expected calendar openTime")
    if open_time:
        if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", open_time) is None:
            raise ValueError("expected calendar openTime")
        date.fromisoformat(open_time)
    return open_time


def publish_run(
    directory: Path, partial: Path, row: dict[str, str], preceding: list[dict[str, str]]
) -> None:
    """Publish complete bytes and replace provenance, rolling back on interruption."""
    descriptor, partial_name = tempfile.mkstemp(dir=directory, suffix=".provenance.partial")
    provenance_partial = Path(partial_name)
    final_path = directory / row["file"] if row["file"] else None
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=PROVENANCE_FIELDS, delimiter="\t")
            writer.writeheader()
            writer.writerows([*preceding, row])
        if final_path is not None:
            if final_path.exists():
                raise FileExistsError(final_path)
            partial.rename(final_path)
        try:
            provenance_partial.replace(directory / "provenance.tsv")
        except BaseException:
            if final_path is not None:
                final_path.unlink()
            raise
    finally:
        provenance_partial.unlink(missing_ok=True)


class RawCnvdFetcher:
    """Fetch with explicit HTTP and time dependencies; failures publish no run."""

    def __init__(
        self,
        get: Callable[[str], AbstractContextManager[HttpDownload]],
        now: Callable[[], datetime],
        monotonic: Callable[[], float],
        sleep: Callable[[float], None],
        max_bytes: int = MigrationLimits().max_raw_cnvd_bytes,
    ) -> None:
        self.get = get
        self.now = now
        self.monotonic = monotonic
        self.sleep = sleep
        # The importer refuses a raw CNVD file above this size (ADR 0008 §6), so a larger
        # download is stopped while it arrives instead of after it has filled the disk.
        self.max_bytes = max_bytes
        self.last_request: float | None = None
        self.request_count = 0
        self.http_429_count = 0

    @contextmanager
    def request(self, url: str) -> Iterator[HttpDownload]:
        """Space all attempts by at least a second; retry 429/5xx once."""
        for attempt in range(2):
            if self.last_request is not None:
                self.sleep(max(0.0, 1.0 - (self.monotonic() - self.last_request)))
            self.last_request = self.monotonic()
            self.request_count += 1
            with self.get(url) as download:
                if download.status == 429:
                    self.http_429_count += 1
                if download.status == 200:
                    yield download
                    return
                if attempt or not (download.status == 429 or 500 <= download.status <= 599):
                    raise ValueError(f"HTTP {download.status}; run not published")
                retry_after = download.headers.get("retry-after")
                delay = 1.0
                if retry_after is not None:
                    try:
                        delay = float(retry_after)
                    except ValueError:
                        delay = (parsedate_to_datetime(retry_after) - self.now()).total_seconds()
            self.sleep(max(1.0, delay))

    def fetch(self, action: str, directory: Path) -> dict[str, str]:
        """Write a base or increment and its provenance, or raise without publishing."""
        started = self.monotonic()
        requests_before = self.request_count
        throttles_before = self.http_429_count
        with lock_directory(directory):
            preceding = read_provenance(directory)
            if action == "base" and (preceding or (directory / "base.ndjson").exists()):
                raise ValueError("directory already holds a base")
            if action == "increment" and not preceding:
                raise ValueError("fetch a base first")
            high_water = max((row["high_water"] for row in preceding), default="")
            since = ""
            if action == "increment":
                if not high_water:
                    raise ValueError("base has no openTime high-water date")
                since = (date.fromisoformat(high_water) - timedelta(days=1)).isoformat()
            descriptor, partial_name = tempfile.mkstemp(dir=directory, suffix=".partial")
            partial = Path(partial_name)
            row = dict.fromkeys(PROVENANCE_FIELDS, "")
            row.update(action=action, since=since)
            digest = hashlib.sha256()
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    if action == "base":
                        with self.request(DUMP_URL) as download:
                            row["last_modified"] = download.headers.get("last-modified", "")
                            row["etag"] = download.headers.get("etag", "")
                            content_length = download.headers.get("content-length")
                            if content_length is not None and int(content_length) > self.max_bytes:
                                raise ValueError("dump exceeds the raw CNVD byte cap")
                            byte_count = 0
                            while chunk := download.body.read(65536):
                                byte_count += len(chunk)
                                if byte_count > self.max_bytes:
                                    raise ValueError("dump exceeds the raw CNVD byte cap")
                                stream.write(chunk)
                                digest.update(chunk)
                            if content_length is not None and byte_count != int(content_length):
                                raise ValueError("incomplete dump body")
                        row["url"] = DUMP_URL
                        row["page_count"] = "0"
                    else:
                        page_number = 1
                        written = 0
                        while True:
                            url = QUERY_URL.format(since=since, page=page_number)
                            with self.request(url) as download:
                                page = download.body.read(self.max_bytes + 1)
                            if len(page) > self.max_bytes:
                                raise ValueError("API page exceeds the raw CNVD byte cap")
                            records = json.loads(page)
                            if not isinstance(records, list) or len(records) > 100:
                                raise ValueError("expected an API page of at most 100 records")
                            for record in records:
                                record_open_time(record)
                                line = (json.dumps(record, ensure_ascii=False) + "\n").encode(
                                    "utf-8"
                                )
                                written += len(line)
                                if written > self.max_bytes:
                                    raise ValueError("increment exceeds the raw CNVD byte cap")
                                stream.write(line)
                                digest.update(line)
                            if len(records) < 100:
                                break
                            page_number += 1
                        row["url"] = QUERY_URL
                        row["page_count"] = str(page_number)
                record_count = 0
                with partial.open("rb") as stream:
                    for line in stream:
                        high_water = max(high_water, record_open_time(json.loads(line)))
                        record_count += 1
                retrieved_at = self.now().astimezone(UTC)
                if preceding and retrieved_at <= datetime.fromisoformat(
                    preceding[-1]["retrieved_at"]
                ):
                    raise ValueError("retrieval clock must advance beyond the previous run")
                row["retrieved_at"] = retrieved_at.isoformat().replace("+00:00", "Z")
                row["file"] = (
                    "base.ndjson"
                    if action == "base"
                    else (
                        f"increment-{retrieved_at.strftime('%Y%m%dT%H%M%S%fZ')}.ndjson"
                        if record_count
                        else ""
                    )
                )
                row["file_sha256"] = digest.hexdigest()
                row["bytes"] = str(partial.stat().st_size)
                row["record_count"] = str(record_count)
                row["high_water"] = high_water
                row["request_count"] = str(self.request_count - requests_before)
                row["http_429_count"] = str(self.http_429_count - throttles_before)
                row["elapsed_seconds"] = f"{self.monotonic() - started:.3f}"
                publish_run(directory, partial, row, preceding)
                return row
            finally:
                partial.unlink(missing_ok=True)


def write_manifest(directory: Path, inputs_path: Path, target: Path) -> None:
    """Combine NVD/KEV declarations and recorded raw files using absolute paths."""
    manifest = load_inputs_manifest(inputs_path.read_bytes())
    declarations = []
    for declaration in manifest.inputs:
        if declaration.source not in {StoreSource.NVD, StoreSource.CISA_KEV}:
            raise ValueError("--inputs must contain only NVD/KEV; remove circl-cnvd inputs first")
        fields = declaration.model_dump(mode="json", exclude_none=True)
        fields["path"] = str((inputs_path.parent / declaration.path).resolve(strict=True))
        declarations.append(fields)
    with lock_directory(directory):
        rows = read_provenance(directory)
        if not rows:
            raise ValueError("fetch a base first")
        for row in rows:
            if row["file"]:
                declarations.append(
                    {
                        "source": "vulnerability-lookup-cnvd",
                        "path": str((directory / row["file"]).resolve(strict=True)),
                        "retrieved_at": row["retrieved_at"],
                    }
                )
        document = yaml.safe_dump({"format_version": 1, "inputs": declarations}, sort_keys=False)
        load_inputs_manifest(document.encode("utf-8"))
        # Exclusive creation also prevents overwriting an existing input manifest.
        with target.open("x", encoding="utf-8") as stream:
            stream.write(document)


def utc_now() -> datetime:
    return datetime.now(UTC)


def interrupt_run(signum: int, frame: object) -> None:
    raise KeyboardInterrupt


def main(argv: list[str] | None = None, *, fetcher: RawCnvdFetcher | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("base", "increment", "manifest"))
    parser.add_argument("directory", type=Path)
    parser.add_argument("--inputs", type=Path, help="existing NVD/KEV-only input manifest")
    parser.add_argument("--output", type=Path, help="fresh combined manifest path")
    arguments = parser.parse_args(argv)
    if (arguments.inputs is None) != (arguments.output is None):
        parser.error("--inputs and --output must be supplied together")
    if arguments.action == "manifest" and arguments.inputs is None:
        parser.error("manifest requires --inputs and --output")
    if arguments.action != "manifest" and arguments.inputs is not None:
        parser.error("--inputs and --output belong to the manifest action")
    if fetcher is None:
        fetcher = RawCnvdFetcher(get_http, utc_now, time.monotonic, time.sleep)
    try:
        if arguments.action != "manifest":
            row = fetcher.fetch(arguments.action, arguments.directory)
            print(json.dumps(row, sort_keys=True))
        if arguments.inputs is not None:
            write_manifest(arguments.directory, arguments.inputs, arguments.output)
    except (OSError, ValueError, http.client.HTTPException) as error:
        parser.exit(1, f"fetch_raw_cnvd.py: {error}\n")
    return 0


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupt_run)
    raise SystemExit(main())
