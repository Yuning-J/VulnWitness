"""Scripted streaming HTTP and time for raw CNVD operator tests; no network or sleep."""

import io
import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

from scripts.operator.fetch_raw_cnvd import HttpDownload, RawCnvdFetcher


class RawCnvdClock:
    def __init__(self) -> None:
        self.seconds = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.seconds

    def now(self) -> datetime:
        return datetime(2026, 10, 24, 10, tzinfo=UTC) + timedelta(seconds=self.seconds)

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.seconds += seconds


class RawCnvdHttp:
    def __init__(self, downloads: list[HttpDownload | BaseException], clock: RawCnvdClock) -> None:
        self.downloads = list(downloads)
        self.clock = clock
        self.calls: list[tuple[str, float]] = []

    @contextmanager
    def get(self, url: str) -> Iterator[HttpDownload]:
        self.calls.append((url, self.clock.monotonic()))
        download = self.downloads.pop(0)
        if isinstance(download, BaseException):
            raise download
        with download.body:
            yield download

    def fetcher(self) -> RawCnvdFetcher:
        return RawCnvdFetcher(self.get, self.clock.now, self.clock.monotonic, self.clock.sleep)


def build_download(
    records: list[object],
    *,
    base: bool = False,
    status: int = 200,
    headers: dict[str, str] | None = None,
) -> HttpDownload:
    if base:
        lines = []
        for record in records:
            lines.append(json.dumps(record))
        body = ("\n".join(lines) + ("\n" if lines else "")).encode()
    else:
        body = json.dumps(records).encode()
    return HttpDownload(status, headers or {}, io.BytesIO(body))
