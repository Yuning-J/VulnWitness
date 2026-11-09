"""Raw CNVD operator downloads and manifest-to-store flow over fake HTTP only."""

import hashlib
import io
from pathlib import Path

import pytest
import yaml

from scripts.operator.fetch_raw_cnvd import (
    DUMP_URL,
    HttpDownload,
    main,
    read_provenance,
    write_manifest,
)
from tests.support.cnvd_inputs import build_raw_cnvd_record, write_cnvd_nvd_inputs
from tests.support.legacy_inputs import (
    build_declaration,
    run_test_migration,
    write_inputs_manifest,
)
from tests.support.raw_cnvd_http import RawCnvdClock, RawCnvdHttp, build_download
from vulnwitness.adapters.store.corpus_store import load_corpus_store
from vulnwitness.domain.migration_report import MigrationOutcome


def test_base_writes_exact_bytes_metadata_digest_and_latest_open_time(tmp_path: Path) -> None:
    records = [build_raw_cnvd_record(1), build_raw_cnvd_record(2, openTime="2026-10-08")]
    headers = {"last-modified": "Sun, 04 Oct 2026 03:42:42 GMT", "etag": '"synthetic"'}
    download = build_download(records, base=True, headers=headers)
    expected_bytes = download.body.getvalue()
    http = RawCnvdHttp([download], RawCnvdClock())

    row = http.fetcher().fetch("base", tmp_path)

    assert (tmp_path / "base.ndjson").read_bytes() == expected_bytes
    assert row["file_sha256"] == hashlib.sha256(expected_bytes).hexdigest()
    assert row["bytes"] == str(len(expected_bytes))
    assert row["last_modified"] == headers["last-modified"]
    assert row["etag"] == headers["etag"]
    assert row["record_count"] == "2"
    assert row["high_water"] == "2026-10-08"
    assert row["retrieved_at"] == "2026-10-24T10:00:00Z"
    assert read_provenance(tmp_path) == [row]
    assert http.calls == [(DUMP_URL, 0.0)]
    assert not list(tmp_path.glob("*.partial"))


def test_second_base_is_refused_without_an_http_request(tmp_path: Path) -> None:
    http = RawCnvdHttp([build_download([build_raw_cnvd_record(1)], base=True)], RawCnvdClock())
    fetcher = http.fetcher()
    fetcher.fetch("base", tmp_path)
    original = (tmp_path / "provenance.tsv").read_bytes()

    with pytest.raises(ValueError, match="already holds a base"):
        fetcher.fetch("base", tmp_path)

    assert len(http.calls) == 1
    assert (tmp_path / "provenance.tsv").read_bytes() == original


def test_increment_uses_maximum_prior_open_time_and_pages_with_request_spacing(
    tmp_path: Path,
) -> None:
    full_page = []
    for number in range(100):
        full_page.append(build_raw_cnvd_record(number + 10, openTime="2026-10-11"))
    downloads = [
        build_download([build_raw_cnvd_record(1, openTime="2026-10-08")], base=True),
        build_download([build_raw_cnvd_record(2, openTime="2026-10-10")]),
        build_download(full_page),
        build_download([build_raw_cnvd_record(3, openTime="2026-10-12")]),
    ]
    clock = RawCnvdClock()
    http = RawCnvdHttp(downloads, clock)
    fetcher = http.fetcher()
    fetcher.fetch("base", tmp_path)
    first = fetcher.fetch("increment", tmp_path)

    second = fetcher.fetch("increment", tmp_path)

    assert first["since"] == "2026-10-07"
    assert second["since"] == "2026-10-09"
    assert second["high_water"] == "2026-10-12"
    assert second["page_count"] == "2"
    assert second["record_count"] == "101"
    assert len((tmp_path / second["file"]).read_bytes().splitlines()) == 101
    assert "per_page=100&page=1" in http.calls[2][0]
    assert "page=2" in http.calls[3][0]
    assert [call[1] for call in http.calls] == [0.0, 1.0, 2.0, 3.0]
    assert clock.sleeps == [1.0, 1.0, 1.0]


@pytest.mark.parametrize(
    "failure",
    [
        OSError("synthetic connection failure"),
        KeyboardInterrupt(),
        HttpDownload(200, {}, io.BytesIO(b"{broken json")),
        HttpDownload(200, {}, io.BytesIO(b'{"wrapped": []}')),
        build_download([{"wrapped": {"number": "CNVD-9999-0001"}}]),
        build_download([], status=403),
    ],
    ids=["connection", "interrupt", "json", "page-shape", "record-shape", "status"],
)
def test_failure_after_full_page_leaves_no_file_or_provenance_row(
    tmp_path: Path, failure: HttpDownload | BaseException
) -> None:
    full_page = []
    for number in range(100):
        full_page.append(build_raw_cnvd_record(number + 10))
    http = RawCnvdHttp(
        [
            build_download([build_raw_cnvd_record(1)], base=True),
            build_download(full_page),
            failure,
        ],
        RawCnvdClock(),
    )
    fetcher = http.fetcher()
    fetcher.fetch("base", tmp_path)
    files_before = sorted(tmp_path.iterdir())
    provenance_before = (tmp_path / "provenance.tsv").read_bytes()

    with pytest.raises((OSError, ValueError, KeyboardInterrupt)):
        fetcher.fetch("increment", tmp_path)

    assert sorted(tmp_path.iterdir()) == files_before
    assert (tmp_path / "provenance.tsv").read_bytes() == provenance_before


def test_zero_records_adds_a_row_without_a_file_and_keeps_high_water(tmp_path: Path) -> None:
    http = RawCnvdHttp(
        [
            build_download([build_raw_cnvd_record(1)], base=True),
            build_download([]),
        ],
        RawCnvdClock(),
    )
    fetcher = http.fetcher()
    fetcher.fetch("base", tmp_path)

    row = fetcher.fetch("increment", tmp_path)

    assert row["record_count"] == "0"
    assert row["file"] == ""
    assert row["bytes"] == "0"
    assert row["file_sha256"] == hashlib.sha256(b"").hexdigest()
    assert row["high_water"] == "2026-10-02"
    assert len(read_provenance(tmp_path)) == 2
    assert list(tmp_path.glob("*.ndjson")) == [tmp_path / "base.ndjson"]


@pytest.mark.parametrize(
    ("status", "retry_after", "expected_delay"),
    [(429, "4", 4.0), (503, "Sat, 24 Oct 2026 10:00:05 GMT", 5.0), (500, None, 1.0)],
)
def test_one_polite_retry_honours_retry_after(
    tmp_path: Path, status: int, retry_after: str | None, expected_delay: float
) -> None:
    headers = {"retry-after": retry_after} if retry_after else {}
    http = RawCnvdHttp(
        [
            build_download([], status=status, headers=headers),
            build_download([build_raw_cnvd_record(1)], base=True),
        ],
        RawCnvdClock(),
    )

    row = http.fetcher().fetch("base", tmp_path)

    assert [call[1] for call in http.calls] == [0.0, expected_delay]
    assert row["request_count"] == "2"
    assert row["http_429_count"] == ("1" if status == 429 else "0")


def test_repeated_server_error_fails_after_one_retry_and_publishes_nothing(tmp_path: Path) -> None:
    http = RawCnvdHttp(
        [
            build_download([], status=503),
            build_download([], status=503),
        ],
        RawCnvdClock(),
    )

    with pytest.raises(ValueError, match="HTTP 503"):
        http.fetcher().fetch("base", tmp_path)

    assert len(http.calls) == 2
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "download",
    [
        HttpDownload(200, {}, io.BytesIO(b"invalid JSON\n")),
        HttpDownload(200, {"content-length": "100"}, io.BytesIO(b"")),
    ],
    ids=["invalid-json", "truncated-body"],
)
def test_invalid_base_publishes_no_file_or_provenance(
    tmp_path: Path, download: HttpDownload
) -> None:
    http = RawCnvdHttp([download], RawCnvdClock())

    with pytest.raises(ValueError):
        http.fetcher().fetch("base", tmp_path)

    assert list(tmp_path.iterdir()) == []


def test_manifest_orders_raw_inputs_resolves_paths_and_imports_later_record(tmp_path: Path) -> None:
    inputs, stores = write_cnvd_nvd_inputs(tmp_path)
    nvd_manifest = write_inputs_manifest(
        inputs,
        [
            build_declaration("nvdcve-2.0-9999.json"),
            build_declaration("nvdcve-2.0-modified.json"),
        ],
    )
    feeds = tmp_path / "feeds"
    manifest = tmp_path / "combined.yaml"
    http = RawCnvdHttp(
        [
            build_download([build_raw_cnvd_record(1)], base=True),
            build_download(
                [build_raw_cnvd_record(1, products=[], formalWay="SYNTHETIC: replacement")]
            ),
            build_download([]),
        ],
        RawCnvdClock(),
    )
    fetcher = http.fetcher()
    assert main(["base", str(feeds)], fetcher=fetcher) == 0
    assert main(["increment", str(feeds)], fetcher=fetcher) == 0
    assert main(["increment", str(feeds)], fetcher=fetcher) == 0

    assert (
        main(
            [
                "manifest",
                str(feeds),
                "--inputs",
                str(nvd_manifest),
                "--output",
                str(manifest),
            ],
            fetcher=fetcher,
        )
        == 0
    )
    report = run_test_migration(manifest, stores / "raw")

    declarations = yaml.safe_load(manifest.read_text())["inputs"]
    assert len(declarations) == 4
    assert declarations[0]["path"] == str(inputs / "nvdcve-2.0-9999.json")
    assert declarations[2]["path"] == str(feeds / "base.ndjson")
    assert "increment-" in declarations[3]["path"]
    assert declarations[2]["retrieved_at"] < declarations[3]["retrieved_at"]
    assert report.outcome is MigrationOutcome.IMPORTED, report.failure
    corpus = load_corpus_store(stores / "raw")
    entry = corpus.records[0].cnvd[0]
    assert entry.products == ()
    assert entry.handling_advice == "SYNTHETIC: replacement"


def test_manifest_refuses_pinned_cnvd_without_writing(tmp_path: Path) -> None:
    manifest = write_inputs_manifest(
        tmp_path, [build_declaration("train.parquet", source="circl-cnvd")]
    )
    target = tmp_path / "combined.yaml"

    with pytest.raises(ValueError, match="circl-cnvd"):
        write_manifest(tmp_path / "feeds", manifest, target)

    assert not target.exists()


def test_increment_without_base_is_refused_before_http(tmp_path: Path) -> None:
    http = RawCnvdHttp([], RawCnvdClock())

    with pytest.raises(ValueError, match="base first"):
        http.fetcher().fetch("increment", tmp_path)

    assert http.calls == []
    assert list(tmp_path.iterdir()) == []
