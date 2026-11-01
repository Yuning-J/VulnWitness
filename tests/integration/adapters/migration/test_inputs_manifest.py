"""Reading the operator's input manifest (ADR 0008 §2): the declaration loader keeps every
timestamp as text, so an unquoted RFC 3339 time validates as written and any other
spelling is refused; aliases, invalid YAML, a non-UTF-8 file and a file over the size cap
are refused; and every refusal is an ``InputsManifestError`` whose message lists a
bounded number of problems in the server's words, never quoting the file."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from tests.support.legacy_inputs import build_declaration, write_inputs_manifest
from vulnwitness.adapters.migration.inputs_manifest import (
    InputsManifestError,
    load_inputs_manifest,
)
from vulnwitness.domain.corpus_store_manifest import NvdArtifact, NvdFeedFormat, StoreSource
from vulnwitness.domain.evidence_set_verification_report import MAX_REPORTED_VIOLATIONS
from vulnwitness.domain.migration_inputs import MAX_MANIFEST_BYTES, MAX_MANIFEST_INPUTS

# Text no problem message could hold unless it quoted the manifest.
MARKER = "QUOTEDMARKER7f3a"
ADR_EXAMPLE_MANIFEST = b"""\
format_version: 1
inputs:
  - source: nvd
    path: feeds/nvdcve-2.0-2024.json.gz
    retrieved_at: "2026-10-24T08:30:00Z"
  - source: nvd
    path: renamed-feed.json.gz
    retrieved_at: "2026-10-24T08:35:00Z"
    artifact: {format: "2.0", series: year, year: 2023}
  - source: cisa-kev
    path: feeds/known_exploited_vulnerabilities.csv
    retrieved_at: "2026-10-24T08:40:00Z"
"""


def build_one_input_manifest(retrieved_at_text: str) -> bytes:
    """A manifest with one NVD input whose ``retrieved_at`` is written exactly as given,
    quoted or not."""
    return (
        "format_version: 1\n"
        "inputs:\n"
        "  - source: nvd\n"
        "    path: feeds/nvdcve-2.0-2024.json.gz\n"
        f"    retrieved_at: {retrieved_at_text}\n"
    ).encode()


def pad_to_size(manifest_bytes: bytes, size_bytes: int) -> bytes:
    """``manifest_bytes`` followed by a YAML comment that brings it to ``size_bytes``."""
    padding_bytes = size_bytes - len(manifest_bytes) - len(b"#\n")
    return manifest_bytes + b"#" + b"x" * padding_bytes + b"\n"


def build_manifest_with_bad_times(input_count: int) -> bytes:
    """A manifest whose ``input_count`` inputs each have a naive retrieval time."""
    lines = ["format_version: 1", "inputs:"]
    for index in range(input_count):
        lines.append("  - source: nvd")
        lines.append(f"    path: feeds/feed-{index}.json.gz")
        lines.append("    retrieved_at: 2026-10-24T08:30:00")
    return ("\n".join(lines) + "\n").encode()


def test_adr_example_manifest_loads_its_three_inputs() -> None:
    manifest = load_inputs_manifest(ADR_EXAMPLE_MANIFEST)

    sources: list[StoreSource] = []
    for declaration in manifest.inputs:
        sources.append(declaration.source)
    assert sources == [StoreSource.NVD, StoreSource.NVD, StoreSource.CISA_KEV]


def test_adr_example_manifest_keeps_the_declared_artifact() -> None:
    manifest = load_inputs_manifest(ADR_EXAMPLE_MANIFEST)

    assert manifest.inputs[1].artifact == NvdArtifact(
        format=NvdFeedFormat.V2_0, series="year", year=2023
    )


def test_manifest_written_by_the_test_builder_loads(tmp_path: Path) -> None:
    manifest_path = write_inputs_manifest(
        tmp_path, [build_declaration("feeds/nvdcve-2.0-2024.json.gz")]
    )

    manifest = load_inputs_manifest(manifest_path.read_bytes())

    assert manifest.inputs[0].retrieved_at == datetime(2026, 10, 24, 8, 30, tzinfo=UTC)


@pytest.mark.parametrize(
    ("retrieved_at_text", "expected_instant"),
    [
        ("2026-10-24T08:30:00Z", datetime(2026, 10, 24, 8, 30, tzinfo=UTC)),
        ("2026-10-24T10:30:00+02:00", datetime(2026, 10, 24, 8, 30, tzinfo=UTC)),
        (
            "2026-10-24T08:30:00.123456Z",
            datetime(2026, 10, 24, 8, 30, 0, 123456, tzinfo=UTC),
        ),
        ("'2026-10-24T08:30:00Z'", datetime(2026, 10, 24, 8, 30, tzinfo=UTC)),
    ],
    ids=["unquoted_utc", "unquoted_offset", "unquoted_six_fraction_digits", "single_quoted"],
)
def test_rfc3339_retrieval_time_validates_as_text_quoted_or_not(
    retrieved_at_text: str, expected_instant: datetime
) -> None:
    manifest = load_inputs_manifest(build_one_input_manifest(retrieved_at_text))

    assert manifest.inputs[0].retrieved_at == expected_instant


def test_unquoted_offset_time_keeps_its_offset() -> None:
    manifest = load_inputs_manifest(build_one_input_manifest("2026-10-24T10:30:00+02:00"))

    assert manifest.inputs[0].retrieved_at.utcoffset() == timedelta(hours=2)


@pytest.mark.parametrize(
    "retrieved_at_text",
    [
        "2026-10-24T08:30:00",
        "2026-10-24 08:30:00Z",
        "2026-10-24 08:30:00",
        "2026-10-24T08:30:00.1234567Z",
        "2026-10-24",
        "2026-10-24t08:30:00z",
        "!!timestamp 2026-10-24T08:30:00Z",
        "1729758600",
    ],
    ids=[
        "unquoted_naive",
        "unquoted_space_separator",
        "unquoted_space_and_naive",
        "unquoted_seven_fraction_digits",
        "unquoted_date_only",
        "unquoted_lower_case",
        "explicit_timestamp_tag",
        "epoch_seconds",
    ],
)
def test_retrieval_time_that_is_not_rfc3339_text_is_refused(retrieved_at_text: str) -> None:
    manifest_bytes = build_one_input_manifest(retrieved_at_text)

    with pytest.raises(InputsManifestError, match="retrieved_at"):
        load_inputs_manifest(manifest_bytes)


def test_manifest_with_an_alias_is_refused() -> None:
    manifest_bytes = (
        b"format_version: 1\n"
        b"inputs:\n"
        b"  - &first {source: nvd, path: a.json.gz, retrieved_at: 2026-10-24T08:30:00Z}\n"
        b"  - *first\n"
    )

    with pytest.raises(InputsManifestError, match="declaration loader"):
        load_inputs_manifest(manifest_bytes)


def test_artifact_format_written_as_a_yaml_number_is_refused() -> None:
    manifest_bytes = (
        b"format_version: 1\n"
        b"inputs:\n"
        b"  - source: nvd\n"
        b"    path: renamed-feed.json.gz\n"
        b"    retrieved_at: 2026-10-24T08:30:00Z\n"
        b"    artifact: {format: 2.0, series: recent}\n"
    )

    with pytest.raises(InputsManifestError, match="artifact"):
        load_inputs_manifest(manifest_bytes)


@pytest.mark.parametrize(
    "manifest_bytes",
    [
        b"format_version: 1\ninputs: [unclosed\n",
        b"format_version: 1\nformat_version: 1\ninputs: []\n",
        b"base: {source: nvd}\ninputs:\n  - <<: {source: nvd}\n",
        b"format_version: 1\n---\nformat_version: 1\n",
        "format_version: 1\ninputs: []\n# caf\xe9\n".encode("latin-1"),
        b"\xff\xfe\x00\x00",
    ],
    ids=[
        "syntax_error",
        "duplicate_key",
        "merge_key",
        "two_documents",
        "latin_1_text",
        "binary_bytes",
    ],
)
def test_manifest_the_declaration_loader_refuses_is_a_manifest_error(
    manifest_bytes: bytes,
) -> None:
    with pytest.raises(InputsManifestError, match="not UTF-8 YAML the declaration loader accepts"):
        load_inputs_manifest(manifest_bytes)


@pytest.mark.parametrize(
    "manifest_bytes",
    [b"", b"- source: nvd\n", b"just text\n", b"format_version: 1\n"],
    ids=["empty_file", "top_level_list", "top_level_scalar", "no_inputs"],
)
def test_document_that_is_not_a_manifest_is_a_manifest_error(manifest_bytes: bytes) -> None:
    with pytest.raises(InputsManifestError):
        load_inputs_manifest(manifest_bytes)


def test_manifest_with_two_kev_inputs_is_a_manifest_error(tmp_path: Path) -> None:
    manifest_path = write_inputs_manifest(
        tmp_path,
        [build_declaration("kev-a.csv", "cisa-kev"), build_declaration("kev-b.csv", "cisa-kev")],
    )

    with pytest.raises(InputsManifestError, match="at most one cisa-kev input"):
        load_inputs_manifest(manifest_path.read_bytes())


def test_manifest_over_the_input_cap_is_a_manifest_error(tmp_path: Path) -> None:
    declarations: list[dict[str, Any]] = []
    for index in range(MAX_MANIFEST_INPUTS + 1):
        declarations.append(build_declaration(f"feeds/feed-{index}.json.gz"))
    manifest_path = write_inputs_manifest(tmp_path, declarations)

    with pytest.raises(InputsManifestError, match=f"one to {MAX_MANIFEST_INPUTS} entries"):
        load_inputs_manifest(manifest_path.read_bytes())


def test_manifest_at_the_size_cap_loads() -> None:
    manifest_bytes = pad_to_size(
        build_one_input_manifest("2026-10-24T08:30:00Z"), MAX_MANIFEST_BYTES
    )

    manifest = load_inputs_manifest(manifest_bytes)

    assert len(manifest.inputs) == 1


def test_manifest_one_byte_over_the_size_cap_is_refused() -> None:
    manifest_bytes = pad_to_size(
        build_one_input_manifest("2026-10-24T08:30:00Z"), MAX_MANIFEST_BYTES + 1
    )

    with pytest.raises(InputsManifestError, match=f"larger than {MAX_MANIFEST_BYTES} bytes"):
        load_inputs_manifest(manifest_bytes)


def test_manifest_error_lists_at_most_the_capped_number_of_problems() -> None:
    manifest_bytes = build_manifest_with_bad_times(MAX_REPORTED_VIOLATIONS + 20)

    with pytest.raises(InputsManifestError) as raised:
        load_inputs_manifest(manifest_bytes)

    assert len(str(raised.value).split("; ")) == MAX_REPORTED_VIOLATIONS


@pytest.mark.parametrize(
    "manifest_text",
    [
        f"format_version: 1\ninputs:\n  - source: {MARKER}\n"
        "    path: a.json.gz\n    retrieved_at: 2026-10-24T08:30:00Z\n",
        "format_version: 1\ninputs:\n  - source: nvd\n"
        f"    path: a.json.gz\n    retrieved_at: {MARKER}\n",
        "format_version: 1\ninputs:\n  - source: nvd\n"
        f"    path: a.json.gz\n    retrieved_at: 2026-10-24T08:30:00Z\n    {MARKER}: 1\n",
        "format_version: 1\ninputs:\n  - source: nvd\n"
        "    path: a.json.gz\n    retrieved_at: 2026-10-24T08:30:00Z\n"
        f"    artifact: {{format: '2.0', series: {MARKER}}}\n",
        "format_version: 1\ninputs:\n  - source: nvd\n"
        "    path: a.json.gz\n    retrieved_at: 2026-10-24T08:30:00Z\n"
        f"    artifact: {{format: '2.0', series: year, year: {MARKER}}}\n",
        f"format_version: {MARKER}\ninputs:\n  - source: nvd\n"
        "    path: a.json.gz\n    retrieved_at: 2026-10-24T08:30:00Z\n",
        f"format_version: 1\n{MARKER}: true\ninputs: []\n",
        f"format_version: 1\ninputs: [{MARKER}\n",
        f"format_version: 1\nanchor: &{MARKER} x\ninputs: *{MARKER}\n",
        f"format_version: 1\n{MARKER}: 1\n{MARKER}: 2\n",
        f"{MARKER}\n",
        "format_version: 1\ninputs:\n  - source: nvd\n"
        f"    path: {MARKER * 80}\n    retrieved_at: 2026-10-24T08:30:00Z\n",
        f"#{MARKER * 70000}\n",
    ],
    ids=[
        "source_value",
        "retrieved_at_value",
        "unknown_input_key",
        "artifact_series",
        "artifact_year",
        "format_version_value",
        "unknown_top_level_key",
        "syntax_error",
        "alias",
        "duplicate_key",
        "top_level_scalar",
        "path_over_the_cap",
        "size_over_the_cap",
    ],
)
def test_manifest_error_never_quotes_the_manifest(manifest_text: str) -> None:
    with pytest.raises(InputsManifestError) as raised:
        load_inputs_manifest(manifest_text.encode())

    assert MARKER not in str(raised.value)
