"""The input manifest's contract (ADR 0008 §2): a declaration's ``retrieved_at`` is RFC 3339
text with an offset and at most six fractional digits, never a parsed datetime; only an
NVD input declares an artifact; a manifest names at most one cisa-kev input and at most
the capped number of inputs."""

from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from tests.support.legacy_inputs import build_declaration
from vulnwitness.domain.corpus_store_manifest import NvdArtifact, NvdFeedFormat
from vulnwitness.domain.migration_inputs import (
    MAX_MANIFEST_BYTES,
    MAX_MANIFEST_INPUTS,
    MAX_MANIFEST_PATH_CHARS,
    InputDeclaration,
    InputsManifest,
)


def build_manifest_fields(declarations: list[dict[str, Any]]) -> dict[str, Any]:
    return {"format_version": 1, "inputs": declarations}


def build_nvd_declarations(count: int) -> list[dict[str, Any]]:
    declarations: list[dict[str, Any]] = []
    for index in range(count):
        declarations.append(build_declaration(f"feeds/feed-{index}.json.gz"))
    return declarations


@pytest.mark.parametrize(
    ("retrieved_at", "expected_instant"),
    [
        ("2026-10-24T08:30:00Z", datetime(2026, 10, 24, 8, 30, tzinfo=UTC)),
        ("2026-10-24T10:30:00+02:00", datetime(2026, 10, 24, 8, 30, tzinfo=UTC)),
        ("2026-10-24T03:30:00-05:00", datetime(2026, 10, 24, 8, 30, tzinfo=UTC)),
        (
            "2026-10-24T08:30:00.123456Z",
            datetime(2026, 10, 24, 8, 30, 0, 123456, tzinfo=UTC),
        ),
        ("2026-10-24T08:30:00.5+00:00", datetime(2026, 10, 24, 8, 30, 0, 500000, tzinfo=UTC)),
    ],
    ids=["utc_z", "positive_offset", "negative_offset", "six_fraction_digits", "one_digit"],
)
def test_rfc3339_retrieval_time_is_read_as_its_instant(
    retrieved_at: str, expected_instant: datetime
) -> None:
    declaration = InputDeclaration.model_validate(
        build_declaration("feeds/nvdcve-2.0-2024.json.gz", retrieved_at=retrieved_at)
    )

    assert declaration.retrieved_at == expected_instant


@pytest.mark.parametrize(
    "retrieved_at",
    ["0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"],
    ids=["year_one_east_of_utc", "year_9999_west_of_utc"],
)
def test_retrieval_time_outside_the_years_utc_can_express_is_refused(retrieved_at: str) -> None:
    declaration_fields = build_declaration(
        "feeds/nvdcve-2.0-2024.json.gz", retrieved_at=retrieved_at
    )

    with pytest.raises(ValidationError, match="outside the years UTC can express"):
        InputDeclaration.model_validate(declaration_fields)


@pytest.mark.parametrize(
    ("retrieved_at", "expected_instant"),
    [
        ("0001-01-01T00:00:00Z", datetime(1, 1, 1, tzinfo=UTC)),
        ("9999-12-31T23:59:59Z", datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC)),
    ],
    ids=["first_utc_second", "last_utc_second"],
)
def test_retrieval_time_at_the_edge_of_the_utc_years_is_accepted(
    retrieved_at: str, expected_instant: datetime
) -> None:
    declaration = InputDeclaration.model_validate(
        build_declaration("feeds/nvdcve-2.0-2024.json.gz", retrieved_at=retrieved_at)
    )

    assert declaration.retrieved_at == expected_instant


def test_retrieval_time_keeps_the_declared_offset() -> None:
    declaration = InputDeclaration.model_validate(
        build_declaration("feeds/nvdcve-2.0-2024.json.gz", retrieved_at="2026-10-24T10:30:00+02:00")
    )

    assert declaration.retrieved_at.utcoffset() == timedelta(hours=2)


@pytest.mark.parametrize(
    "retrieved_at",
    [
        "2026-10-24T08:30:00",
        "2026-10-24 08:30:00Z",
        "2026-10-24T08:30:00.1234567Z",
        "2026-10-24",
        "2026-10-24T08:30Z",
        "2026-10-24t08:30:00Z",
        "2026-10-24T08:30:00z",
        "2026-10-24T08:30:00+0200",
        "2026-10-24T08:30:00Z\n",
        "2026-02-30T08:30:00Z",
        "1729758600",
        "",
    ],
    ids=[
        "naive",
        "space_separator",
        "seven_fraction_digits",
        "date_only",
        "no_seconds",
        "lower_case_t",
        "lower_case_z",
        "offset_without_colon",
        "trailing_newline",
        "impossible_date",
        "epoch_seconds_text",
        "empty",
    ],
)
def test_retrieval_time_that_is_not_rfc3339_text_is_refused(retrieved_at: str) -> None:
    declaration_fields = build_declaration(
        "feeds/nvdcve-2.0-2024.json.gz", retrieved_at=retrieved_at
    )

    with pytest.raises(ValidationError):
        InputDeclaration.model_validate(declaration_fields)


@pytest.mark.parametrize(
    "retrieved_at",
    [
        datetime(2026, 10, 24, 8, 30, tzinfo=UTC),
        datetime(2026, 10, 24, 8, 30, tzinfo=timezone(timedelta(hours=2))),
        datetime(2026, 10, 24, 8, 30),
        1729758600,
    ],
    ids=["aware_datetime", "offset_datetime", "naive_datetime", "epoch_seconds_number"],
)
def test_retrieval_time_that_is_not_text_is_refused(retrieved_at: object) -> None:
    declaration_fields: dict[str, Any] = {
        "source": "nvd",
        "path": "feeds/nvdcve-2.0-2024.json.gz",
        "retrieved_at": retrieved_at,
    }

    with pytest.raises(ValidationError):
        InputDeclaration.model_validate(declaration_fields)


def test_nvd_input_may_declare_its_artifact() -> None:
    declaration = InputDeclaration.model_validate(
        build_declaration(
            "renamed-feed.json.gz", artifact={"format": "2.0", "series": "year", "year": 2023}
        )
    )

    assert declaration.artifact == NvdArtifact(format=NvdFeedFormat.V2_0, series="year", year=2023)


def test_kev_input_declaring_an_artifact_is_refused() -> None:
    declaration_fields = build_declaration(
        "kev.csv", source="cisa-kev", artifact={"format": "2.0", "series": "recent"}
    )

    with pytest.raises(ValidationError):
        InputDeclaration.model_validate(declaration_fields)


@pytest.mark.parametrize(
    "declaration_fields",
    [
        build_declaration("feeds/feed.json.gz", source="csaf"),
        build_declaration("feeds/feed.json.gz", source="NVD"),
        build_declaration(""),
        build_declaration("p" * (MAX_MANIFEST_PATH_CHARS + 1)),
        build_declaration("feeds/nvdcve-2.0-2024.json.gz\x00.txt"),
        build_declaration("renamed.json.gz", artifact={"format": 2.0, "series": "recent"}),
        build_declaration("renamed.json.gz", artifact={"format": "2.0", "series": "year"}),
        build_declaration("feeds/feed.json.gz", source_uri="https://nvd.example/feed"),
        {"source": "nvd", "path": "feeds/feed.json.gz"},
    ],
    ids=[
        "unknown_source",
        "source_in_upper_case",
        "empty_path",
        "path_over_the_cap",
        "path_with_nul",
        "artifact_format_as_number",
        "year_artifact_without_year",
        "free_source_uri",
        "missing_retrieval_time",
    ],
)
def test_malformed_declaration_is_refused(declaration_fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        InputDeclaration.model_validate(declaration_fields)


def test_path_at_the_cap_is_accepted() -> None:
    path = "p" * MAX_MANIFEST_PATH_CHARS

    declaration = InputDeclaration.model_validate(build_declaration(path))

    assert len(declaration.path) == MAX_MANIFEST_PATH_CHARS


def test_manifest_with_one_kev_input_is_accepted() -> None:
    manifest_fields = build_manifest_fields(
        [
            build_declaration("feeds/nvdcve-2.0-2024.json.gz"),
            build_declaration("kev.csv", "cisa-kev"),
        ]
    )

    manifest = InputsManifest.model_validate(manifest_fields)

    assert len(manifest.inputs) == 2


def test_manifest_with_two_kev_inputs_is_refused() -> None:
    manifest_fields = build_manifest_fields(
        [build_declaration("kev-a.csv", "cisa-kev"), build_declaration("kev-b.csv", "cisa-kev")]
    )

    with pytest.raises(ValidationError, match="at most one cisa-kev input"):
        InputsManifest.model_validate(manifest_fields)


def test_manifest_at_the_input_cap_is_accepted() -> None:
    manifest_fields = build_manifest_fields(build_nvd_declarations(MAX_MANIFEST_INPUTS))

    manifest = InputsManifest.model_validate(manifest_fields)

    assert len(manifest.inputs) == MAX_MANIFEST_INPUTS


@pytest.mark.parametrize(
    "manifest_fields",
    [
        build_manifest_fields(build_nvd_declarations(MAX_MANIFEST_INPUTS + 1)),
        build_manifest_fields([]),
        {"format_version": 2, "inputs": build_nvd_declarations(1)},
        {"inputs": build_nvd_declarations(1)},
        {"format_version": 1, "inputs": build_nvd_declarations(1), "target": "store"},
    ],
    ids=[
        "inputs_over_the_cap",
        "no_inputs",
        "other_format_version",
        "missing_format_version",
        "unknown_top_level_field",
    ],
)
def test_malformed_manifest_is_refused(manifest_fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        InputsManifest.model_validate(manifest_fields)


@pytest.mark.parametrize(
    ("cap", "expected_value"),
    [
        (MAX_MANIFEST_BYTES, 1024 * 1024),
        (MAX_MANIFEST_INPUTS, 128),
        (MAX_MANIFEST_PATH_CHARS, 1024),
    ],
    ids=["manifest_bytes", "inputs", "path_chars"],
)
def test_manifest_caps_are_the_adr_values(cap: int, expected_value: int) -> None:
    assert cap == expected_value
