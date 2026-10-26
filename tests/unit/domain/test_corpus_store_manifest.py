"""The corpus store's contract (ADR 0008 §2, §3, §9): an NVD artifact names one published
feed, a standard feed file name gives its artifact and any other name gives none, an NVD
input and a KEV input each carry exactly their own provenance fields, and a store
manifest records imported data with the fixed rollback kind and scope. The contract
version it was created under and the instruction its importer gave are provenance:
bounded, never compared with this release's (ADR 0009 §15)."""

from typing import Any

import pytest
from pydantic import ValidationError

from cve_kgrag.domain.corpus_store_manifest import (
    ROLLBACK_INSTRUCTION,
    CorpusStoreManifest,
    NvdArtifact,
    NvdFeedFormat,
    StoreFile,
    StoreInput,
    read_standard_artifact,
)

INPUT_FILE_SHA256 = "a" * 64
PAYLOAD_SHA256 = "b" * 64
STORE_FILE_SHA256 = "c" * 64


def build_nvd_input_fields(**overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "source": "nvd",
        "artifact": {"format": "2.0", "series": "year", "year": 2024},
        "container": "gzip",
        "source_uri": "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2024.json.gz",
        "source_version": f"sha256:{PAYLOAD_SHA256}",
        "input_file_sha256": INPUT_FILE_SHA256,
        "payload_sha256": PAYLOAD_SHA256,
        "retrieved_at": "2026-10-24T08:30:00Z",
        "source_generated_at": "2026-10-20T00:00:00Z",
        "input_bytes": 1024,
    }
    fields.update(overrides)
    return fields


def build_kev_input_fields(**overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "source": "cisa-kev",
        "artifact": None,
        "container": "plain",
        "source_uri": "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv",
        "source_version": f"sha256:{INPUT_FILE_SHA256}",
        "input_file_sha256": INPUT_FILE_SHA256,
        "payload_sha256": None,
        "retrieved_at": "2026-10-24T08:40:00Z",
        "source_generated_at": None,
        "input_bytes": 512,
    }
    fields.update(overrides)
    return fields


def build_store_manifest_fields(**overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "schema_version": "2.0.0-dev.26",
        "created_at": "2026-10-25T12:00:00Z",
        "importer_version": "2.0.0.dev0",
        "import_identity_sha256": "d" * 64,
        "inputs_manifest_sha256": "e" * 64,
        "inputs": [build_nvd_input_fields()],
        "files": [{"path": "records.jsonl", "sha256": STORE_FILE_SHA256, "size_bytes": 10}],
        "record_count": 1,
        "anchor_count": 1,
        "rollback_instruction": ROLLBACK_INSTRUCTION,
    }
    fields.update(overrides)
    return fields


@pytest.mark.parametrize(
    ("file_name", "expected_artifact"),
    [
        ("nvdcve-2.0-2024.json", NvdArtifact(format=NvdFeedFormat.V2_0, series="year", year=2024)),
        (
            "nvdcve-2.0-2024.json.gz",
            NvdArtifact(format=NvdFeedFormat.V2_0, series="year", year=2024),
        ),
        (
            "nvdcve-2.0-2024.json.zip",
            NvdArtifact(format=NvdFeedFormat.V2_0, series="year", year=2024),
        ),
        (
            "nvdcve-1.1-2002.json.gz",
            NvdArtifact(format=NvdFeedFormat.V1_1, series="year", year=2002),
        ),
        ("nvdcve-2.0-recent.json.gz", NvdArtifact(format=NvdFeedFormat.V2_0, series="recent")),
        ("nvdcve-2.0-modified.json", NvdArtifact(format=NvdFeedFormat.V2_0, series="modified")),
        ("nvdcve-1.1-recent.json.zip", NvdArtifact(format=NvdFeedFormat.V1_1, series="recent")),
        ("nvdcve-1.1-modified.json.gz", NvdArtifact(format=NvdFeedFormat.V1_1, series="modified")),
    ],
    ids=[
        "v2_year_plain",
        "v2_year_gzip",
        "v2_year_zip",
        "v1_first_year_gzip",
        "v2_recent",
        "v2_modified",
        "v1_recent_zip",
        "v1_modified_gzip",
    ],
)
def test_standard_feed_file_name_gives_its_artifact(
    file_name: str, expected_artifact: NvdArtifact
) -> None:
    artifact = read_standard_artifact(file_name)

    assert artifact == expected_artifact


@pytest.mark.parametrize(
    "file_name",
    [
        "renamed-feed.json.gz",
        "NVDCVE-2.0-2024.json",
        "nvdcve-2.0-Recent.json",
        "nvdcve-3.0-2024.json",
        "nvdcve-2-2024.json",
        "nvdcve-2.0-24.json",
        "nvdcve-2.0-20240.json",
        "nvdcve-2.0-2024.gz",
        "nvdcve-2.0-2024.json.bz2",
        "nvdcve-2.0-2024.json.gz.zip",
        "nvdcve-2.0-2024.json\n",
        "nvdcve-2.0-meta.json",
    ],
    ids=[
        "free_name",
        "upper_case_prefix",
        "capitalised_series",
        "unknown_format",
        "format_without_minor",
        "two_digit_year",
        "five_digit_year",
        "missing_json_suffix",
        "unknown_compression",
        "two_containers",
        "trailing_newline",
        "unknown_series",
    ],
)
def test_non_standard_file_name_gives_no_artifact(file_name: str) -> None:
    artifact = read_standard_artifact(file_name)

    assert artifact is None


@pytest.mark.parametrize(
    "file_name",
    ["nvdcve-2.0-2001.json.gz", "nvdcve-1.1-1999.json", "nvdcve-2.0-0000.json"],
    ids=["year_before_first_feed", "v1_year_1999", "year_zero"],
)
def test_feed_name_with_a_year_nvd_never_published_gives_no_artifact(file_name: str) -> None:
    artifact = read_standard_artifact(file_name)

    assert artifact is None


@pytest.mark.parametrize(
    ("artifact_fields", "expected_feed_name"),
    [
        ({"format": "2.0", "series": "year", "year": 2024}, "2024"),
        ({"format": "1.1", "series": "recent"}, "recent"),
        ({"format": "2.0", "series": "modified"}, "modified"),
    ],
    ids=["year_feed", "recent_feed", "modified_feed"],
)
def test_artifact_names_its_feed_by_year_or_series(
    artifact_fields: dict[str, Any], expected_feed_name: str
) -> None:
    artifact = NvdArtifact.model_validate(artifact_fields)

    assert artifact.name_feed() == expected_feed_name


@pytest.mark.parametrize(
    "year", [2002, 2024, 9999], ids=["first_feed_year", "current_year", "last_four_digit_year"]
)
def test_year_artifact_accepts_years_from_the_first_feed(year: int) -> None:
    artifact = NvdArtifact.model_validate({"format": "2.0", "series": "year", "year": year})

    assert artifact.year == year


@pytest.mark.parametrize(
    "artifact_fields",
    [
        {"format": "2.0", "series": "year", "year": 2001},
        {"format": "2.0", "series": "year", "year": 10000},
        {"format": "2.0", "series": "year"},
        {"format": "2.0", "series": "recent", "year": 2024},
        {"format": "2.0", "series": "modified", "year": 2024},
        {"format": 2.0, "series": "recent"},
        {"format": 1.1, "series": "recent"},
        {"format": "2", "series": "recent"},
        {"format": "2.0", "series": "weekly"},
        {"format": "2.0", "series": "recent", "source_uri": "https://nvd.example/feed"},
    ],
    ids=[
        "year_before_first_feed",
        "year_past_four_digits",
        "year_series_without_year",
        "recent_series_with_year",
        "modified_series_with_year",
        "format_as_number_2_0",
        "format_as_number_1_1",
        "format_without_minor",
        "unknown_series",
        "free_source_uri",
    ],
)
def test_invalid_artifact_is_refused(artifact_fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        NvdArtifact.model_validate(artifact_fields)


@pytest.mark.parametrize(
    "input_fields",
    [build_nvd_input_fields(), build_kev_input_fields()],
    ids=["nvd_input", "kev_input"],
)
def test_input_with_its_source_fields_is_accepted(input_fields: dict[str, Any]) -> None:
    store_input = StoreInput.model_validate(input_fields)

    assert store_input.source.value == input_fields["source"]


@pytest.mark.parametrize(
    "input_fields",
    [
        build_nvd_input_fields(artifact=None),
        build_nvd_input_fields(payload_sha256=None),
        build_kev_input_fields(artifact={"format": "2.0", "series": "recent"}),
        build_kev_input_fields(payload_sha256=PAYLOAD_SHA256),
    ],
    ids=[
        "nvd_without_artifact",
        "nvd_without_payload_hash",
        "kev_with_artifact",
        "kev_with_payload_hash",
    ],
)
def test_input_with_another_sources_artifact_or_payload_fields_is_refused(
    input_fields: dict[str, Any],
) -> None:
    with pytest.raises(ValidationError):
        StoreInput.model_validate(input_fields)


def test_kev_input_with_a_generation_time_is_refused() -> None:
    input_fields = build_kev_input_fields(source_generated_at="2026-10-20T00:00:00Z")

    with pytest.raises(ValidationError):
        StoreInput.model_validate(input_fields)


@pytest.mark.parametrize("container", ["gzip", "zip"], ids=["gzip", "zip"])
def test_kev_input_in_a_compressed_container_is_refused(container: str) -> None:
    input_fields = build_kev_input_fields(container=container)

    with pytest.raises(ValidationError):
        StoreInput.model_validate(input_fields)


@pytest.mark.parametrize(
    "input_fields",
    [
        build_nvd_input_fields(source_version=f"sha256:{INPUT_FILE_SHA256}"),
        build_kev_input_fields(source_version=f"sha256:{PAYLOAD_SHA256}"),
    ],
    ids=["nvd_version_from_file_hash", "kev_version_from_another_hash"],
)
def test_input_whose_source_version_is_not_its_payload_or_file_hash_is_refused(
    input_fields: dict[str, Any],
) -> None:
    with pytest.raises(ValidationError):
        StoreInput.model_validate(input_fields)


@pytest.mark.parametrize(
    "input_fields",
    [
        build_nvd_input_fields(source_version=PAYLOAD_SHA256),
        build_nvd_input_fields(source_version=f"sha256:{'B' * 64}"),
        build_nvd_input_fields(source_version=f"md5:{'b' * 32}"),
        build_nvd_input_fields(input_file_sha256="a" * 63),
        build_nvd_input_fields(payload_sha256="g" * 64),
        build_nvd_input_fields(source_uri=""),
        build_nvd_input_fields(input_bytes=-1),
        build_nvd_input_fields(retrieved_at="2026-10-24T08:30:00"),
        build_nvd_input_fields(container="bzip2"),
        build_nvd_input_fields(source="nvd_api"),
    ],
    ids=[
        "version_without_prefix",
        "version_upper_case_hex",
        "version_other_algorithm",
        "file_hash_too_short",
        "payload_hash_not_hex",
        "empty_source_uri",
        "negative_size",
        "naive_retrieval_time",
        "unknown_container",
        "unknown_source",
    ],
)
def test_input_with_a_malformed_field_is_refused(input_fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        StoreInput.model_validate(input_fields)


@pytest.mark.parametrize(
    "path",
    ["records.jsonl", "anchors.jsonl", "kev_entries.jsonl"],
    ids=["records", "anchors", "underscored_name"],
)
def test_store_file_with_a_flat_jsonl_name_is_accepted(path: str) -> None:
    store_file = StoreFile(path=path, sha256=STORE_FILE_SHA256, size_bytes=0)

    assert store_file.path == path


@pytest.mark.parametrize(
    "path",
    [
        "../records.jsonl",
        "nested/records.jsonl",
        "/records.jsonl",
        "manifest.json",
        "Records.jsonl",
        ".jsonl",
        "records.jsonl\n",
    ],
    ids=[
        "parent_directory",
        "subdirectory",
        "absolute",
        "other_suffix",
        "upper_case",
        "no_stem",
        "trailing_newline",
    ],
)
def test_store_file_outside_the_flat_jsonl_names_is_refused(path: str) -> None:
    with pytest.raises(ValidationError):
        StoreFile(path=path, sha256=STORE_FILE_SHA256, size_bytes=0)


def test_store_manifest_records_imported_data_and_the_fixed_rollback() -> None:
    manifest = CorpusStoreManifest.model_validate(build_store_manifest_fields())

    assert (
        manifest.synthetic,
        manifest.rollback_kind,
        manifest.rollback_scope,
        manifest.rollback_instruction,
    ) == (False, "delete_unactivated_target", "before_activation_only", ROLLBACK_INSTRUCTION)


def test_rollback_instruction_is_the_servers_fixed_sentence() -> None:
    assert ROLLBACK_INSTRUCTION == (
        "Before activation, remove the newly created target directory. After activation, "
        "use cve-kgrag store rollback."
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"schema_version": "2.0.0-dev.25"},
        {"schema_version": "2.1.0"},
        {
            "rollback_instruction": (
                "Before activation, remove the newly created target directory. After "
                "activation, use the WP10 store rollback operation."
            )
        },
        {"rollback_instruction": "x" * 512},
    ],
    ids=["earlier_dev_version", "release_version", "earlier_instruction", "longest_instruction"],
)
def test_store_manifest_keeps_the_provenance_its_importer_wrote(overrides: dict[str, Any]) -> None:
    manifest = CorpusStoreManifest.model_validate(build_store_manifest_fields(**overrides))

    for field_name, value in overrides.items():
        assert getattr(manifest, field_name) == value


@pytest.mark.parametrize("missing_field", ["schema_version", "rollback_instruction"])
def test_store_manifest_without_its_provenance_is_refused(missing_field: str) -> None:
    manifest_fields = build_store_manifest_fields()
    del manifest_fields[missing_field]

    with pytest.raises(ValidationError, match=missing_field):
        CorpusStoreManifest.model_validate(manifest_fields)


@pytest.mark.parametrize(
    "manifest_fields",
    [
        build_store_manifest_fields(synthetic=True),
        build_store_manifest_fields(rollback_kind="restore_previous_store"),
        build_store_manifest_fields(rollback_scope="after_activation"),
        build_store_manifest_fields(rollback_instruction=""),
        build_store_manifest_fields(rollback_instruction="x" * 513),
        build_store_manifest_fields(rollback_instruction=ROLLBACK_INSTRUCTION + "\x00"),
        build_store_manifest_fields(rollback_instruction="\u2066" + ROLLBACK_INSTRUCTION),
        build_store_manifest_fields(schema_version="dev.26"),
        build_store_manifest_fields(schema_version="2.0.0-dev.26 "),
        build_store_manifest_fields(schema_version="9" * 30 + ".0.0"),
    ],
    ids=[
        "synthetic_store",
        "other_rollback_kind",
        "other_rollback_scope",
        "empty_instruction",
        "instruction_too_long",
        "instruction_with_a_control_character",
        "instruction_with_a_bidirectional_isolate",
        "schema_version_without_release_numbers",
        "schema_version_with_trailing_space",
        "schema_version_too_long",
    ],
)
def test_store_manifest_with_synthetic_data_or_another_rollback_is_refused(
    manifest_fields: dict[str, Any],
) -> None:
    with pytest.raises(ValidationError):
        CorpusStoreManifest.model_validate(manifest_fields)


@pytest.mark.parametrize(
    "manifest_fields",
    [
        build_store_manifest_fields(inputs=[]),
        build_store_manifest_fields(files=[]),
        build_store_manifest_fields(record_count=0),
        build_store_manifest_fields(anchor_count=0),
        build_store_manifest_fields(store_format_version=2),
        build_store_manifest_fields(created_at="2026-10-25T12:00:00"),
        build_store_manifest_fields(importer_version=""),
        build_store_manifest_fields(store_path="/srv/store"),
    ],
    ids=[
        "no_inputs",
        "no_files",
        "no_records",
        "no_anchors",
        "other_store_format",
        "naive_creation_time",
        "empty_importer_version",
        "unknown_field",
    ],
)
def test_store_manifest_with_a_malformed_field_is_refused(
    manifest_fields: dict[str, Any],
) -> None:
    with pytest.raises(ValidationError):
        CorpusStoreManifest.model_validate(manifest_fields)
