"""Proves how the importer turns a manifest's declarations into its inputs (ADR 0008 §2-§4,
§9): which NVD artifact each file is, which files it refuses, the stable sorted order and
its positions, the provenance it derives (``source_uri``, UTC ``retrieved_at``), the import
identity that names an import whatever the manifest's order or the files' location, and
the target paths it refuses because they would overlap or sit next to an input."""

import dataclasses
import os
import shutil
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from cve_kgrag.adapters.migration.input_resolution import (
    ResolvedInput,
    check_target,
    compute_import_identity,
    resolve_inputs,
)
from cve_kgrag.adapters.migration.migration_limits import MigrationLimits
from cve_kgrag.composition import load_packaged_source_registry
from cve_kgrag.domain.corpus_store_manifest import InputContainer, NvdArtifact, StoreSource
from cve_kgrag.domain.hashing import sha256_hex
from cve_kgrag.domain.migration_inputs import InputsManifest
from cve_kgrag.domain.migration_report import MigrationFailed, MigrationFailureCode
from cve_kgrag.domain.provenance import SourceRegistry
from tests.support.legacy_inputs import (
    FIXED_NOW,
    TEST_IMPORTER_VERSION,
    build_declaration,
    build_kev_row,
    build_v1_feed,
    build_v1_item,
    build_v2_entry,
    build_v2_feed,
    run_test_migration,
    write_gzip_feed,
    write_inputs_manifest,
    write_kev_csv,
    write_plain_feed,
    write_zip_feed,
)

DEFAULT_LIMITS = MigrationLimits()
V2_2024_NAME = "nvdcve-2.0-2024.json.gz"
KEV_NAME = "known_exploited_vulnerabilities.csv"


def build_manifest(declarations: list[dict[str, Any]]) -> InputsManifest:
    return InputsManifest.model_validate({"format_version": 1, "inputs": declarations})


def resolve_declarations(
    manifest_dir: Path,
    declarations: list[dict[str, Any]],
    source_registry: SourceRegistry,
    limits: MigrationLimits = DEFAULT_LIMITS,
) -> tuple[ResolvedInput, ...]:
    return resolve_inputs(
        build_manifest(declarations), manifest_dir, source_registry, FIXED_NOW, limits
    )


def write_v2_feed(path: Path, number: int) -> Path:
    """A gzipped NVD 2.0 feed whose bytes differ for every ``number``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    return write_gzip_feed(path, build_v2_feed([build_v2_entry(number)]))


def write_v1_feed(path: Path, number: int) -> Path:
    """A gzipped NVD 1.1 feed whose bytes differ for every ``number``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    return write_gzip_feed(path, build_v1_feed([build_v1_item(number)]))


def write_kev(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    return write_kev_csv(path, [build_kev_row(1)])


def stand_in_payload_hashes(inputs: tuple[ResolvedInput, ...]) -> dict[str, str | None]:
    """A payload SHA-256 for every NVD input and none for KEV, as a run maps them; the
    values stand in for real payload digests, which the identity takes as given."""
    payload_hashes: dict[str, str | None] = {}
    for resolved_input in inputs:
        input_sha256 = resolved_input.input_file.sha256
        if resolved_input.source is StoreSource.NVD:
            payload_hashes[input_sha256] = sha256_hex(f"payload {input_sha256}".encode())
        else:
            payload_hashes[input_sha256] = None
    return payload_hashes


def compute_identity(
    inputs: tuple[ResolvedInput, ...],
    source_registry: SourceRegistry,
    importer_version: str = TEST_IMPORTER_VERSION,
) -> str:
    return compute_import_identity(
        inputs, stand_in_payload_hashes(inputs), source_registry, importer_version
    )


def list_file_names(inputs: tuple[ResolvedInput, ...]) -> list[tuple[int, str]]:
    positions_and_names: list[tuple[int, str]] = []
    for resolved_input in inputs:
        positions_and_names.append((resolved_input.position, resolved_input.input_file.path.name))
    return positions_and_names


@pytest.fixture
def source_registry() -> SourceRegistry:
    return load_packaged_source_registry()


@pytest.fixture
def manifest_dir(tmp_path: Path) -> Path:
    # Resolved so the paths a test builds compare equal to the resolved paths of inputs.
    directory = tmp_path.resolve() / "inputs"
    directory.mkdir()
    return directory


@pytest.fixture
def mixed_inputs_dir(manifest_dir: Path) -> Path:
    """Five inputs of every source, format and series under ``feeds/``."""
    write_v2_feed(manifest_dir / "feeds" / "nvdcve-2.0-2024.json.gz", 1)
    write_v2_feed(manifest_dir / "feeds" / "nvdcve-2.0-2023.json.gz", 2)
    write_v2_feed(manifest_dir / "feeds" / "nvdcve-2.0-modified.json.gz", 3)
    write_v1_feed(manifest_dir / "feeds" / "nvdcve-1.1-recent.json.gz", 4)
    write_kev(manifest_dir / "feeds" / KEV_NAME)
    return manifest_dir


MIXED_DECLARATIONS = [
    build_declaration("feeds/nvdcve-2.0-2024.json.gz"),
    build_declaration("feeds/nvdcve-2.0-2023.json.gz"),
    build_declaration("feeds/nvdcve-2.0-modified.json.gz"),
    build_declaration("feeds/nvdcve-1.1-recent.json.gz"),
    build_declaration(f"feeds/{KEV_NAME}", source="cisa-kev"),
]


def reverse_declarations(declarations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    reversed_declarations: list[dict[str, Any]] = []
    for declaration in reversed(declarations):
        reversed_declarations.append(declaration)
    return reversed_declarations


# --- resolve_inputs: artifacts -------------------------------------------------------------


@pytest.mark.parametrize(
    ("file_name", "expected_artifact"),
    [
        ("nvdcve-2.0-2024.json.gz", {"format": "2.0", "series": "year", "year": 2024}),
        ("nvdcve-2.0-modified.json.zip", {"format": "2.0", "series": "modified"}),
        ("nvdcve-2.0-recent.json", {"format": "2.0", "series": "recent"}),
        ("nvdcve-1.1-2002.json.gz", {"format": "1.1", "series": "year", "year": 2002}),
        ("nvdcve-1.1-recent.json", {"format": "1.1", "series": "recent"}),
    ],
    ids=["v2_year_gzip", "v2_modified_zip", "v2_recent_plain", "v1_first_year", "v1_recent"],
)
def test_resolve_inputs_with_standard_file_name_takes_artifact_from_name(
    manifest_dir: Path,
    source_registry: SourceRegistry,
    file_name: str,
    expected_artifact: dict[str, Any],
) -> None:
    # Arrange
    write_v2_feed(manifest_dir / file_name, 1)

    # Act
    (resolved_input,) = resolve_declarations(
        manifest_dir, [build_declaration(file_name)], source_registry
    )

    # Assert
    assert resolved_input.artifact == NvdArtifact.model_validate(expected_artifact)


def test_resolve_inputs_with_nonstandard_name_takes_declared_artifact(
    manifest_dir: Path, source_registry: SourceRegistry
) -> None:
    # Arrange
    write_v2_feed(manifest_dir / "renamed-feed.json.gz", 1)
    declared_artifact = {"format": "2.0", "series": "year", "year": 2023}
    declaration = build_declaration("renamed-feed.json.gz", artifact=declared_artifact)

    # Act
    (resolved_input,) = resolve_declarations(manifest_dir, [declaration], source_registry)

    # Assert
    assert resolved_input.artifact == NvdArtifact.model_validate(declared_artifact)


def test_resolve_inputs_with_standard_name_and_agreeing_declaration_takes_that_artifact(
    manifest_dir: Path, source_registry: SourceRegistry
) -> None:
    # Arrange
    write_v2_feed(manifest_dir / V2_2024_NAME, 1)
    declared_artifact = {"format": "2.0", "series": "year", "year": 2024}
    declaration = build_declaration(V2_2024_NAME, artifact=declared_artifact)

    # Act
    (resolved_input,) = resolve_declarations(manifest_dir, [declaration], source_registry)

    # Assert
    assert resolved_input.artifact == NvdArtifact.model_validate(declared_artifact)


@pytest.mark.parametrize(
    "declared_artifact",
    [
        {"format": "1.1", "series": "year", "year": 2024},
        {"format": "2.0", "series": "modified"},
        {"format": "2.0", "series": "year", "year": 2023},
    ],
    ids=["format_differs", "series_differs", "year_differs"],
)
def test_resolve_inputs_with_standard_name_and_disagreeing_declaration_fails_artifact_conflict(
    manifest_dir: Path, source_registry: SourceRegistry, declared_artifact: dict[str, Any]
) -> None:
    # Arrange
    write_v2_feed(manifest_dir / V2_2024_NAME, 1)
    declaration = build_declaration(V2_2024_NAME, artifact=declared_artifact)

    # Act
    with pytest.raises(MigrationFailed) as failure:
        resolve_declarations(manifest_dir, [declaration], source_registry)

    # Assert
    assert failure.value.code is MigrationFailureCode.ARTIFACT_CONFLICT


@pytest.mark.parametrize(
    "file_name",
    [
        "renamed-feed.json.gz",
        "nvdcve-2.0-2024.json.bz2",
        "NVDCVE-2.0-2024.json.gz",
        "nvdcve-2.0-24.json.gz",
        "nvdcve-2.0-2024.json.gz.part",
        "nvdcve-1.0-2024.json.gz",
    ],
    ids=["free_name", "other_suffix", "upper_case", "short_year", "trailing_text", "format_1_0"],
)
def test_resolve_inputs_without_standard_name_or_declaration_fails_artifact_undeclared(
    manifest_dir: Path, source_registry: SourceRegistry, file_name: str
) -> None:
    # Arrange
    write_v2_feed(manifest_dir / file_name, 1)

    # Act
    with pytest.raises(MigrationFailed) as failure:
        resolve_declarations(manifest_dir, [build_declaration(file_name)], source_registry)

    # Assert
    assert failure.value.code is MigrationFailureCode.ARTIFACT_UNDECLARED


def test_resolve_inputs_gives_kev_input_no_artifact(
    manifest_dir: Path, source_registry: SourceRegistry
) -> None:
    # Arrange
    write_kev(manifest_dir / KEV_NAME)
    declaration = build_declaration(KEV_NAME, source="cisa-kev")

    # Act
    (resolved_input,) = resolve_declarations(manifest_dir, [declaration], source_registry)

    # Assert
    assert resolved_input.artifact is None


# --- resolve_inputs: refused files ---------------------------------------------------------


def test_resolve_inputs_with_symlinked_input_fails_not_a_regular_file(
    manifest_dir: Path, source_registry: SourceRegistry
) -> None:
    # Arrange
    write_v2_feed(manifest_dir / "real" / "renamed.json.gz", 1)
    (manifest_dir / V2_2024_NAME).symlink_to(manifest_dir / "real" / "renamed.json.gz")

    # Act
    with pytest.raises(MigrationFailed) as failure:
        resolve_declarations(manifest_dir, [build_declaration(V2_2024_NAME)], source_registry)

    # Assert
    assert failure.value.code is MigrationFailureCode.INPUT_NOT_A_REGULAR_FILE


def test_resolve_inputs_with_dangling_symlink_fails_not_a_regular_file(
    manifest_dir: Path, source_registry: SourceRegistry
) -> None:
    # Arrange
    (manifest_dir / V2_2024_NAME).symlink_to(manifest_dir / "missing.json.gz")

    # Act
    with pytest.raises(MigrationFailed) as failure:
        resolve_declarations(manifest_dir, [build_declaration(V2_2024_NAME)], source_registry)

    # Assert
    assert failure.value.code is MigrationFailureCode.INPUT_NOT_A_REGULAR_FILE


def test_resolve_inputs_with_directory_input_fails_not_a_regular_file(
    manifest_dir: Path, source_registry: SourceRegistry
) -> None:
    # Arrange
    (manifest_dir / V2_2024_NAME).mkdir()

    # Act
    with pytest.raises(MigrationFailed) as failure:
        resolve_declarations(manifest_dir, [build_declaration(V2_2024_NAME)], source_registry)

    # Assert
    assert failure.value.code is MigrationFailureCode.INPUT_NOT_A_REGULAR_FILE


def test_resolve_inputs_with_device_input_fails_not_a_regular_file(
    manifest_dir: Path, source_registry: SourceRegistry
) -> None:
    # Arrange
    declaration = build_declaration(
        "/dev/null", artifact={"format": "2.0", "series": "year", "year": 2024}
    )

    # Act
    with pytest.raises(MigrationFailed) as failure:
        resolve_declarations(manifest_dir, [declaration], source_registry)

    # Assert
    assert failure.value.code is MigrationFailureCode.INPUT_NOT_A_REGULAR_FILE


@pytest.fixture
def fifo_with_writer(manifest_dir: Path) -> Iterator[Path]:
    """A FIFO named like a feed, held open for writing so that opening it to read returns
    at once instead of waiting for a writer."""
    fifo_path = manifest_dir / V2_2024_NAME
    os.mkfifo(fifo_path)
    writer_descriptor = os.open(fifo_path, os.O_RDWR | os.O_NONBLOCK)
    try:
        yield fifo_path
    finally:
        os.close(writer_descriptor)


def test_resolve_inputs_with_fifo_input_fails_not_a_regular_file(
    manifest_dir: Path, source_registry: SourceRegistry, fifo_with_writer: Path
) -> None:
    # Arrange
    declaration = build_declaration(fifo_with_writer.name)

    # Act
    with pytest.raises(MigrationFailed) as failure:
        resolve_declarations(manifest_dir, [declaration], source_registry)

    # Assert
    assert failure.value.code is MigrationFailureCode.INPUT_NOT_A_REGULAR_FILE


def test_resolve_inputs_with_missing_input_fails_input_unreadable(
    manifest_dir: Path, source_registry: SourceRegistry
) -> None:
    # Arrange
    declaration = build_declaration(V2_2024_NAME)

    # Act
    with pytest.raises(MigrationFailed) as failure:
        resolve_declarations(manifest_dir, [declaration], source_registry)

    # Assert
    assert failure.value.code is MigrationFailureCode.INPUT_UNREADABLE


@pytest.fixture
def locked_paths() -> Iterator[list[Path]]:
    """Paths a test makes inaccessible; their permissions are restored afterwards so the
    temporary directory can be removed."""
    paths: list[Path] = []
    try:
        yield paths
    finally:
        for path in paths:
            path.chmod(0o755)


def declare_after_valid_input(manifest_dir: Path, failing_path: str) -> list[dict[str, Any]]:
    """A valid feed declared first and ``failing_path`` second, at manifest index 1."""
    write_v2_feed(manifest_dir / V2_2024_NAME, 1)
    return [build_declaration(V2_2024_NAME), build_declaration(failing_path)]


def test_resolve_inputs_with_input_under_symlink_loop_fails_not_a_regular_file_at_its_index(
    manifest_dir: Path, source_registry: SourceRegistry
) -> None:
    # Arrange
    (manifest_dir / "loop").symlink_to(manifest_dir / "loop")
    declarations = declare_after_valid_input(manifest_dir, f"loop/{V2_2024_NAME}")

    # Act
    with pytest.raises(MigrationFailed) as failure:
        resolve_declarations(manifest_dir, declarations, source_registry)

    # Assert
    assert (failure.value.code, failure.value.manifest_index) == (
        MigrationFailureCode.INPUT_NOT_A_REGULAR_FILE,
        1,
    )


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a directory whatever its mode")
def test_resolve_inputs_with_input_under_inaccessible_directory_fails_input_unreadable(
    manifest_dir: Path, source_registry: SourceRegistry, locked_paths: list[Path]
) -> None:
    # Arrange
    locked_dir = manifest_dir / "locked"
    write_v2_feed(locked_dir / "nvdcve-2.0-2023.json.gz", 2)
    locked_dir.chmod(0o000)
    locked_paths.append(locked_dir)
    declarations = declare_after_valid_input(manifest_dir, "locked/nvdcve-2.0-2023.json.gz")

    # Act
    with pytest.raises(MigrationFailed) as failure:
        resolve_declarations(manifest_dir, declarations, source_registry)

    # Assert
    assert (failure.value.code, failure.value.manifest_index) == (
        MigrationFailureCode.INPUT_UNREADABLE,
        1,
    )


def test_resolve_inputs_with_path_component_over_name_max_fails_input_unreadable(
    manifest_dir: Path, source_registry: SourceRegistry
) -> None:
    # Arrange
    overlong_name = "n" * 300 + ".json.gz"
    declarations = declare_after_valid_input(manifest_dir, overlong_name)

    # Act
    with pytest.raises(MigrationFailed) as failure:
        resolve_declarations(manifest_dir, declarations, source_registry)

    # Assert
    assert (failure.value.code, failure.value.manifest_index) == (
        MigrationFailureCode.INPUT_UNREADABLE,
        1,
    )


def test_resolve_inputs_with_file_over_cap_fails_compressed_file_too_large(
    manifest_dir: Path, source_registry: SourceRegistry
) -> None:
    # Arrange
    feed_path = write_v2_feed(manifest_dir / V2_2024_NAME, 1)
    limits = MigrationLimits(max_compressed_file_bytes=feed_path.stat().st_size - 1)

    # Act
    with pytest.raises(MigrationFailed) as failure:
        resolve_declarations(
            manifest_dir, [build_declaration(V2_2024_NAME)], source_registry, limits
        )

    # Assert
    assert failure.value.code is MigrationFailureCode.COMPRESSED_FILE_TOO_LARGE


def test_resolve_inputs_with_file_exactly_at_cap_accepts_it(
    manifest_dir: Path, source_registry: SourceRegistry
) -> None:
    # Arrange
    feed_path = write_v2_feed(manifest_dir / V2_2024_NAME, 1)
    file_size = feed_path.stat().st_size

    # Act
    (resolved_input,) = resolve_declarations(
        manifest_dir,
        [build_declaration(V2_2024_NAME)],
        source_registry,
        MigrationLimits(max_compressed_file_bytes=file_size),
    )

    # Assert
    assert resolved_input.input_file.size_bytes == file_size


@pytest.mark.parametrize(
    "second_path",
    [
        f"./feeds/{V2_2024_NAME}",
        f"feeds/../feeds/{V2_2024_NAME}",
        f"feeds//{V2_2024_NAME}",
    ],
    ids=["dot_prefix", "parent_step", "double_slash"],
)
def test_resolve_inputs_with_same_file_named_twice_fails_input_repeated(
    manifest_dir: Path, source_registry: SourceRegistry, second_path: str
) -> None:
    # Arrange
    write_v2_feed(manifest_dir / "feeds" / V2_2024_NAME, 1)
    declarations = [build_declaration(f"feeds/{V2_2024_NAME}"), build_declaration(second_path)]

    # Act
    with pytest.raises(MigrationFailed) as failure:
        resolve_declarations(manifest_dir, declarations, source_registry)

    # Assert
    assert failure.value.code is MigrationFailureCode.INPUT_REPEATED


def test_resolve_inputs_with_same_bytes_in_two_files_fails_input_bytes_repeated(
    manifest_dir: Path, source_registry: SourceRegistry
) -> None:
    # Arrange
    write_v2_feed(manifest_dir / V2_2024_NAME, 1)
    shutil.copyfile(manifest_dir / V2_2024_NAME, manifest_dir / "nvdcve-2.0-2023.json.gz")
    declarations = [
        build_declaration(V2_2024_NAME),
        build_declaration("nvdcve-2.0-2023.json.gz"),
    ]

    # Act
    with pytest.raises(MigrationFailed) as failure:
        resolve_declarations(manifest_dir, declarations, source_registry)

    # Assert
    assert failure.value.code is MigrationFailureCode.INPUT_BYTES_REPEATED


# --- resolve_inputs: retrieval time --------------------------------------------------------


@pytest.mark.parametrize(
    "retrieved_at",
    ["2026-10-25T12:00:00.000001Z", "2026-10-25T13:30:00+01:00", "2027-01-01T00:00:00Z"],
    ids=["one_microsecond_late", "late_with_offset", "next_year"],
)
def test_resolve_inputs_retrieved_after_clock_fails_retrieved_in_future(
    manifest_dir: Path, source_registry: SourceRegistry, retrieved_at: str
) -> None:
    # Arrange
    write_v2_feed(manifest_dir / V2_2024_NAME, 1)
    declaration = build_declaration(V2_2024_NAME, retrieved_at=retrieved_at)

    # Act
    with pytest.raises(MigrationFailed) as failure:
        resolve_declarations(manifest_dir, [declaration], source_registry)

    # Assert
    assert failure.value.code is MigrationFailureCode.RETRIEVED_IN_FUTURE


@pytest.mark.parametrize(
    "retrieved_at",
    ["2026-10-25T12:00:00Z", "2026-10-25T13:00:00+01:00", "2026-10-25T07:00:00-05:00"],
    ids=["utc", "east_of_utc", "west_of_utc"],
)
def test_resolve_inputs_retrieved_exactly_at_clock_accepts_input(
    manifest_dir: Path, source_registry: SourceRegistry, retrieved_at: str
) -> None:
    # Arrange
    write_v2_feed(manifest_dir / V2_2024_NAME, 1)
    declaration = build_declaration(V2_2024_NAME, retrieved_at=retrieved_at)

    # Act
    (resolved_input,) = resolve_declarations(manifest_dir, [declaration], source_registry)

    # Assert
    assert resolved_input.retrieved_at == FIXED_NOW


@pytest.mark.parametrize(
    ("retrieved_at", "expected_utc"),
    [
        ("2026-10-24T10:30:00+02:00", datetime(2026, 10, 24, 8, 30, tzinfo=UTC)),
        ("2026-10-24T03:00:00.250000-05:30", datetime(2026, 10, 24, 8, 30, 0, 250000, tzinfo=UTC)),
        ("2026-10-24T08:30:00+00:00", datetime(2026, 10, 24, 8, 30, tzinfo=UTC)),
    ],
    ids=["east_offset", "west_half_hour_offset_fraction", "zero_offset"],
)
def test_resolve_inputs_normalises_retrieved_at_to_utc(
    manifest_dir: Path, source_registry: SourceRegistry, retrieved_at: str, expected_utc: datetime
) -> None:
    # Arrange
    write_v2_feed(manifest_dir / V2_2024_NAME, 1)
    declaration = build_declaration(V2_2024_NAME, retrieved_at=retrieved_at)

    # Act
    (resolved_input,) = resolve_declarations(manifest_dir, [declaration], source_registry)

    # Assert
    assert (resolved_input.retrieved_at, resolved_input.retrieved_at.tzinfo) == (expected_utc, UTC)


# --- resolve_inputs: positions and order ---------------------------------------------------


@pytest.mark.parametrize("failing_index", [0, 1, 2], ids=["first", "middle", "last"])
def test_resolve_inputs_failure_names_the_declaration_by_its_manifest_index(
    manifest_dir: Path, source_registry: SourceRegistry, failing_index: int
) -> None:
    # Arrange
    write_v2_feed(manifest_dir / "nvdcve-2.0-2024.json.gz", 1)
    write_v2_feed(manifest_dir / "nvdcve-2.0-2023.json.gz", 2)
    write_v2_feed(manifest_dir / "undeclared.json.gz", 3)
    declarations = [
        build_declaration("nvdcve-2.0-2024.json.gz"),
        build_declaration("nvdcve-2.0-2023.json.gz"),
    ]
    declarations.insert(failing_index, build_declaration("undeclared.json.gz"))

    # Act
    with pytest.raises(MigrationFailed) as failure:
        resolve_declarations(manifest_dir, declarations, source_registry)

    # Assert
    assert (failure.value.code, failure.value.manifest_index, failure.value.input_position) == (
        MigrationFailureCode.ARTIFACT_UNDECLARED,
        failing_index,
        None,
    )


def test_resolve_inputs_sorts_by_source_then_format_series_and_year(
    mixed_inputs_dir: Path, source_registry: SourceRegistry
) -> None:
    # Arrange
    declarations = MIXED_DECLARATIONS

    # Act
    inputs = resolve_declarations(mixed_inputs_dir, declarations, source_registry)

    # Assert
    assert list_file_names(inputs) == [
        (0, KEV_NAME),
        (1, "nvdcve-1.1-recent.json.gz"),
        (2, "nvdcve-2.0-modified.json.gz"),
        (3, "nvdcve-2.0-2023.json.gz"),
        (4, "nvdcve-2.0-2024.json.gz"),
    ]


def test_resolve_inputs_gives_same_order_and_positions_for_reversed_manifest(
    mixed_inputs_dir: Path, source_registry: SourceRegistry
) -> None:
    # Arrange
    forward_inputs = resolve_declarations(mixed_inputs_dir, MIXED_DECLARATIONS, source_registry)

    # Act
    reversed_inputs = resolve_declarations(
        mixed_inputs_dir, reverse_declarations(MIXED_DECLARATIONS), source_registry
    )

    # Assert
    assert reversed_inputs == forward_inputs


def test_resolve_inputs_orders_inputs_of_one_artifact_by_file_sha256(
    manifest_dir: Path, source_registry: SourceRegistry
) -> None:
    # Arrange
    same_artifact = {"format": "2.0", "series": "year", "year": 2024}
    declarations: list[dict[str, Any]] = []
    for number in range(1, 5):
        write_v2_feed(manifest_dir / f"copy-{number}.json.gz", number)
        declarations.append(build_declaration(f"copy-{number}.json.gz", artifact=same_artifact))

    # Act
    inputs = resolve_declarations(manifest_dir, declarations, source_registry)

    # Assert
    file_hashes: list[str] = []
    for resolved_input in inputs:
        file_hashes.append(resolved_input.input_file.sha256)
    assert file_hashes == sorted(file_hashes)


# --- resolve_inputs: source_uri ------------------------------------------------------------


@pytest.mark.parametrize(
    ("file_name", "source", "expected_source_uri"),
    [
        (
            "nvdcve-2.0-2024.json.gz",
            "nvd",
            "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2024.json.gz",
        ),
        (
            "nvdcve-2.0-modified.json.zip",
            "nvd",
            "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz",
        ),
        (
            "nvdcve-2.0-recent.json",
            "nvd",
            "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz",
        ),
        (
            "nvdcve-1.1-2019.json",
            "nvd",
            "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2019.json.gz",
        ),
        (
            KEV_NAME,
            "cisa-kev",
            "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv",
        ),
    ],
    ids=["v2_year_gzip", "v2_modified_zip", "v2_recent_plain", "v1_year_plain", "kev"],
)
def test_resolve_inputs_builds_source_uri_from_registry_template(
    manifest_dir: Path,
    source_registry: SourceRegistry,
    file_name: str,
    source: str,
    expected_source_uri: str,
) -> None:
    # Arrange
    if file_name.endswith(".zip"):
        write_zip_feed(manifest_dir / file_name, build_v2_feed([build_v2_entry(1)]))
    elif source == "cisa-kev":
        write_kev(manifest_dir / file_name)
    else:
        write_plain_feed(manifest_dir / file_name, build_v2_feed([build_v2_entry(1)]))
    declaration = build_declaration(file_name, source=source)

    # Act
    (resolved_input,) = resolve_declarations(manifest_dir, [declaration], source_registry)

    # Assert
    assert resolved_input.source_uri == expected_source_uri


def test_resolve_inputs_builds_source_uri_of_declared_artifact_not_local_name(
    manifest_dir: Path, source_registry: SourceRegistry
) -> None:
    # Arrange
    write_v2_feed(manifest_dir / "renamed-feed.json.gz", 1)
    declaration = build_declaration(
        "renamed-feed.json.gz", artifact={"format": "2.0", "series": "year", "year": 2023}
    )

    # Act
    (resolved_input,) = resolve_declarations(manifest_dir, [declaration], source_registry)

    # Assert
    assert (
        resolved_input.source_uri
        == "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2023.json.gz"
    )


# --- compute_import_identity ---------------------------------------------------------------


def test_compute_import_identity_is_equal_for_reordered_declarations(
    mixed_inputs_dir: Path, source_registry: SourceRegistry
) -> None:
    # Arrange
    forward_inputs = resolve_declarations(mixed_inputs_dir, MIXED_DECLARATIONS, source_registry)
    reversed_inputs = resolve_declarations(
        mixed_inputs_dir, reverse_declarations(MIXED_DECLARATIONS), source_registry
    )

    # Act
    forward_identity = compute_identity(forward_inputs, source_registry)
    reversed_identity = compute_identity(reversed_inputs, source_registry)

    # Assert
    assert forward_identity == reversed_identity


def test_compute_import_identity_is_equal_for_files_moved_to_another_directory(
    tmp_path: Path, mixed_inputs_dir: Path, source_registry: SourceRegistry
) -> None:
    # Arrange
    moved_dir = tmp_path.resolve() / "elsewhere" / "deeper"
    moved_dir.mkdir(parents=True)
    moved_declarations: list[dict[str, Any]] = []
    for declaration in MIXED_DECLARATIONS:
        file_name = Path(declaration["path"]).name
        shutil.copyfile(mixed_inputs_dir / declaration["path"], moved_dir / file_name)
        moved_declarations.append({**declaration, "path": file_name})
    original_inputs = resolve_declarations(mixed_inputs_dir, MIXED_DECLARATIONS, source_registry)
    moved_inputs = resolve_declarations(moved_dir, moved_declarations, source_registry)

    # Act
    original_identity = compute_identity(original_inputs, source_registry)
    moved_identity = compute_identity(moved_inputs, source_registry)

    # Assert
    assert original_identity == moved_identity


@pytest.mark.parametrize(
    "same_instant",
    [
        "2026-10-24T10:30:00+02:00",
        "2026-10-24T03:00:00-05:30",
        "2026-10-24T08:30:00+00:00",
        "2026-10-24T08:30:00.000000Z",
    ],
    ids=["east_offset", "west_half_hour_offset", "zero_offset", "zero_fraction"],
)
def test_compute_import_identity_is_equal_for_offsets_naming_same_instant(
    manifest_dir: Path, source_registry: SourceRegistry, same_instant: str
) -> None:
    # Arrange
    write_v2_feed(manifest_dir / V2_2024_NAME, 1)
    utc_inputs = resolve_declarations(
        manifest_dir,
        [build_declaration(V2_2024_NAME, retrieved_at="2026-10-24T08:30:00Z")],
        source_registry,
    )
    offset_inputs = resolve_declarations(
        manifest_dir,
        [build_declaration(V2_2024_NAME, retrieved_at=same_instant)],
        source_registry,
    )

    # Act
    utc_identity = compute_identity(utc_inputs, source_registry)
    offset_identity = compute_identity(offset_inputs, source_registry)

    # Assert
    assert utc_identity == offset_identity


def test_compute_import_identity_differs_when_retrieved_at_differs(
    manifest_dir: Path, source_registry: SourceRegistry
) -> None:
    # Arrange
    write_v2_feed(manifest_dir / V2_2024_NAME, 1)
    earlier_inputs = resolve_declarations(
        manifest_dir,
        [build_declaration(V2_2024_NAME, retrieved_at="2026-10-24T08:30:00Z")],
        source_registry,
    )
    later_inputs = resolve_declarations(
        manifest_dir,
        [build_declaration(V2_2024_NAME, retrieved_at="2026-10-24T08:30:01Z")],
        source_registry,
    )

    # Act
    earlier_identity = compute_identity(earlier_inputs, source_registry)
    later_identity = compute_identity(later_inputs, source_registry)

    # Assert
    assert earlier_identity != later_identity


def test_compute_import_identity_differs_when_payload_hash_differs(
    mixed_inputs_dir: Path, source_registry: SourceRegistry
) -> None:
    # Arrange
    inputs = resolve_declarations(mixed_inputs_dir, MIXED_DECLARATIONS, source_registry)
    payload_hashes = stand_in_payload_hashes(inputs)
    other_payload_hashes = dict(payload_hashes)
    other_payload_hashes[inputs[-1].input_file.sha256] = sha256_hex(b"another payload")

    # Act
    identity = compute_import_identity(
        inputs, payload_hashes, source_registry, TEST_IMPORTER_VERSION
    )
    other_identity = compute_import_identity(
        inputs, other_payload_hashes, source_registry, TEST_IMPORTER_VERSION
    )

    # Assert
    assert identity != other_identity


def test_compute_import_identity_differs_when_input_file_hash_differs(
    manifest_dir: Path, source_registry: SourceRegistry
) -> None:
    # Arrange
    write_v2_feed(manifest_dir / "first" / V2_2024_NAME, 1)
    write_v2_feed(manifest_dir / "second" / V2_2024_NAME, 2)
    first_inputs = resolve_declarations(
        manifest_dir, [build_declaration(f"first/{V2_2024_NAME}")], source_registry
    )
    second_inputs = resolve_declarations(
        manifest_dir, [build_declaration(f"second/{V2_2024_NAME}")], source_registry
    )
    shared_payload_hashes = {
        first_inputs[0].input_file.sha256: sha256_hex(b"one payload"),
        second_inputs[0].input_file.sha256: sha256_hex(b"one payload"),
    }

    # Act
    first_identity = compute_import_identity(
        first_inputs, shared_payload_hashes, source_registry, TEST_IMPORTER_VERSION
    )
    second_identity = compute_import_identity(
        second_inputs, shared_payload_hashes, source_registry, TEST_IMPORTER_VERSION
    )

    # Assert
    assert first_identity != second_identity


def test_compute_import_identity_differs_when_container_differs(
    manifest_dir: Path, source_registry: SourceRegistry
) -> None:
    # Arrange
    write_v2_feed(manifest_dir / V2_2024_NAME, 1)
    (gzip_input,) = resolve_declarations(
        manifest_dir, [build_declaration(V2_2024_NAME)], source_registry
    )
    zip_input = dataclasses.replace(
        gzip_input,
        input_file=dataclasses.replace(gzip_input.input_file, container=InputContainer.ZIP),
    )

    # Act
    gzip_identity = compute_identity((gzip_input,), source_registry)
    zip_identity = compute_identity((zip_input,), source_registry)

    # Assert
    assert gzip_identity != zip_identity


def test_compute_import_identity_differs_when_declared_artifact_differs(
    manifest_dir: Path, source_registry: SourceRegistry
) -> None:
    # Arrange
    write_v2_feed(manifest_dir / "renamed-feed.json.gz", 1)
    inputs_as_2023 = resolve_declarations(
        manifest_dir,
        [
            build_declaration(
                "renamed-feed.json.gz", artifact={"format": "2.0", "series": "year", "year": 2023}
            )
        ],
        source_registry,
    )
    inputs_as_2024 = resolve_declarations(
        manifest_dir,
        [
            build_declaration(
                "renamed-feed.json.gz", artifact={"format": "2.0", "series": "year", "year": 2024}
            )
        ],
        source_registry,
    )

    # Act
    identity_as_2023 = compute_identity(inputs_as_2023, source_registry)
    identity_as_2024 = compute_identity(inputs_as_2024, source_registry)

    # Assert
    assert identity_as_2023 != identity_as_2024


def test_compute_import_identity_differs_when_importer_version_differs(
    mixed_inputs_dir: Path, source_registry: SourceRegistry
) -> None:
    # Arrange
    inputs = resolve_declarations(mixed_inputs_dir, MIXED_DECLARATIONS, source_registry)

    # Act
    identity = compute_identity(inputs, source_registry, importer_version="2.0.0.dev0")
    other_identity = compute_identity(inputs, source_registry, importer_version="2.0.0.dev1")

    # Assert
    assert identity != other_identity


def test_compute_import_identity_differs_when_cited_registry_entry_differs(
    mixed_inputs_dir: Path, source_registry: SourceRegistry
) -> None:
    # Arrange
    inputs = resolve_declarations(mixed_inputs_dir, MIXED_DECLARATIONS, source_registry)
    registry_document = source_registry.model_dump(mode="json")
    for source_document in registry_document["sources"]:
        if source_document["name"] == "nvd":
            source_document["terms_or_license_url"] = "https://terms.example/changed"
    changed_registry = SourceRegistry.model_validate(registry_document)

    # Act
    identity = compute_identity(inputs, source_registry)
    changed_identity = compute_identity(inputs, changed_registry)

    # Assert
    assert identity != changed_identity


# --- check_target --------------------------------------------------------------------------


@dataclass(frozen=True)
class TargetLayout:
    """A run directory holding the manifest and its inputs under ``inputs/`` (feeds in
    ``inputs/feeds/``) and a legacy root at ``data/legacy``."""

    run_dir: Path
    manifest_path: Path
    inputs: tuple[ResolvedInput, ...]
    legacy_root: Path


@pytest.fixture
def target_layout(tmp_path: Path, source_registry: SourceRegistry) -> TargetLayout:
    run_dir = tmp_path.resolve() / "run"
    inputs_dir = run_dir / "inputs"
    write_v2_feed(inputs_dir / "feeds" / V2_2024_NAME, 1)
    write_kev(inputs_dir / "feeds" / KEV_NAME)
    declarations = [
        build_declaration(f"feeds/{V2_2024_NAME}"),
        build_declaration(f"feeds/{KEV_NAME}", source="cisa-kev"),
    ]
    manifest_path = write_inputs_manifest(inputs_dir, declarations)
    legacy_root = run_dir / "data" / "legacy"
    legacy_root.mkdir(parents=True)
    return TargetLayout(
        run_dir=run_dir,
        manifest_path=manifest_path,
        inputs=resolve_declarations(inputs_dir, declarations, source_registry),
        legacy_root=legacy_root,
    )


@pytest.mark.parametrize(
    "target_relative_path",
    [
        f"inputs/feeds/{V2_2024_NAME}",
        f"inputs/feeds/{KEV_NAME}",
        f"inputs/feeds/{V2_2024_NAME}/store",
        "inputs",
        "inputs/feeds",
        ".",
        "inputs/inputs.yaml",
        "inputs/inputs.yaml/store",
        "data/legacy",
        "data/legacy/store",
        "data/legacy/deeper/store",
        "data",
    ],
    ids=[
        "equals_nvd_input",
        "equals_kev_input",
        "inside_input",
        "contains_manifest_and_inputs",
        "contains_inputs",
        "contains_everything",
        "equals_manifest",
        "inside_manifest",
        "equals_legacy_root",
        "inside_legacy_root",
        "deep_inside_legacy_root",
        "contains_legacy_root",
    ],
)
def test_check_target_overlapping_protected_path_fails_target_overlaps_input(
    target_layout: TargetLayout, target_relative_path: str
) -> None:
    # Arrange
    target = (target_layout.run_dir / target_relative_path).resolve()

    # Act
    with pytest.raises(MigrationFailed) as failure:
        check_target(
            target, target_layout.manifest_path, target_layout.inputs, target_layout.legacy_root
        )

    # Assert
    assert failure.value.code is MigrationFailureCode.TARGET_OVERLAPS_INPUT


def test_check_target_whose_parent_holds_an_input_fails_target_parent_holds_input(
    target_layout: TargetLayout,
) -> None:
    # Arrange
    target = target_layout.run_dir / "inputs" / "feeds" / "store"

    # Act
    with pytest.raises(MigrationFailed) as failure:
        check_target(
            target, target_layout.manifest_path, target_layout.inputs, target_layout.legacy_root
        )

    # Assert
    assert failure.value.code is MigrationFailureCode.TARGET_PARENT_HOLDS_INPUT


@pytest.mark.parametrize(
    "target_relative_path",
    ["store", "stores/store-1", "data/store"],
    ids=["sibling_of_inputs", "own_parent_directory", "sibling_of_legacy_root"],
)
def test_check_target_clear_of_inputs_and_legacy_root_passes(
    target_layout: TargetLayout, target_relative_path: str
) -> None:
    # Arrange
    target = target_layout.run_dir / target_relative_path

    # Act and assert: the check raises no MigrationFailed
    check_target(
        target, target_layout.manifest_path, target_layout.inputs, target_layout.legacy_root
    )


def test_check_target_inside_legacy_location_without_legacy_root_passes(
    target_layout: TargetLayout,
) -> None:
    # Arrange
    target = target_layout.legacy_root / "store"

    # Act and assert: the check raises no MigrationFailed
    check_target(target, target_layout.manifest_path, target_layout.inputs, None)


def is_case_insensitive(directory: Path) -> bool:
    """Whether the file system holding ``directory`` names one file by two cases."""
    (directory / "case-probe").touch()
    return (directory / "CASE-PROBE").exists()


@pytest.mark.parametrize(
    ("target_relative_path", "expected_code"),
    [
        ("INPUTS/FEEDS/store", MigrationFailureCode.TARGET_PARENT_HOLDS_INPUT),
        ("inputs/Feeds/store", MigrationFailureCode.TARGET_PARENT_HOLDS_INPUT),
        (f"INPUTS/FEEDS/{V2_2024_NAME.upper()}", MigrationFailureCode.TARGET_OVERLAPS_INPUT),
        ("INPUTS/FEEDS", MigrationFailureCode.TARGET_OVERLAPS_INPUT),
        ("INPUTS", MigrationFailureCode.TARGET_OVERLAPS_INPUT),
        ("inputs/INPUTS.YAML", MigrationFailureCode.TARGET_OVERLAPS_INPUT),
        ("DATA/LEGACY/store", MigrationFailureCode.TARGET_OVERLAPS_INPUT),
    ],
    ids=[
        "parent_holds_input_upper_case",
        "parent_holds_input_mixed_case",
        "equals_input_upper_case",
        "contains_inputs_upper_case",
        "contains_manifest_and_inputs_upper_case",
        "equals_manifest_upper_case",
        "inside_legacy_root_upper_case",
    ],
)
def test_check_target_spelled_in_another_case_on_case_insensitive_file_system_fails(
    target_layout: TargetLayout, target_relative_path: str, expected_code: MigrationFailureCode
) -> None:
    # Arrange
    if not is_case_insensitive(target_layout.run_dir):
        pytest.skip("the file system is case-sensitive, so another case names another path")
    target = (target_layout.run_dir / target_relative_path).resolve()

    # Act
    with pytest.raises(MigrationFailed) as failure:
        check_target(
            target, target_layout.manifest_path, target_layout.inputs, target_layout.legacy_root
        )

    # Assert
    assert failure.value.code is expected_code


def test_check_target_through_symlink_to_inputs_directory_fails_target_parent_holds_input(
    target_layout: TargetLayout,
) -> None:
    # Arrange
    feeds_link = target_layout.run_dir / "feeds-link"
    feeds_link.symlink_to(target_layout.run_dir / "inputs" / "feeds")
    target = feeds_link / "store"

    # Act
    with pytest.raises(MigrationFailed) as failure:
        check_target(
            target, target_layout.manifest_path, target_layout.inputs, target_layout.legacy_root
        )

    # Assert
    assert failure.value.code is MigrationFailureCode.TARGET_PARENT_HOLDS_INPUT


@pytest.fixture
def unusable_parents(target_layout: TargetLayout, locked_paths: list[Path]) -> dict[str, Path]:
    """Directories a store cannot be created in, by why: absent, a regular file, or a
    directory the run may not write."""
    run_dir = target_layout.run_dir
    regular_file = run_dir / "regular-file"
    regular_file.write_bytes(b"SYNTHETIC")
    read_only_dir = run_dir / "read-only"
    read_only_dir.mkdir()
    read_only_dir.chmod(0o555)
    locked_paths.append(read_only_dir)
    return {"missing": run_dir / "missing", "file": regular_file, "read_only": read_only_dir}


@pytest.mark.parametrize("is_dry_run", [True, False], ids=["dry_run", "real_run"])
@pytest.mark.parametrize(
    "parent_kind",
    [
        "missing",
        "file",
        pytest.param(
            "read_only",
            marks=pytest.mark.skipif(
                os.geteuid() == 0, reason="root writes a directory whatever its mode"
            ),
        ),
    ],
    ids=["missing_parent", "parent_is_a_file", "read_only_parent"],
)
def test_migration_whose_target_parent_is_unusable_fails_target_unusable(
    target_layout: TargetLayout,
    unusable_parents: dict[str, Path],
    parent_kind: str,
    is_dry_run: bool,
) -> None:
    # Arrange
    target = unusable_parents[parent_kind] / "store"

    # Act
    report = run_test_migration(
        target_layout.manifest_path,
        target,
        legacy_root=target_layout.legacy_root,
        is_dry_run=is_dry_run,
    )

    # Assert
    assert (
        report.failure is not None and report.failure.code is MigrationFailureCode.TARGET_UNUSABLE
    )


@pytest.mark.parametrize(
    ("target_relative_path", "expected_code"),
    [
        ("feeds-link/store", MigrationFailureCode.TARGET_PARENT_HOLDS_INPUT),
        ("store/../inputs/feeds/store", MigrationFailureCode.TARGET_PARENT_HOLDS_INPUT),
        ("input-link", MigrationFailureCode.TARGET_OVERLAPS_INPUT),
        ("legacy-link/store", MigrationFailureCode.TARGET_OVERLAPS_INPUT),
    ],
    ids=[
        "symlinked_parent_holds_input",
        "parent_step_into_inputs",
        "symlink_to_input",
        "symlinked_legacy_root",
    ],
)
def test_migration_resolves_target_path_before_checking_it(
    target_layout: TargetLayout, target_relative_path: str, expected_code: MigrationFailureCode
) -> None:
    # Arrange
    run_dir = target_layout.run_dir
    (run_dir / "feeds-link").symlink_to(run_dir / "inputs" / "feeds")
    (run_dir / "input-link").symlink_to(run_dir / "inputs" / "feeds" / V2_2024_NAME)
    (run_dir / "legacy-link").symlink_to(target_layout.legacy_root)
    (run_dir / "store").mkdir()

    # Act
    report = run_test_migration(
        target_layout.manifest_path,
        run_dir / target_relative_path,
        legacy_root=target_layout.legacy_root,
        is_dry_run=True,
    )

    # Assert
    assert report.failure is not None and report.failure.code is expected_code
