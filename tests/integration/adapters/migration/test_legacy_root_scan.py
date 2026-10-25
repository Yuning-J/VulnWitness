"""Proves the read-only walk of a ``--legacy-root`` tree (ADR 0008 §1): it counts each kind
of legacy derived file and of file never deserialized, lists every kind, ignores what it
does not know, follows no symbolic link, never writes, and fails with its fixed reason
code when the tree passes a bound, cannot be read, or changes while it is walked."""

import json
import shutil
from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

import pytest

from cve_kgrag.adapters.migration.json_fingerprint import classify_json_prefix
from cve_kgrag.adapters.migration.legacy_root_scan import scan_legacy_root
from cve_kgrag.adapters.migration.migration_limits import MigrationLimits
from cve_kgrag.domain.migration_report import (
    LegacyFileKind,
    MigrationFailed,
    MigrationFailureCode,
)
from tests.support.legacy_inputs import (
    build_v2_entry,
    build_v2_feed,
    encode_feed,
    snapshot_tree,
)

PICKLE_BYTES = b"\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00N."
NUMPY_BYTES = b"\x93NUMPY\x01\x00v\x00{'descr': '<f4', 'fortran_order': False, 'shape': (1,), }"
UNRELATED_JSON = b'{"greeting": "SYNTHETIC"}'


def build_findings(**counts: int) -> dict[LegacyFileKind, int]:
    """Every kind with zero, but those ``counts`` names by kind value."""
    findings: dict[LegacyFileKind, int] = dict.fromkeys(LegacyFileKind, 0)
    for kind_value, count in counts.items():
        findings[LegacyFileKind(kind_value)] = count
    return findings


def write_file(path: Path, content: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def write_json(path: Path, document: object) -> Path:
    return write_file(path, json.dumps(document).encode())


def scan(legacy_root: Path, limits: MigrationLimits | None = None) -> dict[LegacyFileKind, int]:
    return scan_legacy_root(legacy_root, classify_json_prefix, limits or MigrationLimits())


@pytest.fixture
def legacy_root(tmp_path: Path) -> Path:
    root = tmp_path.resolve() / "legacy"
    root.mkdir()
    return root


@pytest.fixture
def outside_dir(tmp_path: Path) -> Path:
    """A directory beside the legacy root holding one file of every magic kind."""
    directory = tmp_path.resolve() / "outside"
    write_file(directory / "cache.pkl", PICKLE_BYTES)
    write_file(directory / "vectors.npy", NUMPY_BYTES)
    write_file(directory / "encoder.pt", b"weights")
    return directory


# --- counting ------------------------------------------------------------------------------


DERIVED_JSON_DOCUMENTS: list[tuple[str, object, str]] = [
    (
        "enhanced_documents_2099.json",
        [{"document_type": "cve", "cve_refs": ["CVE-9999-0001"], "content": "SYNTHETIC"}],
        "enhanced_documents",
    ),
    (
        "cve_documents_for_rag.json",
        [{"content": "SYNTHETIC", "metadata": {"cve_id": "CVE-9999-0001"}}],
        "rag_export",
    ),
    (
        "cpe_parsing_results.json",
        {"vendors": {"democorp": 1}, "products": {"gateway": 1}},
        "cpe_parsing_results",
    ),
    ("graph.json", {"nodes": [{"id": "CVE-9999-0001"}], "relationships": []}, "graph_export"),
    ("cve_vendor_map.json", {"CVE-9999-0001": "democorp", "CVE-9999-0002": "democorp"}, "mapping"),
    ("analytics.json", {"basic_stats": {"total_cves": 2}}, "analytics"),
]


@pytest.mark.parametrize(
    ("file_name", "document", "expected_kind"),
    DERIVED_JSON_DOCUMENTS,
    ids=[
        "enhanced_documents",
        "rag_export",
        "cpe_parsing_results",
        "graph_export",
        "mapping",
        "analytics",
    ],
)
def test_scan_legacy_root_counts_derived_json_file_by_its_structure(
    legacy_root: Path, file_name: str, document: object, expected_kind: str
) -> None:
    # Arrange
    write_json(legacy_root / "exports" / file_name, document)

    # Act
    findings = scan(legacy_root)

    # Assert
    assert findings == build_findings(**{expected_kind: 1})


def test_scan_legacy_root_classifies_json_file_after_leading_whitespace(
    legacy_root: Path,
) -> None:
    # Arrange
    write_file(legacy_root / "analytics.json", b'\n  \t{"basic_stats": {"total_cves": 2}}')

    # Act
    findings = scan(legacy_root)

    # Assert
    assert findings == build_findings(analytics=1)


@pytest.mark.parametrize(
    ("file_name", "content", "expected_kind"),
    [
        ("cache.dat", PICKLE_BYTES, "pickle"),
        ("index.pkl", b"not really a pickle", "pickle"),
        ("index.pickle", b"not really a pickle", "pickle"),
        ("INDEX.PKL", b"not really a pickle", "pickle"),
        ("vectors.dat", NUMPY_BYTES, "numpy_array"),
        ("vectors.npy", b"not really an array", "numpy_array"),
        ("vectors.npz", b"PK\x03\x04", "numpy_array"),
        ("encoder.pt", b"weights", "model_archive"),
        ("encoder.pth", b"weights", "model_archive"),
        ("encoder.bin", b"weights", "model_archive"),
        ("encoder.safetensors", b"weights", "model_archive"),
        ("encoder.h5", b"weights", "model_archive"),
        ("encoder.onnx", b"weights", "model_archive"),
        ("tokenizer.model", b"weights", "model_archive"),
        ("tokenizer.model.zip", b"PK\x03\x04", "model_archive"),
    ],
    ids=[
        "pickle_by_magic",
        "pickle_by_pkl_suffix",
        "pickle_by_pickle_suffix",
        "pickle_by_upper_case_suffix",
        "numpy_by_magic",
        "numpy_by_npy_suffix",
        "numpy_by_npz_suffix",
        "model_pt",
        "model_pth",
        "model_bin",
        "model_safetensors",
        "model_h5",
        "model_onnx",
        "model_suffix",
        "model_zip",
    ],
)
def test_scan_legacy_root_counts_file_never_deserialized_by_magic_or_suffix(
    legacy_root: Path, file_name: str, content: bytes, expected_kind: str
) -> None:
    # Arrange
    write_file(legacy_root / "artefacts" / file_name, content)

    # Act
    findings = scan(legacy_root)

    # Assert
    assert findings == build_findings(**{expected_kind: 1})


@pytest.mark.parametrize(
    ("file_name", "content"),
    [
        ("README.txt", b"SYNTHETIC notes"),
        ("table.csv", b"cveID,product\nCVE-9999-0001,Gateway\n"),
        ("empty.json", b""),
        ("unrelated.json", UNRELATED_JSON),
        ("numbers.json", b"[1, 2, 3]"),
        ("broken.json", b"{not json at all"),
        ("archive.zip", b"PK\x03\x04"),
        ("nvdcve-2.0-2099.json", encode_feed(build_v2_feed([build_v2_entry(1)]))),
    ],
    ids=[
        "text",
        "csv",
        "empty",
        "unrelated_json_object",
        "json_list_of_numbers",
        "malformed_json",
        "plain_zip",
        "raw_nvd_feed",
    ],
)
def test_scan_legacy_root_ignores_file_of_unknown_kind(
    legacy_root: Path, file_name: str, content: bytes
) -> None:
    # Arrange
    write_file(legacy_root / file_name, content)

    # Act
    findings = scan(legacy_root)

    # Assert
    assert findings == build_findings()


def test_scan_legacy_root_counts_every_file_of_a_mixed_nested_tree(legacy_root: Path) -> None:
    # Arrange
    write_file(legacy_root / "cache" / "a.pkl", PICKLE_BYTES)
    write_file(legacy_root / "cache" / "deeper" / "b.dat", PICKLE_BYTES)
    write_file(legacy_root / "vectors" / "embeddings.npy", NUMPY_BYTES)
    write_file(legacy_root / "models" / "encoder.safetensors", b"weights")
    write_json(legacy_root / "stats" / "2098.json", {"basic_stats": {}})
    write_json(legacy_root / "stats" / "deeper" / "2099.json", {"basic_stats": {}})
    write_json(legacy_root / "stats" / "deeper" / "graph.json", {"nodes": [], "edges": []})
    write_file(legacy_root / "README.txt", b"SYNTHETIC notes")

    # Act
    findings = scan(legacy_root)

    # Assert
    assert findings == build_findings(
        pickle=2, numpy_array=1, model_archive=1, analytics=2, graph_export=1
    )


def test_scan_legacy_root_of_empty_tree_lists_every_kind_with_zero(legacy_root: Path) -> None:
    # Arrange
    (legacy_root / "empty-subdirectory").mkdir()

    # Act
    findings = scan(legacy_root)

    # Assert
    assert findings == dict.fromkeys(LegacyFileKind, 0)


def test_scan_legacy_root_classifies_long_json_file_from_its_bounded_prefix(
    legacy_root: Path,
) -> None:
    # Arrange
    long_values: list[str] = []
    for number in range(1, 200):
        long_values.append(f"CVE-9999-{number:04d}")
    write_json(legacy_root / "analytics.json", {"basic_stats": {"cves": long_values}})
    limits = MigrationLimits(max_fingerprint_file_bytes=64, max_fingerprint_total_bytes=64)

    # Act
    findings = scan(legacy_root, limits)

    # Assert
    assert findings == build_findings(analytics=1)


# --- symbolic links ------------------------------------------------------------------------


def test_scan_legacy_root_does_not_follow_symlinked_directory(
    legacy_root: Path, outside_dir: Path
) -> None:
    # Arrange
    (legacy_root / "linked-dir").symlink_to(outside_dir, target_is_directory=True)

    # Act
    findings = scan(legacy_root)

    # Assert
    assert findings == build_findings()


def test_scan_legacy_root_does_not_follow_symlink_loop(legacy_root: Path) -> None:
    # Arrange
    write_file(legacy_root / "cache.pkl", PICKLE_BYTES)
    (legacy_root / "loop").symlink_to(legacy_root, target_is_directory=True)
    limits = MigrationLimits(max_walk_depth=2, max_walk_entries=10)

    # Act
    findings = scan(legacy_root, limits)

    # Assert
    assert findings == build_findings(pickle=1)


@pytest.mark.parametrize(
    ("link_name", "target_name"),
    [("cache.pkl", "cache.pkl"), ("vectors.dat", "vectors.npy"), ("encoder.pt", "encoder.pt")],
    ids=["pickle_suffix", "numpy_magic", "model_suffix"],
)
def test_scan_legacy_root_does_not_follow_symlinked_file(
    legacy_root: Path, outside_dir: Path, link_name: str, target_name: str
) -> None:
    # Arrange
    (legacy_root / link_name).symlink_to(outside_dir / target_name)

    # Act
    findings = scan(legacy_root)

    # Assert
    assert findings == build_findings()


# --- reading never writes ------------------------------------------------------------------


def test_scan_legacy_root_leaves_tree_unchanged(legacy_root: Path) -> None:
    # Arrange
    write_file(legacy_root / "cache" / "a.pkl", PICKLE_BYTES)
    write_file(legacy_root / "vectors" / "embeddings.npy", NUMPY_BYTES)
    write_json(legacy_root / "stats" / "analytics.json", {"basic_stats": {}})
    write_file(legacy_root / "README.txt", b"SYNTHETIC notes")
    before = snapshot_tree(legacy_root)

    # Act
    scan(legacy_root)

    # Assert
    assert snapshot_tree(legacy_root) == before


# --- bounds --------------------------------------------------------------------------------


def build_nested_directories(legacy_root: Path, levels: int) -> Path:
    """``levels`` directories nested one inside the next under the root; the innermost."""
    directory = legacy_root
    for level in range(1, levels + 1):
        directory = directory / f"level-{level}"
    directory.mkdir(parents=True)
    return directory


def test_scan_legacy_root_descends_exactly_to_depth_cap(legacy_root: Path) -> None:
    # Arrange
    innermost = build_nested_directories(legacy_root, 3)
    write_file(innermost / "cache.pkl", PICKLE_BYTES)
    limits = MigrationLimits(max_walk_depth=3)

    # Act
    findings = scan(legacy_root, limits)

    # Assert
    assert findings == build_findings(pickle=1)


def test_scan_legacy_root_past_depth_cap_fails_legacy_root_too_deep(legacy_root: Path) -> None:
    # Arrange
    build_nested_directories(legacy_root, 4)
    limits = MigrationLimits(max_walk_depth=3)

    # Act
    with pytest.raises(MigrationFailed) as failure:
        scan(legacy_root, limits)

    # Assert
    assert failure.value.code is MigrationFailureCode.LEGACY_ROOT_TOO_DEEP


def write_flat_tree(legacy_root: Path) -> None:
    """Four entries: three files in the root, none of a known kind, and one directory."""
    write_file(legacy_root / "a.txt", b"SYNTHETIC a")
    write_file(legacy_root / "b.txt", b"SYNTHETIC b")
    write_file(legacy_root / "c.txt", b"SYNTHETIC c")
    (legacy_root / "d").mkdir()


def write_nested_tree(legacy_root: Path) -> None:
    """Four entries: one directory in the root holding three files."""
    write_file(legacy_root / "sub" / "a.txt", b"SYNTHETIC a")
    write_file(legacy_root / "sub" / "b.txt", b"SYNTHETIC b")
    write_file(legacy_root / "sub" / "c.txt", b"SYNTHETIC c")


@pytest.mark.parametrize("is_nested", [False, True], ids=["flat", "nested"])
def test_scan_legacy_root_examines_exactly_entry_cap(legacy_root: Path, is_nested: bool) -> None:
    # Arrange
    if is_nested:
        write_nested_tree(legacy_root)
    else:
        write_flat_tree(legacy_root)
    limits = MigrationLimits(max_walk_entries=4)

    # Act
    findings = scan(legacy_root, limits)

    # Assert
    assert findings == build_findings()


@pytest.mark.parametrize("is_nested", [False, True], ids=["flat", "nested"])
def test_scan_legacy_root_past_entry_cap_fails_legacy_root_too_many_entries(
    legacy_root: Path, is_nested: bool
) -> None:
    # Arrange
    if is_nested:
        write_nested_tree(legacy_root)
    else:
        write_flat_tree(legacy_root)
    limits = MigrationLimits(max_walk_entries=3)

    # Act
    with pytest.raises(MigrationFailed) as failure:
        scan(legacy_root, limits)

    # Assert
    assert failure.value.code is MigrationFailureCode.LEGACY_ROOT_TOO_MANY_ENTRIES


def test_scan_legacy_root_counts_symlinks_against_entry_cap(
    legacy_root: Path, outside_dir: Path
) -> None:
    # Arrange
    for number in range(1, 5):
        (legacy_root / f"link-{number}").symlink_to(outside_dir / "cache.pkl")
    limits = MigrationLimits(max_walk_entries=3)

    # Act
    with pytest.raises(MigrationFailed) as failure:
        scan(legacy_root, limits)

    # Assert
    assert failure.value.code is MigrationFailureCode.LEGACY_ROOT_TOO_MANY_ENTRIES


FINGERPRINT_FILE_BYTES = 32


def write_json_files(legacy_root: Path, count: int, content: bytes) -> None:
    for number in range(1, count + 1):
        write_file(legacy_root / f"unrelated-{number}.json", content)


def test_scan_legacy_root_reads_json_prefixes_up_to_total_budget(legacy_root: Path) -> None:
    # Arrange
    long_json = UNRELATED_JSON.ljust(FINGERPRINT_FILE_BYTES * 2)
    write_json_files(legacy_root, 2, long_json)
    limits = MigrationLimits(
        max_fingerprint_file_bytes=FINGERPRINT_FILE_BYTES,
        max_fingerprint_total_bytes=FINGERPRINT_FILE_BYTES * 2,
    )

    # Act
    findings = scan(legacy_root, limits)

    # Assert
    assert findings == build_findings()


def test_scan_legacy_root_past_total_budget_fails_legacy_root_read_budget(
    legacy_root: Path,
) -> None:
    # Arrange
    long_json = UNRELATED_JSON.ljust(FINGERPRINT_FILE_BYTES * 2)
    write_json_files(legacy_root, 3, long_json)
    limits = MigrationLimits(
        max_fingerprint_file_bytes=FINGERPRINT_FILE_BYTES,
        max_fingerprint_total_bytes=FINGERPRINT_FILE_BYTES * 2,
    )

    # Act
    with pytest.raises(MigrationFailed) as failure:
        scan(legacy_root, limits)

    # Assert
    assert failure.value.code is MigrationFailureCode.LEGACY_ROOT_READ_BUDGET


def test_scan_legacy_root_short_json_files_within_total_budget_pass(legacy_root: Path) -> None:
    # Arrange
    write_json_files(legacy_root, 2, UNRELATED_JSON)
    limits = MigrationLimits(
        max_fingerprint_file_bytes=FINGERPRINT_FILE_BYTES,
        max_fingerprint_total_bytes=len(UNRELATED_JSON) * 2,
    )

    # Act
    findings = scan(legacy_root, limits)

    # Assert
    assert findings == build_findings()


def test_scan_legacy_root_does_not_charge_magic_files_to_fingerprint_budget(
    legacy_root: Path,
) -> None:
    # Arrange
    for number in range(1, 4):
        write_file(legacy_root / f"cache-{number}.pkl", PICKLE_BYTES.ljust(64, b"."))
    limits = MigrationLimits(max_fingerprint_file_bytes=16, max_fingerprint_total_bytes=16)

    # Act
    findings = scan(legacy_root, limits)

    # Assert
    assert findings == build_findings(pickle=3)


# --- unreadable entries --------------------------------------------------------------------


@pytest.fixture
def locked_paths() -> Iterator[list[Path]]:
    """Paths a test makes unreadable; their permissions are restored afterwards so the
    temporary directory can be removed."""
    paths: list[Path] = []
    try:
        yield paths
    finally:
        for path in paths:
            path.chmod(0o755)


@pytest.mark.parametrize(
    "locked_relative_path",
    [".", "locked-dir", "nested/locked-dir"],
    ids=["root", "subdirectory", "nested_subdirectory"],
)
def test_scan_legacy_root_with_unreadable_directory_fails_legacy_root_unreadable(
    legacy_root: Path, locked_paths: list[Path], locked_relative_path: str
) -> None:
    # Arrange
    locked_dir = legacy_root / locked_relative_path
    write_file(locked_dir / "cache.pkl", PICKLE_BYTES)
    locked_dir.chmod(0o000)
    locked_paths.append(locked_dir)

    # Act
    with pytest.raises(MigrationFailed) as failure:
        scan(legacy_root)

    # Assert
    assert failure.value.code is MigrationFailureCode.LEGACY_ROOT_UNREADABLE


class RootDefect(StrEnum):
    MISSING = "missing"
    REGULAR_FILE = "regular_file"
    SYMLINK_TO_DIRECTORY = "symlink_to_directory"


def place_defective_root(root_path: Path, defect: RootDefect, real_dir: Path) -> None:
    """Nothing at ``root_path``, a regular file, or a symbolic link to ``real_dir``."""
    if defect is RootDefect.REGULAR_FILE:
        write_file(root_path, PICKLE_BYTES)
    elif defect is RootDefect.SYMLINK_TO_DIRECTORY:
        root_path.symlink_to(real_dir, target_is_directory=True)


@pytest.mark.parametrize(
    "defect",
    [RootDefect.MISSING, RootDefect.REGULAR_FILE, RootDefect.SYMLINK_TO_DIRECTORY],
    ids=["missing", "regular_file", "symlink_to_directory"],
)
def test_scan_legacy_root_that_is_not_a_directory_fails_legacy_root_unreadable(
    tmp_path: Path, outside_dir: Path, defect: RootDefect
) -> None:
    # Arrange
    root_path = tmp_path.resolve() / "legacy-root"
    place_defective_root(root_path, defect, outside_dir)

    # Act
    with pytest.raises(MigrationFailed) as failure:
        scan(root_path)

    # Assert
    assert failure.value.code is MigrationFailureCode.LEGACY_ROOT_UNREADABLE


@pytest.mark.parametrize(
    "locked_name", ["cache.pkl", "analytics.json"], ids=["magic_kind", "json_kind"]
)
def test_scan_legacy_root_with_unreadable_file_fails_legacy_root_unreadable(
    legacy_root: Path, locked_paths: list[Path], locked_name: str
) -> None:
    # Arrange
    locked_file = write_file(legacy_root / locked_name, PICKLE_BYTES)
    locked_file.chmod(0o000)
    locked_paths.append(locked_file)

    # Act
    with pytest.raises(MigrationFailed) as failure:
        scan(legacy_root)

    # Assert
    assert failure.value.code is MigrationFailureCode.LEGACY_ROOT_UNREADABLE


# --- changes during the walk ---------------------------------------------------------------


class MidWalkChange(StrEnum):
    REMOVE = "remove"
    REPLACE_WITH_SYMLINK = "replace_with_symlink"
    REPLACE_WITH_DIRECTORY = "replace_with_directory"


def apply_change(changed_path: Path, change: MidWalkChange, link_target: Path) -> None:
    if changed_path.is_dir() and not changed_path.is_symlink():
        shutil.rmtree(changed_path)
    else:
        changed_path.unlink()
    if change is MidWalkChange.REPLACE_WITH_SYMLINK:
        changed_path.symlink_to(link_target)
    elif change is MidWalkChange.REPLACE_WITH_DIRECTORY:
        changed_path.mkdir()


@dataclass
class ChangingClassifier:
    """Classifies nothing; the first time the walk asks it about a JSON prefix it applies
    ``change`` to ``changed_path``, as another process could while the walk is under way."""

    changed_path: Path
    change: MidWalkChange
    link_target: Path
    has_changed: bool = False

    def __call__(self, prefix: bytes) -> LegacyFileKind | None:
        if not self.has_changed:
            self.has_changed = True
            apply_change(self.changed_path, self.change, self.link_target)
        return None


@pytest.mark.parametrize(
    ("changed_name", "change"),
    [
        ("b-cache.pkl", MidWalkChange.REMOVE),
        ("z-subdirectory", MidWalkChange.REMOVE),
        ("b-cache.pkl", MidWalkChange.REPLACE_WITH_SYMLINK),
        ("b-cache.pkl", MidWalkChange.REPLACE_WITH_DIRECTORY),
    ],
    ids=[
        "file_removed",
        "directory_removed",
        "file_replaced_by_symlink",
        "file_replaced_by_directory",
    ],
)
def test_scan_legacy_root_with_entry_changed_after_listing_fails_legacy_root_changed(
    legacy_root: Path, outside_dir: Path, changed_name: str, change: MidWalkChange
) -> None:
    # Arrange
    write_file(legacy_root / "a-unrelated.json", UNRELATED_JSON)
    write_file(legacy_root / "b-cache.pkl", PICKLE_BYTES)
    write_file(legacy_root / "z-subdirectory" / "c-cache.pkl", PICKLE_BYTES)
    classifier = ChangingClassifier(
        changed_path=legacy_root / changed_name,
        change=change,
        link_target=outside_dir / "cache.pkl",
    )

    # Act
    with pytest.raises(MigrationFailed) as failure:
        scan_legacy_root(legacy_root, classifier, MigrationLimits())

    # Assert
    assert failure.value.code is MigrationFailureCode.LEGACY_ROOT_CHANGED
