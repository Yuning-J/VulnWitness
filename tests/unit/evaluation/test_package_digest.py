"""The package digest changes with any packaged file's content, tracked or not, and is
the same for the same content wherever it lies."""

from pathlib import Path

from tests.support.evaluation import build_package_dir
from vulnwitness.evaluation.package_digest import fingerprint_package


def test_package_digest_tells_apart_two_changes_to_the_same_file(tmp_path: Path) -> None:
    first_package_dir = build_package_dir(tmp_path / "first")
    second_package_dir = build_package_dir(tmp_path / "second")
    (first_package_dir / "__init__.py").write_text("VERSION = 1\n", encoding="utf-8")
    (second_package_dir / "__init__.py").write_text("VERSION = 2\n", encoding="utf-8")

    first_digest = fingerprint_package(first_package_dir)
    second_digest = fingerprint_package(second_package_dir)

    assert first_digest != second_digest


def test_package_digest_counts_a_data_file_no_repository_tracks(tmp_path: Path) -> None:
    package_dir = build_package_dir(tmp_path)
    digest_before = fingerprint_package(package_dir)
    (package_dir / "knowledge" / "extra_card.yaml").write_text("name: extra\n", encoding="utf-8")

    digest_after = fingerprint_package(package_dir)

    assert digest_after != digest_before


def test_package_digest_is_the_content_wherever_the_package_lies_and_ignores_bytecode(
    tmp_path: Path,
) -> None:
    package_dir = build_package_dir(tmp_path / "checkout")
    installed_package_dir = build_package_dir(tmp_path / "site-packages")
    (installed_package_dir / "__pycache__").mkdir()
    (installed_package_dir / "__pycache__" / "__init__.cpython-312.pyc").write_bytes(b"\x00")

    assert fingerprint_package(installed_package_dir) == fingerprint_package(package_dir)
