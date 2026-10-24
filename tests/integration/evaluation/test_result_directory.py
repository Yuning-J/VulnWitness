"""A result directory is new for each run, readable by its owner only, and never has a
file overwritten."""

import stat
from pathlib import Path

import pytest

from cve_kgrag.evaluation.planner_runner import REPORT_FILE_NAME
from cve_kgrag.evaluation.result_directory import ResultDirectory

OWNER_ONLY_DIRECTORY = 0o700
OWNER_ONLY_FILE = 0o600


def read_mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_result_directory_and_its_files_are_owner_only(tmp_path: Path) -> None:
    output_dir = tmp_path / "eval-results"

    result_directory = ResultDirectory.create(output_dir)
    result_directory.write("deterministic/case.json", b"{}")

    assert result_directory.path.parent == output_dir
    assert result_directory.path.name.startswith("planner-")
    assert read_mode(output_dir) == OWNER_ONLY_DIRECTORY
    assert read_mode(result_directory.path) == OWNER_ONLY_DIRECTORY
    assert read_mode(result_directory.path / "deterministic") == OWNER_ONLY_DIRECTORY
    assert read_mode(result_directory.path / "deterministic" / "case.json") == OWNER_ONLY_FILE


def test_each_run_gets_a_new_result_directory(tmp_path: Path) -> None:
    first_directory = ResultDirectory.create(tmp_path)
    second_directory = ResultDirectory.create(tmp_path)

    assert first_directory.path != second_directory.path


def test_result_file_is_never_overwritten(tmp_path: Path) -> None:
    result_directory = ResultDirectory.create(tmp_path)
    result_directory.write(REPORT_FILE_NAME, b"first")

    with pytest.raises(FileExistsError):
        result_directory.write(REPORT_FILE_NAME, b"second")

    assert (result_directory.path / REPORT_FILE_NAME).read_bytes() == b"first"


def test_output_directory_is_made_but_never_its_parents(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        ResultDirectory.create(tmp_path / "missing" / "eval-results")
