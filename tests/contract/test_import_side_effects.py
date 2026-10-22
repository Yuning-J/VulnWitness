"""Importing a core module has no side effect: it writes no file, creates no directory,
uses no network and starts no process."""

import json
import os
import subprocess
import sys
from pathlib import Path

from tests.support.module_walk import (
    IMPORT_EVERY_MODULE,
    PRINT_SIDE_EFFECTS,
    RECORD_SIDE_EFFECTS,
)


def test_importing_every_core_module_writes_nothing_and_uses_no_network(
    tmp_path: Path,
) -> None:
    # -B keeps the interpreter from writing bytecode, which would otherwise be the one
    # write an import makes. The home, cache, data and temporary directories point at
    # empty directories too, so a write to a default location shows up there.
    home_directories: list[Path] = []
    for directory_name in ("home", "cache", "data", "tmp"):
        home_directory = tmp_path / directory_name
        home_directory.mkdir()
        home_directories.append(home_directory)
    working_directory = tmp_path / "work"
    working_directory.mkdir()
    environment = dict(
        os.environ,
        PYTHONDONTWRITEBYTECODE="1",
        HOME=str(home_directories[0]),
        XDG_CACHE_HOME=str(home_directories[1]),
        XDG_DATA_HOME=str(home_directories[2]),
        TMPDIR=str(home_directories[3]),
    )

    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            "-c",
            RECORD_SIDE_EFFECTS + IMPORT_EVERY_MODULE + PRINT_SIDE_EFFECTS,
        ],
        cwd=working_directory,
        env=environment,
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    )

    written_paths: list[Path] = []
    for directory in (working_directory, *home_directories):
        written_paths.extend(directory.iterdir())
    assert json.loads(completed.stdout) == []
    assert written_paths == []
