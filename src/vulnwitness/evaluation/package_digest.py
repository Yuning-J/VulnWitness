"""The digest that names the package a planner evaluation measured."""

from pathlib import Path

from vulnwitness.domain.hashing import canonical_sha256, sha256_hex

BYTECODE_DIR_NAME = "__pycache__"


def fingerprint_package(package_dir: Path) -> str:
    """SHA-256 of every file under ``package_dir`` but compiled bytecode, which importing
    writes: each file's path relative to it and the SHA-256 of its bytes, in path order.

    Topic cards, fixtures and FiGHT snapshots are packaged files, so a change to any of
    them, tracked or not, changes the digest, as an installed wheel's files do. Hidden and
    editor files count too: the loaders' globs match hidden files, so none is skipped as
    harmless. A symlinked directory is not followed; the package holds none. Raises
    ``OSError`` when a file cannot be read.
    """
    files_by_path: dict[str, Path] = {}
    for file_path in package_dir.rglob("*"):
        relative_path = file_path.relative_to(package_dir)
        if BYTECODE_DIR_NAME in relative_path.parts or not file_path.is_file():
            continue
        files_by_path[relative_path.as_posix()] = file_path
    file_hashes: list[list[str]] = []
    for relative_name in sorted(files_by_path):
        file_hashes.append([relative_name, sha256_hex(files_by_path[relative_name].read_bytes())])
    return canonical_sha256(file_hashes)
