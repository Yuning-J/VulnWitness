"""Seal a recorded session with an HMAC over its recorded files, and verify the seal.

``session check`` proves a session is consistent with itself, not that nobody rewrote a
response and its digest together. A seal binds ``session.json`` and every file under
``calls/`` and ``responses/``, plus ``priority.json`` when present, to a key the sealing
party holds: anyone with the key can later tell whether any of them changed, appeared
or disappeared. ``findings.yaml`` and ``triage.json`` stay editable and are not sealed.
The key never leaves its file and is identified in the seal only by a digest prefix.
"""

import hashlib
import hmac
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from vulnwitness.adapters.regular_files import open_regular_file
from vulnwitness.adapters.session.report_output import write_report
from vulnwitness.domain.hashing import canonical_json_bytes
from vulnwitness.domain.session_seal import SessionSeal

SEAL_FILE: Final = "seal.json"
SEAL_FORMAT_VERSION: Final = 1
SEALED_DIRECTORIES: Final = ("calls", "responses")
MIN_KEY_BYTES: Final = 32
MAX_KEY_BYTES: Final = 4096
MAX_SEALED_FILES: Final = 512


class SealError(ValueError):
    """The key, the session or the seal cannot be used."""


@dataclass(frozen=True)
class SealVerification:
    valid: bool
    changed: tuple[str, ...]
    added: tuple[str, ...]
    removed: tuple[str, ...]


def read_key(key_file: Path, session_directory: Path) -> bytes:
    """The key bytes; refused when short, oversized or kept inside the session."""
    if key_file.resolve().is_relative_to(session_directory.resolve()):
        raise SealError("the key file must not be inside the session directory")
    with open_regular_file(key_file) as stream:
        key = stream.read(MAX_KEY_BYTES + 1)
    if len(key) < MIN_KEY_BYTES or len(key) > MAX_KEY_BYTES:
        raise SealError(f"the key must hold {MIN_KEY_BYTES} to {MAX_KEY_BYTES} bytes")
    return key


def digest_session_files(directory: Path) -> dict[str, str]:
    """Digest session.json, optional priority.json and every entry in calls/ and responses/.

    Every selected entry must be a regular file, never a link.
    """
    paths = [directory / "session.json"]
    if os.path.lexists(directory / "priority.json"):
        paths.append(directory / "priority.json")
    for name in SEALED_DIRECTORIES:
        sealed = directory / name
        if sealed.is_dir() and not sealed.is_symlink():
            paths.extend(sorted(sealed.iterdir()))
    if len(paths) > MAX_SEALED_FILES:
        raise SealError("the session holds too many files to seal")
    digests: dict[str, str] = {}
    for path in paths:
        with open_regular_file(path) as stream:
            digests[path.relative_to(directory).as_posix()] = hashlib.file_digest(
                stream, "sha256"
            ).hexdigest()
    return digests


def compute_mac(key: bytes, files: dict[str, str]) -> str:
    payload = canonical_json_bytes({"format_version": SEAL_FORMAT_VERSION, "files": files})
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def key_id(key: bytes) -> str:
    return hashlib.sha256(b"vulnwitness-seal-key\0" + key).hexdigest()[:16]


def seal_session(directory: Path, key: bytes, force: bool) -> SessionSeal:
    target = directory / SEAL_FILE
    if os.path.lexists(target) and not force:
        raise SealError("seal.json already exists; use --force to reseal")
    files = digest_session_files(directory)
    seal = SessionSeal(
        format_version=SEAL_FORMAT_VERSION,
        algorithm="hmac-sha256",
        key_id=key_id(key),
        files=files,
        mac=compute_mac(key, files),
    )
    write_report(target, seal.model_dump_json(indent=2) + "\n", force)
    return seal


def verify_session_seal(directory: Path, key: bytes) -> SealVerification:
    try:
        with open_regular_file(directory / SEAL_FILE) as stream:
            seal = SessionSeal.model_validate_json(stream.read(1024 * 1024))
    except (OSError, ValueError, RecursionError) as error:
        raise SealError("seal.json is missing, unreadable or invalid") from error
    files = seal.files
    if seal.key_id != key_id(key):
        raise SealError("the key is not the one that sealed this session")
    mac_valid = hmac.compare_digest(compute_mac(key, files), seal.mac)
    current = digest_session_files(directory)
    changed: list[str] = []
    for name in sorted(files.keys() & current.keys()):
        if files[name] != current[name]:
            changed.append(name)
    added = tuple(sorted(current.keys() - files.keys()))
    removed = tuple(sorted(files.keys() - current.keys()))
    return SealVerification(
        valid=mac_valid and not (changed or added or removed),
        changed=tuple(changed),
        added=added,
        removed=removed,
    )
