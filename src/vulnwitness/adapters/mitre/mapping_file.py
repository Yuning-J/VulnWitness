"""Read a mapping, recording its digest and comparing an optional expected SHA-256."""

import json
from importlib.resources import files
from pathlib import Path

from pydantic import ValidationError

from vulnwitness.adapters.regular_files import open_regular_file
from vulnwitness.domain.hashing import sha256_hex
from vulnwitness.domain.weakness_associations import WeaknessMappingSnapshot
from vulnwitness.domain.weakness_mapping import WeaknessMapping
from vulnwitness.settings import MitreSnapshotSettings

MAX_MAPPING_BYTES = 32 * 1024 * 1024


class MitreSnapshotUnavailable(ValueError):
    """A configured snapshot cannot be served; the message gives the explicit reason."""


def parse_mapping_file(snapshot_bytes: bytes, expected_sha256: str | None) -> WeaknessMapping:
    """Compute identity before parsing; an expected digest mismatch refuses serving."""
    snapshot_sha256 = sha256_hex(snapshot_bytes)
    if expected_sha256 is not None and snapshot_sha256 != expected_sha256:
        raise MitreSnapshotUnavailable("mitre_snapshot_hash_mismatch")
    try:
        snapshot = WeaknessMappingSnapshot.model_validate_json(snapshot_bytes)
    except ValidationError:
        raise MitreSnapshotUnavailable("mitre_snapshot_invalid") from None
    return WeaknessMapping(
        snapshot, snapshot_sha256, expected_sha256_compared=expected_sha256 is not None
    )


def load_weakness_mapping(settings: MitreSnapshotSettings | None = None) -> WeaknessMapping:
    """The operator file with its computed identity, or the manifest-pinned excerpt."""
    if settings is None:
        fixture_dir = files("vulnwitness").joinpath("fixtures", "mitre")
        manifest = json.loads(fixture_dir.joinpath("manifest.json").read_bytes())
        notice_bytes = fixture_dir.joinpath("NOTICE.md").read_bytes()
        if sha256_hex(notice_bytes) != manifest["notice_sha256"]:
            raise MitreSnapshotUnavailable("mitre_snapshot_notice_hash_mismatch")
        return parse_mapping_file(
            fixture_dir.joinpath("weakness-mapping.json").read_bytes(), manifest["snapshot_sha256"]
        )
    try:
        with open_regular_file(settings.path) as snapshot_file:
            snapshot_bytes = snapshot_file.read(MAX_MAPPING_BYTES + 1)
    except OSError:
        raise MitreSnapshotUnavailable("mitre_snapshot_unreadable_or_not_regular_file") from None
    if len(snapshot_bytes) > MAX_MAPPING_BYTES:
        raise MitreSnapshotUnavailable("mitre_snapshot_too_large")
    return parse_mapping_file(snapshot_bytes, settings.sha256)


def write_mapping_file(path: Path, snapshot_bytes: bytes) -> None:
    """Create a snapshot without overwriting an input or an operator's existing file."""
    with path.open("xb") as snapshot_file:
        snapshot_file.write(snapshot_bytes)
