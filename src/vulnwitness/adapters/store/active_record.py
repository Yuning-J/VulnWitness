"""``<root>/ACTIVE``: which store the root serves, and the one active before it (ADR 0009
§5).

The record is canonical JSON of ``ActiveRecord``, a local file this program alone writes
and reads, so it has its own format version rather than the contract version. It is
read as untrusted input: never through a symbolic link, within ``MAX_ACTIVE_BYTES``, and
only as the exact canonical bytes of a record this release can read.
"""

from pathlib import Path
from typing import Literal, Self

from pydantic import Field, ValidationError, model_validator

from vulnwitness.adapters.regular_files import open_regular_file
from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.evidence import SHA256_PATTERN
from vulnwitness.domain.hashing import canonical_json_bytes
from vulnwitness.domain.store_status import ACTIVE_RECORD_NAME, StoreName

ACTIVE_FORMAT_VERSION: Literal[1] = 1
# Far above the largest record: two 64-character names and two digests.
MAX_ACTIVE_BYTES = 4 * 1024


class ActiveRecordUnreadableError(ValueError):
    """``ACTIVE`` is there but is not a record this release can read: not a regular file,
    a symbolic link, over the cap, not canonical JSON of the model, of another format
    version, or naming a store by a name the root's rule refuses."""


class StorePointer(ContractModel):
    """A store ``ACTIVE`` records: its name under the root and the SHA-256 of the
    manifest bytes verified when it was recorded."""

    name: StoreName
    store_manifest_sha256: str = Field(pattern=SHA256_PATTERN)


class ActiveRecord(ContractModel):
    active_format_version: Literal[1] = ACTIVE_FORMAT_VERSION
    active: StorePointer
    previous: StorePointer | None

    @model_validator(mode="after")
    def check_two_stores(self) -> Self:
        if self.previous is not None and self.previous.name == self.active.name:
            raise ValueError("the active and previous stores have different names")
        return self


def encode_active_record(active_record: ActiveRecord) -> bytes:
    return canonical_json_bytes(active_record.model_dump(mode="json"))


def read_active_record(store_root: Path) -> ActiveRecord | None:
    """The record ``ACTIVE`` holds, ``None`` when there is none. Raises
    ``ActiveRecordUnreadableError`` for one that cannot be read, any operating-system
    error but its absence included."""
    try:
        active_stream = open_regular_file(store_root / ACTIVE_RECORD_NAME)
    except FileNotFoundError:
        return None
    except OSError:
        raise ActiveRecordUnreadableError("ACTIVE cannot be opened as a regular file") from None
    try:
        with active_stream:
            record_bytes = active_stream.read(MAX_ACTIVE_BYTES + 1)
    except OSError:
        raise ActiveRecordUnreadableError("ACTIVE cannot be read") from None
    if len(record_bytes) > MAX_ACTIVE_BYTES:
        raise ActiveRecordUnreadableError("ACTIVE is larger than a record")
    try:
        active_record = ActiveRecord.model_validate_json(record_bytes)
    except ValidationError:
        raise ActiveRecordUnreadableError("ACTIVE is not a record this release reads") from None
    if encode_active_record(active_record) != record_bytes:
        raise ActiveRecordUnreadableError("ACTIVE is not the canonical form of its record")
    return active_record
