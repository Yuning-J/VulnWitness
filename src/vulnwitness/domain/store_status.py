"""The corpus stores under a store root as ``vulnwitness store`` reports them, and the
reasons a store operation or a server's startup fails (ADR 0009 §4-§9).

Nothing here names the root or holds manifest free text: a report names a store by the
name it has under the root and by its digests.
"""

import re
from enum import StrEnum
from typing import Annotated, Self

from pydantic import AfterValidator, Field, model_validator

from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.corpus_store_manifest import StoreSchemaVersion
from vulnwitness.domain.evidence import SHA256_PATTERN
from vulnwitness.domain.search import SchemaVersion

# One path component that never starts with a dot; ``ACTIVE`` in any case is refused too.
STORE_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
ACTIVE_RECORD_NAME = "ACTIVE"


def is_store_name(name: str) -> bool:
    """Whether ``name`` may name a store under the root: the pattern, and not
    ``ACTIVE`` in any letter case, so no store shadows it on a case-insensitive file
    system."""
    is_pattern_match = re.fullmatch(STORE_NAME_PATTERN, name) is not None
    return is_pattern_match and name.casefold() != ACTIVE_RECORD_NAME.casefold()


def check_store_name(name: str) -> str:
    if not is_store_name(name):
        raise ValueError("a store name is one path component, not ACTIVE in any case")
    return name


StoreName = Annotated[str, Field(pattern=STORE_NAME_PATTERN), AfterValidator(check_store_name)]


class ActiveRecordState(StrEnum):
    """Whether ``ACTIVE`` is there and readable."""

    OK = "ok"
    NO_ACTIVE_STORE = "no_active_store"
    ACTIVE_UNREADABLE = "active_unreadable"


class StoreCondition(StrEnum):
    """A store ``ACTIVE`` records, as found now: ``ok`` when its manifest still hashes to
    the recorded digest and it verifies."""

    OK = "ok"
    STORE_MISSING = "store_missing"
    STORE_CHANGED = "store_changed"
    STORE_FORMAT_UNSUPPORTED = "store_format_unsupported"
    STORE_INVALID = "store_invalid"


class ActiveStoreCondition(StrEnum):
    """The active store as found now, in the reason codes a server's startup gives."""

    OK = "ok"
    ACTIVE_STORE_MISSING = "active_store_missing"
    ACTIVE_STORE_CHANGED = "active_store_changed"
    STORE_FORMAT_UNSUPPORTED = "store_format_unsupported"
    STORE_INVALID = "store_invalid"


ACTIVE_STORE_CONDITIONS = {
    StoreCondition.OK: ActiveStoreCondition.OK,
    StoreCondition.STORE_MISSING: ActiveStoreCondition.ACTIVE_STORE_MISSING,
    StoreCondition.STORE_CHANGED: ActiveStoreCondition.ACTIVE_STORE_CHANGED,
    StoreCondition.STORE_FORMAT_UNSUPPORTED: ActiveStoreCondition.STORE_FORMAT_UNSUPPORTED,
    StoreCondition.STORE_INVALID: ActiveStoreCondition.STORE_INVALID,
}


class ServedStoreIdentity(ContractModel):
    """What a store that verifies serves, and where it came from."""

    import_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    corpus_content_sha256: str = Field(pattern=SHA256_PATTERN)
    cve_search_version: str = Field(
        min_length=1, description="The cve_search capability version a server serving it reports."
    )
    created_under_schema_version: StoreSchemaVersion = Field(
        description="The contract version the store was created under; provenance only."
    )


class ActiveStoreStatus(ContractModel):
    """The store ``ACTIVE`` names as active. ``identity`` is set exactly when it is
    ``ok``: only a store that verifies under the recorded digest has its digests shown."""

    name: StoreName
    store_manifest_sha256: str = Field(
        pattern=SHA256_PATTERN, description="The manifest digest ACTIVE records for it."
    )
    condition: ActiveStoreCondition
    identity: ServedStoreIdentity | None

    @model_validator(mode="after")
    def check_identity_shown_when_ok(self) -> Self:
        if (self.condition is ActiveStoreCondition.OK) != (self.identity is not None):
            raise ValueError("a store's identity is shown exactly when it is ok")
        return self


class PreviousStoreStatus(ContractModel):
    """The store ``ACTIVE`` names as previous, a rollback's target. ``identity`` is set
    exactly when it is ``ok``."""

    name: StoreName
    store_manifest_sha256: str = Field(
        pattern=SHA256_PATTERN, description="The manifest digest ACTIVE records for it."
    )
    condition: StoreCondition
    identity: ServedStoreIdentity | None

    @model_validator(mode="after")
    def check_identity_shown_when_ok(self) -> Self:
        if (self.condition is StoreCondition.OK) != (self.identity is not None):
            raise ValueError("a store's identity is shown exactly when it is ok")
        return self


class StoreStatus(ContractModel):
    """The stores ``ACTIVE`` records under the root, each as found now. With a readable
    record there is an active store, and a previous one or null; otherwise neither."""

    schema_version: SchemaVersion
    active_record: ActiveRecordState
    active_store: ActiveStoreStatus | None
    previous_store: PreviousStoreStatus | None

    @model_validator(mode="after")
    def check_stores_follow_the_record(self) -> Self:
        is_readable = self.active_record is ActiveRecordState.OK
        if is_readable != (self.active_store is not None):
            raise ValueError("an active store is shown exactly when ACTIVE is readable")
        if not is_readable and self.previous_store is not None:
            raise ValueError("a previous store is shown only with a readable ACTIVE")
        previous_name = None if self.previous_store is None else self.previous_store.name
        if self.active_store is not None and previous_name == self.active_store.name:
            raise ValueError("the active and previous stores have different names")
        return self


class StoreOperationFailure(StrEnum):
    """Why ``vulnwitness store`` failed (exit 1); each has a fixed sentence."""

    STORE_ROOT_UNUSABLE = "store_root_unusable"
    STORE_MISSING = "store_missing"
    STORE_CHANGED = "store_changed"
    STORE_INVALID = "store_invalid"
    STORE_FORMAT_UNSUPPORTED = "store_format_unsupported"
    ACTIVE_UNREADABLE = "active_unreadable"
    STORE_LOCK_HELD = "store_lock_held"
    ACTIVE_WRITE_FAILED = "active_write_failed"
    ACTIVE_WRITE_UNCONFIRMED = "active_write_unconfirmed"
    NO_PREVIOUS_STORE = "no_previous_store"


STORE_OPERATION_FAILURE_MESSAGES = {
    StoreOperationFailure.STORE_ROOT_UNUSABLE: (
        "the store root is missing, not a directory, a symbolic link or unreadable"
    ),
    StoreOperationFailure.STORE_MISSING: "no store has that name under the root",
    StoreOperationFailure.STORE_CHANGED: (
        "the store's manifest no longer hashes to the digest ACTIVE records"
    ),
    StoreOperationFailure.STORE_INVALID: "the store fails verification",
    StoreOperationFailure.STORE_FORMAT_UNSUPPORTED: (
        "the store's format version is not one this release reads; re-import it with this "
        "release or activate another store"
    ),
    StoreOperationFailure.ACTIVE_UNREADABLE: (
        "ACTIVE cannot be read, and is left as it is; inspect it and remove it by hand "
        "before activating again"
    ),
    StoreOperationFailure.STORE_LOCK_HELD: "another store operation is running",
    StoreOperationFailure.ACTIVE_WRITE_FAILED: "ACTIVE could not be written; it is unchanged",
    StoreOperationFailure.ACTIVE_WRITE_UNCONFIRMED: (
        "ACTIVE may already name the new store, but the change could not be confirmed; run "
        "vulnwitness store status"
    ),
    StoreOperationFailure.NO_PREVIOUS_STORE: "ACTIVE records no previous store to roll back to",
}

# A store's condition as the reason an operation on it fails.
STORE_CONDITION_FAILURES = {
    StoreCondition.STORE_MISSING: StoreOperationFailure.STORE_MISSING,
    StoreCondition.STORE_CHANGED: StoreOperationFailure.STORE_CHANGED,
    StoreCondition.STORE_FORMAT_UNSUPPORTED: StoreOperationFailure.STORE_FORMAT_UNSUPPORTED,
    StoreCondition.STORE_INVALID: StoreOperationFailure.STORE_INVALID,
}


class StoreUnavailableReason(StrEnum):
    """Why a configured store root cannot be served; a server refuses to start."""

    STORE_ROOT_UNUSABLE = "store_root_unusable"
    NO_ACTIVE_STORE = "no_active_store"
    ACTIVE_UNREADABLE = "active_unreadable"
    ACTIVE_STORE_MISSING = "active_store_missing"
    ACTIVE_STORE_CHANGED = "active_store_changed"
    STORE_INVALID = "store_invalid"
    STORE_FORMAT_UNSUPPORTED = "store_format_unsupported"


# The active store's condition as the reason startup refuses it.
STARTUP_REASONS = {
    StoreCondition.STORE_MISSING: StoreUnavailableReason.ACTIVE_STORE_MISSING,
    StoreCondition.STORE_CHANGED: StoreUnavailableReason.ACTIVE_STORE_CHANGED,
    StoreCondition.STORE_FORMAT_UNSUPPORTED: StoreUnavailableReason.STORE_FORMAT_UNSUPPORTED,
    StoreCondition.STORE_INVALID: StoreUnavailableReason.STORE_INVALID,
}


class StoreOperationFailed(Exception):
    """A store operation failed for ``failure``; nothing under the root changed unless
    ``failure`` is ``active_write_unconfirmed``."""

    def __init__(self, failure: StoreOperationFailure) -> None:
        super().__init__(failure.value)
        self.failure = failure


class StoreUnavailable(Exception):
    """The configured store root cannot be served, for ``reason``; nothing may start."""

    def __init__(self, reason: StoreUnavailableReason) -> None:
        super().__init__(reason.value)
        self.reason = reason
