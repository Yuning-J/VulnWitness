"""``cve-kgrag store``: validate, activate and roll back the stores under a store root,
and report them (ADR 0009 §5-§8).

Activation follows verification: a store is recorded active in ``ACTIVE`` only after
``verify_corpus_store`` accepts it, under the manifest digest that verification read.
Rollback is one level: the previous store, verified again, becomes active and the record
keeps no previous store. Every change to ``ACTIVE`` holds the root's lock from reading
the record to replacing it. Nothing here names the root.
"""

from pathlib import Path

from cve_kgrag.adapters.store.active_record import (
    ActiveRecord,
    ActiveRecordUnreadableError,
    StorePointer,
    read_active_record,
)
from cve_kgrag.adapters.store.active_record_writer import (
    ActiveRecordFiles,
    hold_store_lock,
    write_active_record,
)
from cve_kgrag.adapters.store.corpus_store import VerifiedStore, verify_corpus_store
from cve_kgrag.adapters.store.store_check import check_store
from cve_kgrag.adapters.store.store_root import StoreRootUnusableError, check_store_root
from cve_kgrag.domain.corpus_store_manifest import name_corpus_store_version
from cve_kgrag.domain.search import SCHEMA_VERSION
from cve_kgrag.domain.store_status import (
    ACTIVE_STORE_CONDITIONS,
    STORE_CONDITION_FAILURES,
    ActiveRecordState,
    ActiveStoreStatus,
    PreviousStoreStatus,
    ServedStoreIdentity,
    StoreCondition,
    StoreOperationFailed,
    StoreOperationFailure,
    StoreStatus,
)


def describe_identity(verified_store: VerifiedStore) -> ServedStoreIdentity:
    return ServedStoreIdentity(
        import_identity_sha256=verified_store.manifest.import_identity_sha256,
        corpus_content_sha256=verified_store.corpus_content_sha256,
        cve_search_version=name_corpus_store_version(verified_store.corpus_content_sha256),
        created_under_schema_version=verified_store.manifest.schema_version,
    )


class StoreActivation:
    """The store operations over one store root, writing ``ACTIVE`` through
    ``files``. Each operation raises ``StoreOperationFailed`` with its reason."""

    def __init__(self, store_root: Path, files: ActiveRecordFiles) -> None:
        self._store_root = store_root
        self._files = files

    def validate(self, name: str) -> VerifiedStore:
        """Verify the store named ``name``, changing nothing."""
        self._check_root()
        return self._verify(name, recorded_manifest_sha256=None)

    def activate(self, name: str) -> StoreStatus:
        """Verify the store named ``name`` and record it active, with the store active
        before it as the previous store; the status after the change.

        Activating the store already active verifies it again and keeps the previous
        store; ``ACTIVE`` is replaced only when the store's manifest digest differs from
        the one recorded, so a rollback still lands on the store active before it."""
        self._check_root()
        with hold_store_lock(self._store_root):
            active_record = self._read_record()
            verified_store = self._verify(name, recorded_manifest_sha256=None)
            activated_store = StorePointer(
                name=name, store_manifest_sha256=verified_store.store_manifest_sha256
            )
            next_record = self._record_activation(active_record, activated_store)
            if next_record != active_record:
                write_active_record(self._store_root, next_record, self._files)
        return StoreStatus(
            schema_version=SCHEMA_VERSION,
            active_record=ActiveRecordState.OK,
            active_store=self._describe_verified_active_store(activated_store, verified_store),
            previous_store=self._describe_previous_store(next_record.previous),
        )

    def roll_back(self) -> StoreStatus:
        """Make the previous store active again, verified again under the digest
        ``ACTIVE`` records for it, with no previous store; the status after the change."""
        self._check_root()
        with hold_store_lock(self._store_root):
            active_record = self._read_record()
            if active_record is None or active_record.previous is None:
                raise StoreOperationFailed(StoreOperationFailure.NO_PREVIOUS_STORE)
            previous_store = active_record.previous
            verified_store = self._verify(previous_store.name, previous_store.store_manifest_sha256)
            write_active_record(
                self._store_root,
                ActiveRecord(active=previous_store, previous=None),
                self._files,
            )
        return StoreStatus(
            schema_version=SCHEMA_VERSION,
            active_record=ActiveRecordState.OK,
            active_store=self._describe_verified_active_store(previous_store, verified_store),
            previous_store=None,
        )

    def describe_status(self) -> StoreStatus:
        """The stores ``ACTIVE`` records, each checked and, when its manifest matches,
        verified, so a digest shown is one a server starting now would serve."""
        self._check_root()
        try:
            active_record = read_active_record(self._store_root)
        except ActiveRecordUnreadableError:
            return StoreStatus(
                schema_version=SCHEMA_VERSION,
                active_record=ActiveRecordState.ACTIVE_UNREADABLE,
                active_store=None,
                previous_store=None,
            )
        if active_record is None:
            return StoreStatus(
                schema_version=SCHEMA_VERSION,
                active_record=ActiveRecordState.NO_ACTIVE_STORE,
                active_store=None,
                previous_store=None,
            )
        active_check = check_store(
            self._store_root,
            active_record.active.name,
            active_record.active.store_manifest_sha256,
            verify_corpus_store,
        )
        identity = None
        if active_check.read_store is not None:
            identity = describe_identity(active_check.read_store)
        return StoreStatus(
            schema_version=SCHEMA_VERSION,
            active_record=ActiveRecordState.OK,
            active_store=ActiveStoreStatus(
                name=active_record.active.name,
                store_manifest_sha256=active_record.active.store_manifest_sha256,
                condition=ACTIVE_STORE_CONDITIONS[active_check.condition],
                identity=identity,
            ),
            previous_store=self._describe_previous_store(active_record.previous),
        )

    def _check_root(self) -> None:
        try:
            check_store_root(self._store_root)
        except StoreRootUnusableError:
            raise StoreOperationFailed(StoreOperationFailure.STORE_ROOT_UNUSABLE) from None

    def _read_record(self) -> ActiveRecord | None:
        """The record, ``None`` when there is none. An unreadable one is refused and left
        as it is: a later release may have written it, and replacing it could lose that
        release's rollback target."""
        try:
            return read_active_record(self._store_root)
        except ActiveRecordUnreadableError:
            raise StoreOperationFailed(StoreOperationFailure.ACTIVE_UNREADABLE) from None

    def _verify(self, name: str, recorded_manifest_sha256: str | None) -> VerifiedStore:
        store_check = check_store(
            self._store_root, name, recorded_manifest_sha256, verify_corpus_store
        )
        if store_check.read_store is None:
            raise StoreOperationFailed(STORE_CONDITION_FAILURES[store_check.condition])
        return store_check.read_store

    def _record_activation(
        self, active_record: ActiveRecord | None, activated_store: StorePointer
    ) -> ActiveRecord:
        """The record once ``activated_store`` is active: the store active before it
        becomes the previous store, whatever state that store is in now (a rollback
        verifies it again), unless it is the same store, whose previous store is kept."""
        if active_record is None:
            return ActiveRecord(active=activated_store, previous=None)
        if active_record.active.name == activated_store.name:
            return ActiveRecord(active=activated_store, previous=active_record.previous)
        return ActiveRecord(active=activated_store, previous=active_record.active)

    def _describe_verified_active_store(
        self, active_store: StorePointer, verified_store: VerifiedStore
    ) -> ActiveStoreStatus:
        """The active store as the verification just run found it."""
        return ActiveStoreStatus(
            name=active_store.name,
            store_manifest_sha256=active_store.store_manifest_sha256,
            condition=ACTIVE_STORE_CONDITIONS[StoreCondition.OK],
            identity=describe_identity(verified_store),
        )

    def _describe_previous_store(
        self, previous_store: StorePointer | None
    ) -> PreviousStoreStatus | None:
        if previous_store is None:
            return None
        previous_check = check_store(
            self._store_root,
            previous_store.name,
            previous_store.store_manifest_sha256,
            verify_corpus_store,
        )
        identity = None
        if previous_check.read_store is not None:
            identity = describe_identity(previous_check.read_store)
        return PreviousStoreStatus(
            name=previous_store.name,
            store_manifest_sha256=previous_store.store_manifest_sha256,
            condition=previous_check.condition,
            identity=identity,
        )
