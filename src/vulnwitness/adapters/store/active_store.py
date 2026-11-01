"""Load the store a configured root serves, at startup (ADR 0009 §9).

Startup reads ``ACTIVE`` and the store it names and writes nothing anywhere under the
root, so a read-only root serves. It never migrates, activates or rebuilds anything on
disk. A root that cannot be served refuses to start with a closed reason, never a path
or file content, and never falls back to the packaged fixture: an operator who
configured real data must not be served synthetic data instead.
"""

from collections.abc import Callable
from functools import partial
from pathlib import Path

from vulnwitness.adapters.store.active_record import (
    ActiveRecordUnreadableError,
    read_active_record,
)
from vulnwitness.adapters.store.corpus_store import CorpusStore, load_corpus_store
from vulnwitness.adapters.store.store_check import ReadStoreT, check_store
from vulnwitness.adapters.store.store_root import StoreRootUnusableError, check_store_root
from vulnwitness.domain.store_status import (
    STARTUP_REASONS,
    StoreUnavailable,
    StoreUnavailableReason,
)


def ignore_store_name(store_name: str) -> None:
    """Announces nothing: for a caller that has no one to tell a store is loading."""


def announce_and_load(announce_loading: Callable[[str], None], store_dir: Path) -> CorpusStore:
    """Tell ``announce_loading`` the store's name, then load it (``load_corpus_store``)."""
    announce_loading(store_dir.name)
    return load_corpus_store(store_dir)


def load_active_store(
    store_root: Path, announce_loading: Callable[[str], None] = ignore_store_name
) -> CorpusStore:
    """The store ``ACTIVE`` names, loaded and verified under the manifest digest it
    records. ``announce_loading`` is told the store's name once the root, ``ACTIVE`` and
    the store's manifest digest have passed their checks, just before the store, which
    can take minutes, is read. Raises ``StoreUnavailable``."""
    return read_active_store(store_root, partial(announce_and_load, announce_loading))


def read_active_store(store_root: Path, read_store: Callable[[Path], ReadStoreT]) -> ReadStoreT:
    """The store ``ACTIVE`` names, read with ``read_store`` under the manifest digest it
    records, after the same checks as at startup. Raises ``StoreUnavailable``."""
    try:
        check_store_root(store_root)
    except StoreRootUnusableError:
        raise StoreUnavailable(StoreUnavailableReason.STORE_ROOT_UNUSABLE) from None
    try:
        active_record = read_active_record(store_root)
    except ActiveRecordUnreadableError:
        raise StoreUnavailable(StoreUnavailableReason.ACTIVE_UNREADABLE) from None
    if active_record is None:
        raise StoreUnavailable(StoreUnavailableReason.NO_ACTIVE_STORE)
    active_check = check_store(
        store_root,
        active_record.active.name,
        active_record.active.store_manifest_sha256,
        read_store,
    )
    if active_check.read_store is None:
        raise StoreUnavailable(STARTUP_REASONS[active_check.condition])
    return active_check.read_store
