"""Load the store a configured root serves, at startup (ADR 0009 §9).

Startup reads ``ACTIVE`` and the store it names and writes nothing anywhere under the
root, so a read-only root serves. It never migrates, activates or rebuilds anything on
disk. A root that cannot be served refuses to start with a closed reason, never a path
or file content, and never falls back to the packaged fixture: an operator who
configured real data must not be served synthetic data instead.
"""

from pathlib import Path

from cve_kgrag.adapters.store.active_record import (
    ActiveRecordUnreadableError,
    read_active_record,
)
from cve_kgrag.adapters.store.corpus_store import CorpusStore, load_corpus_store
from cve_kgrag.adapters.store.store_check import check_store
from cve_kgrag.adapters.store.store_root import StoreRootUnusableError, check_store_root
from cve_kgrag.domain.store_status import (
    StoreCondition,
    StoreUnavailable,
    StoreUnavailableReason,
)

STARTUP_REASONS = {
    StoreCondition.STORE_MISSING: StoreUnavailableReason.ACTIVE_STORE_MISSING,
    StoreCondition.STORE_CHANGED: StoreUnavailableReason.ACTIVE_STORE_CHANGED,
    StoreCondition.STORE_FORMAT_UNSUPPORTED: StoreUnavailableReason.STORE_FORMAT_UNSUPPORTED,
    StoreCondition.STORE_INVALID: StoreUnavailableReason.STORE_INVALID,
}


def load_active_store(store_root: Path) -> CorpusStore:
    """The store ``ACTIVE`` names, loaded and verified under the manifest digest it
    records. Raises ``StoreUnavailable``."""
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
        load_corpus_store,
    )
    if active_check.read_store is None:
        raise StoreUnavailable(STARTUP_REASONS[active_check.condition])
    return active_check.read_store
