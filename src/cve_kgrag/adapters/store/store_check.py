"""Find a named store under the root as it is now (ADR 0009 §5, §7, §8).

A store ``ACTIVE`` records is checked in a fixed order: it must be there, as a directory
and not a symbolic link; its manifest must still hash to the recorded digest, checked on
the raw manifest bytes before anything is parsed, so a store replaced under its name is
told from a broken one without verifying it; and it must then verify, its format version
read first. The digest is compared again on the bytes the verification parsed, so a
store replaced between the two reads is still refused.
"""

import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Generic, Protocol, TypeVar

from cve_kgrag.adapters.store.corpus_store import (
    CorpusStoreIntegrityError,
    UnsupportedStoreFormatError,
    read_manifest_bytes,
)
from cve_kgrag.domain.hashing import sha256_hex
from cve_kgrag.domain.store_status import StoreCondition


class ReadStore(Protocol):
    @property
    def store_manifest_sha256(self) -> str: ...


ReadStoreT = TypeVar("ReadStoreT", bound=ReadStore)


@dataclass(frozen=True)
class StoreCheck(Generic[ReadStoreT]):
    """What checking a store found: its condition, and what reading it gave when it is
    ``ok``."""

    condition: StoreCondition
    read_store: ReadStoreT | None


def check_store(
    store_root: Path,
    name: str,
    recorded_manifest_sha256: str | None,
    read_store: Callable[[Path], ReadStoreT],
) -> StoreCheck[ReadStoreT]:
    """The store named ``name`` under ``store_root``, read with ``read_store``
    (``verify_corpus_store`` or ``load_corpus_store``). ``recorded_manifest_sha256`` is
    the digest ``ACTIVE`` records for it, or ``None`` for a store being activated."""
    store_dir = store_root / name
    try:
        store_status = os.lstat(store_dir)
    except FileNotFoundError:
        return StoreCheck(StoreCondition.STORE_MISSING, None)
    except OSError:
        return StoreCheck(StoreCondition.STORE_INVALID, None)
    if not stat.S_ISDIR(store_status.st_mode):
        return StoreCheck(StoreCondition.STORE_INVALID, None)
    if recorded_manifest_sha256 is not None:
        try:
            manifest_sha256 = sha256_hex(read_manifest_bytes(store_dir))
        except (CorpusStoreIntegrityError, OSError):
            return StoreCheck(StoreCondition.STORE_INVALID, None)
        if manifest_sha256 != recorded_manifest_sha256:
            return StoreCheck(StoreCondition.STORE_CHANGED, None)
    try:
        store = read_store(store_dir)
    except UnsupportedStoreFormatError:
        return StoreCheck(StoreCondition.STORE_FORMAT_UNSUPPORTED, None)
    except (CorpusStoreIntegrityError, OSError):
        return StoreCheck(StoreCondition.STORE_INVALID, None)
    is_recorded = recorded_manifest_sha256 in (None, store.store_manifest_sha256)
    if not is_recorded:
        return StoreCheck(StoreCondition.STORE_CHANGED, None)
    return StoreCheck(StoreCondition.OK, store)
