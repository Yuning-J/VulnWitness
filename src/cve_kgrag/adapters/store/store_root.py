"""The store root: the directory holding the corpus stores and ``ACTIVE`` (ADR 0009 §4).

A store lives directly under the root, named by one path component. The name rule keeps
every hidden entry (a migration's ``.<name>.partial-*`` and ``.<name>.staging-*``
siblings, the root's ``.lock`` and temporary files) from being a store, and keeps a store
from shadowing ``ACTIVE`` on a case-insensitive file system.
"""

import os
import stat
from pathlib import Path


class StoreRootUnusableError(OSError):
    """The root is missing, not a directory, a symbolic link, or cannot be read."""


def check_store_root(store_root: Path) -> None:
    """Raise ``StoreRootUnusableError`` unless ``store_root`` is a directory that can be
    read. It is checked with ``lstat``, so a symbolic link at the root path is refused,
    while links among its parent directories are followed."""
    try:
        root_status = os.lstat(store_root)
    except OSError:
        raise StoreRootUnusableError("the store root cannot be found") from None
    if not stat.S_ISDIR(root_status.st_mode):
        raise StoreRootUnusableError("the store root is not a directory")
    try:
        root_descriptor = os.open(store_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        raise StoreRootUnusableError("the store root cannot be read") from None
    os.close(root_descriptor)
    if not os.access(store_root, os.X_OK):
        raise StoreRootUnusableError("the store root cannot be searched")
