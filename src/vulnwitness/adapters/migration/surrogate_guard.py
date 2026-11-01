"""Refuse a JSON high-surrogate escape with no low-surrogate escape after it, before the
parser sees it (ADR 0008 §8)."""

import re

from vulnwitness.adapters.migration.input_files import PayloadStream
from vulnwitness.domain.migration_report import MigrationFailed, MigrationFailureCode

HIGH_SURROGATE_ESCAPE = re.compile(rb"\\u[dD][89abAB][0-9a-fA-F]{2}")
LOW_SURROGATE_ESCAPE = re.compile(rb"\\u[dD][c-fC-F][0-9a-fA-F]{2}")
SURROGATE_PAIR_BYTES = 12


class SurrogateGuard:
    """Hands the payload to the parser unchanged, refusing a JSON high-surrogate escape
    that no low-surrogate escape follows. The yajl backend would turn it into ``?``, a
    silent change to the entry, where ``json.loads`` keeps it; a lone low surrogate and
    invalid UTF-8 the backend refuses itself.

    An escape is a backslash preceded by an even run of backslashes, counted across read
    boundaries. The last ``SURROGATE_PAIR_BYTES - 1`` bytes of a read are checked with the
    next read, so a pair split between reads is seen whole.
    """

    def __init__(self, source: PayloadStream) -> None:
        self._source = source
        self._pending = b""
        self._backslashes_before_pending = 0

    def read(self, size: int = -1) -> bytes:
        chunk = self._source.read(size)
        window = self._pending + chunk
        check_end = len(window) if not chunk else max(0, len(window) - SURROGATE_PAIR_BYTES + 1)
        for escape_match in HIGH_SURROGATE_ESCAPE.finditer(window, 0, check_end + 5):
            escape_start = escape_match.start()
            if escape_start >= check_end or not self._starts_escape(window, escape_start):
                continue
            following = window[escape_start + 6 : escape_start + SURROGATE_PAIR_BYTES]
            if LOW_SURROGATE_ESCAPE.fullmatch(following) is None:
                raise MigrationFailed(MigrationFailureCode.INVALID_JSON)
        checked = window[:check_end]
        trailing_backslashes = len(checked) - len(checked.rstrip(b"\\"))
        if trailing_backslashes == len(checked):
            trailing_backslashes += self._backslashes_before_pending
        self._backslashes_before_pending = trailing_backslashes
        self._pending = window[check_end:]
        return chunk

    def _starts_escape(self, window: bytes, backslash_index: int) -> bool:
        preceding = window[:backslash_index]
        backslash_run = len(preceding) - len(preceding.rstrip(b"\\"))
        if backslash_run == len(preceding):
            backslash_run += self._backslashes_before_pending
        return backslash_run % 2 == 0
