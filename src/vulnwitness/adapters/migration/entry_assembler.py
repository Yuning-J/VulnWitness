"""Build one JSON value from a streaming parser's events, within the importer's entry caps
(ADR 0008 §8).

The cap counts an entry's keys and values, never more than their encoded bytes, so an
entry within the byte cap is always accepted; its memory is a bounded multiple of those
bytes, largest for an entry of many empty containers. Numbers the backend cannot hand
over as ``json.loads`` would (``NaN``, ``Infinity``, a number past the float range, an
integer of magnitude 2**63 or more) never reach the assembler: the backend refuses
them, and the reader reports that as ``invalid_json``.
"""

from typing import Any, cast

from vulnwitness.domain.migration_report import MigrationFailed, MigrationFailureCode


class EntryAssembler:
    """Builds one JSON value from parser events, refusing what the importer never reads:
    a repeated key, nesting past ``max_depth``, and more than ``max_bytes`` of keys and
    values."""

    def __init__(self, max_depth: int, max_bytes: int) -> None:
        self._max_depth = max_depth
        self._max_bytes = max_bytes
        self._containers: list[dict[str, Any] | list[Any]] = []
        self._pending_keys: list[str | None] = []
        self._counted_bytes = 0
        self.value: Any = None
        self.is_complete = False

    def accept(self, event: str, event_value: Any) -> None:
        if event == "map_key":
            self._count(len(event_value))
            current = self._containers[-1]
            if not isinstance(current, dict) or event_value in current:
                raise MigrationFailed(MigrationFailureCode.DUPLICATE_JSON_KEY)
            self._pending_keys[-1] = event_value
            return
        if event in {"start_map", "start_array"}:
            if len(self._containers) >= self._max_depth:
                raise MigrationFailed(MigrationFailureCode.ENTRY_TOO_DEEP)
            container: dict[str, Any] | list[Any] = {} if event == "start_map" else []
            self._place(container)
            self._containers.append(container)
            self._pending_keys.append(None)
            return
        if event in {"end_map", "end_array"}:
            finished = self._containers.pop()
            self._pending_keys.pop()
            if not self._containers:
                self.value = finished
                self.is_complete = True
            return
        self._count(count_scalar_bytes(event, event_value))
        self._place(event_value)
        if not self._containers:
            self.value = event_value
            self.is_complete = True

    def _place(self, value: Any) -> None:
        if not self._containers:
            return
        current = self._containers[-1]
        if isinstance(current, list):
            current.append(value)
            return
        # The parser emits a key before every value of an object.
        key = cast(str, self._pending_keys[-1])
        current[key] = value
        self._pending_keys[-1] = None

    def _count(self, value_bytes: int) -> None:
        self._counted_bytes += value_bytes
        if self._counted_bytes > self._max_bytes:
            raise MigrationFailed(MigrationFailureCode.ENTRY_TOO_LARGE)


def count_scalar_bytes(event: str, event_value: Any) -> int:
    """A scalar's share of the entry cap, never more than its encoded bytes: a string's
    characters, one byte for a number, four for a literal."""
    if event == "string" and isinstance(event_value, str):
        return len(event_value)
    if event == "number":
        return 1
    return 4
