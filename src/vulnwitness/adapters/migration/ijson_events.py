"""ijson's event parser, with its backend named so every machine parses alike. Needs the
``migration`` extra."""

from collections.abc import Iterator
from typing import Any, Protocol

import ijson

IJSON_BACKEND = "yajl2_c"

ParserEvent = tuple[str, Any]


class ReadableBytes(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...


def parse_basic_events(source: ReadableBytes | bytes, buffer_bytes: int) -> Iterator[ParserEvent]:
    """The events of ``source`` read ``buffer_bytes`` at a time, numbers as ``json.loads``
    gives them (``use_float``). Raises ``ijson.JSONError`` for JSON that does not parse."""
    backend = ijson.get_backend(IJSON_BACKEND)
    events: Iterator[ParserEvent] = backend.basic_parse(
        source, buf_size=buffer_bytes, use_float=True
    )
    return events
