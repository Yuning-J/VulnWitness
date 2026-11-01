"""Read an NVD JSON 1.1 or 2.0 feed as a stream of entries (ADR 0008 §1, §8). Needs the
``migration`` extra; loaded only through the ``migration_parsers`` entry point
(``build_migration_parsers``).

The feed is parsed with ijson's ``yajl2_c`` backend, named explicitly so every machine
parses alike, and numbers come out as ``json.loads`` gives them (``use_float``). The
backend itself refuses ``NaN``, ``Infinity``, a number past the float range and an
integer of magnitude 2**63 or more, and the reader reports each as
``invalid_json``. Entries are assembled from the parser's events (``EntryAssembler``),
never with ``ijson.items``, which would build a whole entry before it could be measured;
the payload stream stops reading past the entry cap plus one parser buffer
(``MigrationLimits``).

The format is told by content: 2.0 has a ``vulnerabilities`` array and declares
``format`` ``NVD_CVE`` and ``version`` ``2.0``; 1.1 has a ``CVE_Items`` array and
declares the CVE JSON 4.0 schema. Top-level fields are collected wherever they appear,
each key and value counted against the entry cap, so the declaration is checked once the
whole feed has been read.

A feed must also be whole: it declares how many entries it holds and holds exactly that
many. A 2.0 feed starts at ``startIndex`` 0 and its ``totalResults`` is the number of
entries read; a 1.1 feed's ``CVE_data_numberOfCVEs`` is. A page of a larger API result,
or a feed cut short by a tool that kept it valid JSON, fails as ``incomplete_feed``
rather than leaving its missing CVEs to look absent from NVD.
"""

from collections.abc import Iterator

import ijson

from vulnwitness.adapters.migration.entry_assembler import EntryAssembler
from vulnwitness.adapters.migration.ijson_events import ParserEvent, parse_basic_events
from vulnwitness.adapters.migration.input_files import PayloadStream
from vulnwitness.adapters.migration.json_fingerprint import classify_json_prefix
from vulnwitness.adapters.migration.parser_types import (
    EntryHandler,
    FeedHeader,
    MigrationParsers,
)
from vulnwitness.adapters.migration.surrogate_guard import SurrogateGuard
from vulnwitness.domain.corpus_store_manifest import NvdFeedFormat
from vulnwitness.domain.migration_report import MigrationFailed, MigrationFailureCode

# Top-level text kept from a feed; longer values are not declarations the importer reads,
# and a longer key is none a feed has.
MAX_HEADER_VALUE_CHARS = 256
# A feed has fewer than ten top-level members; more is not a feed.
MAX_TOP_LEVEL_KEYS = 32
ENTRY_ARRAYS = {"vulnerabilities": NvdFeedFormat.V2_0, "CVE_Items": NvdFeedFormat.V1_1}
FORMAT_DECLARATIONS: dict[NvdFeedFormat, dict[str, str]] = {
    NvdFeedFormat.V2_0: {"format": "NVD_CVE", "version": "2.0"},
    NvdFeedFormat.V1_1: {
        "CVE_data_type": "CVE",
        "CVE_data_format": "MITRE",
        "CVE_data_version": "4.0",
    },
}
GENERATED_AT_KEYS = {NvdFeedFormat.V2_0: "timestamp", NvdFeedFormat.V1_1: "CVE_data_timestamp"}
# A top-level value the reader keeps: short text, or an integer such as a 2.0 count.
HeaderValue = str | int


def parse_events(payload: PayloadStream) -> Iterator[ParserEvent]:
    """The payload's parser events; raises ``MigrationFailed`` for JSON that does not
    parse, invalid Unicode included (``SurrogateGuard``)."""
    try:
        yield from parse_basic_events(SurrogateGuard(payload), payload.limits.parser_buffer_bytes)
    except (ijson.JSONError, UnicodeDecodeError):
        raise MigrationFailed(MigrationFailureCode.INVALID_JSON) from None


def read_nvd_feed(payload: PayloadStream, handle_entry: EntryHandler) -> FeedHeader:
    """Hand every entry of the feed to ``handle_entry`` as it is read, then check what
    the feed declares; raises ``MigrationFailed`` for anything that is not a feed the
    importer reads, or that breaks a cap."""
    events = parse_events(payload)
    first_event = next(events, None)
    if first_event is None or first_event[0] != "start_map":
        raise MigrationFailed(MigrationFailureCode.UNRECOGNISED_FORMAT)
    top_level_keys: set[str] = set()
    header_values: dict[str, HeaderValue] = {}
    feed_format: NvdFeedFormat | None = None
    entry_count = 0
    # Every top-level key and the value after it count against the entry cap, from the
    # moment the previous member ends, so no huge key or string is held whole.
    payload.begin_entry()
    for event, event_value in events:
        if event == "end_map":
            break
        # Only keys and their values follow at the top level of an object.
        key = event_value
        if key in top_level_keys:
            raise MigrationFailed(MigrationFailureCode.DUPLICATE_JSON_KEY)
        if len(top_level_keys) >= MAX_TOP_LEVEL_KEYS or len(key) > MAX_HEADER_VALUE_CHARS:
            raise MigrationFailed(MigrationFailureCode.UNRECOGNISED_FORMAT)
        top_level_keys.add(key)
        if key in ENTRY_ARRAYS:
            if feed_format is not None:
                raise MigrationFailed(MigrationFailureCode.UNRECOGNISED_FORMAT)
            feed_format = ENTRY_ARRAYS[key]
            entry_count = read_entries(events, payload, feed_format, handle_entry)
        else:
            header_value = read_header_value(events)
            if header_value is not None:
                header_values[key] = header_value
        payload.begin_entry()
    payload.end_entry()
    # Reading on to the end checks nothing follows the feed and lets the payload's hash
    # cover every byte.
    if next(events, None) is not None:
        raise MigrationFailed(MigrationFailureCode.INVALID_JSON)
    if feed_format is None:
        raise MigrationFailed(MigrationFailureCode.UNRECOGNISED_FORMAT)
    for declared_key, declared_value in FORMAT_DECLARATIONS[feed_format].items():
        if header_values.get(declared_key) != declared_value:
            raise MigrationFailed(MigrationFailureCode.UNRECOGNISED_FORMAT)
    if not is_whole_feed(feed_format, header_values, entry_count):
        raise MigrationFailed(MigrationFailureCode.INCOMPLETE_FEED)
    generated_at_text = header_values.get(GENERATED_AT_KEYS[feed_format])
    return FeedHeader(
        feed_format=feed_format,
        generated_at_text=generated_at_text if isinstance(generated_at_text, str) else None,
    )


def is_whole_feed(
    feed_format: NvdFeedFormat, header_values: dict[str, HeaderValue], entry_count: int
) -> bool:
    """Whether the feed declares its entry count and holds exactly that many entries: a
    2.0 feed from ``startIndex`` 0 with ``totalResults`` entries, a 1.1 feed with
    ``CVE_data_numberOfCVEs`` entries, written as decimal text."""
    if feed_format is NvdFeedFormat.V2_0:
        return header_values.get("startIndex") == 0 and (
            header_values.get("totalResults") == entry_count
        )
    return header_values.get("CVE_data_numberOfCVEs") == str(entry_count)


def read_entries(
    events: Iterator[ParserEvent],
    payload: PayloadStream,
    feed_format: NvdFeedFormat,
    handle_entry: EntryHandler,
) -> int:
    """Read the entry array, assembling and handing over one entry at a time; how many
    entries it held."""
    first_event = next(events, None)
    if first_event is None or first_event[0] != "start_array":
        raise MigrationFailed(MigrationFailureCode.UNRECOGNISED_FORMAT)
    # The assembler draws an entry's later events from ``events`` itself, so each turn of
    # this loop starts one entry.
    for entry_index, (event, event_value) in enumerate(events):
        if event == "end_array":
            return entry_index
        payload.begin_entry()
        assembler = EntryAssembler(payload.limits.max_entry_depth, payload.limits.max_entry_bytes)
        assembler.accept(event, event_value)
        while not assembler.is_complete:
            next_event = next(events, None)
            if next_event is None:
                raise MigrationFailed(MigrationFailureCode.INVALID_JSON)
            assembler.accept(*next_event)
        payload.end_entry()
        if not isinstance(assembler.value, dict):
            raise MigrationFailed(MigrationFailureCode.UNRECOGNISED_FORMAT)
        handle_entry(feed_format, entry_index, assembler.value)
    raise MigrationFailed(MigrationFailureCode.INVALID_JSON)


def read_header_value(events: Iterator[ParserEvent]) -> HeaderValue | None:
    """A top-level value: its text when it is a short string, the integer when it is a
    JSON integer, else ``None``. A container is skipped, bounded by the payload's caps
    like any other byte."""
    value_event = next(events, None)
    if value_event is None:
        raise MigrationFailed(MigrationFailureCode.INVALID_JSON)
    event, event_value = value_event
    if event == "string" and isinstance(event_value, str):
        return event_value if len(event_value) <= MAX_HEADER_VALUE_CHARS else None
    # ``use_float`` gives a JSON integer as ``int`` and anything with a fraction or an
    # exponent as ``float``, so ``0.0`` is never read as a start index of 0.
    if event == "number" and type(event_value) is int:
        return event_value
    if event in {"start_map", "start_array"}:
        depth = 1
        while depth:
            nested_event = next(events, None)
            if nested_event is None:
                raise MigrationFailed(MigrationFailureCode.INVALID_JSON)
            if nested_event[0] in {"start_map", "start_array"}:
                depth += 1
            elif nested_event[0] in {"end_map", "end_array"}:
                depth -= 1
    return None


def build_migration_parsers() -> MigrationParsers:
    """The ``migration_parsers`` entry point: the parsers the ``migration`` extra
    provides."""
    return MigrationParsers(read_nvd_feed=read_nvd_feed, classify_json_prefix=classify_json_prefix)
