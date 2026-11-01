"""``read_nvd_feed`` over authored feed bytes (ADR 0008 §1, §8).

Proves which payloads are read as NVD 2.0 and 1.1 feeds, with their header fields before
or after the entry array; the reason code each malformed, ambiguous or oversized feed
fails with; that entries reach the handler in order, as ``(format, index, entry)``, and
equal to what ``json.loads`` reads from the same bytes, whatever the parser's buffer
boundaries; that a huge entry, one huge string or a huge top-level member is refused
before it is read whole; that a top-level key too long or too many top-level members is
no feed; that only a whole feed is read, its declared entry count equal to the entries it
holds, and a page of a larger result fails as ``incomplete_feed``; and that the payload
hash covers every byte the payload holds.
"""

import io
import json
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any

import pytest

from tests.support.legacy_inputs import (
    V1_FEED_TIMESTAMP,
    V2_FEED_TIMESTAMP,
    build_v1_feed,
    build_v1_item,
    build_v2_entry,
    build_v2_feed,
    encode_feed,
)
from vulnwitness.adapters.migration.input_files import DecompressionBudget, PayloadStream
from vulnwitness.adapters.migration.migration_limits import MigrationLimits
from vulnwitness.adapters.migration.nvd_feed_reader import (
    MAX_HEADER_VALUE_CHARS,
    MAX_TOP_LEVEL_KEYS,
    read_nvd_feed,
)
from vulnwitness.adapters.migration.parser_types import FeedHeader
from vulnwitness.domain.corpus_store_manifest import NvdFeedFormat
from vulnwitness.domain.hashing import canonical_sha256, sha256_hex
from vulnwitness.domain.migration_report import MigrationFailed, MigrationFailureCode

DEFAULT_LIMITS = MigrationLimits()
V2_DECLARATION = '"format": "NVD_CVE", "version": "2.0"'
ENTRY_ARRAY_KEYS = {NvdFeedFormat.V2_0: "vulnerabilities", NvdFeedFormat.V1_1: "CVE_Items"}
GENERATED_AT_KEYS = {NvdFeedFormat.V2_0: "timestamp", NvdFeedFormat.V1_1: "CVE_data_timestamp"}
GENERATED_AT_TEXTS = {NvdFeedFormat.V2_0: V2_FEED_TIMESTAMP, NvdFeedFormat.V1_1: V1_FEED_TIMESTAMP}
TINY_BUFFER_BYTES = 16
SMALL_ENTRY_CAP_BYTES = 128
# A string far past every cap a test sets, so only an early refusal keeps it unread.
HUGE_STRING_CHARS = 100_000
# Padding lengths that move the first entry through every offset of a 16-byte buffer.
BUFFER_OFFSETS = range(TINY_BUFFER_BYTES)
SMALL_ENTRY_LIMITS = MigrationLimits(
    max_entry_bytes=SMALL_ENTRY_CAP_BYTES, parser_buffer_bytes=TINY_BUFFER_BYTES
)
# The members every 2.0 feed here holds: its two declarations, its two counts and its
# entry array.
V2_FEED_MEMBER_COUNT = 5
# Far past the small entry cap, though no one key or value in it is.
MANY_SMALL_MEMBERS_COUNT = 2_000


class MemberPosition(Enum):
    """Where a test's extra top-level member sits in a 2.0 feed."""

    FIRST = "first"
    BEFORE_ENTRIES = "before_entries"
    AFTER_ENTRIES = "after_entries"


@dataclass(frozen=True)
class HandedEntry:
    feed_format: NvdFeedFormat
    entry_index: int
    entry: dict[str, Any]


@dataclass
class EntryRecorder:
    """An entry handler that keeps every call it receives, in order."""

    handed_entries: list[HandedEntry] = field(default_factory=list)

    def record(self, feed_format: NvdFeedFormat, entry_index: int, entry: dict[str, Any]) -> None:
        self.handed_entries.append(HandedEntry(feed_format, entry_index, entry))


def open_feed(feed_bytes: bytes, limits: MigrationLimits = DEFAULT_LIMITS) -> PayloadStream:
    return PayloadStream(
        source=io.BytesIO(feed_bytes),
        budget=DecompressionBudget(remaining_bytes=limits.max_total_decompressed_bytes),
        limits=limits,
    )


def read_feed(
    feed_bytes: bytes, limits: MigrationLimits = DEFAULT_LIMITS
) -> tuple[FeedHeader, list[HandedEntry]]:
    recorder = EntryRecorder()
    header = read_nvd_feed(open_feed(feed_bytes, limits), recorder.record)
    return header, recorder.handed_entries


def read_entry_values(
    feed_bytes: bytes, limits: MigrationLimits = DEFAULT_LIMITS
) -> list[dict[str, Any]]:
    _, handed_entries = read_feed(feed_bytes, limits)
    entries: list[dict[str, Any]] = []
    for handed_entry in handed_entries:
        entries.append(handed_entry.entry)
    return entries


def read_failure_code(
    feed_bytes: bytes, limits: MigrationLimits = DEFAULT_LIMITS
) -> MigrationFailureCode:
    with pytest.raises(MigrationFailed) as failure:
        read_nvd_feed(open_feed(feed_bytes, limits), EntryRecorder().record)
    return failure.value.code


def build_feed(feed_format: NvdFeedFormat, entry_count: int = 2) -> dict[str, Any]:
    if feed_format is NvdFeedFormat.V2_0:
        entries: list[dict[str, Any]] = []
        for number in range(1, entry_count + 1):
            entries.append(build_v2_entry(number))
        return build_v2_feed(entries)
    items: list[dict[str, Any]] = []
    for number in range(1, entry_count + 1):
        items.append(build_v1_item(number))
    return build_v1_feed(items)


def build_v2_feed_paged_by_another_size(entry_count: int) -> dict[str, Any]:
    """A whole 2.0 feed whose ``resultsPerPage`` is not its ``totalResults``."""
    feed = build_feed(NvdFeedFormat.V2_0, entry_count)
    feed["resultsPerPage"] = 2000
    return feed


def order_feed_fields(feed: dict[str, Any], array_key: str, is_array_first: bool) -> dict[str, Any]:
    """``feed`` with its entry array as its first or its last field."""
    ordered_feed: dict[str, Any] = {}
    if is_array_first:
        ordered_feed[array_key] = feed[array_key]
    for key, value in feed.items():
        if key != array_key:
            ordered_feed[key] = value
    if not is_array_first:
        ordered_feed[array_key] = feed[array_key]
    return ordered_feed


def build_v2_counts(start_index_text: str, total_results_text: str) -> str:
    """The ``startIndex`` and ``totalResults`` members of a 2.0 feed, each value written
    as the given JSON text."""
    return '"startIndex": ' + start_index_text + ', "totalResults": ' + total_results_text


def build_whole_v2_counts(entry_count: int) -> str:
    """The counts of a whole 2.0 feed of ``entry_count`` entries."""
    return build_v2_counts("0", str(entry_count))


def build_v2_feed_bytes(entry_texts: list[str], padding: str = "") -> bytes:
    """A whole 2.0 feed holding ``entry_texts`` verbatim, after a ``padding`` header field
    that moves where the entries fall in the parser's buffers. The counts follow the
    entries, so they move nothing before them."""
    return (
        "{"
        + V2_DECLARATION
        + ', "padding": "'
        + padding
        + '", "vulnerabilities": ['
        + ", ".join(entry_texts)
        + "], "
        + build_whole_v2_counts(len(entry_texts))
        + "}"
    ).encode()


def build_v2_feed_declaring_counts(
    start_index_text: str, total_results_text: str, are_counts_first: bool
) -> bytes:
    """A 2.0 feed of one empty entry declaring the given counts, before or after its
    entry array."""
    members = [V2_DECLARATION, '"vulnerabilities": [{}]']
    counts = build_v2_counts(start_index_text, total_results_text)
    if are_counts_first:
        members.insert(0, counts)
    else:
        members.append(counts)
    return ("{" + ", ".join(members) + "}").encode()


def build_v2_feed_with_extra_member(member_text: str, position: MemberPosition) -> bytes:
    """A whole 2.0 feed of one empty entry with ``member_text`` as one more top-level
    member at ``position``."""
    members = [V2_DECLARATION, build_whole_v2_counts(1)]
    if position is MemberPosition.FIRST:
        members.insert(0, member_text)
    elif position is MemberPosition.BEFORE_ENTRIES:
        members.append(member_text)
    members.append('"vulnerabilities": [{}]')
    if position is MemberPosition.AFTER_ENTRIES:
        members.append(member_text)
    return ("{" + ", ".join(members) + "}").encode()


def build_object_of_many_small_members(member_count: int) -> str:
    members: list[str] = []
    for number in range(member_count):
        members.append(f'"k{number:05d}": 0')
    return "{" + ", ".join(members) + "}"


def build_v2_feed_with_member_count(member_count: int) -> bytes:
    """A whole 2.0 feed of ``member_count`` top-level members: short extra members first,
    then its declarations, its counts and its entry array."""
    members: list[str] = []
    for number in range(member_count - V2_FEED_MEMBER_COUNT):
        members.append(f'"extra{number:02d}": "x"')
    members.append(V2_DECLARATION)
    members.append(build_whole_v2_counts(1))
    members.append('"vulnerabilities": [{}]')
    return ("{" + ", ".join(members) + "}").encode()


def find_first_entry_offset(feed_bytes: bytes) -> int:
    array_offset = feed_bytes.index(b'"vulnerabilities"')
    return feed_bytes.index(b"[", array_offset) + 1


def build_entry_text_of_size(fields_text: str, size_bytes: int) -> str:
    """An entry object holding ``fields_text`` and a padding string, ``size_bytes`` long
    in UTF-8."""
    frame_bytes = len('{,"p":""}')
    padding = "x" * (size_bytes - len(fields_text.encode()) - frame_bytes)
    return "{" + fields_text + ',"p":"' + padding + '"}'


def build_nested_entry_text(depth: int, opening: str, closing: str, innermost: str) -> str:
    """An entry object whose ``innermost`` container sits ``depth`` containers deep, the
    entry itself counted; ``opening`` and ``closing`` wrap one level each."""
    nested_text = innermost
    for _ in range(depth - 2):
        nested_text = opening + nested_text + closing
    return '{"nested": ' + nested_text + "}"


# Recognition and header fields


@pytest.mark.parametrize(
    "feed_format", [NvdFeedFormat.V2_0, NvdFeedFormat.V1_1], ids=["2.0", "1.1"]
)
@pytest.mark.parametrize("is_array_first", [True, False], ids=["array_first", "array_last"])
def test_feed_is_recognised_with_its_generation_time_wherever_its_header_fields_sit(
    feed_format: NvdFeedFormat, is_array_first: bool
) -> None:
    feed = order_feed_fields(build_feed(feed_format), ENTRY_ARRAY_KEYS[feed_format], is_array_first)

    header, _ = read_feed(encode_feed(feed))

    assert header == FeedHeader(
        feed_format=feed_format, generated_at_text=GENERATED_AT_TEXTS[feed_format]
    )


@pytest.mark.parametrize(
    "feed_format", [NvdFeedFormat.V2_0, NvdFeedFormat.V1_1], ids=["2.0", "1.1"]
)
def test_feed_without_a_generation_time_returns_none_for_it(feed_format: NvdFeedFormat) -> None:
    feed = build_feed(feed_format)
    del feed[GENERATED_AT_KEYS[feed_format]]

    header, _ = read_feed(encode_feed(feed))

    assert header == FeedHeader(feed_format=feed_format, generated_at_text=None)


def test_feed_whose_generation_time_is_too_long_to_be_one_returns_none_for_it() -> None:
    feed = build_v2_feed([build_v2_entry(1)], timestamp="2026-10-20T00:00:00.000" + "0" * 300)

    header, _ = read_feed(encode_feed(feed))

    assert header.generated_at_text is None


@pytest.mark.parametrize(
    "feed_format", [NvdFeedFormat.V2_0, NvdFeedFormat.V1_1], ids=["2.0", "1.1"]
)
def test_handler_receives_format_index_and_entry_for_every_entry_in_feed_order(
    feed_format: NvdFeedFormat,
) -> None:
    feed = build_feed(feed_format, entry_count=3)
    expected_entries: list[HandedEntry] = []
    for entry_index, entry in enumerate(feed[ENTRY_ARRAY_KEYS[feed_format]]):
        expected_entries.append(HandedEntry(feed_format, entry_index, entry))

    _, handed_entries = read_feed(encode_feed(feed))

    assert handed_entries == expected_entries


def test_feed_with_an_empty_entry_array_returns_its_header_and_hands_over_nothing() -> None:
    feed_bytes = encode_feed(build_v2_feed([]))

    header_and_entries = read_feed(feed_bytes)

    assert header_and_entries == (
        FeedHeader(feed_format=NvdFeedFormat.V2_0, generated_at_text=V2_FEED_TIMESTAMP),
        [],
    )


@pytest.mark.parametrize(
    ("feed_format", "declared_key", "declared_value"),
    [
        (NvdFeedFormat.V2_0, "version", "2.1"),
        (NvdFeedFormat.V2_0, "version", 2.0),
        (NvdFeedFormat.V2_0, "format", "NVD_CPE"),
        (NvdFeedFormat.V1_1, "CVE_data_version", "1.1"),
        (NvdFeedFormat.V1_1, "CVE_data_version", 4.0),
        (NvdFeedFormat.V1_1, "CVE_data_format", "NVD"),
        (NvdFeedFormat.V1_1, "CVE_data_type", "CPE"),
    ],
    ids=[
        "2.0_declaring_version_2.1",
        "2.0_declaring_version_as_a_number",
        "2.0_declaring_another_format",
        "1.1_declaring_version_1.1",
        "1.1_declaring_version_as_a_number",
        "1.1_declaring_another_data_format",
        "1.1_declaring_another_data_type",
    ],
)
def test_feed_with_a_wrong_declaration_fails_as_unrecognised_format(
    feed_format: NvdFeedFormat, declared_key: str, declared_value: object
) -> None:
    feed = build_feed(feed_format)
    feed[declared_key] = declared_value

    failure_code = read_failure_code(encode_feed(feed))

    assert failure_code is MigrationFailureCode.UNRECOGNISED_FORMAT


@pytest.mark.parametrize(
    ("feed_format", "declared_key"),
    [
        (NvdFeedFormat.V2_0, "format"),
        (NvdFeedFormat.V2_0, "version"),
        (NvdFeedFormat.V1_1, "CVE_data_type"),
        (NvdFeedFormat.V1_1, "CVE_data_format"),
        (NvdFeedFormat.V1_1, "CVE_data_version"),
    ],
    ids=[
        "2.0_without_format",
        "2.0_without_version",
        "1.1_without_data_type",
        "1.1_without_data_format",
        "1.1_without_data_version",
    ],
)
def test_feed_missing_a_declaration_fails_as_unrecognised_format(
    feed_format: NvdFeedFormat, declared_key: str
) -> None:
    feed = build_feed(feed_format)
    del feed[declared_key]

    failure_code = read_failure_code(encode_feed(feed))

    assert failure_code is MigrationFailureCode.UNRECOGNISED_FORMAT


@pytest.mark.parametrize(
    "feed_bytes",
    [
        b'{"format": "NVD_CVE", "version": "2.0", "timestamp": "2026-10-20T00:00:00.000"}',
        b'{"format": "NVD_CVE", "version": "2.0", "vulnerabilities": [], "CVE_Items": []}',
        b'{"CVE_data_type": "CVE", "CVE_data_format": "MITRE", "CVE_data_version": "4.0",'
        b' "vulnerabilities": []}',
        b'{"CVE_data_type": "CVE", "CVE_data_format": "MITRE", "CVE_data_version": "4.0",'
        b' "format": "NVD_CVE", "version": "2.0", "CVE_Items": [], "vulnerabilities": []}',
        b'{"format": "NVD_CVE", "version": "2.0", "meta": {"vulnerabilities": []}}',
        b'{"format": "NVD_CVE", "version": "2.0", "vulnerabilities": {}}',
        b'{"format": "NVD_CVE", "version": "2.0", "vulnerabilities": null}',
        b'{"format": "NVD_CVE", "version": "2.0", "vulnerabilities": "none"}',
        b'{"format": "NVD_CVE", "version": "2.0", "vulnerabilities": [1]}',
        b'{"format": "NVD_CVE", "version": "2.0", "vulnerabilities": ["CVE-9999-0001"]}',
        b'{"format": "NVD_CVE", "version": "2.0", "vulnerabilities": [[]]}',
        b'{"format": "NVD_CVE", "version": "2.0", "vulnerabilities": [null]}',
        b"{}",
        b"[]",
        b'[{"format": "NVD_CVE", "version": "2.0", "vulnerabilities": []}]',
        b'"NVD_CVE"',
        b"42",
        b"null",
        b"true",
    ],
    ids=[
        "no_entry_array",
        "both_entry_arrays",
        "2.0_array_with_1.1_declaration",
        "both_arrays_with_both_declarations",
        "entry_array_only_nested_in_a_header_value",
        "entry_array_is_an_object",
        "entry_array_is_null",
        "entry_array_is_a_string",
        "entry_is_a_number",
        "entry_is_a_string",
        "entry_is_an_array",
        "entry_is_null",
        "empty_object",
        "top_level_array",
        "top_level_array_holding_a_feed",
        "top_level_string",
        "top_level_number",
        "top_level_null",
        "top_level_boolean",
    ],
)
def test_payload_that_is_not_one_nvd_feed_fails_as_unrecognised_format(feed_bytes: bytes) -> None:
    failure_code = read_failure_code(feed_bytes)

    assert failure_code is MigrationFailureCode.UNRECOGNISED_FORMAT


HUGE_STRING_MEMBER = '"comment": "' + "x" * HUGE_STRING_CHARS + '"'
TOP_LEVEL_MEMBERS_PAST_THE_ENTRY_CAP = [
    (HUGE_STRING_MEMBER, MemberPosition.FIRST),
    (HUGE_STRING_MEMBER, MemberPosition.BEFORE_ENTRIES),
    (
        '"meta": ' + build_object_of_many_small_members(MANY_SMALL_MEMBERS_COUNT),
        MemberPosition.BEFORE_ENTRIES,
    ),
    (HUGE_STRING_MEMBER, MemberPosition.AFTER_ENTRIES),
]
TOP_LEVEL_MEMBER_IDS = [
    "string_as_the_first_member",
    "string_before_the_entries",
    "object_before_the_entries",
    "string_after_the_entries",
]


@pytest.mark.parametrize(
    ("member_text", "position"), TOP_LEVEL_MEMBERS_PAST_THE_ENTRY_CAP, ids=TOP_LEVEL_MEMBER_IDS
)
def test_top_level_member_past_the_entry_cap_fails_as_entry_too_large(
    member_text: str, position: MemberPosition
) -> None:
    feed_bytes = build_v2_feed_with_extra_member(member_text, position)

    failure_code = read_failure_code(feed_bytes, SMALL_ENTRY_LIMITS)

    assert failure_code is MigrationFailureCode.ENTRY_TOO_LARGE


@pytest.mark.parametrize(
    ("member_text", "position"),
    [
        ('"comment": "democorp"', MemberPosition.FIRST),
        ('"comment": "democorp"', MemberPosition.BEFORE_ENTRIES),
        ('"meta": ' + build_object_of_many_small_members(4), MemberPosition.BEFORE_ENTRIES),
        ('"comment": "democorp"', MemberPosition.AFTER_ENTRIES),
    ],
    ids=TOP_LEVEL_MEMBER_IDS,
)
def test_top_level_member_within_the_entry_cap_is_read_past(
    member_text: str, position: MemberPosition
) -> None:
    feed_bytes = build_v2_feed_with_extra_member(member_text, position)

    entries = read_entry_values(feed_bytes, SMALL_ENTRY_LIMITS)

    assert entries == [{}]


def test_top_level_key_as_long_as_a_header_value_may_be_is_read_past() -> None:
    member_text = '"' + "k" * MAX_HEADER_VALUE_CHARS + '": "democorp"'

    entries = read_entry_values(build_v2_feed_with_extra_member(member_text, MemberPosition.FIRST))

    assert entries == [{}]


def test_top_level_key_longer_than_a_header_value_fails_as_unrecognised_format() -> None:
    member_text = '"' + "k" * (MAX_HEADER_VALUE_CHARS + 1) + '": "democorp"'

    failure_code = read_failure_code(
        build_v2_feed_with_extra_member(member_text, MemberPosition.FIRST)
    )

    assert failure_code is MigrationFailureCode.UNRECOGNISED_FORMAT


def test_feed_of_exactly_the_most_top_level_members_is_read() -> None:
    feed_bytes = build_v2_feed_with_member_count(MAX_TOP_LEVEL_KEYS)

    header_and_entries = read_feed(feed_bytes)

    assert header_and_entries == (
        FeedHeader(feed_format=NvdFeedFormat.V2_0, generated_at_text=None),
        [HandedEntry(NvdFeedFormat.V2_0, 0, {})],
    )


def test_feed_of_one_more_than_the_most_top_level_members_fails_as_unrecognised_format() -> None:
    feed_bytes = build_v2_feed_with_member_count(MAX_TOP_LEVEL_KEYS + 1)

    failure_code = read_failure_code(feed_bytes)

    assert failure_code is MigrationFailureCode.UNRECOGNISED_FORMAT


# Whole feeds


@pytest.mark.parametrize("are_counts_first", [True, False], ids=["counts_first", "counts_last"])
@pytest.mark.parametrize(
    ("start_index_text", "total_results_text"),
    [
        ("2000", "1"),
        ("0", "2"),
        ("0", "0"),
        ("-1", "1"),
        ("0", "1.0"),
        ("0", "1e0"),
        ("0", '"1"'),
        ("0", "true"),
        ("0", "null"),
        ("0.0", "1"),
        ("-0.0", "1"),
        ('"0"', "1"),
        ("false", "1"),
    ],
    ids=[
        "api_page_past_the_first",
        "first_page_of_a_larger_result",
        "total_smaller_than_the_entries",
        "negative_start_index",
        "total_as_a_float",
        "total_as_an_exponent",
        "total_as_text",
        "total_as_a_boolean",
        "total_as_null",
        "start_index_as_a_float",
        "start_index_as_negative_float_zero",
        "start_index_as_text",
        "start_index_as_a_boolean",
    ],
)
def test_v2_feed_of_one_entry_not_declaring_a_whole_feed_fails_as_incomplete_feed(
    start_index_text: str, total_results_text: str, are_counts_first: bool
) -> None:
    """Python counts ``1.0``, ``True`` and ``0.0`` equal to ``1`` and ``0``, so a feed of
    one entry shows that only a JSON integer is read as a count."""
    feed_bytes = build_v2_feed_declaring_counts(
        start_index_text, total_results_text, are_counts_first
    )

    failure_code = read_failure_code(feed_bytes)

    assert failure_code is MigrationFailureCode.INCOMPLETE_FEED


@pytest.mark.parametrize("are_counts_first", [True, False], ids=["counts_first", "counts_last"])
def test_v2_feed_starting_at_minus_zero_is_read_as_starting_at_zero(
    are_counts_first: bool,
) -> None:
    """yajl reads the JSON integer ``-0`` as the integer 0, as ``json.loads`` does."""
    feed_bytes = build_v2_feed_declaring_counts("-0", "1", are_counts_first)

    entries = read_entry_values(feed_bytes)

    assert entries == [{}]


@pytest.mark.parametrize(
    ("feed_format", "count_key"),
    [
        (NvdFeedFormat.V2_0, "startIndex"),
        (NvdFeedFormat.V2_0, "totalResults"),
        (NvdFeedFormat.V1_1, "CVE_data_numberOfCVEs"),
    ],
    ids=["2.0_without_start_index", "2.0_without_total_results", "1.1_without_number_of_cves"],
)
def test_feed_not_declaring_its_entry_count_fails_as_incomplete_feed(
    feed_format: NvdFeedFormat, count_key: str
) -> None:
    feed = build_feed(feed_format)
    del feed[count_key]

    failure_code = read_failure_code(encode_feed(feed))

    assert failure_code is MigrationFailureCode.INCOMPLETE_FEED


@pytest.mark.parametrize(
    "declared_count",
    ["3", "1", 2, "02", " 2", "2 ", "2.0", ""],
    ids=[
        "more_than_the_entries",
        "fewer_than_the_entries",
        "integer_instead_of_text",
        "leading_zero",
        "leading_space",
        "trailing_space",
        "decimal_point",
        "empty_text",
    ],
)
def test_v1_feed_of_two_entries_declaring_another_count_fails_as_incomplete_feed(
    declared_count: object,
) -> None:
    feed = build_feed(NvdFeedFormat.V1_1, entry_count=2)
    feed["CVE_data_numberOfCVEs"] = declared_count

    failure_code = read_failure_code(encode_feed(feed))

    assert failure_code is MigrationFailureCode.INCOMPLETE_FEED


@pytest.mark.parametrize(
    ("feed_format", "feed"),
    [
        (
            NvdFeedFormat.V2_0,
            order_feed_fields(build_feed(NvdFeedFormat.V2_0), "vulnerabilities", False),
        ),
        (
            NvdFeedFormat.V2_0,
            order_feed_fields(build_feed(NvdFeedFormat.V2_0), "vulnerabilities", True),
        ),
        (NvdFeedFormat.V2_0, build_feed(NvdFeedFormat.V2_0, entry_count=0)),
        (NvdFeedFormat.V2_0, build_v2_feed_paged_by_another_size(entry_count=2)),
        (NvdFeedFormat.V1_1, build_feed(NvdFeedFormat.V1_1, entry_count=2)),
        (NvdFeedFormat.V1_1, build_feed(NvdFeedFormat.V1_1, entry_count=0)),
    ],
    ids=[
        "2.0_counts_before_the_entries",
        "2.0_counts_after_the_entries",
        "2.0_empty_with_total_results_0",
        "2.0_results_per_page_other_than_total_results",
        "1.1_count_as_decimal_text",
        "1.1_empty_with_count_0",
    ],
)
def test_whole_feed_hands_over_every_entry(
    feed_format: NvdFeedFormat, feed: dict[str, Any]
) -> None:
    entries = read_entry_values(encode_feed(feed))

    assert entries == feed[ENTRY_ARRAY_KEYS[feed_format]]


@pytest.mark.parametrize(
    ("feed_format", "declared_key", "declared_value", "count_key", "count_value"),
    [
        (NvdFeedFormat.V2_0, "version", "2.1", "totalResults", 5),
        (NvdFeedFormat.V2_0, "format", "NVD_CPE", "startIndex", 2000),
        (NvdFeedFormat.V1_1, "CVE_data_version", "1.1", "CVE_data_numberOfCVEs", "5"),
    ],
    ids=[
        "2.0_wrong_version_and_total",
        "2.0_wrong_format_and_start_index",
        "1.1_wrong_version_and_count",
    ],
)
def test_feed_with_a_wrong_declaration_and_a_wrong_count_fails_as_unrecognised_format(
    feed_format: NvdFeedFormat,
    declared_key: str,
    declared_value: str,
    count_key: str,
    count_value: object,
) -> None:
    feed = build_feed(feed_format)
    feed[declared_key] = declared_value
    feed[count_key] = count_value

    failure_code = read_failure_code(encode_feed(feed))

    assert failure_code is MigrationFailureCode.UNRECOGNISED_FORMAT


@pytest.mark.parametrize("is_array_first", [True, False], ids=["counts_last", "counts_first"])
def test_page_of_a_larger_result_hands_over_every_entry_before_failing_as_incomplete_feed(
    is_array_first: bool,
) -> None:
    """The count is checked once the whole feed is read, so a wrong count declared before
    the entries does not keep them from the handler; the run fails as a whole."""
    feed = order_feed_fields(
        build_feed(NvdFeedFormat.V2_0, entry_count=3), "vulnerabilities", is_array_first
    )
    feed["startIndex"] = 2000
    feed["totalResults"] = 10_000
    expected_entries: list[HandedEntry] = []
    for entry_index, entry in enumerate(feed["vulnerabilities"]):
        expected_entries.append(HandedEntry(NvdFeedFormat.V2_0, entry_index, entry))
    recorder = EntryRecorder()

    with pytest.raises(MigrationFailed) as failure:
        read_nvd_feed(open_feed(encode_feed(feed)), recorder.record)

    assert failure.value.code is MigrationFailureCode.INCOMPLETE_FEED
    assert recorder.handed_entries == expected_entries


# Duplicate keys and nesting


@pytest.mark.parametrize(
    "feed_bytes",
    [
        b'{"format": "NVD_CVE", "format": "NVD_CVE", "version": "2.0", "vulnerabilities": []}',
        b'{"format": "NVD_CVE", "version": "2.0", "vulnerabilities": [], "vulnerabilities": []}',
        b'{"format": "NVD_CVE", "version": "2.0", "timestamp": "a", "vulnerabilities": [],'
        b' "timestamp": "b"}',
        b'{"format": "NVD_CVE", "version": "2.0", "vulnerabilities": [{"cve": {}, "cve": {}}]}',
        b'{"format": "NVD_CVE", "version": "2.0",'
        b' "vulnerabilities": [{"cve": {"id": "CVE-9999-0001", "id": "CVE-9999-0002"}}]}',
        b'{"format": "NVD_CVE", "version": "2.0",'
        b' "vulnerabilities": [{"a": [{"b": {"c": 1, "c": 1}}]}]}',
    ],
    ids=[
        "declaration_key_at_top_level",
        "entry_array_key_at_top_level",
        "unread_header_key_at_top_level",
        "entry_top_level_key",
        "key_inside_an_entry",
        "deeply_nested_key_with_equal_values",
    ],
)
def test_repeated_key_in_one_object_fails_as_duplicate_json_key(feed_bytes: bytes) -> None:
    failure_code = read_failure_code(feed_bytes)

    assert failure_code is MigrationFailureCode.DUPLICATE_JSON_KEY


def test_same_key_in_sibling_objects_of_an_entry_is_not_a_duplicate() -> None:
    entry_text = (
        '{"cve": {"metrics": [{"source": "a"}, {"source": "b"}]}, "other": {"source": "c"}}'
    )

    entries = read_entry_values(build_v2_feed_bytes([entry_text]))

    assert entries == [json.loads(entry_text)]


@pytest.mark.parametrize(
    ("opening", "closing", "innermost"),
    [('{"a": ', "}", "{}"), ("[", "]", "[]"), ("[", "]", "{}")],
    ids=["objects", "arrays", "arrays_around_an_object"],
)
def test_entry_nested_exactly_to_the_depth_cap_is_handed_over(
    opening: str, closing: str, innermost: str
) -> None:
    limits = MigrationLimits(max_entry_depth=5)
    entry_text = build_nested_entry_text(5, opening, closing, innermost)

    entries = read_entry_values(build_v2_feed_bytes([entry_text]), limits)

    assert entries == [json.loads(entry_text)]


@pytest.mark.parametrize(
    ("opening", "closing", "innermost"),
    [('{"a": ', "}", "{}"), ("[", "]", "[]"), ("[", "]", "{}")],
    ids=["objects", "arrays", "arrays_around_an_object"],
)
def test_entry_nested_one_past_the_depth_cap_fails_as_entry_too_deep(
    opening: str, closing: str, innermost: str
) -> None:
    limits = MigrationLimits(max_entry_depth=5)
    entry_text = build_nested_entry_text(6, opening, closing, innermost)

    failure_code = read_failure_code(build_v2_feed_bytes([entry_text]), limits)

    assert failure_code is MigrationFailureCode.ENTRY_TOO_DEEP


# Numbers and strings


@pytest.mark.parametrize(
    "feed_bytes",
    [
        build_v2_feed_bytes(['{"score": 1e999}']),
        build_v2_feed_bytes(['{"score": -1e999}']),
        build_v2_feed_bytes(['{"scores": [1, 2, 1E400]}']),
        b'{"format": "NVD_CVE", "version": "2.0", "totalResults": 1e999, "vulnerabilities": []}',
        b'{"format": "NVD_CVE", "version": "2.0", "meta": {"n": [-1e999]}, "vulnerabilities": []}',
    ],
    ids=[
        "positive_overflow_in_an_entry",
        "negative_overflow_in_an_entry",
        "upper_case_exponent_overflow_in_an_entry",
        "overflow_in_a_header_value",
        "overflow_in_a_header_container",
    ],
)
def test_number_overflowing_to_infinity_fails_as_invalid_json(feed_bytes: bytes) -> None:
    """yajl refuses a number past the float range itself, so no infinity is ever read."""
    failure_code = read_failure_code(feed_bytes)

    assert failure_code is MigrationFailureCode.INVALID_JSON


@pytest.mark.parametrize(
    "integer_text",
    ["9223372036854775808", "-9223372036854775809", "-9223372036854775808"],
    ids=["int64_max_plus_one", "int64_min_minus_one", "int64_min"],
)
def test_integer_yajl_cannot_hold_in_a_signed_64_bit_value_fails_as_invalid_json(
    integer_text: str,
) -> None:
    """yajl refuses these itself rather than handing them over as big integers. It
    accumulates the magnitude before applying the sign, so the smallest 64-bit integer is
    refused too, though ``json.loads`` reads it."""
    feed_bytes = build_v2_feed_bytes(['{"n": ' + integer_text + "}"])

    failure_code = read_failure_code(feed_bytes)

    assert failure_code is MigrationFailureCode.INVALID_JSON


@pytest.mark.parametrize(
    "literal", ["NaN", "Infinity", "-Infinity"], ids=["nan", "infinity", "negative_infinity"]
)
def test_non_finite_literal_that_json_loads_would_accept_fails_as_invalid_json(
    literal: str,
) -> None:
    feed_bytes = build_v2_feed_bytes(['{"score": ' + literal + "}"])

    failure_code = read_failure_code(feed_bytes)

    assert failure_code is MigrationFailureCode.INVALID_JSON


@pytest.mark.parametrize(
    "entry_bytes",
    [
        b'{"value": "\\ud800"}',
        b'{"\\ud800": 1}',
        b'{"value": "\\udc00"}',
        b'{"\\udc00": 1}',
        b'{"value": "\\udc00\\ud83d"}',
        b'{"value": "\xed\xa0\x80"}',
        b'{"value": "\xff"}',
        b'{"value": "\xc3"}',
    ],
    ids=[
        "lone_high_surrogate_escape_in_a_value",
        "lone_high_surrogate_escape_in_a_key",
        "lone_low_surrogate_escape_in_a_value",
        "lone_low_surrogate_escape_in_a_key",
        "reversed_surrogate_pair_escape",
        "surrogate_encoded_as_utf8_bytes",
        "invalid_utf8_byte",
        "truncated_utf8_sequence",
    ],
)
def test_string_that_is_not_valid_unicode_fails_as_invalid_json(entry_bytes: bytes) -> None:
    feed_bytes = (
        b'{"format": "NVD_CVE", "version": "2.0", "vulnerabilities": [' + entry_bytes + b"]}"
    )

    failure_code = read_failure_code(feed_bytes)

    assert failure_code is MigrationFailureCode.INVALID_JSON


PARITY_ENTRY_TEXTS = [
    json.dumps(build_v2_entry(1)),
    '{"metrics": [{"baseScore": 7.5, "exploitabilityScore": 3.9, "impactScore": 0.1}]}',
    '{"n": [0, 1, -1, 9223372036854775807, -9223372036854775807]}',
    '{"z": [-0.0, 0.0, -0, 0]}',
    '{"e": [1E2, 1e-7, 2.5e+3, -4.2E-2, 1e-400, 5e-324, 1.7976931348623157e308, 1.0]}',
    '{"t": "caf\\u00e9 \\ud83d\\ude00 \\u0000 \\"q\\" \\\\ \\/ \\b\\f\\n\\r\\t"}',
    '{"t": "café 中文 😀", "κλειδί": "τιμή"}',
    '{"b": [true, false, null], "s": "", "o": {}, "a": []}',
    '{"a": {"b": [[], {}, [{"c": [1, [2.5, [3e0]]]}]]}}',
]
PARITY_ENTRY_IDS = [
    "synthetic_2.0_entry",
    "floats",
    "integers_within_64_bits",
    "negative_zero",
    "exponents_and_extremes",
    "escapes",
    "raw_utf8",
    "literals_and_empties",
    "nested_containers",
]


@pytest.mark.parametrize("entry_text", PARITY_ENTRY_TEXTS, ids=PARITY_ENTRY_IDS)
def test_entry_handed_over_equals_json_loads_of_the_same_bytes(entry_text: str) -> None:
    feed_bytes = build_v2_feed_bytes([entry_text])

    entries = read_entry_values(feed_bytes)

    assert entries == json.loads(feed_bytes)["vulnerabilities"]


@pytest.mark.parametrize("entry_text", PARITY_ENTRY_TEXTS, ids=PARITY_ENTRY_IDS)
def test_entry_handed_over_hashes_as_json_loads_of_the_same_bytes(entry_text: str) -> None:
    feed_bytes = build_v2_feed_bytes([entry_text])
    (loaded_entry,) = json.loads(feed_bytes)["vulnerabilities"]

    (entry,) = read_entry_values(feed_bytes)

    assert canonical_sha256(entry) == canonical_sha256(loaded_entry)


@pytest.mark.parametrize("buffer_bytes", [1, 3, TINY_BUFFER_BYTES], ids=["1", "3", "16"])
@pytest.mark.parametrize("padding_chars", BUFFER_OFFSETS, ids=str)
def test_entries_crossing_parser_buffer_boundaries_equal_json_loads(
    buffer_bytes: int, padding_chars: int
) -> None:
    entry_texts = [
        "{}",
        '{"id": "CVE-9999-0001", "score": -12.5e-1}',
        '{"text": "café 中文 😀 \\u00e9", "list": [true, null, 0]}',
        json.dumps(build_v2_entry(2)),
    ]
    feed_bytes = build_v2_feed_bytes(entry_texts, padding="p" * padding_chars)

    entries = read_entry_values(feed_bytes, MigrationLimits(parser_buffer_bytes=buffer_bytes))

    assert entries == json.loads(feed_bytes)["vulnerabilities"]


# Entry size


@pytest.mark.parametrize("padding_chars", [0, 8, 15], ids=str)
@pytest.mark.parametrize(
    "fields_text",
    [
        '"a":"democorp"',
        '"k1":"v","k2":"v","k3":"v","k4":"v","k5":"v"',
        '"n":[' + ",".join(["0"] * 20) + "]",
        '"b":[true,false,null,true,false,null,true,false,null]',
        '"a":{"b":[{"c":[]},{},[[]]]}',
        '"t":"café 中文 😀"',
        '\n  "a" : [ 1 , 2 ] ,\n  "b" : "x"\n',
    ],
    ids=["one_string", "many_keys", "numbers", "literals", "nested", "non_ascii", "whitespace"],
)
def test_entry_exactly_at_the_byte_cap_is_handed_over(fields_text: str, padding_chars: int) -> None:
    limits = MigrationLimits(
        max_entry_bytes=SMALL_ENTRY_CAP_BYTES, parser_buffer_bytes=TINY_BUFFER_BYTES
    )
    entry_text = build_entry_text_of_size(fields_text, SMALL_ENTRY_CAP_BYTES)
    feed_bytes = build_v2_feed_bytes([entry_text, entry_text], padding="p" * padding_chars)

    entries = read_entry_values(feed_bytes, limits)

    assert entries == json.loads(feed_bytes)["vulnerabilities"]


@pytest.mark.parametrize(
    "entry_text",
    [
        '{"a": "' + "x" * SMALL_ENTRY_CAP_BYTES + '"}',
        '{"description": "' + "x" * HUGE_STRING_CHARS + '"}',
        "{" + ", ".join(f'"key{number:03d}": "value"' for number in range(40)) + "}",
        '{"a": [' + ", ".join(['"democorp"'] * 40) + "]}",
        '{"a":' + " " * (SMALL_ENTRY_CAP_BYTES + 3 * TINY_BUFFER_BYTES) + "1}",
    ],
    ids=[
        "string_one_past_the_cap",
        "one_huge_string",
        "many_keys",
        "many_strings",
        "whitespace_past_the_cap_and_its_read_ahead",
    ],
)
def test_entry_over_the_byte_cap_fails_as_entry_too_large(entry_text: str) -> None:
    limits = MigrationLimits(
        max_entry_bytes=SMALL_ENTRY_CAP_BYTES, parser_buffer_bytes=TINY_BUFFER_BYTES
    )

    failure_code = read_failure_code(build_v2_feed_bytes([entry_text]), limits)

    assert failure_code is MigrationFailureCode.ENTRY_TOO_LARGE


@pytest.mark.parametrize("padding_chars", BUFFER_OFFSETS, ids=str)
def test_one_huge_string_is_refused_before_the_parser_reads_past_the_cap_and_three_buffers(
    padding_chars: int,
) -> None:
    # The parser has read up to one buffer past an entry's start when the entry begins,
    # the cap allows one buffer of read-ahead, and the refusing read adds at most one.
    limits = MigrationLimits(
        max_entry_bytes=SMALL_ENTRY_CAP_BYTES, parser_buffer_bytes=TINY_BUFFER_BYTES
    )
    entry_text = '{"description": "' + "x" * HUGE_STRING_CHARS + '"}'
    feed_bytes = build_v2_feed_bytes([entry_text], padding="p" * padding_chars)
    entry_offset = find_first_entry_offset(feed_bytes)
    payload = open_feed(feed_bytes, limits)

    with pytest.raises(MigrationFailed):
        read_nvd_feed(payload, EntryRecorder().record)

    assert payload.position - entry_offset <= SMALL_ENTRY_CAP_BYTES + 3 * TINY_BUFFER_BYTES


def test_entry_size_is_counted_afresh_for_every_entry() -> None:
    limits = MigrationLimits(
        max_entry_bytes=SMALL_ENTRY_CAP_BYTES, parser_buffer_bytes=TINY_BUFFER_BYTES
    )
    entry_text = '{"a": "' + "x" * (SMALL_ENTRY_CAP_BYTES - 8) + '"}'
    feed_bytes = build_v2_feed_bytes([entry_text] * 10)

    entries = read_entry_values(feed_bytes, limits)

    assert entries == json.loads(feed_bytes)["vulnerabilities"]


# Malformed JSON and the payload hash


@pytest.mark.parametrize(
    "trailing_bytes",
    [b" x", b"{}", b"]", b",", b"\x00", b'"tail"', b" \n {}"],
    ids=[
        "word",
        "second_object",
        "closing_bracket",
        "comma",
        "nul_byte",
        "string",
        "spaced_object",
    ],
)
def test_feed_followed_by_anything_but_whitespace_fails_as_invalid_json(
    trailing_bytes: bytes,
) -> None:
    feed_bytes = encode_feed(build_feed(NvdFeedFormat.V2_0)) + trailing_bytes

    failure_code = read_failure_code(feed_bytes)

    assert failure_code is MigrationFailureCode.INVALID_JSON


@pytest.mark.parametrize(
    "cut_before",
    [
        b'{"vulnerabilities"',
        b'"vulnerabilities"',
        b'[{"cve"',
        b'"sourceIdentifier"',
        b', "resultsPerPage"',
        b'VD_CVE"',
        b'"2026-10-20T00:00:00.000"',
    ],
    ids=[
        "empty_payload",
        "after_the_opening_brace",
        "at_the_entry_array_start",
        "inside_an_entry",
        "right_after_the_entry_array",
        "inside_a_header_value",
        "after_the_last_header_key",
    ],
)
def test_truncated_feed_fails_as_invalid_json(cut_before: bytes) -> None:
    feed = order_feed_fields(build_feed(NvdFeedFormat.V2_0), "vulnerabilities", True)
    feed_bytes = encode_feed(feed)

    failure_code = read_failure_code(feed_bytes[: feed_bytes.index(cut_before)])

    assert failure_code is MigrationFailureCode.INVALID_JSON


def test_feed_missing_its_final_brace_fails_as_invalid_json() -> None:
    feed_bytes = encode_feed(build_feed(NvdFeedFormat.V2_0))

    failure_code = read_failure_code(feed_bytes[:-1])

    assert failure_code is MigrationFailureCode.INVALID_JSON


@pytest.mark.parametrize(
    ("leading_bytes", "trailing_bytes"),
    [(b"", b""), (b"", b"\n"), (b"", b" \n\t\r\n  "), (b"\n  ", b"\n")],
    ids=["no_whitespace", "trailing_newline", "trailing_mixed_whitespace", "leading_and_trailing"],
)
def test_payload_hash_covers_every_byte_including_surrounding_whitespace(
    leading_bytes: bytes, trailing_bytes: bytes
) -> None:
    feed_bytes = leading_bytes + encode_feed(build_feed(NvdFeedFormat.V2_0)) + trailing_bytes
    payload = open_feed(feed_bytes)

    read_nvd_feed(payload, EntryRecorder().record)

    assert payload.read_payload_sha256() == sha256_hex(feed_bytes)


@pytest.mark.parametrize("buffer_bytes", [1, 2, 3, 5, 7, 11, 13, 16], ids=str)
def test_surrogate_pair_split_across_reads_is_read_as_its_character(buffer_bytes: int) -> None:
    feed_bytes = build_v2_feed_bytes(['{"text": "\\ud83d\\ude00"}'])
    limits = replace(DEFAULT_LIMITS, parser_buffer_bytes=buffer_bytes)

    entries = read_entry_values(feed_bytes, limits)

    assert entries == [{"text": "\U0001f600"}]


@pytest.mark.parametrize("buffer_bytes", [1, 3, 7, 16, 64], ids=str)
def test_lone_high_surrogate_is_refused_at_any_read_boundary(buffer_bytes: int) -> None:
    feed_bytes = build_v2_feed_bytes(['{"text": "a\\ud800b"}'])
    limits = replace(DEFAULT_LIMITS, parser_buffer_bytes=buffer_bytes)

    failure_code = read_failure_code(feed_bytes, limits)

    assert failure_code is MigrationFailureCode.INVALID_JSON


@pytest.mark.parametrize("buffer_bytes", [1, 3, 7, 16, 64], ids=str)
def test_escaped_backslash_before_surrogate_like_text_is_plain_text(buffer_bytes: int) -> None:
    """``\\\\ud800`` is a backslash, then the text ``ud800``: no escape at all."""
    feed_bytes = build_v2_feed_bytes(['{"text": "\\\\ud800"}'])
    limits = replace(DEFAULT_LIMITS, parser_buffer_bytes=buffer_bytes)

    entries = read_entry_values(feed_bytes, limits)

    assert entries == [{"text": "\\ud800"}]
