"""What the importer's JSON parsers hand back, and the parsers themselves as one value.
The parsers need the ``migration`` extra and are loaded only through the
``migration_parsers`` entry point, so the rest of the importer imports these types alone.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from vulnwitness.adapters.migration.input_files import PayloadStream
from vulnwitness.domain.corpus_store_manifest import NvdFeedFormat
from vulnwitness.domain.migration_report import LegacyFileKind


@dataclass(frozen=True)
class FeedHeader:
    """What a feed declares about itself: its format and its generation time as written."""

    feed_format: NvdFeedFormat
    generated_at_text: str | None


# Called with the feed's format, the entry's index in the feed and the entry.
EntryHandler = Callable[[NvdFeedFormat, int, dict[str, Any]], None]


@dataclass(frozen=True)
class MigrationParsers:
    """``read_nvd_feed`` streams a feed's entries to a handler and returns its header;
    ``classify_json_prefix`` tells a legacy derived file by its first bytes."""

    read_nvd_feed: Callable[[PayloadStream, EntryHandler], FeedHeader]
    classify_json_prefix: Callable[[bytes], LegacyFileKind | None]
