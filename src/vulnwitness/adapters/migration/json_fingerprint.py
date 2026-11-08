"""Tell a legacy derived JSON file by the keys its first bytes show (ADR 0008 §1). Needs
the ``migration`` extra.

Only a bounded prefix is parsed, so a large file is never read whole and a cut-off
document is expected: the classifier reads the top-level shape and the keys of the
first object it meets, then stops. The rules follow the keys the CVE-KGRAG writers
emit (commit ``b64eef3``); a file matching none is not a derived file the importer
knows.
"""

import re

import ijson

from vulnwitness.adapters.migration.ijson_events import parse_basic_events
from vulnwitness.domain.migration_report import LegacyFileKind

# Keys read before giving up on a prefix: enough for the shapes below.
MAX_FINGERPRINT_KEYS = 64
PREFIX_BUFFER_BYTES = 64 * 1024
LEGACY_ID_KEY_PATTERN = r"^(?:CVE-[0-9]{4}-[0-9]+|CWE-[0-9]+)$"


def classify_top_level_object(keys: list[str]) -> LegacyFileKind | None:
    """A derived file whose top level is an object, by its keys."""
    key_set = set(keys)
    if "basic_stats" in key_set or {"timestamp", "cve_analysis"} <= key_set:
        return LegacyFileKind.ANALYTICS
    if "documents_by_year" in key_set:
        return LegacyFileKind.ANALYTICS
    # A graph export's node list can run past the prefix before its relationships begin,
    # so a top-level "nodes" key alone tells it; no NVD feed or KEV catalog has one.
    if "nodes" in key_set:
        return LegacyFileKind.GRAPH_EXPORT
    if "vendors" in key_set and key_set & {"products", "skipped_cves_no_cpe"}:
        return LegacyFileKind.CPE_PARSING_RESULTS
    if keys and all(re.fullmatch(LEGACY_ID_KEY_PATTERN, key) for key in keys):
        return LegacyFileKind.MAPPING
    return None


def classify_document(keys: list[str]) -> LegacyFileKind | None:
    """A derived file whose top level is a list, by its first element's keys."""
    key_set = set(keys)
    if {"document_type", "cve_refs"} <= key_set:
        return LegacyFileKind.ENHANCED_DOCUMENTS
    has_text = bool(key_set & {"content", "text"})
    if has_text and key_set & {"metadata", "cwe_refs", "weaknesses", "cve_id"}:
        return LegacyFileKind.RAG_EXPORT
    return None


def read_prefix_keys(prefix: bytes) -> tuple[str, list[str]]:
    """The top-level shape (``object``, ``list`` or ``other``) and the keys of the first
    object the prefix shows: the top-level object's, or a list's first element's."""
    events = parse_basic_events(prefix, PREFIX_BUFFER_BYTES)
    keys: list[str] = []
    shape = "other"
    try:
        first_event = next(events, None)
        if first_event is None or first_event[0] not in {"start_map", "start_array"}:
            return shape, keys
        shape = "object" if first_event[0] == "start_map" else "list"
        # The depth of the object whose keys are read: the top level, or a list's element.
        key_depth = 1 if shape == "object" else 2
        depth = 1
        for event, event_value in events:
            if event in {"start_map", "start_array"}:
                depth += 1
            elif event in {"end_map", "end_array"}:
                depth -= 1
                if depth < key_depth:
                    break
            elif event == "map_key" and depth == key_depth:
                keys.append(event_value)
                if len(keys) >= MAX_FINGERPRINT_KEYS:
                    break
            elif depth < key_depth:
                # A list whose first element is not an object has no keys to read.
                break
    except (ijson.JSONError, UnicodeDecodeError):
        # A prefix is usually cut off mid-document, possibly inside a character; what was
        # read so far still counts.
        pass
    return shape, keys


def classify_json_prefix(prefix: bytes) -> LegacyFileKind | None:
    """The kind of legacy derived file ``prefix`` begins, or ``None``."""
    if prefix.startswith(b"PAR1"):
        return None
    shape, keys = read_prefix_keys(prefix)
    if shape == "object":
        return classify_top_level_object(keys)
    if shape == "list":
        return classify_document(keys)
    return None
