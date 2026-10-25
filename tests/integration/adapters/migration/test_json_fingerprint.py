"""``classify_json_prefix`` over authored file prefixes (ADR 0008 §1).

Proves that each legacy derived JSON shape CVE-KGRAG writes is told by its keys, whole or
cut off once those keys have been read; that NVD feeds, other JSON and non-JSON bytes are
not taken for a derived file; and that a string the parser cannot decode ends the read
without raising, keeping what was read before it.
"""

import json
from typing import Any

import pytest

from cve_kgrag.adapters.migration.json_fingerprint import classify_json_prefix
from cve_kgrag.domain.migration_report import LegacyFileKind
from tests.support.legacy_inputs import (
    build_v1_feed,
    build_v1_item,
    build_v2_entry,
    build_v2_feed,
    encode_feed,
)

ENHANCED_DOCUMENT = {
    "id": "doc-CVE-9999-0001",
    "document_type": "cve",
    "content": "SYNTHETIC: democorp gateway mishandles input.",
    "cve_refs": ["CVE-9999-0001"],
    "cwe_refs": ["CWE-79"],
    "metadata": {"year": 9999},
}
GRAPH_NODES = [{"id": "CVE-9999-0001", "label": "CVE"}, {"id": "CWE-79", "label": "CWE"}]
GRAPH_LINKS = [{"source": "CVE-9999-0001", "target": "CWE-79", "type": "HAS_WEAKNESS"}]


def encode_document(document: Any) -> bytes:
    return json.dumps(document).encode()


def cut_after(document: Any, marker: str) -> bytes:
    """The document's bytes up to and including the first ``marker``: a prefix cut off
    mid-document."""
    document_bytes = encode_document(document)
    marker_bytes = marker.encode()
    return document_bytes[: document_bytes.index(marker_bytes) + len(marker_bytes)]


@pytest.mark.parametrize(
    ("prefix", "expected_kind"),
    [
        (encode_document([ENHANCED_DOCUMENT]), LegacyFileKind.ENHANCED_DOCUMENTS),
        (
            encode_document([{"content": "SYNTHETIC: text.", "metadata": {"cve_id": "x"}}]),
            LegacyFileKind.RAG_EXPORT,
        ),
        (
            encode_document([{"content": "SYNTHETIC: text.", "cwe_refs": ["CWE-79"]}]),
            LegacyFileKind.RAG_EXPORT,
        ),
        (
            encode_document([{"content": "SYNTHETIC: text.", "weaknesses": ["CWE-79"]}]),
            LegacyFileKind.RAG_EXPORT,
        ),
        (
            encode_document([{"text": "SYNTHETIC: text.", "cve_id": "CVE-9999-0001"}]),
            LegacyFileKind.RAG_EXPORT,
        ),
        (
            encode_document({"nodes": GRAPH_NODES, "relationships": GRAPH_LINKS}),
            LegacyFileKind.GRAPH_EXPORT,
        ),
        (
            encode_document({"nodes": GRAPH_NODES, "edges": GRAPH_LINKS}),
            LegacyFileKind.GRAPH_EXPORT,
        ),
        (
            encode_document({"directed": True, "nodes": GRAPH_NODES, "links": GRAPH_LINKS}),
            LegacyFileKind.GRAPH_EXPORT,
        ),
        (
            encode_document({"nodes": GRAPH_NODES}),
            LegacyFileKind.GRAPH_EXPORT,
        ),
        (
            encode_document({"vendors": {"democorp": 1}, "products": {"gateway": 1}}),
            LegacyFileKind.CPE_PARSING_RESULTS,
        ),
        (
            encode_document({"vendors": {"democorp": 1}, "skipped_cves_no_cpe": ["CVE-9999-0002"]}),
            LegacyFileKind.CPE_PARSING_RESULTS,
        ),
        (
            encode_document({"basic_stats": {"total_cves": 2}}),
            LegacyFileKind.ANALYTICS,
        ),
        (
            encode_document({"timestamp": "2099-01-01T00:00:00", "cve_analysis": {"total": 2}}),
            LegacyFileKind.ANALYTICS,
        ),
        (
            encode_document({"documents_by_year": {"9999": 2}}),
            LegacyFileKind.ANALYTICS,
        ),
        (
            encode_document({"CVE-9999-0001": ["CWE-79"], "CVE-9999-0002": ["CWE-89"]}),
            LegacyFileKind.MAPPING,
        ),
        (
            encode_document({"CWE-79": ["CVE-9999-0001"], "CWE-89": ["CVE-9999-0002"]}),
            LegacyFileKind.MAPPING,
        ),
        (
            encode_document({"CVE-9999-0001": ["CWE-79"], "CWE-89": ["CVE-9999-0002"]}),
            LegacyFileKind.MAPPING,
        ),
    ],
    ids=[
        "enhanced_documents",
        "rag_export_with_metadata",
        "rag_export_with_cwe_refs",
        "rag_export_with_weaknesses",
        "rag_export_text_with_cve_id",
        "graph_export_with_relationships",
        "graph_export_with_edges",
        "graph_export_with_links",
        "graph_export_with_nodes_alone",
        "cpe_parsing_results_with_products",
        "cpe_parsing_results_with_skipped_cves",
        "analytics_with_basic_stats",
        "analytics_with_timestamp_and_cve_analysis",
        "analytics_with_documents_by_year",
        "mapping_by_cve_id",
        "mapping_by_cwe_id",
        "mapping_by_both_ids",
    ],
)
def test_whole_derived_file_is_classified_by_its_keys(
    prefix: bytes, expected_kind: LegacyFileKind
) -> None:
    file_kind = classify_json_prefix(prefix)

    assert file_kind is expected_kind


@pytest.mark.parametrize(
    ("prefix", "expected_kind"),
    [
        (
            cut_after([ENHANCED_DOCUMENT, ENHANCED_DOCUMENT], '"cwe_refs": ["CWE'),
            LegacyFileKind.ENHANCED_DOCUMENTS,
        ),
        (
            cut_after([{"content": "SYNTHETIC: text.", "metadata": {"source": "nvd"}}], '"sou'),
            LegacyFileKind.RAG_EXPORT,
        ),
        (
            cut_after({"nodes": GRAPH_NODES, "relationships": GRAPH_LINKS}, '"HAS_WEAK'),
            LegacyFileKind.GRAPH_EXPORT,
        ),
        (
            cut_after({"nodes": GRAPH_NODES, "edges": GRAPH_LINKS}, '"edges"'),
            LegacyFileKind.GRAPH_EXPORT,
        ),
        (
            cut_after({"nodes": GRAPH_NODES, "relationships": GRAPH_LINKS}, '"nodes": [{'),
            LegacyFileKind.GRAPH_EXPORT,
        ),
        (
            cut_after({"vendors": {"democorp": 1}, "products": {"gateway": 1}}, '{"gate'),
            LegacyFileKind.CPE_PARSING_RESULTS,
        ),
        (
            cut_after({"basic_stats": {"total_cves": 2}}, '"basic_stats"'),
            LegacyFileKind.ANALYTICS,
        ),
        (
            cut_after({"basic_stats": {"total_cves": 2}}, '"total_c'),
            LegacyFileKind.ANALYTICS,
        ),
        (
            cut_after(
                {"CVE-9999-0001": ["CWE-79"], "CVE-9999-0002": ["CWE-89"]}, '"CVE-9999-0002": ['
            ),
            LegacyFileKind.MAPPING,
        ),
    ],
    ids=[
        "enhanced_documents_inside_the_first_document",
        "rag_export_inside_metadata",
        "graph_export_inside_the_links",
        "graph_export_right_after_the_link_key",
        "graph_export_inside_the_node_list",
        "cpe_parsing_results_inside_products",
        "analytics_right_after_the_deciding_key",
        "analytics_inside_a_nested_key",
        "mapping_inside_a_value",
    ],
)
def test_prefix_cut_off_after_the_deciding_keys_is_still_classified(
    prefix: bytes, expected_kind: LegacyFileKind
) -> None:
    file_kind = classify_json_prefix(prefix)

    assert file_kind is expected_kind


def test_prefix_cut_off_inside_a_multibyte_character_is_still_classified() -> None:
    prefix = encode_document({"nodes": [], "edges": []})[:-1] + b', "name": "caf\xc3'

    file_kind = classify_json_prefix(prefix)

    assert file_kind is LegacyFileKind.GRAPH_EXPORT


@pytest.mark.parametrize(
    "prefix",
    [
        encode_feed(build_v2_feed([build_v2_entry(1), build_v2_entry(2)])),
        encode_feed(build_v1_feed([build_v1_item(1), build_v1_item(2)])),
        cut_after(build_v2_feed([build_v2_entry(1)]), '"vulnerabilities": [{"cve'),
        encode_document({"name": "SYNTHETIC", "items": [1, 2]}),
        encode_document({}),
        encode_document([]),
        encode_document([1, 2]),
        encode_document([{"title": "SYNTHETIC"}]),
        encode_document([{"content": "SYNTHETIC: text without a second key."}]),
        encode_document([{"metadata": {"cve_id": "CVE-9999-0001"}}]),
        encode_document([[ENHANCED_DOCUMENT]]),
        encode_document({"documents": [ENHANCED_DOCUMENT]}),
        encode_document({"relationships": GRAPH_LINKS}),
        encode_document({"vendors": {"democorp": 1}}),
        encode_document({"timestamp": "2099-01-01T00:00:00"}),
        encode_document({"CVE-9999-0001": ["CWE-79"], "note": "SYNTHETIC"}),
        encode_document({"cve-9999-0001": ["CWE-79"]}),
        encode_document("SYNTHETIC"),
        encode_document(42),
        encode_document(None),
    ],
    ids=[
        "nvd_2.0_feed",
        "nvd_1.1_feed",
        "nvd_2.0_feed_prefix",
        "arbitrary_object",
        "empty_object",
        "empty_list",
        "list_of_numbers",
        "list_of_unknown_objects",
        "list_with_text_alone",
        "list_with_metadata_alone",
        "list_of_lists",
        "object_wrapping_documents",
        "graph_links_alone",
        "cpe_vendors_alone",
        "analytics_timestamp_alone",
        "mapping_with_a_key_that_is_no_id",
        "mapping_with_lower_case_ids",
        "top_level_string",
        "top_level_number",
        "top_level_null",
    ],
)
def test_json_that_is_no_legacy_derived_file_is_not_classified(prefix: bytes) -> None:
    file_kind = classify_json_prefix(prefix)

    assert file_kind is None


@pytest.mark.parametrize(
    "prefix",
    [
        b"",
        b"   ",
        b"SYNTHETIC: not json",
        b"\x80\x04\x95\x10\x00\x00\x00\x00\x00\x00\x00",
        b"\x93NUMPY\x01\x00v\x00",
        b"PK\x03\x04\x14\x00\x00\x00",
        b"cveID,vendorProject,product\r\nCVE-9999-0001,Democorp,Gateway\r\n",
        b"\xff\xfe{\x00",
        b"{'basic_stats': {}}",
    ],
    ids=[
        "empty",
        "whitespace_only",
        "text",
        "pickle",
        "numpy_array",
        "zip_archive",
        "kev_csv",
        "utf16_bytes",
        "python_literal",
    ],
)
def test_bytes_that_are_not_json_are_not_classified(prefix: bytes) -> None:
    file_kind = classify_json_prefix(prefix)

    assert file_kind is None


@pytest.mark.parametrize(
    ("prefix", "expected_kind"),
    [
        (b'{"basic_stats": {"note": "\\udc00"}}', LegacyFileKind.ANALYTICS),
        (b'[{"metadata": {}, "content": "\\udc00"}]', LegacyFileKind.RAG_EXPORT),
        (b'{"nodes": [], "edges": [], "name": "\xed\xa0\x80"}', LegacyFileKind.GRAPH_EXPORT),
        (b'{"\\udc00": 1}', None),
        (b'{"\\ud800": 1}', None),
    ],
    ids=[
        "lone_low_surrogate_after_the_analytics_key",
        "lone_low_surrogate_after_the_rag_keys",
        "surrogate_utf8_bytes_after_the_graph_keys",
        "lone_low_surrogate_as_the_first_key",
        "lone_high_surrogate_as_the_first_key",
    ],
)
def test_string_that_is_not_valid_unicode_ends_the_read_keeping_the_keys_before_it(
    prefix: bytes, expected_kind: LegacyFileKind | None
) -> None:
    file_kind = classify_json_prefix(prefix)

    assert file_kind is expected_kind
