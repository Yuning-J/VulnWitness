"""Anchored synthetic records covering product identity, backlog and version conditions."""

from typing import Any

from tests.support.builders import build_bundle_with, build_versioned_product
from vulnwitness.adapters.fixture.synthetic_fixture import FixtureBundle
from vulnwitness.domain.cve import VersionRange

PRODUCT = "oai-cn5g-amf"
VENDOR = "test_core"
OTHER_VENDOR = "another_core"
FIELD_HIT = "CVE-9999-6101"
FIELD_NO_HIT = "CVE-9999-6102"
FIELD_UNKNOWN = "CVE-9999-6103"
MENTION_ONLY = "CVE-9999-6104"
OTHER_VENDOR_HIT = "CVE-9999-6105"
OWN_PRODUCT = "CVE-9999-6106"
SUBSTRING_MENTION = "CVE-9999-6107"
SCATTERED_MENTION = "CVE-9999-6108"
UNRELATED_PRODUCT = "CVE-9999-6109"
UNAFFECTED_ONLY = "CVE-9999-6110"
CROSS_ENTRY = "CVE-9999-6111"
UNDATED_FIELD = "CVE-9999-6112"
SMF_PRODUCT_ONLY = "CVE-9999-6113"
SMF_VENDOR_AND_PRODUCT = "CVE-9999-6114"


def build_product_query_bundle(fixture_bundle: FixtureBundle) -> FixtureBundle:
    """The packaged fixture plus independent, anchored CVEs; no store or source IO."""
    hit_entry = build_versioned_product(
        vendor=VENDOR, product=PRODUCT, version_ranges=(VersionRange(exact="2.0"),)
    )
    no_hit_entry = hit_entry.model_copy(update={"version_ranges": (VersionRange(exact="1.0"),)})
    unknown_entry = hit_entry.model_copy(update={"version_ranges": (), "status": "unknown"})
    other_vendor_entry = hit_entry.model_copy(update={"vendor": OTHER_VENDOR})
    unrelated_entry = hit_entry.model_copy(update={"product": "different_product"})
    specifications: tuple[tuple[str, str, dict[str, Any]], ...] = (
        # Repeated identity/conditions exercise CVE and pair deduplication.
        (
            FIELD_HIT,
            "[SYNTHETIC] unrelated text",
            {
                "affected": (hit_entry, no_hit_entry),
                "published": "2024-01-01T00:00:00Z",
            },
        ),
        (
            FIELD_NO_HIT,
            "[SYNTHETIC] unrelated text",
            {
                "affected": (no_hit_entry,),
                "published": "2030-01-01T00:00:00Z",
            },
        ),
        (
            FIELD_UNKNOWN,
            "[SYNTHETIC] unrelated text",
            {
                "affected": (unknown_entry,),
                "published": "2024-01-01T00:00:00Z",
            },
        ),
        (
            MENTION_ONLY,
            "[SYNTHETIC] OAI cn5g-AMF in TEST_CORE crashes",
            {
                "published": "2035-01-01T00:00:00Z",
            },
        ),
        (
            OTHER_VENDOR_HIT,
            "[SYNTHETIC] unrelated text",
            {
                "affected": (other_vendor_entry,),
                "published": "2025-01-01T00:00:00Z",
            },
        ),
        (
            OWN_PRODUCT,
            "[SYNTHETIC] oai-cn5g-amf crashes",
            {
                "affected": (unrelated_entry,),
            },
        ),
        (SUBSTRING_MENTION, "[SYNTHETIC] oai-cn5g-amfx crashes", {}),
        (SCATTERED_MENTION, "[SYNTHETIC] oai unrelated cn5g amf", {}),
        (
            UNRELATED_PRODUCT,
            "[SYNTHETIC] unrelated text",
            {
                "affected": (unrelated_entry,),
            },
        ),
        (
            UNAFFECTED_ONLY,
            "[SYNTHETIC] oai-cn5g-amf crashes",
            {
                "affected": (hit_entry.model_copy(update={"status": "unaffected"}),),
            },
        ),
        (
            CROSS_ENTRY,
            "[SYNTHETIC] unrelated text",
            {
                "affected": (
                    unrelated_entry,
                    other_vendor_entry.model_copy(
                        update={"version_ranges": (VersionRange(exact="1.0"),)}
                    ),
                ),
            },
        ),
        (
            UNDATED_FIELD,
            "[SYNTHETIC] oai-cn5g-amf crashes",
            {
                "affected": (unknown_entry,),
            },
        ),
        (SMF_PRODUCT_ONLY, '[SYNTHETIC] Simple Machines Forum "SMF" crashes.', {}),
        (SMF_VENDOR_AND_PRODUCT, "[SYNTHETIC] SMF crashes in free5GC.", {}),
    )
    for cve_id, description, fields in specifications:
        fixture_bundle = build_bundle_with(fixture_bundle, cve_id, description, **fields)
    return fixture_bundle
