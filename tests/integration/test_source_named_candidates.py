"""CNA/ADP-named records that the CPE inventory misses are listed apart as candidates."""

from tests.support.builders import build_bundle_with, build_versioned_product
from vulnwitness.adapters.fixture.synthetic_fixture import FixtureBundle
from vulnwitness.composition import build_product_query_service
from vulnwitness.domain.cve import SourceAffected, SourceAffectedProduct
from vulnwitness.domain.product_query import ProductQueryRequest
from vulnwitness.interfaces.product_query_summary import render_product_query_summary


def source_block(vendor: str, product: str, *cpes: str) -> tuple[SourceAffected, ...]:
    return (
        SourceAffected(
            source="cna@open5gs.example",
            products=(SourceAffectedProduct(vendor=vendor, product=product, cpes=cpes),),
        ),
    )


def build_bundle(fixture_bundle: FixtureBundle) -> FixtureBundle:
    bundle = build_bundle_with(
        fixture_bundle,
        "CVE-2026-7001",
        "SYNTHETIC: field-matched flaw.",
        affected=(build_versioned_product(vendor="open5gs", product="open5gs"),),
        source_affected=source_block("Open5GS", "Open5GS"),
    )
    bundle = build_bundle_with(
        bundle,
        "CVE-2026-7002",
        "SYNTHETIC: an unenriched flaw in the session management code.",
        nvd_status="Deferred",
        source_affected=source_block("Open5GS", "Open5GS"),
    )
    bundle = build_bundle_with(
        bundle,
        "CVE-2026-7003",
        "SYNTHETIC: a flaw named only through the CNA's CPE.",
        nvd_status="Deferred",
        source_affected=source_block(
            "The Open5GS Project", "core", "cpe:2.3:a:open5gs:open5gs:*:*:*:*:*:*:*:*"
        ),
    )
    return build_bundle_with(
        bundle,
        "CVE-2026-7004",
        "SYNTHETIC: another vendor's product.",
        nvd_status="Deferred",
        source_affected=source_block("Other Vendor", "Open5GS"),
    )


def test_cna_named_records_are_candidates_outside_the_inventory(
    fixture_bundle: FixtureBundle,
) -> None:
    service = build_product_query_service(build_bundle(fixture_bundle))

    response = service.query(ProductQueryRequest(vendor="open5gs", product="open5gs"))

    assert [item.record.cve_id for item in response.items] == ["CVE-2026-7001"]
    assert response.total_available == 1
    assert response.source_named_total == 2
    assert [c.cve_id for c in response.source_named_candidates] == [
        "CVE-2026-7003",
        "CVE-2026-7002",
    ]
    by_id = {candidate.cve_id: candidate for candidate in response.source_named_candidates}
    assert by_id["CVE-2026-7002"].vendor == "Open5GS"
    assert by_id["CVE-2026-7002"].nvd_status == "Deferred"
    assert by_id["CVE-2026-7003"].product == "core"
    text = render_product_query_summary(response)
    assert "Source-named candidates (not in the inventory or its count): 2." in text
    assert "Not Scheduled (API:" in text


def test_separators_and_case_are_alike(fixture_bundle: FixtureBundle) -> None:
    bundle = build_bundle_with(
        fixture_bundle,
        "CVE-2026-7010",
        "SYNTHETIC: unenriched.",
        source_affected=source_block("Demo Corp", "Demo-Gateway"),
    )

    response = build_product_query_service(bundle).query(
        ProductQueryRequest(vendor="demo_corp", product="demo_gateway")
    )

    assert response.source_named_total == 1
