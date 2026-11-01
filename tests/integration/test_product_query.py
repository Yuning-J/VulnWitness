"""Product queries read exact fields and explicitly distinguish CPE-less mentions."""

import pytest

from tests.support.builders import build_bundle_with
from tests.support.product_queries import (
    CROSS_ENTRY,
    FIELD_HIT,
    FIELD_NO_HIT,
    FIELD_UNKNOWN,
    MENTION_ONLY,
    OTHER_VENDOR,
    OTHER_VENDOR_HIT,
    OWN_PRODUCT,
    PRODUCT,
    SMF_PRODUCT_ONLY,
    SMF_VENDOR_AND_PRODUCT,
    UNAFFECTED_ONLY,
    UNDATED_FIELD,
    UNRELATED_PRODUCT,
    VENDOR,
)
from vulnwitness.adapters.fixture.synthetic_fixture import FixtureBundle
from vulnwitness.composition import build_product_query_service
from vulnwitness.domain.product_query import ProductQueryRequest


@pytest.mark.parametrize(
    "vendor,product,expected_ids",
    [
        (
            VENDOR.upper(),
            None,
            {
                FIELD_HIT,
                FIELD_NO_HIT,
                FIELD_UNKNOWN,
                MENTION_ONLY,
                OWN_PRODUCT,
                UNRELATED_PRODUCT,
                CROSS_ENTRY,
                UNDATED_FIELD,
            },
        ),
        (
            None,
            PRODUCT.upper(),
            {
                FIELD_HIT,
                FIELD_NO_HIT,
                FIELD_UNKNOWN,
                MENTION_ONLY,
                OTHER_VENDOR_HIT,
                UNAFFECTED_ONLY,
                CROSS_ENTRY,
                UNDATED_FIELD,
            },
        ),
        (
            VENDOR.upper(),
            PRODUCT.upper(),
            {
                FIELD_HIT,
                FIELD_NO_HIT,
                FIELD_UNKNOWN,
                MENTION_ONLY,
                UNDATED_FIELD,
            },
        ),
    ],
    ids=["vendor_only_all_products", "product_only_all_vendors", "same_entry_vendor_and_product"],
)
def test_explicit_names_return_every_exact_field_and_eligible_mention(
    product_query_bundle: FixtureBundle,
    vendor: str | None,
    product: str | None,
    expected_ids: set[str],
) -> None:
    # Arrange
    service = build_product_query_service(product_query_bundle)
    request = ProductQueryRequest(vendor=vendor, product=product, limit=20)

    # Act
    vulnerabilities = service.query(request)

    # Assert
    cve_ids: set[str] = set()
    for vulnerability in vulnerabilities.items:
        cve_ids.add(vulnerability.record.cve_id)
    assert cve_ids == expected_ids
    assert len(vulnerabilities.items) == vulnerabilities.total_available == len(expected_ids)


def test_ambiguous_product_reports_every_vendor_even_beyond_the_cap(
    product_query_bundle: FixtureBundle,
) -> None:
    # Arrange
    service = build_product_query_service(product_query_bundle)

    # Act
    vulnerabilities = service.query(ProductQueryRequest(product=PRODUCT, limit=1))

    # Assert
    assert vulnerabilities.limit == len(vulnerabilities.items) == 1
    assert vulnerabilities.total_available == 8
    assert vulnerabilities.matched_products[0].vendor == OTHER_VENDOR
    assert vulnerabilities.matched_products[1].vendor == VENDOR
    assert len(vulnerabilities.matched_products) == 2


def test_description_mentions_require_vendor_and_product_tokens(
    product_query_bundle: FixtureBundle,
) -> None:
    # Arrange
    service = build_product_query_service(product_query_bundle)

    # Act
    vulnerabilities = service.query(ProductQueryRequest(vendor=VENDOR, product=PRODUCT))

    # Assert
    bases_by_id = {}
    for vulnerability in vulnerabilities.items:
        bases_by_id[vulnerability.record.cve_id] = vulnerability.basis.model_dump(mode="json")
    assert bases_by_id[MENTION_ONLY] == {
        "kind": "description_mention",
        "matched_phrase": "oai cn5g amf",
    }
    assert UNAFFECTED_ONLY not in bases_by_id
    assert vulnerabilities.description_mentions_vendor_unconfirmed == 1
    assert bases_by_id[UNDATED_FIELD] == {
        "kind": "product_field",
        "matched_products": [{"vendor": VENDOR, "product": PRODUCT}],
    }


@pytest.mark.parametrize("version", [None, "2.0", "9.0", "release-x"])
def test_version_never_filters_out_any_matching_cve(
    product_query_bundle: FixtureBundle,
    version: str | None,
) -> None:
    # Arrange
    service = build_product_query_service(product_query_bundle)

    # Act
    vulnerabilities = service.query(
        ProductQueryRequest(vendor=VENDOR, product=PRODUCT, version=version)
    )

    # Assert
    assert vulnerabilities.total_available == len(vulnerabilities.items) == 5
    assert all(candidate.applicability == "unknown" for candidate in vulnerabilities.items)
    assert all(
        (candidate.nvd_version_note is None) == (version is None)
        for candidate in vulnerabilities.items
    )


def test_version_facts_keep_nvd_wording_and_unknown_reasons(
    product_query_bundle: FixtureBundle,
) -> None:
    # Arrange
    service = build_product_query_service(product_query_bundle)

    # Act
    vulnerabilities = service.query(
        ProductQueryRequest(vendor=VENDOR, product=PRODUCT, version="2.0")
    )

    # Assert
    notes_by_id = {}
    for vulnerability in vulnerabilities.items:
        notes_by_id[vulnerability.record.cve_id] = vulnerability.nvd_version_note
    hit = notes_by_id[FIELD_HIT]
    assert hit is not None and hit.outcome == "hit"
    assert "matches an NVD CPE version condition" in hit.wording
    assert hit.matched_entry.vendor == VENDOR
    no_hit = notes_by_id[FIELD_NO_HIT]
    assert no_hit is not None and no_hit.outcome == "no_hit"
    assert "matches none of the NVD CPE version conditions" in no_hit.wording
    assert "this does not show the version is unaffected" in no_hit.wording
    unknown = notes_by_id[FIELD_UNKNOWN]
    assert unknown is not None and unknown.outcome == "unknown"
    assert unknown.reason_code == "no_version_condition"
    mention = notes_by_id[MENTION_ONLY]
    assert mention is not None and mention.outcome == "unknown"
    assert mention.reason_code == "description_mention_only"


@pytest.mark.parametrize(
    "version,expected_ids",
    [
        (
            None,
            [FIELD_NO_HIT, FIELD_HIT, FIELD_UNKNOWN, UNDATED_FIELD, MENTION_ONLY],
        ),
        (
            "2.0",
            [FIELD_HIT, FIELD_UNKNOWN, UNDATED_FIELD, MENTION_ONLY, FIELD_NO_HIT],
        ),
    ],
    ids=["basis_then_date_missing_last_and_id", "version_fact_before_basis_and_date"],
)
def test_grouping_follows_version_basis_publication_and_cve_id(
    product_query_bundle: FixtureBundle,
    version: str | None,
    expected_ids: list[str],
) -> None:
    # Arrange
    service = build_product_query_service(product_query_bundle)

    # Act
    vulnerabilities = service.query(
        ProductQueryRequest(vendor=VENDOR, product=PRODUCT, version=version)
    )

    # Assert
    cve_ids: list[str] = []
    for vulnerability in vulnerabilities.items:
        cve_ids.append(vulnerability.record.cve_id)
    assert cve_ids == expected_ids


@pytest.mark.parametrize(
    "vendor,product,expected_ids,excluded_count",
    [
        (None, "smf", {SMF_PRODUCT_ONLY, SMF_VENDOR_AND_PRODUCT}, 0),
        ("free5gc", "smf", {SMF_VENDOR_AND_PRODUCT}, 1),
        ("does-not-exist", "smf", set(), 2),
        ("free5gc", None, {SMF_VENDOR_AND_PRODUCT}, 0),
    ],
    ids=["product_only", "vendor_and_product", "unknown_vendor", "vendor_only"],
)
def test_smf_mentions_honor_every_explicit_name_and_count_exclusions_before_cap(
    product_query_bundle: FixtureBundle,
    vendor: str | None,
    product: str | None,
    expected_ids: set[str],
    excluded_count: int,
) -> None:
    service = build_product_query_service(product_query_bundle)

    vulnerabilities = service.query(ProductQueryRequest(vendor=vendor, product=product, limit=1))

    assert vulnerabilities.total_available == len(expected_ids)
    assert vulnerabilities.description_mentions_vendor_unconfirmed == excluded_count
    assert len(vulnerabilities.items) == min(1, len(expected_ids))
    for vulnerability in vulnerabilities.items:
        assert vulnerability.record.cve_id in expected_ids
        assert vulnerability.basis.kind == "description_mention"
    assert vulnerabilities.matched_products == ()


@pytest.mark.parametrize(
    "description,is_match",
    [
        ("SMF crashes in TEST-CORE.", True),
        ("TEST_CORE has an issue in SMF.", True),
        ("SMF crashes in test_corex.", False),
        ("SMF crashes in test unrelated core.", False),
        ("TEST_CORE has an issue in SMFx.", False),
    ],
    ids=[
        "product_first",
        "vendor_first",
        "vendor_substring",
        "vendor_scattered",
        "product_substring",
    ],
)
def test_each_description_name_is_a_separate_consecutive_whole_token_phrase(
    fixture_bundle: FixtureBundle, description: str, is_match: bool
) -> None:
    bundle = build_bundle_with(fixture_bundle, SMF_VENDOR_AND_PRODUCT, f"[SYNTHETIC] {description}")
    service = build_product_query_service(bundle)

    vulnerabilities = service.query(ProductQueryRequest(vendor="test_core", product="smf"))

    assert vulnerabilities.total_available == int(is_match)
    if is_match:
        assert vulnerabilities.items[0].basis.model_dump() == {
            "kind": "description_mention",
            "matched_phrase": "smf",
        }


def test_product_punctuation_and_whole_name_are_preserved_for_field_matches(
    fixture_bundle: FixtureBundle,
) -> None:
    # Arrange
    service = build_product_query_service(fixture_bundle)

    # Act
    vulnerabilities = service.query(ProductQueryRequest(product="demo gateway"))

    # Assert
    assert vulnerabilities.items == ()
    assert vulnerabilities.total_available == 0


def test_vendor_constraint_excludes_other_products_version_conditions(
    product_query_bundle: FixtureBundle,
) -> None:
    # Arrange
    service = build_product_query_service(product_query_bundle)

    # Act
    vulnerabilities = service.query(ProductQueryRequest(vendor=VENDOR, version="1.0", limit=20))

    # Assert
    for vulnerability in vulnerabilities.items:
        if vulnerability.record.cve_id == CROSS_ENTRY:
            note = vulnerability.nvd_version_note
            assert note is not None and note.outcome == "no_hit"
            assert OTHER_VENDOR not in note.wording
            break
    else:
        pytest.fail("vendor-only query omitted the multi-product CVE")
