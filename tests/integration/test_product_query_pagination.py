"""Inventory pages preserve complete ordering, counts, identities and page evidence."""

import base64
import json
from itertools import pairwise
from typing import Any

import pytest

from tests.support.builders import build_bundle_with
from tests.support.product_queries import (
    FIELD_HIT,
    FIELD_NO_HIT,
    FIELD_UNKNOWN,
    MENTION_ONLY,
    PRODUCT,
    UNDATED_FIELD,
    VENDOR,
)
from vulnwitness.adapters.fixture.synthetic_fixture import FixtureBundle
from vulnwitness.composition import build_product_query_service
from vulnwitness.domain.product_query import ProductQueryRequest
from vulnwitness.domain.product_query_cursor import InvalidProductCursor, build_product_cursor


@pytest.mark.parametrize("page_size", [1, 2, 3, 5, 20])
@pytest.mark.parametrize("version", [None, "2.0"])
def test_pages_return_every_match_once_in_the_documented_order(
    product_query_bundle: FixtureBundle, page_size: int, version: str | None
) -> None:
    # Arrange
    service = build_product_query_service(product_query_bundle)
    request = ProductQueryRequest(vendor=VENDOR, product=PRODUCT, version=version, limit=page_size)
    expected_ids = [FIELD_NO_HIT, FIELD_HIT, FIELD_UNKNOWN, UNDATED_FIELD, MENTION_ONLY]
    if version is not None:
        expected_ids = [FIELD_HIT, FIELD_UNKNOWN, UNDATED_FIELD, MENTION_ONLY, FIELD_NO_HIT]
    cve_ids: list[str] = []
    pages = []

    # Act
    while True:
        page = service.query(request)
        pages.append(page)
        for vulnerability in page.items:
            cve_ids.append(vulnerability.record.cve_id)
        if page.next_cursor is None:
            break
        request = request.model_copy(update={"cursor": page.next_cursor})
        assert len(pages) <= len(expected_ids)

    # Assert
    assert cve_ids == expected_ids
    for page in pages:
        assert page.total_available == len(expected_ids)
        assert 1 <= len(page.items) <= page_size
        assert page.description_mentions_vendor_unconfirmed == 1
        assert page.matched_products == pages[0].matched_products
        page_evidence_ids = set()
        for vulnerability in page.items:
            page_evidence_ids.update(vulnerability.record.evidence_ids)
        returned_evidence_ids = set()
        for anchor in page.evidence:
            returned_evidence_ids.add(anchor.evidence_id)
        assert returned_evidence_ids == page_evidence_ids
    assert pages[0].cursor is None
    for previous_page, page in pairwise(pages):
        assert page.cursor == previous_page.next_cursor


def test_continuation_is_stateless_and_accepts_equivalent_case_folded_names(
    product_query_bundle: FixtureBundle,
) -> None:
    # Arrange
    request = ProductQueryRequest(vendor=VENDOR, product=PRODUCT, limit=1)
    first_page = build_product_query_service(product_query_bundle).query(request)
    continuation = ProductQueryRequest(
        vendor=VENDOR.upper(), product=PRODUCT.upper(), limit=1, cursor=first_page.next_cursor
    )

    # Act
    second_page = build_product_query_service(product_query_bundle).query(continuation)

    # Assert
    assert first_page.items[0].record.cve_id == FIELD_NO_HIT
    assert second_page.items[0].record.cve_id == FIELD_HIT
    assert second_page.vendor == VENDOR
    assert second_page.product == PRODUCT
    assert second_page.cursor == first_page.next_cursor


def test_inventory_traversal_returns_more_than_twenty_matching_records(
    fixture_bundle: FixtureBundle,
) -> None:
    # Arrange
    expected_ids = []
    for number in range(23):
        cve_id = f"CVE-9999-{7000 + number}"
        expected_ids.append(cve_id)
        fixture_bundle = build_bundle_with(
            fixture_bundle, cve_id, "[SYNTHETIC] Inventory widget crashes."
        )
    service = build_product_query_service(fixture_bundle)
    request = ProductQueryRequest(product="inventory widget", limit=20)

    # Act
    first_page = service.query(request)
    second_page = service.query(request.model_copy(update={"cursor": first_page.next_cursor}))

    # Assert
    cve_ids = []
    for vulnerability in (*first_page.items, *second_page.items):
        cve_ids.append(vulnerability.record.cve_id)
    assert cve_ids == expected_ids
    assert len(first_page.items) == 20
    assert len(second_page.items) == 3
    assert first_page.total_available == second_page.total_available == 23
    assert second_page.next_cursor is None


@pytest.mark.parametrize("cursor", ["", "!", "e30", "bm90LWpzb24", "é", "a" * 8192])
def test_malformed_continuation_raises_a_typed_cursor_error(
    product_query_bundle: FixtureBundle, cursor: str
) -> None:
    # Arrange
    service = build_product_query_service(product_query_bundle)
    request = ProductQueryRequest(product=PRODUCT, cursor=cursor)

    # Act / Assert
    with pytest.raises(InvalidProductCursor, match="Invalid product query cursor"):
        service.query(request)


@pytest.mark.parametrize(
    "changed_fields",
    [
        {"vendor": "another_core"},
        {"product": "different_product"},
        {"version": "2.0"},
        {"limit": 2},
        {"vendor": None},
        {"product": None},
    ],
)
def test_continuation_for_different_request_raises_a_typed_cursor_error(
    product_query_bundle: FixtureBundle, changed_fields: dict[str, Any]
) -> None:
    # Arrange
    service = build_product_query_service(product_query_bundle)
    request = ProductQueryRequest(vendor=VENDOR, product=PRODUCT, limit=1)
    first_page = service.query(request)
    continuation = request.model_copy(update={"cursor": first_page.next_cursor, **changed_fields})

    # Act / Assert
    with pytest.raises(InvalidProductCursor):
        service.query(continuation)


@pytest.mark.parametrize("offset", [-1, 0, True, "1", 1.5, 999999999999999999])
def test_invalid_offset_raises_a_typed_cursor_error(
    product_query_bundle: FixtureBundle, offset: object
) -> None:
    # Arrange
    service = build_product_query_service(product_query_bundle)
    request = ProductQueryRequest(product=PRODUCT, limit=1)
    cursor = build_product_cursor(request, 1)
    cursor_fields = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
    cursor_fields["offset"] = offset
    cursor = (
        base64.urlsafe_b64encode(json.dumps(cursor_fields, separators=(",", ":")).encode())
        .decode()
        .rstrip("=")
    )
    continuation = request.model_copy(update={"cursor": cursor})

    # Act / Assert
    with pytest.raises(InvalidProductCursor):
        service.query(continuation)


def test_empty_matches_have_no_continuation(fixture_bundle: FixtureBundle) -> None:
    # Arrange
    service = build_product_query_service(fixture_bundle)

    # Act
    page = service.query(ProductQueryRequest(product="unknown-widget", limit=1))

    # Assert
    assert page.items == ()
    assert page.total_available == 0
    assert page.cursor is None
    assert page.next_cursor is None
