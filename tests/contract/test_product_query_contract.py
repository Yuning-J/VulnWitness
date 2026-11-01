"""Product requests and service answers are checked through the committed schema export."""

import json
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from tests.support.paths import REPOSITORY_SCHEMA_DIR
from tests.support.product_queries import PRODUCT
from vulnwitness.adapters.fixture.synthetic_fixture import FixtureBundle
from vulnwitness.composition import build_product_query_service
from vulnwitness.domain.product_query import ProductQueryRequest, ProductQueryResponse


@pytest.mark.parametrize(
    "arguments,is_valid",
    [
        ({}, False),
        ({"version": "2.0"}, False),
        ({"vendor": None, "product": None}, False),
        ({"vendor": "democorp"}, True),
        ({"product": PRODUCT}, True),
        ({"vendor": "democorp", "product": PRODUCT, "version": "release-x"}, True),
        ({"product": PRODUCT, "limit": 20}, True),
        ({"product": PRODUCT, "limit": 21}, False),
        ({"product": PRODUCT, "limit": 0}, False),
        ({"product": PRODUCT, "limit": True}, False),
        ({"product": PRODUCT, "limit": "2"}, False),
        ({"product": PRODUCT, "limit": 2.0}, True),
        ({"product": PRODUCT, "version": " "}, False),
        ({"product": " "}, False),
        ({"product": "x\ny"}, False),
        ({"product": 123}, False),
        ({"vendor": "ß" * 128}, True),
        ({"product": PRODUCT, "query": "crash"}, False),
        ({"product": PRODUCT, "cursor": None}, True),
        ({"product": PRODUCT, "cursor": "opaque-continuation"}, True),
        ({"product": PRODUCT, "cursor": ""}, True),
        ({"product": PRODUCT, "cursor": 1}, False),
        ({"product": PRODUCT, "cursor": "a" * 8193}, False),
    ],
)
def test_request_schema_and_model_agree_on_explicit_fields(
    arguments: dict[str, Any],
    is_valid: bool,
) -> None:
    # Arrange
    schema = json.loads((REPOSITORY_SCHEMA_DIR / "product_query_request.schema.json").read_text())

    # Act
    schema_accepts = Draft202012Validator(schema).is_valid(arguments)
    try:
        ProductQueryRequest.model_validate(arguments)
        model_accepts = True
    except ValidationError:
        model_accepts = False

    # Assert
    assert schema_accepts == model_accepts == is_valid


@pytest.mark.parametrize("version", [None, "2.0", "release-x"])
def test_service_answers_with_all_bases_and_version_facts_validate_against_export(
    product_query_bundle: FixtureBundle,
    version: str | None,
) -> None:
    # Arrange
    service = build_product_query_service(product_query_bundle)
    schema = json.loads((REPOSITORY_SCHEMA_DIR / "product_query_response.schema.json").read_text())

    # Act
    vulnerabilities = service.query(ProductQueryRequest(product=PRODUCT, version=version))

    # Assert
    Draft202012Validator(schema).validate(vulnerabilities.model_dump(mode="json"))
    assert (
        ProductQueryResponse.model_validate_json(vulnerabilities.model_dump_json())
        == vulnerabilities
    )


@pytest.mark.parametrize(
    "field,value", [("kind", "lexical"), ("matched_products", []), ("matched_phrase", "oai")]
)
def test_response_export_rejects_invalid_product_field_basis(
    product_query_bundle: FixtureBundle,
    field: str,
    value: Any,
) -> None:
    # Arrange
    service = build_product_query_service(product_query_bundle)
    schema = json.loads((REPOSITORY_SCHEMA_DIR / "product_query_response.schema.json").read_text())
    vulnerabilities = service.query(ProductQueryRequest(product=PRODUCT, version="2.0"))
    serialized = vulnerabilities.model_dump(mode="json")

    # Act
    serialized["items"][0]["basis"][field] = value

    # Assert
    assert not Draft202012Validator(schema).is_valid(serialized)
    with pytest.raises(ValidationError):
        ProductQueryResponse.model_validate(serialized)


@pytest.mark.parametrize("count", [None, -1, True, "1", 1.5])
def test_response_export_and_model_reject_missing_or_invalid_exclusion_counts(
    product_query_bundle: FixtureBundle, count: Any
) -> None:
    service = build_product_query_service(product_query_bundle)
    schema = json.loads((REPOSITORY_SCHEMA_DIR / "product_query_response.schema.json").read_text())
    vulnerabilities = service.query(ProductQueryRequest(vendor="free5gc", product="smf"))
    serialized = vulnerabilities.model_dump(mode="json")
    if count is None:
        del serialized["description_mentions_vendor_unconfirmed"]
    else:
        serialized["description_mentions_vendor_unconfirmed"] = count

    assert not Draft202012Validator(schema).is_valid(serialized)
    with pytest.raises(ValidationError):
        ProductQueryResponse.model_validate(serialized)
