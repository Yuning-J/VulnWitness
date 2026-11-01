"""Unknown inventory totals remain nullable without weakening their numeric bounds."""

import json

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from vulnwitness.domain.triage import TriageInventory
from vulnwitness.schema_snapshots import render_schema


@pytest.mark.parametrize(
    "total_available,accepted",
    [(None, True), (0, True), (1.0, True), (-1, False), (True, False), ("1", False), (1.5, False)],
)
def test_inventory_total_bounds_agree_in_the_model_and_published_schema(
    total_available: object, accepted: bool
) -> None:
    # Arrange
    document = {
        "pages_read": 0,
        "items_seen": 0,
        "total_available": total_available,
        "complete": False,
        "page_calls": [],
        "cve_ids": [],
    }
    validator = Draft202012Validator(json.loads(render_schema(TriageInventory, "serialization")))

    # Act
    schema_accepts = validator.is_valid(document)
    try:
        TriageInventory.model_validate(document)
        model_accepts = True
    except ValidationError:
        model_accepts = False

    # Assert
    assert schema_accepts == model_accepts == accepted
