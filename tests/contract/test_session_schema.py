"""Authored citation sequences have the same bounds in models and published schemas."""

import json

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from cve_kgrag.domain.session_record import SessionCorpusIdentity, SessionFindings
from cve_kgrag.schema_snapshots import render_schema


@pytest.mark.parametrize(
    "sequence,accepted",
    [
        (0, False),
        (False, False),
        (1, True),
        (100, True),
        (101, False),
        (1.5, False),
    ],
)
def test_citation_sequence_bounds_agree_with_the_published_schema(
    sequence: object,
    accepted: bool,
) -> None:
    # Arrange
    document = {
        "findings": [
            {
                "id": "review",
                "statement": "An authored observation",
                "kind": "analyst_note",
                "status": "unconfirmed",
                "citations": [{"call": sequence, "evidence_id": "ev:" + "0" * 24}],
            }
        ],
        "selections": {"cve_ids": [], "product_queries": []},
        "open_questions": [],
    }
    validator = Draft202012Validator(json.loads(render_schema(SessionFindings, "validation")))
    # Act
    schema_accepts = validator.is_valid(document)
    try:
        SessionFindings.model_validate(document)
        model_accepts = True
    except ValidationError:
        model_accepts = False
    # Assert
    assert schema_accepts == model_accepts == accepted


@pytest.mark.parametrize(
    "kind,store_name,accepted",
    [
        ("synthetic_fixture", None, True),
        ("synthetic_fixture", "store", False),
        ("corpus_store", None, False),
        ("corpus_store", "store", True),
    ],
)
def test_dataset_store_names_agree_with_the_published_schema(
    kind: str,
    store_name: str | None,
    accepted: bool,
) -> None:
    # Arrange
    document = {
        "served": {"kind": kind, "cve_search_version": "test-version"},
        "store_name": store_name,
        "store_manifest_sha256": "0" * 64,
        "corpus_content_sha256": "1" * 64,
    }
    validator = Draft202012Validator(json.loads(render_schema(SessionCorpusIdentity, "validation")))
    # Act
    schema_accepts = validator.is_valid(document)
    try:
        SessionCorpusIdentity.model_validate(document)
        model_accepts = True
    except ValidationError:
        model_accepts = False
    # Assert
    assert schema_accepts == model_accepts == accepted
