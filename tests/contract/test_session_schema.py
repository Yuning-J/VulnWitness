"""Authored citation sequences have the same bounds in models and published schemas."""

import json
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from tests.support.paths import REPOSITORY_SCHEMA_DIR
from tests.support.workspaces import agent_note
from vulnwitness.domain.session_record import SessionCorpusIdentity, SessionFindings
from vulnwitness.domain.workspace import AddFindingsRequest
from vulnwitness.schema_snapshots import render_schema


@pytest.mark.parametrize("author,accepted", [(None, True), ("agent", True), ("workflow", False)])
@pytest.mark.parametrize("kind", ["analyst_note", "product_field_match"])
def test_confirmed_agent_requests_agree_with_committed_schema(
    author: str | None, accepted: bool, kind: str
) -> None:
    # Arrange
    finding = agent_note("confirmed", status="confirmed")
    if kind == "product_field_match":
        finding["kind"] = kind
        del finding["statement"]
        finding["claim"] = {
            "kind": kind,
            "call": 1,
            "cve_id": "CVE-9999-0001",
            "vendor": "democorp",
            "product": "demo_gateway",
        }
    if author is not None:
        finding["author"] = author
    request = {"session_id": "inv_" + "a" * 20, "findings": [finding]}
    schema = json.loads((REPOSITORY_SCHEMA_DIR / "add_findings_request.schema.json").read_text())

    # Act
    schema_accepts = Draft202012Validator(schema).is_valid(request)
    try:
        AddFindingsRequest.model_validate(request)
        runtime_accepts = True
    except ValidationError:
        runtime_accepts = False

    # Assert
    assert schema_accepts == runtime_accepts == accepted


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
                "author": "user",
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


@pytest.mark.parametrize(
    "change,accepted",
    [
        ("valid", True),
        ("no_claim", False),
        ("no_claim_kind", False),
        ("wrong_kind", False),
        ("no_author", False),
        ("workflow", True),
        ("workflow_confirmed", False),
        ("narrative", True),
        ("workflow_narrative", False),
        ("narrative_claim", False),
        ("narrative_no_statement", False),
    ],
)
def test_finding_claim_and_author_rules_agree_with_the_published_schema(
    change: str,
    accepted: bool,
) -> None:
    # Arrange
    finding: dict[str, Any] = {
        "id": "assertion",
        "author": "agent",
        "kind": "product_field_match",
        "status": "unconfirmed",
        "citations": [],
        "claim": {
            "kind": "product_field_match",
            "call": 1,
            "cve_id": "CVE-9999-0001",
            "vendor": "democorp",
            "product": "demo_gateway",
        },
    }
    if change == "no_claim":
        del finding["claim"]
    elif change == "no_claim_kind":
        del finding["claim"]["kind"]
    elif change == "wrong_kind":
        finding["kind"] = "description_mention"
    elif change == "no_author":
        del finding["author"]
    elif change.startswith("workflow"):
        finding["author"] = "workflow"
        if change == "workflow_confirmed":
            finding["status"] = "confirmed"
    if "narrative" in change:
        finding["kind"] = "analyst_note"
        finding["statement"] = "A free narrative."
        if change != "narrative_claim":
            del finding["claim"]
        if change == "narrative_no_statement":
            del finding["statement"]
    document = {"findings": [finding], "selections": {}, "open_questions": []}
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
