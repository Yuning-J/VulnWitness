"""The register and artifact are published contracts with closed nested fact models."""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from tests.support.priority import (
    build_priority_artifact,
    build_priority_inputs,
    build_register_document,
)
from vulnwitness.adapters.priority_policy import default_priority_policy_file, load_priority_policy
from vulnwitness.adapters.strict_yaml import load_declaration_yaml
from vulnwitness.application.priority_decision import evaluate_priority
from vulnwitness.domain.asset_register import AssetRegister
from vulnwitness.domain.priority_decision import PriorityArtifact
from vulnwitness.schema_snapshots import render_contract_schemas


def test_fictional_vehicle_example_validates_against_the_register_schema() -> None:
    example = Path(__file__).parents[2] / "docs/examples/priority-assets.yaml"
    document = load_declaration_yaml(example.read_text())
    schema = json.loads(render_contract_schemas()["asset_register.schema.json"])

    Draft202012Validator(schema).validate(document)
    register = AssetRegister.model_validate(document)

    assert len(register.assets) == 3
    categories = []
    for asset in register.assets:
        categories.append(asset.system_category)
    assert tuple(categories) == (
        "external_connection",
        "software_update",
        "other",
    )
    assert all(assessment.justification for assessment in register.assessments)


def test_asset_register_schema_accepts_the_operator_document() -> None:
    register_document = build_register_document()
    schema = json.loads(render_contract_schemas()["asset_register.schema.json"])

    Draft202012Validator(schema).validate(register_document)
    assert AssetRegister.model_validate(register_document).assets[0].name == "gateway"


@pytest.mark.parametrize("applicability", ["affected", "not_affected"])
def test_asset_register_schema_requires_justification_for_explicit_assessments(
    applicability: str,
) -> None:
    register_document = build_register_document()
    register_document["assessments"][0]["applicability"] = applicability
    del register_document["assessments"][0]["justification"]
    schema = json.loads(render_contract_schemas()["asset_register.schema.json"])

    assert not Draft202012Validator(schema).is_valid(register_document)
    with pytest.raises(ValidationError):
        AssetRegister.model_validate(register_document)


def test_priority_schema_accepts_serialised_artifact_with_all_explanations() -> None:
    policy = load_priority_policy(default_priority_policy_file()).policy
    asset, assessment, facts = build_priority_inputs(
        kev="unknown", high_grade="present", authorities=("CNVD",)
    )
    artifact = build_priority_artifact((evaluate_priority(policy, asset, assessment, facts),))
    schema = json.loads(render_contract_schemas()["priority.schema.json"])

    Draft202012Validator(schema).validate(json.loads(artifact.to_json_bytes()))


@pytest.mark.parametrize("invalid_fact", ["kev-date", "grade-authority", "extra-fact"])
def test_priority_schema_and_model_reject_inconsistent_or_unknown_facts(invalid_fact: str) -> None:
    policy = load_priority_policy(default_priority_policy_file()).policy
    asset, assessment, facts = build_priority_inputs()
    artifact = build_priority_artifact((evaluate_priority(policy, asset, assessment, facts),))
    artifact_document = json.loads(artifact.to_json_bytes())
    fact_document = artifact_document["decisions"][0]["facts"]
    if invalid_fact == "kev-date":
        fact_document["kev"]["snapshot_retrieved_at"] = None
    elif invalid_fact == "grade-authority":
        fact_document["high_grade"]["value"] = "present"
    else:
        fact_document["exploitability"] = "high"
    schema = json.loads(render_contract_schemas()["priority.schema.json"])

    assert not Draft202012Validator(schema).is_valid(artifact_document)
    with pytest.raises(ValidationError):
        PriorityArtifact.model_validate(artifact_document)
