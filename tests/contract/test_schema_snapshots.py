"""Committed v2 JSON Schema snapshots match the models."""

import json

import pytest

from tests.support.paths import REPOSITORY_SCHEMA_DIR
from vulnwitness.domain.search import SCHEMA_VERSION
from vulnwitness.schema_snapshots import find_schema_drift, render_contract_schemas


def test_committed_schemas_match_generated_schemas() -> None:
    assert find_schema_drift(REPOSITORY_SCHEMA_DIR) == []


def test_schema_manifest_records_current_schema_version() -> None:
    manifest = json.loads((REPOSITORY_SCHEMA_DIR / "manifest.json").read_text())

    assert manifest["schema_version"] == SCHEMA_VERSION


def test_cve_record_schema_pins_scope_invariants_as_constants() -> None:
    cve_record_schema = REPOSITORY_SCHEMA_DIR / "cve_record.schema.json"
    properties = json.loads(cve_record_schema.read_text())["properties"]

    assert properties["protocol_design_claim"]["const"] == "not_established"
    assert properties["formal_seed_eligible"]["const"] is False
    assert properties["record_kind"]["const"] == "cve"


def test_every_snapshot_declares_draft_2020_12() -> None:
    manifest = json.loads((REPOSITORY_SCHEMA_DIR / "manifest.json").read_text())

    declared_drafts: set[str] = set()
    for file_name in manifest["files"]:
        declared_drafts.add(json.loads((REPOSITORY_SCHEMA_DIR / file_name).read_text())["$schema"])

    assert declared_drafts == {"https://json-schema.org/draft/2020-12/schema"}


@pytest.mark.parametrize(
    "file_name", ["knowledge_capabilities.schema.json", "knowledge_evidence_set.schema.json"]
)
def test_capability_order_description_names_the_pinned_subjects_in_their_order(
    file_name: str,
) -> None:
    capabilities_schema = json.loads(render_contract_schemas()[file_name])["properties"][
        "source_capabilities"
    ]

    description_positions: list[int] = []
    for subject_slot in capabilities_schema["prefixItems"]:
        pinned_subject = subject_slot["allOf"][1]["properties"]["source"]["const"]
        description_positions.append(capabilities_schema["description"].find(pinned_subject))

    assert -1 not in description_positions
    assert description_positions == sorted(description_positions)


# Pydantic's constraint names; JSON Schema spells them minimum, maximum, exclusiveMinimum
# and exclusiveMaximum, and a validator ignores any other keyword.
PYDANTIC_CONSTRAINT_NAMES = frozenset({"ge", "le", "gt", "lt"})
# Keywords whose values map names to subschemas, so their keys are not keywords.
SUBSCHEMA_MAPS = frozenset({"properties", "$defs", "patternProperties", "dependentSchemas"})


def find_pydantic_constraint_names(schema_node: object, location: str) -> list[str]:
    """Where a pydantic constraint name stands in for a JSON Schema keyword."""
    findings: list[str] = []
    if isinstance(schema_node, list):
        for index, item in enumerate(schema_node):
            findings.extend(find_pydantic_constraint_names(item, f"{location}[{index}]"))
    elif isinstance(schema_node, dict):
        for keyword, value in schema_node.items():
            if keyword in SUBSCHEMA_MAPS and isinstance(value, dict):
                for subschema_name, subschema in value.items():
                    findings.extend(
                        find_pydantic_constraint_names(
                            subschema, f"{location}/{keyword}/{subschema_name}"
                        )
                    )
                continue
            if keyword in PYDANTIC_CONSTRAINT_NAMES:
                findings.append(f"{location}/{keyword}")
            findings.extend(find_pydantic_constraint_names(value, f"{location}/{keyword}"))
    return findings


def test_no_snapshot_states_a_bound_under_a_keyword_validators_ignore() -> None:
    manifest = json.loads((REPOSITORY_SCHEMA_DIR / "manifest.json").read_text())

    findings: list[str] = []
    for file_name in manifest["files"]:
        snapshot = json.loads((REPOSITORY_SCHEMA_DIR / file_name).read_text())
        findings.extend(find_pydantic_constraint_names(snapshot, file_name))

    assert findings == []
