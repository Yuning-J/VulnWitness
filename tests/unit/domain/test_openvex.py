"""The analyst's applicability becomes the OpenVEX status; nothing is derived."""

from datetime import date

from tests.support.priority import (
    build_priority_artifact,
    build_priority_inputs,
    build_register_document,
)
from vulnwitness.adapters.priority_policy import load_priority_policy, packaged_priority_policy_file
from vulnwitness.application.priority_decision import evaluate_priority
from vulnwitness.domain.asset_register import AssetRegister
from vulnwitness.domain.openvex import (
    NO_ACTION_RECORDED,
    OPENVEX_CONTEXT,
    asset_product_id,
    build_openvex,
)


def build_register() -> AssetRegister:
    document = build_register_document()
    first = dict(document["assessments"][0])
    document["assessments"] = [
        {**first, "cve_id": "CVE-2026-0001", "applicability": "affected"},
        {
            **first,
            "cve_id": "CVE-2026-0002",
            "applicability": "not_affected",
            "justification": "The component is not present.",
        },
        {**first, "cve_id": "CVE-2026-0003", "applicability": "unknown"},
    ]
    return AssetRegister.model_validate(document)


def test_statuses_follow_the_analyst_and_unknown_is_under_investigation() -> None:
    register = build_register()

    document = build_openvex(register, "Example PSIRT", date(2026, 11, 16))

    assert document["@context"] == OPENVEX_CONTEXT
    assert document["timestamp"] == "2026-11-16T00:00:00Z"
    statements = document["statements"]
    assert isinstance(statements, list)
    affected, not_affected, unknown = statements
    assert affected["status"] == "affected"
    assert affected["action_statement"] == NO_ACTION_RECORDED
    assert not_affected["status"] == "not_affected"
    assert not_affected["impact_statement"] == "The component is not present."
    assert unknown["status"] == "under_investigation"
    assert affected["status_notes"] == "The deployed version is affected."
    assert unknown["status_notes"] == "The deployed version is affected."
    asset = register.assessments[0].asset
    assert affected["products"] == [{"@id": asset_product_id(asset)}]
    assert " " not in asset_product_id("Aster head unit")


def test_affected_statement_quotes_the_recorded_recommendation() -> None:
    register = build_register()
    asset, assessment, facts = build_priority_inputs(kev="listed")
    policy = load_priority_policy(packaged_priority_policy_file("cn-auto-demo")).policy
    decision = evaluate_priority(policy, asset, assessment, facts)
    decision = decision.model_copy(
        update={"asset": register.assessments[0].asset, "cve_id": "CVE-2026-0001"}
    )
    priority = build_priority_artifact((decision,)).model_copy(
        update={"register_sha256": register.compute_content_sha256()}
    )

    document = build_openvex(register, "Example PSIRT", date(2026, 11, 16), priority)

    statements = document["statements"]
    assert isinstance(statements, list)
    assert statements[0]["action_statement"].startswith(
        "VulnWitness policy cn-auto-demo recommends act: "
    )


def test_identity_is_deterministic_and_input_bound() -> None:
    register = build_register()

    first = build_openvex(register, "Example PSIRT", date(2026, 11, 16))
    again = build_openvex(register, "Example PSIRT", date(2026, 11, 16))
    other = build_openvex(register, "Example PSIRT", date(2026, 11, 17))

    assert first == again
    assert first["@id"] != other["@id"]
