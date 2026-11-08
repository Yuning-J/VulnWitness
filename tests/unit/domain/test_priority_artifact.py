"""Artifact bytes and pair order are deterministic and retain their input identities."""

import json

import pytest
from pydantic import ValidationError

from tests.support.priority import build_priority_artifact, build_priority_inputs
from vulnwitness.adapters.priority_policy import default_priority_policy_file, load_priority_policy
from vulnwitness.application.priority_decision import evaluate_priority
from vulnwitness.domain.priority_decision import PriorityArtifact


def test_repeated_evaluation_and_serialisation_are_byte_identical() -> None:
    policy = load_priority_policy(default_priority_policy_file()).policy
    asset, assessment, facts = build_priority_inputs()

    first_artifact = build_priority_artifact((evaluate_priority(policy, asset, assessment, facts),))
    second_artifact = build_priority_artifact(
        (evaluate_priority(policy, asset, assessment, facts),)
    )
    artifact_bytes = first_artifact.to_json_bytes()

    assert artifact_bytes == first_artifact.to_json_bytes() == second_artifact.to_json_bytes()
    assert PriorityArtifact.model_validate_json(artifact_bytes).to_json_bytes() == artifact_bytes


def test_artifact_orders_pairs_by_asset_then_cve_and_response_digests_by_call() -> None:
    policy = load_priority_policy(default_priority_policy_file()).policy
    asset, assessment, facts = build_priority_inputs()
    decision = evaluate_priority(policy, asset, assessment, facts)
    decisions = (
        decision.model_copy(update={"asset": "zebra"}),
        decision.model_copy(update={"asset": "alpha", "cve_id": "CVE-2026-9999"}),
        decision.model_copy(update={"asset": "alpha", "cve_id": "CVE-2026-1234"}),
    )
    artifact_fields = build_priority_artifact(decisions).model_dump(mode="json")
    artifact_fields["response_digests"] = [
        {"call": 2, "response_sha256": "b" * 64},
        {"call": 1, "response_sha256": "a" * 64},
    ]

    artifact = PriorityArtifact.model_validate(artifact_fields)
    artifact_document = json.loads(artifact.to_json_bytes())

    assert artifact_document["decisions"][0]["asset"] == "alpha"
    assert artifact_document["decisions"][0]["cve_id"] == "CVE-2026-1234"
    assert artifact_document["decisions"][1]["cve_id"] == "CVE-2026-9999"
    assert artifact_document["decisions"][2]["asset"] == "zebra"
    assert artifact_document["response_digests"][0]["call"] == 1


def test_artifact_preserves_the_explicit_after_reference_date_flag() -> None:
    artifact_fields = build_priority_artifact(()).model_dump(mode="json")
    artifact_fields["used_after_reference_date_information"] = True

    artifact = PriorityArtifact.model_validate(artifact_fields)

    assert json.loads(artifact.to_json_bytes())["used_after_reference_date_information"] is True


@pytest.mark.parametrize("duplicate", ["decision", "response-call"])
def test_artifact_rejects_duplicate_pair_or_response_call(duplicate: str) -> None:
    policy = load_priority_policy(default_priority_policy_file()).policy
    asset, assessment, facts = build_priority_inputs()
    decision = evaluate_priority(policy, asset, assessment, facts)
    artifact_fields = build_priority_artifact((decision,)).model_dump(mode="json")
    if duplicate == "decision":
        artifact_fields["decisions"].append(artifact_fields["decisions"][0])
    else:
        artifact_fields["response_digests"] = [
            {"call": 1, "response_sha256": "a" * 64},
            {"call": 1, "response_sha256": "b" * 64},
        ]

    with pytest.raises(ValidationError, match="duplicate"):
        PriorityArtifact.model_validate(artifact_fields)
