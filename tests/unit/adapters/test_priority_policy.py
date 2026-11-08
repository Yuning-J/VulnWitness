"""The packaged table has a stable identity and malformed policy files fail closed."""

from pathlib import Path

import pytest

from vulnwitness.adapters.priority_policy import (
    PriorityPolicyError,
    default_priority_policy_file,
    load_priority_policy,
)


@pytest.mark.parametrize(
    "malformation",
    [
        "syntax",
        "duplicate-key",
        "unknown-key",
        "unknown-fact",
        "unknown-value",
        "bad-operator",
        "equals-many",
        "empty-membership",
        "duplicate-rule",
        "no-default",
        "early-default",
        "unsupported-template",
        "broken-template",
        "bad-format",
        "non-utf8",
    ],
)
def test_malformed_policy_is_rejected(tmp_path: Path, malformation: str) -> None:
    policy_text = default_priority_policy_file().read_text(encoding="utf-8")
    if malformation == "syntax":
        policy_text = "rules: ["
    elif malformation == "duplicate-key":
        policy_text += "\nname: replacement\n"
    elif malformation == "unknown-key":
        policy_text += "\nextra: true\n"
    elif malformation == "unknown-fact":
        policy_text = policy_text.replace("fact: applicability", "fact: exploitability", 1)
    elif malformation == "unknown-value":
        policy_text = policy_text.replace("values: [unknown]", "values: [absent]", 1)
    elif malformation == "bad-operator":
        policy_text = policy_text.replace("operator: equals", "operator: less_than", 1)
    elif malformation == "equals-many":
        policy_text = policy_text.replace("values: [unknown]", "values: [unknown, affected]", 1)
    elif malformation == "empty-membership":
        policy_text = policy_text.replace(
            "values: [external_connection, software_update]", "values: []", 1
        )
    elif malformation == "duplicate-rule":
        policy_text = policy_text.replace("id: rule-2", "id: rule-1", 1)
    elif malformation == "no-default":
        policy_text = policy_text.replace(
            "conditions: []", "conditions: [{fact: kev, operator: equals, values: [unknown]}]"
        )
    elif malformation == "early-default":
        policy_text = policy_text.replace(
            "conditions:\n      - fact: applicability\n        operator: equals\n"
            "        values: [unknown]",
            "conditions: []",
            1,
        )
    elif malformation == "unsupported-template":
        policy_text = policy_text.replace("{justification}", "{justification.__class__}")
    elif malformation == "broken-template":
        policy_text = policy_text.replace("{justification}", "{justification")
    elif malformation == "bad-format":
        policy_text = policy_text.replace("format_version: 1", "format_version: true")
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_bytes(b"\xff" if malformation == "non-utf8" else policy_text.encode())

    with pytest.raises(PriorityPolicyError):
        load_priority_policy(policy_file)


def test_policy_digest_ignores_yaml_formatting_and_changes_with_content(tmp_path: Path) -> None:
    policy_file = default_priority_policy_file()
    loaded_policy = load_priority_policy(policy_file)
    policy_text = policy_file.read_text(encoding="utf-8")
    formatted_file = tmp_path / "formatted.yaml"
    formatted_file.write_text("# Reviewed policy\n" + policy_text, encoding="utf-8")
    changed_file = tmp_path / "changed.yaml"
    changed_file.write_text(policy_text.replace("cn-auto-demo", "other-policy"), encoding="utf-8")

    assert load_priority_policy(formatted_file).content_sha256 == loaded_policy.content_sha256
    assert load_priority_policy(policy_file).content_sha256 == loaded_policy.content_sha256
    assert load_priority_policy(changed_file).content_sha256 != loaded_policy.content_sha256
    assert len(loaded_policy.content_sha256) == 64
