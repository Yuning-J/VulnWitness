"""Every malformed or ambiguous YAML document raises a YAML error, never a bare one."""

import pytest
import yaml

from cve_kgrag.adapters.strict_yaml import StrictYamlError, load_strict_yaml


@pytest.mark.parametrize(
    ("text", "violation"),
    [
        ("a: 1\na: 2\n", "duplicate key"),
        ("? [a, b]\n: 1\n", "unhashable key"),
        ("base: &x {k: 1}\nderived:\n  <<: *x\n", "merge key"),
        ("[" * 100000, "nesting"),
        ("when: 2024-02-30\n", "value cannot be constructed"),
        (f"count: {'9' * 5000}\n", "value cannot be constructed"),
        ("flag: !!bool maybe\n", "value cannot be constructed"),
        ("when: !!timestamp now\n", "value cannot be constructed"),
    ],
    ids=[
        "duplicate_key",
        "unhashable_key",
        "merge_key",
        "deep_nesting",
        "impossible_date",
        "integer_too_long",
        "bool_tag_on_a_word",
        "timestamp_tag_on_a_word",
    ],
)
def test_ambiguous_or_hostile_document_raises_a_strict_yaml_error(
    text: str, violation: str
) -> None:
    with pytest.raises(StrictYamlError, match=violation):
        load_strict_yaml(text)


@pytest.mark.parametrize(
    "text",
    ["a: [unclosed", "items: !!set [a, b]\n", "pairs: !!omap a\n"],
    ids=["syntax_error", "set_tag_on_a_sequence", "omap_tag_on_a_scalar"],
)
def test_malformed_document_is_a_yaml_error(text: str) -> None:
    with pytest.raises(yaml.YAMLError):
        load_strict_yaml(text)


def test_plain_document_loads_like_safe_load() -> None:
    text = "name: demo\nitems:\n  - 1\n  - two\n"

    assert load_strict_yaml(text) == yaml.safe_load(text)
