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
    ],
    ids=["duplicate_key", "unhashable_key", "merge_key", "deep_nesting"],
)
def test_ambiguous_or_hostile_document_raises_a_strict_yaml_error(
    text: str, violation: str
) -> None:
    with pytest.raises(StrictYamlError, match=violation):
        load_strict_yaml(text)


def test_syntax_error_is_a_yaml_error() -> None:
    with pytest.raises(yaml.YAMLError):
        load_strict_yaml("a: [unclosed")


def test_plain_document_loads_like_safe_load() -> None:
    text = "name: demo\nitems:\n  - 1\n  - two\n"

    assert load_strict_yaml(text) == yaml.safe_load(text)
