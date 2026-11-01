"""Every malformed or ambiguous YAML document raises a YAML error, never a bare one. An
operator's declaration is read stricter still: any alias is refused at its line and every
timestamp stays the text written, while the strict loader keeps resolving both."""

from datetime import UTC, datetime

import pytest
import yaml

from vulnwitness.adapters.strict_yaml import (
    StrictYamlError,
    load_declaration_yaml,
    load_strict_yaml,
)


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


@pytest.mark.parametrize(
    ("text", "line"),
    [
        ("base: &x 1\ncopy: *x\n", 2),
        ("items:\n  - &x a\n  - *x\n", 3),
        ("base: &x {k: 1}\nderived:\n  <<: *x\n", 3),
        ("? &x key\n: 1\nother: {*x : 2}\n", 3),
    ],
    ids=["alias_value", "alias_in_sequence", "alias_behind_a_merge_key", "alias_as_a_key"],
)
def test_declaration_with_an_alias_is_refused_at_the_alias_line(text: str, line: int) -> None:
    with pytest.raises(StrictYamlError, match=f"alias at line {line} is not accepted"):
        load_declaration_yaml(text)


@pytest.mark.parametrize(
    "timestamp_text",
    [
        "2026-10-24T08:30:00Z",
        "2026-10-24T10:30:00+02:00",
        "2026-10-24T08:30:00.1234567Z",
        "2026-10-24 08:30:00",
        "2026-10-24",
        "2024-02-30",
    ],
    ids=[
        "utc_time",
        "offset_time",
        "seven_fraction_digits",
        "space_separated_naive_time",
        "date",
        "impossible_date",
    ],
)
def test_declaration_keeps_an_unquoted_timestamp_as_its_text(timestamp_text: str) -> None:
    document = load_declaration_yaml(f"when: {timestamp_text}\n")

    assert document == {"when": timestamp_text}


@pytest.mark.parametrize(
    ("text", "violation"),
    [
        ("a: 1\na: 2\n", "duplicate key"),
        ("derived:\n  <<: {k: 1}\n", "merge key"),
        ("? [a, b]\n: 1\n", "unhashable key"),
        ("count: !!int ten\n", "value cannot be constructed"),
    ],
    ids=["duplicate_key", "merge_key", "unhashable_key", "int_tag_on_a_word"],
)
def test_declaration_keeps_the_strict_loaders_refusals(text: str, violation: str) -> None:
    with pytest.raises(StrictYamlError, match=violation):
        load_declaration_yaml(text)


def test_declaration_without_aliases_or_timestamps_loads_like_safe_load() -> None:
    text = "name: demo\ncount: 3\nratio: 2.0\nitems: [1, two, true, null]\n"

    assert load_declaration_yaml(text) == yaml.safe_load(text)


def test_strict_loader_still_resolves_aliases_and_timestamps() -> None:
    # A declaration read first shows the declaration loader leaves the strict loader's
    # resolvers as they were.
    load_declaration_yaml("when: 2026-10-24T08:30:00Z\n")

    document = load_strict_yaml("when: &x 2026-10-24T08:30:00Z\nagain: *x\n")

    assert document == {
        "when": datetime(2026, 10, 24, 8, 30, tzinfo=UTC),
        "again": datetime(2026, 10, 24, 8, 30, tzinfo=UTC),
    }
