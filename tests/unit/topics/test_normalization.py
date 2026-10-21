"""Text splits into words, with boundaries wherever a separator may not join an alias."""

from cve_kgrag.topics.normalization import TERM_BOUNDARY, alias_key, split_terms


def test_consecutive_ideographs_stay_joinable() -> None:
    assert split_terms("\u534f\u8bae\u6f0f\u6d1e") == ["\u534f", "\u8bae", "\u6f0f", "\u6d1e"]


def test_change_of_script_is_a_boundary() -> None:
    assert split_terms("aka\u534f\u8bae") == ["aka", TERM_BOUNDARY, "\u534f", "\u8bae"]


def test_letters_outside_ascii_stay_inside_their_word() -> None:
    assert split_terms("5G\u00e9aka") == ["5g\u00e9aka"]


def test_alias_key_ignores_joining_punctuation_and_case() -> None:
    assert alias_key("5G-AKA") == alias_key("5g aka") == alias_key("5GAKA") == "5gaka"
