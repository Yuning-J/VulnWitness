"""Text splits into words, with boundaries wherever a separator may not join an alias."""

import pytest

from vulnwitness.domain.text import TOKEN, list_query_terms, normalize_query
from vulnwitness.topics.normalization import TERM_BOUNDARY, alias_key, split_terms

# One probe per kind of character that can stand against an ASCII word with nothing
# between: every kind must leave the ASCII words exactly as the CVE side reads them.
WORD_READING_PROBES = {
    "accented_letter": "5G\u00e9aka threats",
    "accent_inside_an_ordinary_word": "na\u00efve parser crash",
    "greek_letter": "\u03b1aka attacks",
    "cyrillic_letter": "\u0436aka attacks",
    "thai_letter": "\u0e01aka attacks",
    "hangul_jamo": "\u1100aka attacks",
    "hangul_filler": "\u3164aka attacks",
    "halfwidth_hangul_filler": "\uffa0aka attacks",
    "arabic_indic_digit": "\u0665aka attacks",
    "modifier_letter_apostrophe": "EAP-AKA\u02bc threats",
    "zero_width_space": "x\u200baka attacks",
    "soft_hyphen": "5G\u00ad-AKA crash",
    "ideograph": "5G-AKA\u534f\u8bae",
    "fullwidth_letters": "\uff15\uff27\uff0d\uff21\uff2b\uff21",
}


def list_ascii_words(terms: list[str]) -> list[str]:
    ascii_words: list[str] = []
    for term in terms:
        if TOKEN.fullmatch(term):
            ascii_words.append(term)
    return ascii_words


def test_consecutive_ideographs_stay_joinable() -> None:
    assert split_terms("\u534f\u8bae\u6f0f\u6d1e") == ["\u534f", "\u8bae", "\u6f0f", "\u6d1e"]


def test_change_of_script_is_a_boundary() -> None:
    assert split_terms("aka\u534f\u8bae") == ["aka", TERM_BOUNDARY, "\u534f", "\u8bae"]


@pytest.mark.parametrize(
    ("text", "expected_terms"),
    [
        ("5G\u00e9aka", ["5g", TERM_BOUNDARY, "\u00e9", TERM_BOUNDARY, "aka"]),
        ("na\u00efve", ["na", TERM_BOUNDARY, "\u00ef", TERM_BOUNDARY, "ve"]),
        ("\u0665aka", ["\u0665", TERM_BOUNDARY, "aka"]),
        ("aka\u02bc", ["aka", TERM_BOUNDARY, "\u02bc"]),
    ],
    ids=["accented_letter", "accent_inside_a_word", "non_ascii_digit", "modifier_letter"],
)
def test_ascii_word_meeting_a_non_ascii_word_character_is_a_boundary(
    text: str, expected_terms: list[str]
) -> None:
    assert split_terms(text) == expected_terms


def test_run_of_non_ascii_letters_stays_one_word() -> None:
    assert split_terms("\u00e9\u03b1\u0436") == ["\u00e9\u03b1\u0436"]


@pytest.mark.parametrize(
    ("text", "expected_terms"),
    [
        ("5g\u200baka", ["5g", TERM_BOUNDARY, "aka"]),
        ("x\u200baka", ["x", TERM_BOUNDARY, "aka"]),
        ("5G\u00ad-AKA", ["5g", TERM_BOUNDARY, "aka"]),
        ("a\u200bka", ["a", TERM_BOUNDARY, "ka"]),
    ],
    ids=["zero_width_space", "zero_width_space_after_one_letter", "soft_hyphen", "inside_a_word"],
)
def test_format_character_is_a_boundary_no_alias_joins_across(
    text: str, expected_terms: list[str]
) -> None:
    """A format character (Unicode category Cf) displays nothing, so an alias split by
    one is not read as written; the words on either side stay the CVE side's tokens."""
    assert split_terms(text) == expected_terms


def test_alias_key_ignores_joining_punctuation_and_case() -> None:
    assert alias_key("5G-AKA") == alias_key("5g aka") == alias_key("5GAKA") == "5gaka"


@pytest.mark.parametrize(
    "query", list(WORD_READING_PROBES.values()), ids=list(WORD_READING_PROBES.keys())
)
def test_ascii_words_of_a_query_are_the_tokens_of_the_once_normalized_query(query: str) -> None:
    """A local property of the registry's reading; the CVE search terms normalize twice
    and can differ (next test)."""
    assert list_ascii_words(split_terms(query)) == TOKEN.findall(normalize_query(query))


@pytest.mark.parametrize(
    ("query", "expected_registry_words", "expected_search_terms"),
    [
        ("na\u00df\u0301 threats", ["nass", "threats"], ["nas", "threats"]),
        ("x H\u0302\u0331 attacks", ["x", "attacks"], ["x", "h", "attacks"]),
        ("na\u00df\u00b4 threats", ["nass", "threats"], ["nass", "threats"]),
    ],
    ids=["sharp_s_and_combining_acute", "h_circumflex_and_macron_below", "spacing_acute_agrees"],
)
def test_twice_normalized_search_terms_can_differ_from_the_registry_words(
    query: str, expected_registry_words: list[str], expected_search_terms: list[str]
) -> None:
    """``normalize_query`` is not idempotent: normalizing again composes the second ``s``
    of a case-folded ``\\u00df`` with the acute after it, and leaves a case-folded
    ``\\u0124`` (``\\u0125``) as ``h`` followed by its marks. The search terms normalize
    twice, the registry once, so such a search term is not a registry word (ADR 0002 §8)."""
    registry_words = list_ascii_words(split_terms(query))

    search_terms = list_query_terms(query)

    assert registry_words == expected_registry_words
    assert search_terms == expected_search_terms
