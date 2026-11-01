"""Query normalization, tokenization and CVE-ID extraction."""

import time
import unicodedata

import pytest

from tests.support.investigation import MODEL_DISGUISED_LOW_SIGNAL_WORDS
from vulnwitness.domain.text import (
    DEFAULT_IGNORABLE_RANGES,
    asks_affectedness,
    extract_search_text,
    find_cve_ids,
    find_version_mentions,
    list_query_terms,
    mentions_cve_id_token,
    normalize_query,
    remove_cve_id_tokens,
    tokenize,
)

NAMED_ID = "CVE-9999-0003"


def test_normalize_query_folds_case_width_and_whitespace() -> None:
    assert normalize_query("  \uff15G-AKA \t Attack ") == "5g-aka attack"


def test_tokenize_splits_on_punctuation_and_drops_stopwords() -> None:
    assert tokenize("The 5G-AKA flaw in demo_gateway") == ["5g", "aka", "flaw", "demo", "gateway"]


def test_tokenize_keeps_compact_spelling_as_one_token() -> None:
    assert tokenize("5gaka") == ["5gaka"]


def test_find_cve_ids_is_case_insensitive_deduplicated_and_ordered() -> None:
    text = "cve-9999-0002 and CVE-9999-0001, again CVE-9999-0002"

    assert find_cve_ids(text) == ["CVE-9999-0002", "CVE-9999-0001"]


def test_find_cve_ids_ignores_malformed_identifiers() -> None:
    assert find_cve_ids("CVE-99-1 CVE-9999-12 XCVE-9999-0001x") == []


def test_remove_cve_id_tokens_leaves_remaining_terms() -> None:
    assert remove_cve_id_tokens("cve-9999-0001 sql injection") == "sql injection"


@pytest.mark.parametrize(
    ("text", "expected_cve_ids"),
    [
        ("CVE-9999-0003\u6f0f\u6d1e", ["CVE-9999-0003"]),
        ("\u8bf7\u67e5CVE-9999-0003\u6f0f\u6d1e", ["CVE-9999-0003"]),
        ("CVE-9999-0003\u306e\u8106\u5f31\u6027", ["CVE-9999-0003"]),
        ("CVE-9999-0003\ucde8\uc57d\uc810", ["CVE-9999-0003"]),
        ("CVE-9999-0003\u548cCVE-9999-0004", ["CVE-9999-0003", "CVE-9999-0004"]),
        ("(CVE-9999-0003)", ["CVE-9999-0003"]),
        (
            "\uff23\uff36\uff25\uff0d\uff19\uff19\uff19\uff19\uff0d\uff10\uff10\uff10\uff13",
            ["CVE-9999-0003"],
        ),
        ("CVE-9999-0003\u0e40\u0e1b\u0e47\u0e19", ["CVE-9999-0003"]),
        ("\u0e42\u0e2b\u0e27\u0e48CVE-9999-0003", ["CVE-9999-0003"]),
        ("CVE-9999-0003\u0ea5\u0eb2\u0ea7", ["CVE-9999-0003"]),
        ("CVE-9999-0003\u1785\u17c6", ["CVE-9999-0003"]),
        ("CVE-9999-0003\u1000\u1001", ["CVE-9999-0003"]),
        ("CVE-9999-0003\uff7e\uff77", ["CVE-9999-0003"]),
        ("CVE-9999-0003\U00020000", ["CVE-9999-0003"]),
        ("CVE-9999-0003\u3131", ["CVE-9999-0003"]),
        ("CVE-9999-0003\u3005", ["CVE-9999-0003"]),
        ("CVE-9999-0003\u0443\u044f\u0437", ["CVE-9999-0003"]),
        ("CVE-9999-0003\u200b\u6f0f\u6d1e", ["CVE-9999-0003"]),
        ("\u200bCVE-9999-0003\u200b", ["CVE-9999-0003"]),
        ("cve\u20109999\u20110003", ["CVE-9999-0003"]),
        ("CVE\u20139999\u20140003", ["CVE-9999-0003"]),
        ("CVE\u22129999\ufe630003", ["CVE-9999-0003"]),
    ],
    ids=[
        "han_after",
        "han_around",
        "kana_after",
        "hangul_after",
        "han_between",
        "brackets",
        "fullwidth",
        "thai_after",
        "thai_tone_mark_before",
        "lao_after",
        "khmer_after",
        "myanmar_after",
        "halfwidth_katakana_after",
        "cjk_extension_b_after",
        "hangul_compatibility_jamo_after",
        "iteration_mark_after",
        "cyrillic_after",
        "zero_width_space_then_han",
        "zero_width_spaces_around",
        "unicode_and_non_breaking_hyphens",
        "en_and_em_dashes",
        "minus_sign_and_small_hyphen",
    ],
)
def test_find_cve_ids_reads_an_id_against_non_latin_text_or_with_any_dash(
    text: str, expected_cve_ids: list[str]
) -> None:
    assert find_cve_ids(text) == expected_cve_ids


@pytest.mark.parametrize(
    "text",
    [
        "CVE-9999-0003\u0664",
        "CVE-9999-0003\u0967\u0968",
        "CVE-9999-0003\u3007",
        "CVE-9999-0003\u00b2",
        "CVE-9999-0003\u2460",
        "CVE-9999-0003\u2163",
        "CVE-9999-0003\u00e9",
        "CVE-9999-0003_x",
        "\u0664CVE-9999-0003",
        "CVE-9999-0003\u2488",
        "\u013fCVE-9999-0003",
        "CVE-9999-0003\u0301",
        "CVE-9999-0003\u200b4",
        "4\u200bCVE-9999-0003",
        "x\u0301CVE-9999-0003",
        "CVE\u200b-9999-0003",
        "CVE-9999-\u202e3000",
        "CVE-9999-0003\u31644",
        "CVE-9999-0003\ue000",
    ],
    ids=[
        "arabic_indic_digit",
        "devanagari_digits",
        "ideographic_zero",
        "superscript_two",
        "circled_one",
        "roman_numeral_four",
        "latin_letter",
        "underscore",
        "leading_digit",
        "digit_with_full_stop_symbol",
        "letter_folding_to_letter_and_dot",
        "combining_mark",
        "zero_width_space_then_digit",
        "digit_then_zero_width_space",
        "letter_with_combining_mark_before",
        "zero_width_space_inside",
        "direction_override_inside",
        "hangul_filler_then_digit",
        "private_use_character",
    ],
)
def test_find_cve_ids_never_shortens_a_malformed_token_into_another_id(text: str) -> None:
    assert find_cve_ids(text) == []


def list_number_like_characters() -> list[str]:
    """Every character that is a number or that NFKC folds into text holding a digit."""
    number_like_characters: list[str] = []
    for code_point in range(0x110000):
        if 0xD800 <= code_point <= 0xDFFF:
            continue
        character = chr(code_point)
        folded = unicodedata.normalize("NFKC", character)
        is_number = unicodedata.category(character).startswith("N")
        if is_number or any(folded_character.isdigit() for folded_character in folded):
            number_like_characters.append(character)
    return number_like_characters


def test_no_number_like_character_after_an_id_names_a_shorter_or_other_id() -> None:
    misread_characters: list[str] = []
    for character in list_number_like_characters():
        cve_ids = find_cve_ids(NAMED_ID + character)
        folded = unicodedata.normalize("NFKC", character)
        is_decimal_digit = unicodedata.category(character) == "Nd"
        if cve_ids == [] or (is_decimal_digit and cve_ids == [NAMED_ID + folded]):
            continue
        misread_characters.append(f"U+{ord(character):04X}")

    assert misread_characters == []


@pytest.mark.parametrize(
    "text",
    [
        "xCVE-9999-0003 ausf",
        "CVE-9999-0003a ausf",
        "CVE-9999-0003\u0664 ausf",
        "CVE-9999-0003\u00b2 ausf",
        "CVE-9999-0003 ausf",
    ],
    ids=["letter_before", "letter_after", "digit_after", "superscript_after", "well_formed"],
)
def test_token_holding_an_id_is_never_searched_as_words(text: str) -> None:
    assert mentions_cve_id_token(text)
    assert tokenize(remove_cve_id_tokens(text)) == ["ausf"]


def list_invisible_characters() -> list[str]:
    """Every format character, every default-ignorable code point and every control
    character other than whitespace."""
    invisible_characters: list[str] = []
    for code_point in range(0x110000):
        if 0xD800 <= code_point <= 0xDFFF:
            continue
        character = chr(code_point)
        category = unicodedata.category(character)
        is_ignorable = any(first <= code_point <= last for first, last in DEFAULT_IGNORABLE_RANGES)
        is_control = category == "Cc" and not character.isspace()
        if is_ignorable or is_control or category == "Cf":
            invisible_characters.append(character)
    return invisible_characters


def test_invisible_character_beside_an_id_never_splits_a_digit_off_it() -> None:
    split_characters: list[str] = []
    for character in list_invisible_characters():
        for text in [NAMED_ID + character + "4", "4" + character + NAMED_ID]:
            if find_cve_ids(text) or tokenize(remove_cve_id_tokens(text)):
                split_characters.append(f"U+{ord(character):04X}")

    assert split_characters == []


def list_combining_marks() -> list[str]:
    combining_marks: list[str] = []
    for code_point in range(0x110000):
        if 0xD800 <= code_point <= 0xDFFF:
            continue
        if unicodedata.category(chr(code_point)).startswith("M"):
            combining_marks.append(chr(code_point))
    return combining_marks


@pytest.mark.parametrize(
    "insert_at", [1, 4, 6, 12], ids=["in_cve", "after_dash", "in_year", "last_digit"]
)
def test_invisible_character_or_mark_inside_an_id_is_never_searched_or_looked_up(
    insert_at: int,
) -> None:
    leaking_characters: list[str] = []
    for character in list_invisible_characters() + list_combining_marks():
        text = NAMED_ID[:insert_at] + character + NAMED_ID[insert_at:]
        if find_cve_ids(text) or tokenize(remove_cve_id_tokens(text)):
            leaking_characters.append(f"U+{ord(character):04X}")

    assert leaking_characters == []


@pytest.mark.parametrize(
    "text",
    [
        "CVE 9999 0003",
        "CVE_9999_0003",
        "cve - 9999 - 0003",
        "CVE99990003",
        "CVE\u00ad9999\u00ad0003",
        "CVE.9999.0003",
        "CVE:9999:0003",
        "CVE#9999-0003",
        "CVE--9999--0003",
        "CVE- -9999-0003",
        "CVE    9999 0003",
        "CVE\u30fc9999\u30fc0003",
        "CVE\u301c9999\u301c0003",
        "CVE\u28009999\u28000003",
        "CVE-\u0669\u0669\u0669\u0669-\u0660\u0660\u0660\u0663",
        "CVE-\u096f\u096f\u096f\u096f-\u0966\u0966\u0966\u0969",
        "CVE-\u0669\u0669\u0669\u0669-0003",
        "CVE-9999-000\u0663",
        "CVE-9999-000\x073",
        "CVE-9999-000\x7f3",
        "CVE-9999-000\x9b3",
        "CVE ID 9999-0003",
        "CVE-ID-9999-0003",
        "CVE ID: 9999-0003",
        "CVE number 9999-0003",
        "CVE-9999-000 3",
        "CVE-9999-0,003",
        "CVE-9999-0\u2009003",
        "CVE-9999-003",
        "CVE-999-0003",
        "CVE-99 99-0003",
        "\u0421VE-9999-0003",
        "CV\u0415-9999-0003",
        "CV\u0395-9999-0003",
        "\u03f9VE-9999-0003",
        "\u03f2ve-9999-0003",
        "C\u03bdE-9999-0003",
        "\u1d04\u1d20\u1d07-9999-0003",
        "\u13df\u13d9\u13ac-9999-0003",
        "\ua4da\ua4e6\ua4f0-9999-0003",
        "\u00c7VE-9999-0003",
        "C\u0327VE-9999-0003",
        "CV\u00c9-9999-0003",
    ],
    ids=[
        "spaces",
        "underscores",
        "spaced_dashes",
        "no_separator",
        "soft_hyphens",
        "full_stops",
        "colons",
        "number_sign",
        "double_dashes",
        "dash_space_dash",
        "run_of_spaces",
        "katakana_prolonged_sound_marks",
        "wave_dashes",
        "braille_blanks",
        "arabic_indic_digits",
        "devanagari_digits",
        "arabic_indic_year",
        "arabic_indic_last_digit",
        "bell_inside",
        "delete_inside",
        "c1_control_inside",
        "id_word",
        "id_word_dashed",
        "id_word_and_colon",
        "number_word",
        "space_inside_number",
        "comma_grouped_number",
        "thin_space_grouped_number",
        "short_number",
        "short_year",
        "space_inside_year",
        "cyrillic_es",
        "cyrillic_ie",
        "greek_epsilon",
        "greek_capital_lunate_sigma",
        "greek_small_lunate_sigma",
        "greek_nu",
        "latin_small_capitals",
        "cherokee_letters",
        "lisu_letters",
        "precomposed_c_cedilla",
        "decomposed_c_cedilla",
        "precomposed_e_acute",
    ],
)
def test_text_read_as_an_id_but_not_written_as_one_is_neither_named_nor_searched(
    text: str,
) -> None:
    assert find_cve_ids(text) == []
    assert mentions_cve_id_token(text)
    assert tokenize(remove_cve_id_tokens(text + " ausf")) == ["ausf"]


def list_characters_folding_to_no_letter_or_digit() -> list[str]:
    """Every assigned character that neither is nor NFKC-folds into a letter or digit."""
    separator_characters: list[str] = []
    for code_point in range(0x110000):
        character = chr(code_point)
        if unicodedata.category(character) in ("Cn", "Co", "Cs"):
            continue
        folded = unicodedata.normalize("NFKC", character)
        if not any(folded_character.isalnum() for folded_character in folded):
            separator_characters.append(character)
    return separator_characters


def test_no_character_without_a_letter_or_digit_between_or_inside_id_parts_is_searched() -> None:
    leaking_characters: list[str] = []
    for character in list_characters_folding_to_no_letter_or_digit():
        for text in [
            f"CVE{character}9999{character}0003",
            f"CVE-99{character}99-0003",
            f"CVE-9999-000{character}3",
        ]:
            is_named = find_cve_ids(text) not in ([], [NAMED_ID])
            if is_named or tokenize(remove_cve_id_tokens(text + " ausf")) != ["ausf"]:
                leaking_characters.append(f"U+{ord(character):04X}")

    assert leaking_characters == []


def test_id_run_together_with_a_near_id_leaves_no_part_of_either_to_search() -> None:
    text = "CVE-9999-0003CVE 9999 0007 ausf"

    assert find_cve_ids(text) == []
    assert tokenize(remove_cve_id_tokens(text)) == ["ausf"]


def test_id_followed_by_another_number_still_names_the_id() -> None:
    text = "CVE-9999-0003 2022"

    assert find_cve_ids(text) == [NAMED_ID]
    assert remove_cve_id_tokens(text) == "2022"


@pytest.mark.parametrize(
    "text",
    [
        "y" + "\ufe0f" * 5000 + "CVE-2021-44228",
        "y" + "\u0301" * 5000 + "CVE-2021-44228",
        "y" + "\u0301" * 5000 + "cve 2021 44228",
    ],
    ids=[
        "variation_selectors",
        "combining_marks_before_an_id",
        "combining_marks_before_a_likeness",
    ],
)
def test_tokens_beside_a_long_run_of_invisible_characters_are_found_in_linear_time(
    text: str,
) -> None:
    # Widening a token must read each invisible character or mark once. The bound
    # allows scheduling slack while rejecting a quadratic reading of this long run.
    started = time.perf_counter()
    mentions_cve_id_token(text)
    elapsed_seconds = time.perf_counter() - started

    assert elapsed_seconds < 1.0


@pytest.mark.parametrize(
    ("text", "expected_terms"),
    [
        ("cve 2021 report 3", ["2021", "report", "3"]),
        ("5G-AKA crash 2021", ["5g", "aka", "crash", "2021"]),
        ("CVE count 2021 12345", ["count", "2021", "12345"]),
        ("CVE 2022 log4j", ["2022", "log4j"]),
    ],
    ids=["word_between_numbers", "no_word_cve", "word_before_numbers", "word_after_a_year"],
)
def test_numbers_beside_the_word_cve_are_searched_without_it(
    text: str, expected_terms: list[str]
) -> None:
    assert not mentions_cve_id_token(text)
    assert list_query_terms(text) == expected_terms


@pytest.mark.parametrize(
    "query",
    [
        "CVE of 2021-44228",
        "the CVE is 2021-44228",
        "nvdcve in 2021 and 2022",
        "nvdcve cves 2021 44228",
        "\u0421VE cves 2021 44228",
    ],
    ids=[
        "stopword_after_the_word_cve",
        "stopwords_around_the_word_cve",
        "stopwords_after_a_word_ending_in_cve",
        "low_signal_word_after_a_word_ending_in_cve",
        "low_signal_word_after_a_lookalike_cve",
    ],
)
def test_search_text_leaves_out_the_id_likeness_its_words_form(query: str) -> None:
    search_text = extract_search_text(query)

    assert not mentions_cve_id_token(search_text)
    assert list_query_terms(query) == []


@pytest.mark.parametrize(
    ("query", "expected_search_text"),
    [
        ("cve", ""),
        ("CVEs", ""),
        ("CVE", ""),
        ("cve ausf crash", "ausf crash"),
        ("CVE 2022 log4j", "2022 log4j"),
        ("cves of ausf", "of ausf"),
        ("\uff23\uff36\uff25\uff53 ausf", "ausf"),
        ("nvdcve cvelist ausf", "nvdcve cvelist ausf"),
    ],
    ids=[
        "word",
        "plural",
        "upper_case",
        "before_terms",
        "before_a_year",
        "plural_before_a_stopword",
        "fullwidth_plural",
        "words_containing_cve",
    ],
)
def test_search_text_leaves_out_the_low_signal_words(query: str, expected_search_text: str) -> None:
    assert extract_search_text(query) == expected_search_text


@pytest.mark.parametrize(
    ("query", "expected_cve_ids", "expected_terms"),
    [
        ("CVE-2024-1234 cve", ["CVE-2024-1234"], []),
        ("cve CVE-2024-1234 cves ausf", ["CVE-2024-1234"], ["ausf"]),
        ("CVE 2022 log4j", [], ["2022", "log4j"]),
        ("cves of ausf", [], ["ausf"]),
        ("the cve of a cves", [], []),
        ("nvdcve cvelist", [], ["nvdcve", "cvelist"]),
    ],
    ids=[
        "id_then_word",
        "word_id_plural_and_term",
        "word_before_a_year",
        "plural_before_a_stopword",
        "only_stopwords_and_low_signal_words",
        "words_containing_cve",
    ],
)
def test_query_terms_keep_the_named_ids_apart_and_drop_the_low_signal_words(
    query: str, expected_cve_ids: list[str], expected_terms: list[str]
) -> None:
    assert find_cve_ids(query) == expected_cve_ids
    assert list_query_terms(query) == expected_terms


def test_tokenize_keeps_the_low_signal_words_the_index_is_built_from() -> None:
    assert tokenize("CVE cves") == ["cve", "cves"]


@pytest.mark.parametrize(
    "spelling",
    MODEL_DISGUISED_LOW_SIGNAL_WORDS.values(),
    ids=MODEL_DISGUISED_LOW_SIGNAL_WORDS.keys(),
)
def test_disguised_low_signal_word_leaves_no_search_term(spelling: str) -> None:
    assert list_query_terms(spelling) == []
    assert list_query_terms(f"{spelling} ausf") == ["ausf"]


@pytest.mark.parametrize(
    ("query", "expected_terms"),
    [
        ("c ve", ["c", "ve"]),
        ("c-ve", ["c", "ve"]),
        ("cve s", ["s"]),
        ("cve's ausf crash", ["ausf", "crash"]),
        ("cve'sx", ["sx"]),
        ("x\u200bcve", ["x"]),
        ("don't cve", ["don", "t"]),
    ],
    ids=[
        "space_inside",
        "hyphen_inside",
        "letter_after_a_space",
        "possessive_before_terms",
        "longer_word_after_an_apostrophe",
        "invisible_character_before_the_word",
        "other_possessive_word",
    ],
)
def test_visible_separators_keep_words_apart_from_a_low_signal_word(
    query: str, expected_terms: list[str]
) -> None:
    assert list_query_terms(query) == expected_terms


def test_possessive_low_signal_word_still_marks_the_numbers_after_it_as_an_id() -> None:
    assert list_query_terms("CVE's 2021-44228") == []


@pytest.mark.parametrize(
    ("normalized_query", "expected_mentions"),
    [
        ("is kamailio 5.8.2 affected", [("kamailio", "5.8.2")]),
        ("is open5gs v2.7.2 affected by cve-2026-8746.", [("open5gs", "v2.7.2")]),
        ("open5gs 2.7 and free5gc 3.4.1", [("open5gs", "2.7"), ("free5gc", "3.4.1")]),
        ("server at 10.0.0.1", []),
        ("openairinterface 5g core", []),
        ("kamailio version 5.8.2", [("version", "5.8.2")]),
        ("is acme-f5gc 1.2.3 affected", []),
        ("linux_kernel 5.10.1", []),
    ],
    ids=[
        "three_part_version",
        "v_prefix_before_a_full_stop",
        "two_mentions",
        "ipv4_address_is_no_version",
        "undotted_number_is_no_version",
        "only_the_word_right_before_counts",
        "hyphenated_name",
        "underscored_name",
    ],
)
def test_find_version_mentions_reads_each_word_followed_by_a_dotted_version(
    normalized_query: str, expected_mentions: list[tuple[str, str]]
) -> None:
    assert find_version_mentions(normalized_query) == expected_mentions


@pytest.mark.parametrize(
    ("normalized_query", "expected"),
    [
        ("is kamailio 5.8.2 affected", True),
        ("which versions are vulnerable", True),
        ("kamailio 5.8.2 vulnerabilities", False),
    ],
    ids=["affected", "vulnerable", "vulnerabilities_asks_nothing_of_a_version"],
)
def test_asks_affectedness_only_for_words_that_ask_whether_a_product_is_affected(
    normalized_query: str, expected: bool
) -> None:
    assert asks_affectedness(normalized_query) is expected
