"""M7b gold rules (``gold_rules``): a rule is parsed only in the shape the rubric states,
CVE and technique predicates never mix, explicit ID lists carry one reason per ID, and terms
match as whole words, case-insensitively, over the fields each subject kind reads."""

from typing import Any

import pytest

from cve_kgrag.evaluation.gold_rules import (
    CVE_PREDICATES,
    MAX_RULE_DEPTH,
    TECHNIQUE_PREDICATES,
    CveSubject,
    GoldRuleError,
    TechniqueSubject,
    build_technique_subject,
    parse_rule,
)
from tests.support.builders import build_cve_record


def build_subject(**overrides: Any) -> CveSubject:
    return CveSubject.from_record(build_cve_record(**overrides))


def describe(text: str, lang: str = "en") -> list[dict[str, str]]:
    return [{"lang": lang, "value": text, "source": "test"}]


def build_affected(vendor: str, product: str) -> dict[str, str]:
    return {"vendor": vendor, "product": product, "status": "affected"}


def nest(depth: int) -> dict[str, Any]:
    rule: dict[str, Any] = {"description_any": ["x"]}
    for _ in range(depth - 1):
        rule = {"all_of": [rule]}
    return rule


@pytest.mark.parametrize(
    "node",
    [
        ["description_any", ["x"]],
        {"description_any": ["x"], "cpe": ["a:b"]},
        {"unknown_predicate": ["x"]},
        {"technique_any": ["x"]},
        {"all_of": []},
        {"any_of": {"description_any": ["x"]}},
        {"description_any": []},
        {"description_any": "x"},
        {"description_any": ["x", "x"]},
        {"description_any": [" "]},
        {"description_any": [7]},
        {"cpe": ["vendor-only"]},
        {"cpe": ["a:b:c"]},
        {"kev": "yes"},
        {"cve_ids": ["CVE-2024-0001"]},
        {"cve_ids": {"ids": ["CVE-2024-0001"], "reasons": {}}},
        {
            "cve_ids": {
                "ids": ["CVE-2024-0001"],
                "reasons": {"CVE-2024-0001": "a", "CVE-2024-0002": "b"},
            }
        },
        {"cve_ids": {"ids": ["CVE-2024-0001"], "reasons": {"CVE-2024-0001": " "}}},
        {"cve_ids": {"ids": ["CVE-2024-0001", "CVE-2024-0001"], "reasons": {"CVE-2024-0001": "a"}}},
        {"cve_ids": {"ids": ["FGT1234"], "reasons": {"FGT1234": "a"}}},
        {"cve_ids": {"ids": ["CVE-2024-0001"], "reasons": {"CVE-2024-0001": "a"}, "note": "x"}},
        nest(MAX_RULE_DEPTH + 1),
    ],
    ids=[
        "not_a_mapping",
        "two_keys",
        "unknown_predicate",
        "technique_predicate_in_a_cve_rule",
        "empty_combinator",
        "combinator_without_a_list",
        "empty_values",
        "values_not_a_list",
        "repeated_value",
        "blank_value",
        "value_not_a_string",
        "cpe_without_product",
        "cpe_with_a_third_part",
        "kev_not_a_boolean",
        "ids_without_reasons",
        "reason_missing",
        "reason_for_an_id_not_listed",
        "blank_reason",
        "repeated_id",
        "technique_id_in_a_cve_list",
        "extra_key_in_an_id_list",
        "nested_too_deep",
    ],
)
def test_cve_rule_outside_the_grammar_is_refused(node: object) -> None:
    with pytest.raises(GoldRuleError):
        parse_rule(node, CVE_PREDICATES)


@pytest.mark.parametrize(
    "node",
    [
        {"description_any": ["x"]},
        {"cpe": ["a:b"]},
        {"technique_ids": {"ids": ["CVE-2024-0001"], "reasons": {"CVE-2024-0001": "a"}}},
    ],
    ids=["description_predicate", "cpe_predicate", "cve_id_in_a_technique_list"],
)
def test_technique_rule_outside_the_grammar_is_refused(node: object) -> None:
    with pytest.raises(GoldRuleError):
        parse_rule(node, TECHNIQUE_PREDICATES)


def test_rule_at_the_depth_limit_is_read() -> None:
    rule = parse_rule(nest(MAX_RULE_DEPTH), CVE_PREDICATES)

    assert rule.matches(build_subject(descriptions=describe("x")))


@pytest.mark.parametrize(
    ("term", "text", "expected_match"),
    [
        ("AMF", "a flaw in the AMF handler", True),
        ("amf", "a flaw in the AMF handler", True),
        ("AMF", "a flaw in AMFX", False),
        ("AMF", "a flaw in SAMF", False),
        ("Nausf", "the Nausf_UEAuthentication_Authenticate response", True),
        ("SEAF", "seaf-server mishandles a token", True),
        ("5G AKA", "during 5G AKA the AUSF", True),
        ("5G AKA", "during 5G-AKA the AUSF", False),
        ("GTP-U", "crafted GTP-U packets", True),
    ],
    ids=[
        "word",
        "other_case",
        "letter_after",
        "letter_before",
        "underscore_after",
        "hyphen_after",
        "phrase",
        "phrase_spelled_otherwise",
        "term_with_a_hyphen",
    ],
)
def test_description_term_matches_only_as_a_whole_word(
    term: str, text: str, expected_match: bool
) -> None:
    rule = parse_rule({"description_any": [term]}, CVE_PREDICATES)

    assert rule.matches(build_subject(descriptions=describe(text))) is expected_match


def test_description_terms_read_english_descriptions_only() -> None:
    rule = parse_rule({"description_any": ["Open5GS"]}, CVE_PREDICATES)
    subject = build_subject(
        descriptions=[*describe("ein Fehler in Open5GS", "de"), *describe("a gateway flaw")]
    )

    assert not rule.matches(subject)


@pytest.mark.parametrize(
    ("text", "expected_match"),
    [("AMF and NAS", True), ("AMF alone", False)],
    ids=["both_terms", "one_term"],
)
def test_description_all_needs_every_term(text: str, expected_match: bool) -> None:
    rule = parse_rule({"description_all": ["AMF", "NAS"]}, CVE_PREDICATES)

    assert rule.matches(build_subject(descriptions=describe(text))) is expected_match


@pytest.mark.parametrize(
    ("node", "expected_match"),
    [
        ({"cpe": ["Open5GS:Open5GS"]}, True),
        ({"cpe": ["open5gs:other"]}, False),
        ({"cpe_vendor": ["OPEN5GS"]}, True),
        ({"cpe_vendor": ["free5gc"]}, False),
    ],
    ids=["pair_in_another_case", "other_product", "vendor_in_another_case", "other_vendor"],
)
def test_cpe_predicates_match_affected_products_case_insensitively(
    node: dict[str, Any], expected_match: bool
) -> None:
    subject = build_subject(affected=[build_affected("open5gs", "open5gs")])

    assert parse_rule(node, CVE_PREDICATES).matches(subject) is expected_match


def test_reference_fragment_matches_inside_a_url_in_any_case() -> None:
    rule = parse_rule({"reference_contains": ["github.com/aligungr"]}, CVE_PREDICATES)
    subject = build_subject(references=[{"url": "https://GitHub.com/aligungr/UERANSIM/commit/1"}])

    assert rule.matches(subject)


@pytest.mark.parametrize(
    ("kev", "expected_match"), [(True, True), (False, False)], ids=["kev_true", "kev_false"]
)
def test_kev_predicate_matches_a_listed_record(kev: bool, expected_match: bool) -> None:
    rule = parse_rule({"kev": kev}, CVE_PREDICATES)
    subject = build_subject(kev={"date_added": "2099-01-05"})

    assert rule.matches(subject) is expected_match


def test_cve_id_list_matches_only_the_ids_it_names() -> None:
    rule = parse_rule(
        {"cve_ids": {"ids": ["CVE-9999-0002"], "reasons": {"CVE-9999-0002": "named"}}},
        CVE_PREDICATES,
    )

    assert rule.matches(build_subject(cve_id="CVE-9999-0002"))
    assert not rule.matches(build_subject(cve_id="CVE-9999-0001"))


@pytest.mark.parametrize(
    ("combinator", "expected_match"),
    [("all_of", False), ("any_of", True), ("none_of", False)],
    ids=["all_of", "any_of", "none_of"],
)
def test_combinators_join_their_parts(combinator: str, expected_match: bool) -> None:
    rule = parse_rule(
        {combinator: [{"description_any": ["AMF"]}, {"description_any": ["UPF"]}]},
        CVE_PREDICATES,
    )

    assert rule.matches(build_subject(descriptions=describe("an AMF flaw"))) is expected_match


def test_technique_terms_read_narrative_fields_and_not_mitigations() -> None:
    technique = {
        "id": "FGT1234.501",
        "name": "Test technique",
        "procedureexamples": [{"name": "Example", "description": "the AUSF is attacked"}],
        "mitigations": [{"id": "FGM5001", "mitigates": "rate limiting at the SEAF"}],
    }
    subject = build_technique_subject(technique)

    assert parse_rule({"technique_any": ["AUSF"]}, TECHNIQUE_PREDICATES).matches(subject)
    assert not parse_rule({"technique_any": ["SEAF"]}, TECHNIQUE_PREDICATES).matches(subject)


def test_technique_id_list_matches_only_the_ids_it_names() -> None:
    rule = parse_rule(
        {"technique_ids": {"ids": ["FGT5044"], "reasons": {"FGT5044": "named"}}},
        TECHNIQUE_PREDICATES,
    )

    assert rule.matches(TechniqueSubject(subject_id="FGT5044", text=""))
    assert not rule.matches(TechniqueSubject(subject_id="FGT5040", text=""))


@pytest.mark.parametrize(
    "technique", [{"name": "no id"}, {"id": "T1234"}], ids=["missing_id", "malformed_id"]
)
def test_technique_without_a_valid_id_is_refused(technique: dict[str, Any]) -> None:
    with pytest.raises(GoldRuleError):
        build_technique_subject(technique)
