"""Loading an M7b gold file (``load_gold_file``): a file in the rubric's shape is read with
its rules parsed, and every other file is refused by case position, never by quoting it."""

from typing import Any

import pytest

from cve_kgrag.evaluation.gold_cases import GoldFileError
from cve_kgrag.evaluation.labelled_cases import (
    EvidenceCategory,
    SetName,
    Split,
    Sufficiency,
    load_gold_file,
)
from tests.support.gold_files import build_case_row, encode_gold_file

PROTOCOL_RULES = {
    "techniques": {
        "relevant": {"technique_any": ["AUSF"]},
        "required": {"technique_ids": {"ids": ["FGT5044"], "reasons": {"FGT5044": "named"}}},
    }
}


def test_gold_file_is_read_with_each_case_and_its_rules() -> None:
    gold_bytes = encode_gold_file(
        [
            build_case_row(),
            build_case_row(
                id="aka-threats",
                split="holdout",
                request={"query": "5G AKA threats", "scope": "protocol_context_only"},
                needs=["protocol_context"],
                rules=PROTOCOL_RULES,
            ),
        ]
    )

    gold_file = load_gold_file(gold_bytes)

    implementation_case, protocol_case = gold_file.cases
    assert implementation_case.case_id == "democorp-gateway"
    assert implementation_case.needs == (EvidenceCategory.IMPLEMENTATION_CVES,)
    assert implementation_case.sufficiency is Sufficiency.SUFFICIENT
    assert set(implementation_case.cve_rules or {}) == {SetName.RELEVANT, SetName.REQUIRED}
    assert implementation_case.technique_rules is None
    assert protocol_case.split is Split.HOLDOUT
    assert protocol_case.cve_rules is None
    assert set(protocol_case.technique_rules or {}) == {SetName.RELEVANT, SetName.REQUIRED}


def without(row: dict[str, Any], key: str) -> dict[str, Any]:
    trimmed_row = dict(row)
    del trimmed_row[key]
    return trimmed_row


@pytest.mark.parametrize(
    ("case_rows", "expected_problem"),
    [
        ([build_case_row(), build_case_row()], "case 2 repeats"),
        ([build_case_row(id="Not An ID")], "breaks its shape"),
        ([without(build_case_row(), "confirmed_by")], "breaks its shape"),
        ([build_case_row(confirmed_by="assistant")], "breaks its shape"),
        ([build_case_row(label={"sufficiency": "probably", "reason": "x"})], "breaks its shape"),
        ([build_case_row(needs=[])], "breaks its shape"),
        ([build_case_row(note="extra")], "breaks its shape"),
        (
            [build_case_row(needs=["implementation_cves", "implementation_cves"])],
            "case 1: needs lists",
        ),
        ([build_case_row(needs=["protocol_context"])], "case 1: needs protocol_context"),
        (
            [build_case_row(rules={"cves": {"required": {"description_any": ["democorp"]}}})],
            "case 1: a required rule needs a relevant rule",
        ),
        (
            [build_case_row(rules={"cves": {"relevant": {"technique_any": ["AUSF"]}}})],
            "case 1: a rule uses a predicate",
        ),
    ],
    ids=[
        "repeated_case_id",
        "malformed_case_id",
        "missing_confirmation",
        "confirmed_by_the_drafter",
        "unknown_sufficiency",
        "no_needs",
        "unknown_field",
        "repeated_need",
        "need_without_rules",
        "required_without_relevant",
        "technique_predicate_in_cve_rules",
    ],
)
def test_gold_file_outside_the_rubric_is_refused_by_position(
    case_rows: list[dict[str, Any]], expected_problem: str
) -> None:
    with pytest.raises(GoldFileError) as refused:
        load_gold_file(encode_gold_file(case_rows))

    assert expected_problem in str(refused.value)
    assert "Not An ID" not in str(refused.value)


@pytest.mark.parametrize(
    "gold_bytes",
    [b"cases: [unterminated", b"\xff\xfe", b"- a list\n"],
    ids=["broken_yaml", "not_utf_8", "not_a_mapping"],
)
def test_file_that_is_not_a_gold_file_is_refused(gold_bytes: bytes) -> None:
    with pytest.raises(GoldFileError):
        load_gold_file(gold_bytes)
