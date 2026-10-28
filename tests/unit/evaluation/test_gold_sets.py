"""Deriving M7b gold sets (``GoldSetCollector``, ``format_gold_sets``): allowed is relevant
minus required, the sets must keep required within relevant and irrelevant outside it,
each case's label must be what its sets support, and the sets file is canonical."""

import json
from typing import Any

import pytest

from cve_kgrag.evaluation.gold_cases import GoldFileError
from cve_kgrag.evaluation.gold_rules import GoldRuleError, TechniqueSubject
from cve_kgrag.evaluation.gold_sets import (
    GoldSetCollector,
    format_gold_sets,
    read_technique_subjects,
)
from cve_kgrag.evaluation.labelled_cases import GoldFile, SubjectKind, load_gold_file
from tests.support.builders import build_cve_record
from tests.support.fight_excerpt import EXCERPT_BYTES
from tests.support.gold_files import build_case_row, encode_gold_file

RECORD_TEXTS = {
    "CVE-9999-0001": "democorp gateway crashes on long input",
    "CVE-9999-0002": "democorp router leaks memory",
    "CVE-9999-0003": "acme gateway crashes",
}
TECHNIQUES = (
    TechniqueSubject(subject_id="FGT5044", text="forces the home network to send keys"),
    TechniqueSubject(subject_id="FGT5040", text="weak SUCI values reveal a private key"),
)
NO_MATCH_RULE = {"description_any": ["nothing-matches-this"]}


def derive(case_rows: list[dict[str, Any]]) -> tuple[GoldFile, dict[str, Any]]:
    gold_file = load_gold_file(encode_gold_file(case_rows))
    collector = GoldSetCollector(gold_file)
    for cve_id, text in RECORD_TEXTS.items():
        collector.keep_record(
            build_cve_record(
                cve_id=cve_id, descriptions=[{"lang": "en", "value": text, "source": "test"}]
            )
        )
    return gold_file, collector.derive(TECHNIQUES)


def build_negative_row(**overrides: Any) -> dict[str, Any]:
    """An insufficient case whose wide check finds the acme record, marked irrelevant."""
    row = build_case_row(
        id="acme-router",
        rules={
            "cves": {
                "relevant": NO_MATCH_RULE,
                "required": NO_MATCH_RULE,
                "irrelevant": {"description_any": ["acme"]},
                "wide_check": {"description_any": ["acme"]},
            }
        },
        label={"sufficiency": "insufficient", "reason": "No acme router CVE exists."},
    )
    row.update(overrides)
    return row


def test_allowed_is_relevant_minus_required() -> None:
    _, gold_sets = derive([build_case_row()])

    cve_sets = gold_sets["democorp-gateway"][SubjectKind.CVES]
    assert cve_sets.required == ("CVE-9999-0001",)
    assert cve_sets.allowed == ("CVE-9999-0002",)
    assert cve_sets.irrelevant == ()
    assert cve_sets.wide_check is None


def test_technique_sets_are_derived_from_the_techniques() -> None:
    _, gold_sets = derive(
        [
            build_case_row(
                needs=["protocol_context"],
                rules={
                    "techniques": {
                        "relevant": {"technique_any": ["keys", "SUCI"]},
                        "required": {
                            "technique_ids": {"ids": ["FGT5044"], "reasons": {"FGT5044": "x"}}
                        },
                    }
                },
            )
        ]
    )

    technique_sets = gold_sets["democorp-gateway"][SubjectKind.TECHNIQUES]
    assert technique_sets.required == ("FGT5044",)
    assert technique_sets.allowed == ("FGT5040",)


@pytest.mark.parametrize(
    ("cve_rules", "expected_problem"),
    [
        (
            {
                "relevant": {"description_any": ["router"]},
                "required": {"description_any": ["gateway"]},
            },
            "required holds an item relevant does not",
        ),
        (
            {
                "relevant": {"description_any": ["democorp"]},
                "required": {"description_all": ["democorp", "gateway"]},
                "irrelevant": {"description_any": ["router"]},
            },
            "irrelevant overlaps relevant",
        ),
    ],
    ids=["required_outside_relevant", "irrelevant_inside_relevant"],
)
def test_sets_that_break_the_set_constraints_are_refused(
    cve_rules: dict[str, Any], expected_problem: str
) -> None:
    with pytest.raises(GoldFileError) as refused:
        derive([build_case_row(rules={"cves": cve_rules})])

    assert expected_problem in str(refused.value)


@pytest.mark.parametrize(
    "case_row",
    [
        build_case_row(
            needs=["implementation_cves", "affectedness"],
            label={"sufficiency": "partial", "reason": "No affectedness source."},
        ),
        build_negative_row(),
        build_case_row(
            rules={"cves": {"relevant": NO_MATCH_RULE, "required": NO_MATCH_RULE}},
            label={"sufficiency": "uncertain", "reason": "The owner cannot settle it."},
        ),
    ],
    ids=[
        "partial_for_affectedness",
        "insufficient_with_wide_hits_all_irrelevant",
        "uncertain_is_not_checked",
    ],
)
def test_label_the_sets_support_is_accepted(case_row: dict[str, Any]) -> None:
    _, gold_sets = derive([case_row])

    assert case_row["id"] in gold_sets


@pytest.mark.parametrize(
    ("case_row", "expected_problem"),
    [
        (
            build_case_row(rules={"cves": {"relevant": NO_MATCH_RULE, "required": NO_MATCH_RULE}}),
            "sufficient, but a needed category has none",
        ),
        (
            build_case_row(needs=["implementation_cves", "affectedness"]),
            "sufficient, but a needed category has none",
        ),
        (
            build_case_row(label={"sufficiency": "partial", "reason": "x"}),
            "partial needs one needed category",
        ),
        (
            build_case_row(
                rules={"cves": {"relevant": NO_MATCH_RULE, "required": NO_MATCH_RULE}},
                label={"sufficiency": "partial", "reason": "x"},
            ),
            "partial needs one needed category",
        ),
        (
            build_case_row(label={"sufficiency": "insufficient", "reason": "x"}),
            "insufficient, but has required items",
        ),
        (
            build_negative_row(
                rules={"cves": {"relevant": NO_MATCH_RULE, "required": NO_MATCH_RULE}}
            ),
            "insufficient without a wide check",
        ),
        (
            build_negative_row(
                rules={
                    "cves": {
                        "relevant": NO_MATCH_RULE,
                        "required": NO_MATCH_RULE,
                        "wide_check": {"description_any": ["acme"]},
                    }
                }
            ),
            "its wide check found items not marked irrelevant",
        ),
    ],
    ids=[
        "sufficient_with_no_required_items",
        "sufficient_with_affectedness_needed",
        "partial_with_every_category_covered",
        "partial_with_no_category_covered",
        "insufficient_with_required_items",
        "insufficient_without_a_wide_check",
        "insufficient_with_unreviewed_wide_hits",
    ],
)
def test_label_the_sets_do_not_support_is_refused(
    case_row: dict[str, Any], expected_problem: str
) -> None:
    with pytest.raises(GoldFileError) as refused:
        derive([case_row])

    assert expected_problem in str(refused.value)


def test_sets_file_is_canonical_json_naming_its_sources() -> None:
    gold_file, gold_sets = derive([build_negative_row(), build_case_row()])

    sets_bytes = format_gold_sets(gold_file, gold_sets)

    assert sets_bytes.endswith(b"\n")
    sets_document = json.loads(sets_bytes)
    assert json.dumps(sets_document, indent=2, sort_keys=True).encode() + b"\n" == sets_bytes
    assert sets_document["corpus_content_sha256"] == gold_file.corpus_content_sha256
    assert sets_document["fight_snapshot_sha256"] == gold_file.fight_snapshot_sha256
    assert sets_document["cases"]["acme-router"]["cves"] == {
        "required": [],
        "allowed": [],
        "irrelevant": ["CVE-9999-0003"],
        "wide_check": ["CVE-9999-0003"],
    }
    assert "wide_check" not in sets_document["cases"]["democorp-gateway"]["cves"]


def test_packaged_excerpt_reads_as_its_six_techniques() -> None:
    subjects = read_technique_subjects(EXCERPT_BYTES)

    assert len(subjects) == 6
    assert "FGT5044" in {subject.subject_id for subject in subjects}


@pytest.mark.parametrize(
    "snapshot_bytes",
    [b"techniques: [unterminated", b"name: no techniques\n", b"techniques:\n  - just text\n"],
    ids=["broken_yaml", "no_techniques_list", "technique_not_a_mapping"],
)
def test_snapshot_that_is_not_fight_yaml_is_refused(snapshot_bytes: bytes) -> None:
    with pytest.raises(GoldRuleError):
        read_technique_subjects(snapshot_bytes)
