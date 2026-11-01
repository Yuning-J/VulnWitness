"""Untrusted relevance reply parts are independent, recorded observations."""

import json

import pytest

from tests.support.builders import build_cve_record, build_versioned_product
from tests.support.planners import build_text_reply
from vulnwitness.domain.relevance import RelevanceLabel
from vulnwitness.domain.relevance_reply import parse_relevance_reply
from vulnwitness.domain.relevance_terms import is_question_component, list_term_sources


@pytest.mark.parametrize(
    ("component", "question", "is_component"),
    [
        ("\uff27\uff21\uff34\uff25\uff37\uff21\uff39", "Gateway flaws", True),
        ("5G-AMF", "5g amf and smf", True),
        ("amf smf", "amf and smf", True),
        ("amf flaw", "amf smf flaw", False),
        ("am", "amf flaws", False),
        ("the", "the gateway", False),
    ],
)
def test_gap_component_matches_only_contiguous_normalized_search_terms(
    component: str,
    question: str,
    is_component: bool,
) -> None:
    # Arrange / Act
    component_matches = is_question_component(component, question)

    # Assert
    assert component_matches is is_component


def test_invalid_gap_and_one_bad_label_preserve_the_other_valid_labels() -> None:
    # Arrange
    reply = build_text_reply(
        '{"labels": {"key1": "relevant", "key2": "invented"}, '
        '"gap": {"component": "foreign", "reason": "coverage_unclear", "note": "check"}}'
    )

    # Act
    proposal = parse_relevance_reply(
        reply, {"key1": "CVE-9999-0001", "key2": "CVE-9999-0002"}, "gateway"
    )

    # Assert
    assert proposal.labels == {"key1": RelevanceLabel.RELEVANT}
    assert proposal.gap is None
    assert proposal.issues == ("missing_or_invalid_label:key2", "component_outside_question")


def test_duplicate_json_keys_are_recorded_as_malformed() -> None:
    # Arrange
    reply = build_text_reply('{"labels": {"key1": "relevant", "key1": "not_relevant"}}')

    # Act
    proposal = parse_relevance_reply(reply, {"key1": "CVE-9999-0001"}, "gateway")

    # Assert
    assert proposal.labels == {}
    assert proposal.issues == ("malformed_reply",)


def test_product_sources_share_search_normalization_and_keep_the_cpe_field() -> None:
    # Arrange
    record = build_cve_record(
        affected=[
            build_versioned_product(
                vendor="\uff26\uff29\uff38\uff34\uff35\uff32\uff25",
                product="gateway",
                cpe=r"cpe:2.3:a:vendor:shared\:component:*:*:*:*:*:*:*:*",
            )
        ]
    )

    # Act
    sources = list_term_sources(("question",), (record,))

    # Assert
    assert sources["fixture"].field == "vendor"
    assert sources["shared"].field == "cpe_product"
    assert sources["component"].cve_id == record.cve_id
    assert sources["question"].cve_id is None
    assert "vendor" not in sources


def test_normalized_component_over_the_contract_limit_is_absent_and_recorded() -> None:
    # Arrange
    component = "\ufb03" * 200
    reply = build_text_reply(
        json.dumps(
            {
                "labels": {"key1": "relevant"},
                "gap": {"component": component, "reason": "coverage_unclear", "note": "check"},
            }
        )
    )

    # Act
    proposal = parse_relevance_reply(reply, {"key1": "CVE-9999-0001"}, component)

    # Assert
    assert proposal.gap is None
    assert proposal.labels == {"key1": RelevanceLabel.RELEVANT}
    assert proposal.issues == ("invalid_gap",)
