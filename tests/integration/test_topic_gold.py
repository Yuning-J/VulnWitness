"""The packaged topic card, FiGHT excerpt and CVE fixture meet the hand-labelled gold file."""

from typing import Any

import pytest
import yaml

from tests.support.paths import GOLD_DIR
from vulnwitness.adapters.fixture.synthetic_fixture import FixtureBundle
from vulnwitness.adapters.topics.yaml_cards import default_topic_dir, load_topic_cards
from vulnwitness.composition import build_topic_context_service
from vulnwitness.domain.topic_context import TopicContextRequest
from vulnwitness.topics.registry import TopicRegistry

GOLD_FILE = GOLD_DIR / "m3_topic_queries.yaml"
GOLD = yaml.safe_load(GOLD_FILE.read_text(encoding="utf-8"))


def label_case(case: dict[str, Any]) -> str:
    return f"{case['query']}|{case.get('scope', 'resolve')}"


@pytest.mark.parametrize("case", GOLD["resolution"], ids=label_case)
def test_query_resolves_as_labelled(case: dict[str, Any]) -> None:
    registry = TopicRegistry(load_topic_cards(default_topic_dir()))

    resolution = registry.resolve(case["query"])

    topic_matches: list[tuple[str, str]] = []
    for match in resolution.matches:
        topic_matches.append((match.topic_id, match.match_kind.value))
    excluded_terms: list[str] = []
    for excluded_term in resolution.excluded_terms:
        excluded_terms.append(excluded_term.term)
    expected_matches = [] if case["topic"] is None else [(case["topic"], case["match_kind"])]
    assert topic_matches == expected_matches
    assert excluded_terms == case["excluded"]


@pytest.mark.parametrize("case", GOLD["context"], ids=label_case)
def test_topic_context_matches_the_labelled_sections(
    fixture_bundle: FixtureBundle, case: dict[str, Any]
) -> None:
    service = build_topic_context_service(fixture_bundle)

    response = service.explore(
        TopicContextRequest(query=case["query"], scope=case["scope"], limit=20)
    )

    technique_ids: list[str] = []
    for item in response.protocol_context:
        technique_ids.append(item.technique_id)
    implementation_labels: list[dict[str, str]] = []
    for topic_candidate in response.implementation_candidates:
        implementation_labels.append(
            {
                "cve_id": topic_candidate.candidate.record.cve_id,
                "tier": topic_candidate.relevance.tier.value,
            }
        )
    excluded_cve_ids: list[str] = []
    for excluded_candidate in response.excluded_implementation_candidates:
        excluded_cve_ids.append(excluded_candidate.candidate.candidate.record.cve_id)
    assert response.status.value == case["status"]
    assert technique_ids == case["protocol_context"]
    assert implementation_labels == case["implementation_candidates"]
    assert excluded_cve_ids == case["excluded_implementation_candidates"]
    assert set(technique_ids).isdisjoint(GOLD["never_in_protocol_context"])
