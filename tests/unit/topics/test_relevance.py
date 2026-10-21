"""CVE records are tiered by how they name a topic; tiers never touch scope or severity."""

import pytest

from cve_kgrag.domain.cve import CveRecord
from cve_kgrag.domain.taxonomy import RetrievalChannel
from cve_kgrag.domain.topic import RelevanceTier
from cve_kgrag.topics.relevance import assess_relevance
from tests.support.builders import build_cve_record, build_topic

LEXICAL = {RetrievalChannel.LEXICAL}


def build_described_record(description: str, product: str = "widget") -> CveRecord:
    return build_cve_record(
        descriptions=[{"lang": "en", "value": description, "source": "test"}],
        affected=[{"vendor": "democorp", "product": product, "status": "affected"}],
    )


def test_description_naming_the_protocol_is_an_explicit_mention() -> None:
    record = build_described_record("[SYNTHETIC] A D-KX handshake flaw in KeyHub.")

    assessment = assess_relevance(record, build_topic(), LEXICAL)

    assert assessment is not None
    assert assessment.tier is RelevanceTier.EXPLICIT_PROTOCOL_MENTION
    assert assessment.matched_terms == ("DKX", "D-KX")


def test_entity_corroborated_by_a_second_topic_term_is_a_component_implementation() -> None:
    record = build_described_record(
        "[SYNTHETIC] A crash in the demo network admin page.", product="keyhub"
    )

    assessment = assess_relevance(record, build_topic(), LEXICAL)

    assert assessment is not None
    assert assessment.tier is RelevanceTier.PROTOCOL_COMPONENT_IMPLEMENTATION


def test_two_ecosystem_terms_are_adjacent() -> None:
    record = build_described_record("[SYNTHETIC] A demo network router in the demo core leaks.")

    assessment = assess_relevance(record, build_topic(), LEXICAL)

    assert assessment is not None
    assert assessment.tier is RelevanceTier.TELECOM_ECOSYSTEM_ADJACENT


@pytest.mark.parametrize(
    "description",
    [
        "[SYNTHETIC] The KeyHub web console crashes.",
        "[SYNTHETIC] A demo network router leaks memory.",
    ],
    ids=["entity_alone", "ecosystem_term_alone"],
)
def test_one_acronym_alone_does_not_tier_a_record(description: str) -> None:
    record = build_described_record(description)

    assert assess_relevance(record, build_topic(), LEXICAL) is None


def test_term_inside_a_longer_found_term_does_not_count_twice() -> None:
    topic = build_topic(ecosystem_terms=["demo network", "network"])
    record = build_described_record("[SYNTHETIC] A demo network router leaks memory.")

    assert assess_relevance(record, topic, LEXICAL) is None


def test_semantic_match_naming_nothing_is_semantic_only_even_beside_lexical() -> None:
    record = build_described_record("[SYNTHETIC] Unrelated text.")

    assessment = assess_relevance(
        record, build_topic(), {RetrievalChannel.LEXICAL, RetrievalChannel.SEMANTIC}
    )

    assert assessment is not None
    assert assessment.tier is RelevanceTier.SEMANTIC_ONLY


def test_record_matched_only_semantically_is_semantic_only() -> None:
    record = build_described_record("[SYNTHETIC] Unrelated text.")

    assessment = assess_relevance(record, build_topic(), {RetrievalChannel.SEMANTIC})

    assert assessment is not None
    assert assessment.tier is RelevanceTier.SEMANTIC_ONLY


def test_record_naming_nothing_of_the_topic_is_not_relevant() -> None:
    record = build_described_record("[SYNTHETIC] Demo text about a network.")

    assert assess_relevance(record, build_topic(), LEXICAL) is None


def test_terms_from_two_different_texts_never_join_into_an_alias() -> None:
    record = build_cve_record(
        descriptions=[
            {"lang": "en", "value": "[SYNTHETIC] Flaw in d", "source": "test"},
            {"lang": "de", "value": "kx Modul", "source": "test"},
        ]
    )

    assert assess_relevance(record, build_topic(), LEXICAL) is None


def test_two_spellings_of_one_term_count_once() -> None:
    topic = build_topic(ecosystem_terms=["demo network", "demo-network"])
    record = build_described_record("[SYNTHETIC] A demo-network router leaks memory.")

    assert assess_relevance(record, topic, LEXICAL) is None


def test_protocol_named_only_by_a_product_is_not_an_explicit_mention() -> None:
    record = build_described_record("[SYNTHETIC] A crash in the admin page.", product="dkx")

    assert assess_relevance(record, build_topic(), LEXICAL) is None
