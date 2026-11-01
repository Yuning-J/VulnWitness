"""Query terms resolve to topics only through reviewed aliases; exclusions explain misses."""

import pytest

from tests.support.builders import build_topic
from vulnwitness.domain.topic import ProtocolTopic, TopicMatchKind
from vulnwitness.topics.registry import TopicRegistry, TopicRegistryError


def resolve(query: str) -> tuple[list[tuple[TopicMatchKind, str]], list[str]]:
    resolution = TopicRegistry([build_topic()]).resolve(query)
    matches: list[tuple[TopicMatchKind, str]] = []
    for match in resolution.matches:
        matches.append((match.match_kind, match.matched_alias))
    excluded_terms: list[str] = []
    for excluded_term in resolution.excluded_terms:
        excluded_terms.append(excluded_term.term)
    return matches, excluded_terms


@pytest.mark.parametrize(
    ("query", "expected_kind", "expected_alias"),
    [
        ("dkx", TopicMatchKind.EXACT_ALIAS, "DKX"),
        ("D-KX flaw", TopicMatchKind.EXACT_ALIAS, "DKX"),
        ("d kx", TopicMatchKind.EXACT_ALIAS, "DKX"),
        ("the demo key-exchange", TopicMatchKind.CANONICAL_NAME, "Demo Key Exchange"),
        ("kx keyhub crash", TopicMatchKind.CONTEXTUAL_ALIAS, "KX"),
    ],
    ids=["compact", "hyphenated", "spaced", "canonical_name", "contextual"],
)
def test_spellings_of_an_alias_resolve_the_topic(
    query: str, expected_kind: TopicMatchKind, expected_alias: str
) -> None:
    matches, excluded_terms = resolve(query)

    assert matches == [(expected_kind, expected_alias)]
    assert excluded_terms == []


@pytest.mark.parametrize(
    ("query", "expected_excluded"),
    [
        ("dk", ["dk"]),
        ("dk vulnerability", ["dk"]),
        ("EAP-KX keyhub", ["EAP-KX"]),
        ("dkxs", []),
        ("d", []),
    ],
    ids=[
        "bare_term",
        "bare_term_in_sentence",
        "excluded_phrase_blocks_context",
        "longer_word",
        "prefix",
    ],
)
def test_terms_that_are_not_aliases_resolve_nothing(
    query: str, expected_excluded: list[str]
) -> None:
    matches, excluded_terms = resolve(query)

    assert matches == []
    assert excluded_terms == expected_excluded


@pytest.mark.parametrize(
    "query",
    ["d, kx", "d. kx", "d (kx)", "d/kx", "d.k.x."],
    ids=["comma", "period", "parenthesis", "slash", "dotted_letters"],
)
def test_alias_never_matches_across_punctuation(query: str) -> None:
    matches, _ = resolve(query)

    assert matches == []


def test_letter_outside_ascii_inside_an_alias_breaks_it() -> None:
    matches, _ = resolve("d\u00e9kx")

    assert matches == []


def test_excluded_term_written_against_a_letter_outside_ascii_is_reported() -> None:
    """The ASCII run is a word of its own, as the CVE side reads it."""
    matches, excluded_terms = resolve("\u00e9dk vulnerability")

    assert matches == []
    assert excluded_terms == ["dk"]


@pytest.mark.parametrize(
    ("query", "expected_excluded"),
    [
        ("5G\u00e9aka threats", ["aka"]),
        ("\u00e9aka", ["aka"]),
        ("EAP-AKA\u02bc threats", ["EAP-AKA'"]),
        ("x\u200baka attacks", ["aka"]),
        ("5g\u200baka", ["aka"]),
        ("EAP\u200b-AKA' threats", ["aka"]),
    ],
    ids=[
        "accented_letter_before_the_alias",
        "alias_alone_after_an_accented_letter",
        "modifier_letter_apostrophe",
        "zero_width_space_before_the_alias",
        "zero_width_space_inside_the_topic_alias",
        "zero_width_space_splits_an_excluded_phrase",
    ],
)
def test_excluded_alias_beside_a_non_ascii_or_format_character_is_reported_without_a_topic(
    topic_registry: TopicRegistry, query: str, expected_excluded: list[str]
) -> None:
    resolution = topic_registry.resolve(query)

    excluded_terms: list[str] = []
    for excluded_term in resolution.excluded_terms:
        excluded_terms.append(excluded_term.term)
    assert resolution.matches == ()
    assert excluded_terms == expected_excluded


def test_canonical_name_and_alias_together_report_no_excluded_term() -> None:
    matches, excluded_terms = resolve("Demo Key Exchange (D-KX)")

    assert matches == [(TopicMatchKind.CANONICAL_NAME, "Demo Key Exchange")]
    assert excluded_terms == []


def test_longer_exact_match_outranks_a_broader_topic() -> None:
    broader_topic = build_topic(
        topic_id="test:d",
        canonical_name="Demo Family",
        exact_aliases=["D"],
        contextual_aliases=[],
        exclusions=[],
    )
    registry = TopicRegistry([broader_topic, build_topic()])

    resolution = registry.resolve("D-KX")

    topic_ids: list[str] = []
    for match in resolution.matches:
        topic_ids.append(match.topic_id)
    assert topic_ids == ["test:dkx", "test:d"]


def test_excluded_phrase_beside_an_exact_alias_is_reported_without_blocking_it() -> None:
    matches, excluded_terms = resolve("DKX versus EAP-KX")

    assert matches == [(TopicMatchKind.EXACT_ALIAS, "DKX")]
    assert excluded_terms == ["EAP-KX"]


def test_match_carries_topic_version_hash_and_review_status() -> None:
    registry = TopicRegistry([build_topic()])

    match = registry.resolve("dkx").matches[0]

    registered_topic = registry.get_topic("test:dkx")
    assert registered_topic is not None
    assert match.topic_version == "1.0.0"
    assert match.topic_sha256 == registered_topic.content_sha256
    assert match.review_status == "pending_review"


@pytest.mark.parametrize(
    ("topics", "violation"),
    [
        ([build_topic(), build_topic()], "duplicate topic"),
        (
            [build_topic(), build_topic(topic_id="test:other", canonical_name="Other")],
            "names both",
        ),
        (
            [build_topic(exclusions=[{"term": "d-kx", "reason": "contradiction"}])],
            "both an alias and excluded",
        ),
        (
            [build_topic(contextual_aliases=[{"alias": "dkx", "requires_any": ["keyhub"]}])],
            "both exact and contextual",
        ),
        (
            [
                build_topic(exclusions=[]),
                build_topic(
                    topic_id="test:other",
                    canonical_name="Other",
                    exact_aliases=["KX"],
                    contextual_aliases=[],
                    exclusions=[],
                ),
            ],
            "contextual for test:dkx but exact for test:other",
        ),
        (
            [build_topic(exclusions=[{"term": "KX", "reason": "also the contextual alias"}])],
            "both an alias and excluded",
        ),
        ([build_topic(exclusions=[{"term": "--", "reason": "no word"}])], "has no word"),
        ([build_topic(entities=[{"name": "_", "role": "no word"}])], "has no word"),
        ([build_topic(ecosystem_terms=["demo (network)"])], "spans punctuation"),
        ([build_topic(query_templates=["x" * 513])], "must hold searchable terms"),
        ([build_topic(query_templates=["the of and"])], "must hold searchable terms"),
        ([build_topic(query_templates=["CVEs of the CVE"])], "must hold searchable terms"),
        ([build_topic(query_templates=["CVE-9999-0001 dkx"])], "names a CVE ID"),
        ([build_topic(ecosystem_terms=["demo network", "Demo-Network"])], "are one term"),
        (
            [
                build_topic(
                    entities=[{"name": "KeyHub", "role": "r"}, {"name": "key hub", "role": "r"}]
                )
            ],
            "are one term",
        ),
    ],
    ids=[
        "duplicate_id",
        "alias_in_two_topics",
        "alias_also_excluded",
        "alias_exact_and_contextual",
        "contextual_alias_exact_in_another_topic",
        "contextual_alias_also_excluded",
        "exclusion_without_word",
        "entity_without_word",
        "term_spanning_punctuation",
        "query_template_too_long",
        "query_template_without_terms",
        "query_template_of_low_signal_words",
        "query_template_with_cve_id",
        "ecosystem_term_spelled_twice",
        "entity_spelled_twice",
    ],
)
def test_contradictory_cards_are_rejected(topics: list[ProtocolTopic], violation: str) -> None:
    with pytest.raises(TopicRegistryError, match=violation):
        TopicRegistry(topics)


def test_reviewed_status_without_reviewer_is_rejected() -> None:
    review = {"status": "reviewed", "reviewer": None, "reviewed_on": None, "basis": "x"}

    with pytest.raises(ValueError, match="reviewer"):
        build_topic(review=review)


def test_compact_spelling_ranks_like_the_hyphenated_one_against_a_broader_topic() -> None:
    broader_topic = build_topic(
        topic_id="test:d",
        canonical_name="Demo Family",
        exact_aliases=["D"],
        contextual_aliases=[],
        exclusions=[],
    )
    registry = TopicRegistry([broader_topic, build_topic()])

    resolution = registry.resolve("dkx weaknesses in d")

    assert resolution.matches[0].topic_id == "test:dkx"


def test_repeated_excluded_term_is_reported_once() -> None:
    _, excluded_terms = resolve("dk and dk")

    assert excluded_terms == ["dk"]


@pytest.mark.parametrize(
    ("query", "expected_alias"),
    [
        ("d\u2212kx", "DKX"),
        ("d-kx\u534f\u8bae", "DKX"),
    ],
    ids=["unicode_minus", "followed_by_cjk"],
)
def test_unicode_minus_and_a_following_ideograph_do_not_break_an_alias(
    query: str, expected_alias: str
) -> None:
    matches, _ = resolve(query)

    assert matches == [(TopicMatchKind.EXACT_ALIAS, expected_alias)]


@pytest.mark.parametrize(
    "query",
    ["d - kx", "d _kx_", "d\n-kx", "d\u00adkx", "d\u200bkx"],
    ids=["spaced_dash", "spaced_underscore", "line_break", "soft_hyphen", "zero_width_space"],
)
def test_spaced_broken_or_invisible_separators_are_boundaries(query: str) -> None:
    """A format character (soft hyphen, zero-width space) displays nothing, so no alias
    joins across one: the alias is not written as the query shows it."""
    matches, _ = resolve(query)

    assert matches == []
