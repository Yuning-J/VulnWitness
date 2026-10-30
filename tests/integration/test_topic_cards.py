"""Packaged topic cards load as validated, pending-review knowledge; bad cards fail loudly."""

from pathlib import Path

import pytest

from cve_kgrag.adapters.topics.yaml_cards import (
    TopicCardError,
    default_topic_dir,
    load_topic_cards,
)
from cve_kgrag.domain.topic import ReviewStatus


def test_packaged_5g_aka_card_is_pending_human_review() -> None:
    topics = load_topic_cards(default_topic_dir())

    card = topics[0]
    assert len(topics) == 1
    assert card.topic_id == "3gpp:5g-aka"
    assert card.review.status is ReviewStatus.PENDING_REVIEW
    assert card.review.reviewer is None
    assert card.exact_aliases == ("5G-AKA", "5G AKA", "5gaka")


@pytest.mark.parametrize(
    "card_text",
    [
        "topic_id: [unclosed",
        "topic_id: 'not a valid id'\n",
        (default_topic_dir() / "3gpp-5g-aka.yaml").read_text(encoding="utf-8") + "exclusions: []\n",
    ],
    ids=["invalid_yaml", "contract_violation", "duplicate_key_hiding_a_reviewed_field"],
)
def test_invalid_card_fails_the_whole_load(tmp_path: Path, card_text: str) -> None:
    (tmp_path / "broken.yaml").write_text(card_text, encoding="utf-8")

    with pytest.raises(TopicCardError, match=r"broken\.yaml"):
        load_topic_cards(tmp_path)


def test_files_without_the_card_suffix_are_ignored(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("not a card", encoding="utf-8")

    assert load_topic_cards(tmp_path) == []


def test_card_that_is_not_utf8_fails_with_its_file_name(tmp_path: Path) -> None:
    (tmp_path / "latin1.yaml").write_bytes(b"topic_id: 'caf\xe9'\n")

    with pytest.raises(TopicCardError, match=r"latin1\.yaml"):
        load_topic_cards(tmp_path)


def test_pending_card_naming_a_reviewer_is_rejected(tmp_path: Path) -> None:
    card_text = (default_topic_dir() / "3gpp-5g-aka.yaml").read_text(encoding="utf-8")
    (tmp_path / "card.yaml").write_text(
        card_text.replace("reviewer: null", "reviewer: someone"), encoding="utf-8"
    )

    with pytest.raises(TopicCardError, match="reviewer"):
        load_topic_cards(tmp_path)


def test_only_yaml_suffixed_files_are_cards(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("topic_id: [unclosed", encoding="utf-8")

    assert load_topic_cards(tmp_path) == []


def test_no_packaged_card_has_a_contextual_alias() -> None:
    """A contextual alias written without its context is reported neither as a match nor
    as an excluded term, so ``find_fight_block`` cannot see it and the query's words would
    reach a direct FiGHT search. A card that gains one must revisit that rule first
    (docs/rebuild/m7b-c-fight-direct-search.md §3)."""
    topics = load_topic_cards(default_topic_dir())

    cards_with_contextual_aliases: list[str] = []
    for topic in topics:
        if topic.contextual_aliases:
            cards_with_contextual_aliases.append(topic.topic_id)

    assert topics != []
    assert cards_with_contextual_aliases == []
