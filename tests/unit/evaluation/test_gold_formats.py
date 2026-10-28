"""Classifying a gold file (``read_gold_document``, ``classify_gold_document``): one strict
parse within the cap, then the top-level key names alone decide the format, and every
other mapping, part of the labelled-case keys included, is refused without quoting it."""

import pytest

from cve_kgrag.evaluation.gold_cases import MAX_GOLD_FILE_BYTES, GoldFileError
from cve_kgrag.evaluation.gold_formats import (
    GoldFormat,
    classify_gold_document,
    read_gold_document,
)

DIGEST = "0" * 64


@pytest.mark.parametrize(
    ("gold_document", "expected_format"),
    [
        ({"trajectories": []}, GoldFormat.TRAJECTORIES),
        (
            {"cases": [], "corpus_content_sha256": DIGEST, "fight_snapshot_sha256": DIGEST},
            GoldFormat.LABELLED_CASES,
        ),
    ],
    ids=["trajectories", "labelled_cases"],
)
def test_document_with_one_format_s_keys_is_classified(
    gold_document: dict[str, object], expected_format: GoldFormat
) -> None:
    assert classify_gold_document(gold_document) is expected_format


@pytest.mark.parametrize(
    "gold_document",
    [
        {"cases": []},
        {"cases": [], "corpus_content_sha256": DIGEST},
        {"corpus_content_sha256": DIGEST, "fight_snapshot_sha256": DIGEST},
        {"trajectories": [], "cases": []},
        {
            "trajectories": [],
            "cases": [],
            "corpus_content_sha256": DIGEST,
            "fight_snapshot_sha256": DIGEST,
        },
        {"other": "\x1b[31mforged"},
        ["trajectories"],
        "trajectories",
    ],
    ids=[
        "cases_alone",
        "cases_and_corpus_only",
        "digests_without_cases",
        "trajectories_and_cases",
        "trajectories_and_every_labelled_key",
        "neither",
        "a_list",
        "a_string",
    ],
)
def test_document_of_neither_format_is_refused_without_quoting_it(
    gold_document: object,
) -> None:
    with pytest.raises(GoldFileError) as refused:
        classify_gold_document(gold_document)

    assert "forged" not in str(refused.value)
    assert "\x1b" not in str(refused.value)


@pytest.mark.parametrize(
    "gold_bytes",
    [
        b"x" * (MAX_GOLD_FILE_BYTES + 1),
        b"trajectories: [unterminated",
        b"\xff\xfe",
        b"a: 1\na: 2\n",
    ],
    ids=["over_the_cap", "broken_yaml", "not_utf_8", "repeated_key"],
)
def test_file_the_strict_loader_refuses_is_refused(gold_bytes: bytes) -> None:
    with pytest.raises(GoldFileError):
        read_gold_document(gold_bytes)
