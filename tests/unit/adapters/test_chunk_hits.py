"""Vector-store answers become one bounded, ordered match per CVE."""

import pytest

from tests.support.collect import list_cve_ids
from vulnwitness.adapters.semantic.chunk_hits import (
    ChunkHit,
    MalformedChunkHitError,
    collapse_chunk_hits,
    read_chroma_query_hits,
)


def test_chroma_answer_rows_become_chunk_hits() -> None:
    query_hits = {
        "ids": [["CVE-9999-0001_chunk_0", "CVE-9999-0002_chunk_3"]],
        "metadatas": [[{"cve_id": "CVE-9999-0001"}, {"cve_id": "CVE-9999-0002"}]],
        "distances": [[0.1, 0.4]],
    }

    chunk_hits = read_chroma_query_hits(query_hits)

    assert chunk_hits == [ChunkHit("CVE-9999-0001", 0.1), ChunkHit("CVE-9999-0002", 0.4)]


@pytest.mark.parametrize(
    "query_hits",
    [
        {"metadatas": [[{"cve_id": "CVE-9999-0001"}]]},
        {"metadatas": [[{"cve_id": "CVE-9999-0001"}]], "distances": [[True]]},
        {"metadatas": [[{"cve_id": "chunk-7"}]], "distances": [[0.1]]},
        {"metadatas": [[{}], [{}]], "distances": [[0.1], [0.2]]},
        {"metadatas": [[{"cve_id": "CVE-9999-0001"}]], "distances": [[float("-inf")]]},
        {"metadatas": [[{"cve_id": "CVE-9999-0001"}]], "distances": [[float("nan")]]},
        {"metadatas": [[{"cve_id": "CVE-9999-0001"}]], "distances": [[-0.5]]},
        {"metadatas": [[{"cve_id": "CVE-٢٠٢٤-١٢٣٤"}]], "distances": [[0.1]]},
        {"metadatas": [[{"cve_id": "cve-9999-0001"}]], "distances": [[0.1]]},
        {"metadatas": [[{"cve_id": "CVE-2024-" + "1" * 40}]], "distances": [[0.1]]},
    ],
    ids=[
        "no_distances",
        "boolean_distance",
        "non_cve_id",
        "two_query_rows",
        "negative_infinite_distance",
        "nan_distance",
        "negative_distance",
        "non_ascii_digits",
        "lower_case_id",
        "over_long_id",
    ],
)
def test_malformed_chroma_answer_is_rejected(query_hits: dict[str, object]) -> None:
    with pytest.raises(MalformedChunkHitError):
        read_chroma_query_hits(query_hits)


def test_collapse_keeps_nearest_chunk_per_cve() -> None:
    chunk_hits = [
        ChunkHit("CVE-9999-0003", 0.3),
        ChunkHit("CVE-9999-0002", 0.2),
        ChunkHit("CVE-9999-0003", 0.1),
        ChunkHit("CVE-9999-0001", 0.5),
    ]

    matches = collapse_chunk_hits(chunk_hits, limit=2, allowed_cve_ids=None)

    assert list_cve_ids(matches) == ["CVE-9999-0003", "CVE-9999-0002"]
    assert matches[0].score == round(1 / 1.1, 6)


def test_collapse_breaks_equal_distances_by_cve_id() -> None:
    chunk_hits = [ChunkHit("CVE-9999-0002", 0.4), ChunkHit("CVE-9999-0001", 0.4)]

    matches = collapse_chunk_hits(chunk_hits, limit=2, allowed_cve_ids=None)

    assert list_cve_ids(matches) == ["CVE-9999-0001", "CVE-9999-0002"]


def test_collapse_scores_stay_positive_beyond_unit_distance() -> None:
    matches = collapse_chunk_hits([ChunkHit("CVE-9999-0001", 3.0)], limit=1, allowed_cve_ids=None)

    assert matches[0].score == 0.25
