"""Reciprocal-rank fusion with exact-ID dominance."""

from tests.support.collect import list_cve_ids
from vulnwitness.application.fusion import RRF_K, ChannelResult, fuse_channel_results
from vulnwitness.domain.search import RetrievalMatch
from vulnwitness.domain.taxonomy import RetrievalChannel


def build_match(cve_id: str, score: float = 1.0) -> RetrievalMatch:
    return RetrievalMatch(
        cve_id=cve_id, score=score, matched_fields=("description",), matched_terms=("x",)
    )


def test_exact_hit_outranks_better_scored_lexical_hits() -> None:
    fused = fuse_channel_results(
        [
            ChannelResult(RetrievalChannel.EXACT_ID, [build_match("CVE-9999-0009")]),
            ChannelResult(
                RetrievalChannel.LEXICAL,
                [build_match("CVE-9999-0001", 9.0), build_match("CVE-9999-0002", 8.0)],
            ),
        ]
    )

    assert list_cve_ids(fused) == ["CVE-9999-0009", "CVE-9999-0001", "CVE-9999-0002"]


def test_exact_hits_keep_requested_order() -> None:
    fused = fuse_channel_results(
        [
            ChannelResult(
                RetrievalChannel.EXACT_ID,
                [build_match("CVE-9999-0002"), build_match("CVE-9999-0001")],
            )
        ]
    )

    assert list_cve_ids(fused) == ["CVE-9999-0002", "CVE-9999-0001"]


def test_record_found_by_two_channels_sums_reciprocal_ranks_and_keeps_both_hits() -> None:
    fused = fuse_channel_results(
        [
            ChannelResult(RetrievalChannel.EXACT_ID, [build_match("CVE-9999-0001")]),
            ChannelResult(
                RetrievalChannel.LEXICAL,
                [build_match("CVE-9999-0002"), build_match("CVE-9999-0001")],
            ),
        ]
    )

    assert fused[0].relevance_score == round(1 / (RRF_K + 1) + 1 / (RRF_K + 2), 6)
    channels: list[RetrievalChannel] = []
    for channel_hit in fused[0].channel_hits:
        channels.append(channel_hit.channel)
    assert channels == [RetrievalChannel.EXACT_ID, RetrievalChannel.LEXICAL]


def test_equal_fused_scores_are_ordered_by_cve_id() -> None:
    fused = fuse_channel_results(
        [
            ChannelResult(RetrievalChannel.LEXICAL, [build_match("CVE-9999-0002")]),
            ChannelResult(RetrievalChannel.SEMANTIC, [build_match("CVE-9999-0001")]),
        ]
    )

    assert list_cve_ids(fused) == ["CVE-9999-0001", "CVE-9999-0002"]


def test_structured_hit_annotates_a_candidate_without_creating_or_scoring_one() -> None:
    fused = fuse_channel_results(
        [
            ChannelResult(
                RetrievalChannel.STRUCTURED,
                [build_match("CVE-9999-0001"), build_match("CVE-9999-0002")],
            ),
            ChannelResult(RetrievalChannel.LEXICAL, [build_match("CVE-9999-0002")]),
        ]
    )

    channels: list[RetrievalChannel] = []
    for channel_hit in fused[0].channel_hits:
        channels.append(channel_hit.channel)
    assert list_cve_ids(fused) == ["CVE-9999-0002"]
    assert fused[0].relevance_score == round(1 / (RRF_K + 1), 6)
    assert channels == [RetrievalChannel.LEXICAL, RetrievalChannel.STRUCTURED]


def test_graph_only_candidate_ranks_below_every_direct_match() -> None:
    fused = fuse_channel_results(
        [
            ChannelResult(
                RetrievalChannel.LEXICAL,
                [build_match("CVE-9999-0001"), build_match("CVE-9999-0002")],
            ),
            ChannelResult(RetrievalChannel.GRAPH, [build_match("CVE-9999-0003")]),
        ]
    )

    assert list_cve_ids(fused) == ["CVE-9999-0001", "CVE-9999-0002", "CVE-9999-0003"]
