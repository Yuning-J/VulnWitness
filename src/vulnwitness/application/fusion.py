"""Deterministic reciprocal-rank fusion across retrieval channels.

Candidates are ordered in three tiers:

1. records with an exact-ID hit, in the order the IDs were requested;
2. records the lexical or semantic channel matched directly;
3. records reached only through graph expansion.

Within tiers 2 and 3, records are ordered by descending fused score, ties broken
by ascending CVE ID, so graph neighbours only fill places that direct matches
leave free. Structured hits record why a candidate satisfied the filters. They
neither create a candidate nor add to its score: every record a filter admits
satisfies it equally, so a filter carries no relevance signal.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field

from vulnwitness.domain.search import ChannelHit, RetrievalMatch
from vulnwitness.domain.taxonomy import RetrievalChannel

# Cormack et al.'s RRF constant: damps the advantage of rank 1 over rank 2.
RRF_K = 60
DIRECT_CHANNELS = frozenset({RetrievalChannel.LEXICAL, RetrievalChannel.SEMANTIC})


@dataclass(frozen=True)
class ChannelResult:
    channel: RetrievalChannel
    matches: Sequence[RetrievalMatch]


@dataclass
class FusedCandidate:
    cve_id: str
    relevance_score: float = 0.0
    exact_id_position: int | None = None
    has_direct_hit: bool = False
    channel_hits: list[ChannelHit] = field(default_factory=list)


def fusion_sort_key(candidate: FusedCandidate) -> tuple[int, int, float, str]:
    if candidate.exact_id_position is not None:
        return (0, candidate.exact_id_position, 0.0, candidate.cve_id)
    tier = 1 if candidate.has_direct_hit else 2
    return (tier, 0, -candidate.relevance_score, candidate.cve_id)


def build_channel_hit(
    channel: RetrievalChannel, channel_rank: int, match: RetrievalMatch
) -> ChannelHit:
    return ChannelHit(
        channel=channel,
        channel_rank=channel_rank,
        raw_score=match.score,
        matched_fields=match.matched_fields,
        matched_terms=match.matched_terms,
        graph_paths=match.graph_paths,
    )


def fuse_channel_results(channel_results: Sequence[ChannelResult]) -> list[FusedCandidate]:
    candidates_by_id: dict[str, FusedCandidate] = {}
    for channel_result in channel_results:
        if channel_result.channel is RetrievalChannel.STRUCTURED:
            continue
        for channel_rank, match in enumerate(channel_result.matches, start=1):
            candidate = candidates_by_id.setdefault(match.cve_id, FusedCandidate(match.cve_id))
            candidate.relevance_score += 1.0 / (RRF_K + channel_rank)
            if channel_result.channel is RetrievalChannel.EXACT_ID:
                candidate.exact_id_position = channel_rank
            if channel_result.channel in DIRECT_CHANNELS:
                candidate.has_direct_hit = True
            candidate.channel_hits.append(
                build_channel_hit(channel_result.channel, channel_rank, match)
            )

    for channel_result in channel_results:
        if channel_result.channel is not RetrievalChannel.STRUCTURED:
            continue
        for channel_rank, match in enumerate(channel_result.matches, start=1):
            annotated_candidate = candidates_by_id.get(match.cve_id)
            if annotated_candidate is not None:
                annotated_candidate.channel_hits.append(
                    build_channel_hit(channel_result.channel, channel_rank, match)
                )

    fused = list(candidates_by_id.values())
    for candidate in fused:
        candidate.relevance_score = round(candidate.relevance_score, 6)
    fused.sort(key=fusion_sort_key)
    return fused
