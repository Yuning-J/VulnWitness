"""Per-request record of the channels a search ran, how each backend fared and what it matched."""

from dataclasses import dataclass, field

from vulnwitness.application.fusion import ChannelResult
from vulnwitness.domain.search import (
    ChannelOutcome,
    RetrievalOutcome,
    SearchWarning,
    SearchWarningCode,
)
from vulnwitness.domain.taxonomy import BackendStatus, RetrievalChannel, describe_backend_failure

# The channels that answer with their own top-k of what they matched; the exact-ID channel
# answers the named IDs and the structured channel only constrains.
RANKED_SEARCH_CHANNELS = frozenset(
    {RetrievalChannel.LEXICAL, RetrievalChannel.SEMANTIC, RetrievalChannel.GRAPH}
)
WARNING_CODE_BY_FAILURE = {
    BackendStatus.UNAVAILABLE: SearchWarningCode.BACKEND_UNAVAILABLE,
    BackendStatus.INCOMPLETE_INDEX: SearchWarningCode.BACKEND_INCOMPLETE,
    BackendStatus.ERROR: SearchWarningCode.BACKEND_ERROR,
}


@dataclass
class ChannelLog:
    channel_results: list[ChannelResult] = field(default_factory=list)
    channels_executed: list[RetrievalChannel] = field(default_factory=list)
    channel_outcomes: list[ChannelOutcome] = field(default_factory=list)
    warnings: list[SearchWarning] = field(default_factory=list)

    def record(self, channel: RetrievalChannel, outcome: RetrievalOutcome) -> None:
        """Log one backend call; only a successful call contributes matches."""
        self.channels_executed.append(channel)
        self.channel_outcomes.append(
            ChannelOutcome(
                channel=channel,
                status=outcome.status,
                detail=describe_backend_failure(outcome.failure),
            )
        )
        if outcome.status is BackendStatus.OK:
            self.channel_results.append(ChannelResult(channel, outcome.matches))
            return
        self.warn(WARNING_CODE_BY_FAILURE[outcome.status], channel.value)

    def warn(self, code: SearchWarningCode, subject: str) -> None:
        self.warnings.append(SearchWarning(code=code, subject=subject))

    def fills_top_k(self, top_k: int) -> bool:
        """Whether a channel that cuts its own top-k (``RANKED_SEARCH_CHANNELS``) answered
        with ``top_k`` matches or more, so it may have cut further ones."""
        return any(
            channel_result.channel in RANKED_SEARCH_CHANNELS
            and len(channel_result.matches) >= top_k
            for channel_result in self.channel_results
        )

    def list_seed_ids(self) -> tuple[str, ...]:
        """Records matched by the exact-ID, lexical or semantic channel, in first-match order."""
        seed_ids: list[str] = []
        for channel_result in self.channel_results:
            if channel_result.channel in {RetrievalChannel.STRUCTURED, RetrievalChannel.GRAPH}:
                continue
            for match in channel_result.matches:
                if match.cve_id not in seed_ids:
                    seed_ids.append(match.cve_id)
        return tuple(seed_ids)
