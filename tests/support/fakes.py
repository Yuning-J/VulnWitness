"""Fake knowledge backends: canned, recording, failing, slow, deadline-nearing, blocking,
raising and inventing text retrievers, a blocking FiGHT source, one whose searches fail and
one listing extra evidence,
recorders that pass every request through to a real backend, and in-memory, blocking and
misanswering affectedness sources."""

import threading
from collections.abc import Sequence, Set
from dataclasses import dataclass, field
from typing import Any, cast

from cve_kgrag.domain.affectedness import AffectednessFailure, AffectednessRequest
from cve_kgrag.domain.evidence import EvidenceAnchor
from cve_kgrag.domain.search import RetrievalMatch, RetrievalOutcome
from cve_kgrag.domain.taxonomy import BackendFailure, BackendStatus
from cve_kgrag.domain.threat_context import (
    FightSnapshotInfo,
    ThreatContextItem,
    ThreatContextOutcome,
)
from cve_kgrag.ports.retrieval import LexicalRetriever
from cve_kgrag.ports.sources import FightSource
from tests.support.clocks import SteppingClock

# No fixture stores this record, so a channel returning it invents evidence.
INVENTED_CVE_ID = "CVE-9999-7777"


def build_lexical_match(cve_id: str) -> RetrievalMatch:
    """A lexical match naming no term, so it fits any search the service sends."""
    return RetrievalMatch(
        cve_id=cve_id, score=1.0, matched_fields=("description",), matched_terms=()
    )


def build_failure(
    status: BackendStatus, failure: BackendFailure = BackendFailure.UNREACHABLE
) -> RetrievalOutcome:
    return RetrievalOutcome(status=status, failure=failure)


@dataclass
class CannedRetriever:
    """A text channel (lexical or semantic) that ignores its input and returns one outcome."""

    outcome: RetrievalOutcome

    def search(
        self, query_text: str, limit: int, allowed_cve_ids: Set[str] | None
    ) -> RetrievalOutcome:
        return self.outcome


@dataclass
class RecordingRetriever:
    """A text channel that records every query text it is asked and answers with ``outcome``."""

    outcome: RetrievalOutcome
    query_texts: list[str] = field(default_factory=list)

    def search(
        self, query_text: str, limit: int, allowed_cve_ids: Set[str] | None
    ) -> RetrievalOutcome:
        self.query_texts.append(query_text)
        return self.outcome


@dataclass
class RecordingGraph:
    """A graph channel that records the seeds of every expansion and finds no neighbour."""

    seed_id_lists: list[tuple[str, ...]] = field(default_factory=list)

    def expand(
        self, seed_cve_ids: Sequence[str], limit: int, allowed_cve_ids: Set[str] | None
    ) -> RetrievalOutcome:
        self.seed_id_lists.append(tuple(seed_cve_ids))
        return RetrievalOutcome(status=BackendStatus.OK)


@dataclass
class RecordedChannels:
    """The lexical, semantic and graph channels of a search service, each recording its
    calls; both text channels match CVE-9999-0001 whatever they are asked."""

    lexical: RecordingRetriever
    semantic: RecordingRetriever
    graph: RecordingGraph


def build_recorded_channels() -> RecordedChannels:
    any_text_match = RetrievalOutcome(
        status=BackendStatus.OK, matches=(build_lexical_match("CVE-9999-0001"),)
    )
    return RecordedChannels(
        lexical=RecordingRetriever(any_text_match),
        semantic=RecordingRetriever(any_text_match),
        graph=RecordingGraph(),
    )


@dataclass
class LexicalRequestRecorder:
    """Delegates to ``inner`` and records each search as ``(query_text, limit)``."""

    inner: LexicalRetriever
    requests: list[tuple[str, int]] = field(default_factory=list)

    def search(
        self, query_text: str, limit: int, allowed_cve_ids: Set[str] | None
    ) -> RetrievalOutcome:
        self.requests.append((query_text, limit))
        return self.inner.search(query_text, limit, allowed_cve_ids)


@dataclass
class FightRequestRecorder:
    """Delegates to ``inner`` and records each search as ``(terms, limit)``."""

    inner: FightSource
    requests: list[tuple[tuple[str, ...], int]] = field(default_factory=list)

    def describe(self) -> FightSnapshotInfo | None:
        return self.inner.describe()

    def search(self, terms: Sequence[str], limit: int) -> ThreatContextOutcome:
        self.requests.append((tuple(terms), limit))
        return self.inner.search(terms, limit)

    def list_evidence(self) -> Sequence[EvidenceAnchor]:
        return self.inner.list_evidence()

    def list_techniques(self) -> Sequence[ThreatContextItem]:
        return self.inner.list_techniques()


@dataclass
class DeadlineNearingRetriever:
    """Delegates to ``inner``. Its first search leaves ``clock`` at ``seconds`` and makes every
    later read advance it by ``seconds_per_read``, so that search lands in time and the next
    deadline check finds the time up."""

    inner: LexicalRetriever
    clock: SteppingClock
    seconds: float
    seconds_per_read: float
    has_searched: bool = False

    def search(
        self, query_text: str, limit: int, allowed_cve_ids: Set[str] | None
    ) -> RetrievalOutcome:
        if not self.has_searched:
            self.has_searched = True
            self.clock.now_seconds = self.seconds
            self.clock.seconds_per_read = self.seconds_per_read
        return self.inner.search(query_text, limit, allowed_cve_ids)


@dataclass
class SlowRetriever:
    """Delegates to ``inner`` after moving ``clock`` forward by ``seconds`` per search."""

    inner: LexicalRetriever
    clock: SteppingClock
    seconds: float

    def search(
        self, query_text: str, limit: int, allowed_cve_ids: Set[str] | None
    ) -> RetrievalOutcome:
        self.clock.advance(self.seconds)
        return self.inner.search(query_text, limit, allowed_cve_ids)


@dataclass
class InventingRetriever:
    """Answers every search with a record the repository does not hold."""

    cve_id: str = INVENTED_CVE_ID

    def search(
        self, query_text: str, limit: int, allowed_cve_ids: Set[str] | None
    ) -> RetrievalOutcome:
        invented_match = build_lexical_match(self.cve_id)
        return RetrievalOutcome(status=BackendStatus.OK, matches=(invented_match,))


@dataclass
class BlockingRetriever:
    """A text channel whose every search records its query, sets ``entered`` and then
    blocks until ``release`` is set, then finds nothing: an adapter that never returns while
    a test runs."""

    release: threading.Event
    entered: threading.Event = field(default_factory=threading.Event)
    received_queries: list[str] = field(default_factory=list)

    def search(
        self, query_text: str, limit: int, allowed_cve_ids: Set[str] | None
    ) -> RetrievalOutcome:
        self.received_queries.append(query_text)
        self.entered.set()
        self.release.wait()
        return RetrievalOutcome(status=BackendStatus.OK)


@dataclass
class RaisingRetriever:
    """A text channel whose every search raises ``RuntimeError(message)``."""

    message: str

    def search(
        self, query_text: str, limit: int, allowed_cve_ids: Set[str] | None
    ) -> RetrievalOutcome:
        raise RuntimeError(self.message)


@dataclass
class BlockingFightSource:
    """Delegates to ``inner``, except that every search blocks until ``release`` is set."""

    inner: FightSource
    release: threading.Event

    def describe(self) -> FightSnapshotInfo | None:
        return self.inner.describe()

    def search(self, terms: Sequence[str], limit: int) -> ThreatContextOutcome:
        self.release.wait()
        return self.inner.search(terms, limit)

    def list_evidence(self) -> Sequence[EvidenceAnchor]:
        return self.inner.list_evidence()

    def list_techniques(self) -> Sequence[ThreatContextItem]:
        return self.inner.list_techniques()


@dataclass
class ExtraEvidenceFightSource:
    """Delegates to ``inner``, but lists ``extra_evidence`` after its anchors: a snapshot
    adapter handing the catalog anchors no search serves."""

    inner: FightSource
    extra_evidence: tuple[EvidenceAnchor, ...]

    def describe(self) -> FightSnapshotInfo | None:
        return self.inner.describe()

    def search(self, terms: Sequence[str], limit: int) -> ThreatContextOutcome:
        return self.inner.search(terms, limit)

    def list_evidence(self) -> Sequence[EvidenceAnchor]:
        return (*self.inner.list_evidence(), *self.extra_evidence)

    def list_techniques(self) -> Sequence[ThreatContextItem]:
        return self.inner.list_techniques()


@dataclass
class RewordingFightSource:
    """Delegates to ``inner``, but copies each searched item with ``item_changes`` and
    without validation, as a source explaining its matches in its own words would."""

    inner: FightSource
    item_changes: dict[str, Any]

    def describe(self) -> FightSnapshotInfo | None:
        return self.inner.describe()

    def search(self, terms: Sequence[str], limit: int) -> ThreatContextOutcome:
        fight_outcome = self.inner.search(terms, limit)
        reworded_items: list[ThreatContextItem] = []
        for item in fight_outcome.items:
            reworded_items.append(item.model_copy(update=self.item_changes))
        return fight_outcome.model_copy(update={"items": tuple(reworded_items)})

    def list_evidence(self) -> Sequence[EvidenceAnchor]:
        return self.inner.list_evidence()

    def list_techniques(self) -> Sequence[ThreatContextItem]:
        return self.inner.list_techniques()


@dataclass
class FailingFightSource:
    """Describes, lists and is pinned like ``inner``, but every search fails as unavailable:
    a configured snapshot whose backend is down."""

    inner: FightSource
    failure: BackendFailure = BackendFailure.UNREACHABLE

    def describe(self) -> FightSnapshotInfo | None:
        return self.inner.describe()

    def search(self, terms: Sequence[str], limit: int) -> ThreatContextOutcome:
        return ThreatContextOutcome(status=BackendStatus.UNAVAILABLE, failure=self.failure)

    def list_evidence(self) -> Sequence[EvidenceAnchor]:
        return self.inner.list_evidence()

    def list_techniques(self) -> Sequence[ThreatContextItem]:
        return self.inner.list_techniques()


@dataclass
class InMemoryTrustifyPort:
    """An affectedness source that gives ``described_failure`` as the reason affectedness
    is unavailable, answers every check with ``failure``, and records each check it is
    asked with its timeout."""

    failure: AffectednessFailure
    described_failure: AffectednessFailure = AffectednessFailure.SOURCE_UNAVAILABLE
    received_checks: list[tuple[AffectednessRequest, float]] = field(default_factory=list)

    def describe(self) -> AffectednessFailure:
        return self.described_failure

    def check_affectedness(
        self, request: AffectednessRequest, timeout_seconds: float
    ) -> AffectednessFailure:
        self.received_checks.append((request, timeout_seconds))
        return self.failure


@dataclass
class BlockingTrustifyPort:
    """An affectedness source whose every check blocks until ``release`` is set, then times
    out: an adapter that never returns while a test runs."""

    release: threading.Event

    def describe(self) -> AffectednessFailure:
        return AffectednessFailure.SOURCE_UNAVAILABLE

    def check_affectedness(
        self, request: AffectednessRequest, timeout_seconds: float
    ) -> AffectednessFailure:
        self.release.wait()
        return AffectednessFailure.TIMEOUT


@dataclass
class MisansweringTrustifyPort:
    """An affectedness source that gives ``reason`` as why affectedness is unavailable and
    answers every check with ``answer``, whatever each is: an adapter breaking the port's
    promise."""

    answer: object
    reason: object = AffectednessFailure.SOURCE_UNAVAILABLE

    def describe(self) -> AffectednessFailure:
        return cast(AffectednessFailure, self.reason)

    def check_affectedness(
        self, request: AffectednessRequest, timeout_seconds: float
    ) -> AffectednessFailure:
        return cast(AffectednessFailure, self.answer)
