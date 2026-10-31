"""What every deployment in one process serves from, built once and shared read-only
(ADR 0009 §12).

The data plane holds the served dataset and everything built over it: the topic cards,
the search service with its repository and indexes, the one FiGHT source and its pin,
and the evidence catalog served content is re-checked against. None of it holds request
state once built: a search keeps its channel log per call, the indexes and the catalog
are read-only, the domain models are frozen, and the FiGHT source's search only reads its
index. So deployments share it while each keeps its own call runner, budgets, planner and
per-request state, and a replay never counts against an investigation's admission.
"""

from dataclasses import dataclass

from cve_kgrag.application.product_query import ProductQueryService
from cve_kgrag.application.search import SearchService
from cve_kgrag.domain.evidence_catalog import EvidenceCatalog
from cve_kgrag.domain.served_dataset import ServedDataset
from cve_kgrag.domain.threat_context import KnownFightSnapshot
from cve_kgrag.ports.sources import FightSource
from cve_kgrag.topics.registry import TopicRegistry


@dataclass(frozen=True)
class ServingDataPlane:
    """The served dataset, the topic cards, the search service over the dataset's records,
    the FiGHT source with the catalog entry pinned for it (``None`` when it serves no
    pinned snapshot), and the evidence catalog holding the dataset's records and anchors
    and the FiGHT source's techniques and anchors."""

    served_dataset: ServedDataset
    topic_registry: TopicRegistry
    search_service: SearchService
    product_query_service: ProductQueryService
    fight_source: FightSource
    pinned_fight_snapshot: KnownFightSnapshot | None
    evidence_catalog: EvidenceCatalog
