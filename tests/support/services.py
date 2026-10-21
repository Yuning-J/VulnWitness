"""Search services over the synthetic fixture with individual channels replaced."""

from typing import Any

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.adapters.graph.in_memory_graph import InMemoryRelationGraph
from cve_kgrag.adapters.lexical.bm25_index import Bm25LexicalIndex
from cve_kgrag.adapters.memory.in_memory_evidence_catalog import InMemoryEvidenceCatalog
from cve_kgrag.adapters.memory.in_memory_repository import InMemoryKnowledgeRepository
from cve_kgrag.adapters.structured.in_memory_filter import InMemoryStructuredIndex
from cve_kgrag.application.search import SearchService


def build_fixture_service(bundle: FixtureBundle, **retrievers: Any) -> SearchService:
    """The composed fixture service, except for the retrievers passed by keyword."""
    repository = InMemoryKnowledgeRepository(bundle.records, bundle.evidence)
    channels: dict[str, Any] = {
        "lexical_retriever": Bm25LexicalIndex(repository.list_cves()),
        "structured_retriever": InMemoryStructuredIndex(repository.list_cves()),
        "graph_retriever": InMemoryRelationGraph(repository.list_cves()),
        "semantic_retriever": None,
    }
    channels.update(retrievers)
    evidence_catalog = InMemoryEvidenceCatalog(bundle.evidence, bundle.records)
    return SearchService(repository, evidence_catalog, **channels)
