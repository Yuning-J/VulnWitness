"""What an investigation runs against, as the composition root wired it."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from vulnwitness.application.investigation_tools import ToolExecutor
from vulnwitness.application.product_query import ProductQueryService
from vulnwitness.application.search import SearchService
from vulnwitness.application.threaded_call_runner import ThreadedCallRunner
from vulnwitness.application.topic_context import TopicContextService
from vulnwitness.domain.evidence_catalog import EvidenceCatalog
from vulnwitness.domain.investigation import SourceCapability
from vulnwitness.domain.served_dataset import ServedDataset
from vulnwitness.domain.threat_context import KnownFightSnapshot
from vulnwitness.ports.affectedness import TrustifyPort
from vulnwitness.topics.registry import TopicRegistry


@dataclass(frozen=True)
class InvestigationDeployment:
    """A deployment's sources, the catalog and pin its served content is checked against,
    the capabilities it serves, and its call runner and clocks. The investigation service
    runs every request against it, and replay runs a recorded request against it again.

    ``served_dataset`` names the CVE records and evidence the deployment serves, which its
    ``cve_search`` capability version states. ``source_capabilities`` is what the
    composition root found the deployment's sources
    serve: every capability subject but ``model_planner``, which describes the planner of
    the service running against the deployment. ``search_service`` and
    ``topic_context_service`` are the ones the tool executor searches and explores topics
    with, and ``trustify_port`` the port whose reason affectedness is unavailable the
    ``affectedness`` capability states, for callers that use them outside an
    investigation. ``monotonic_clock``
    must be a real monotonic clock in production (``time.monotonic``): the call runner
    waits in real seconds.
    """

    served_dataset: ServedDataset
    topic_registry: TopicRegistry
    tool_executor: ToolExecutor
    search_service: SearchService
    product_query_service: ProductQueryService
    topic_context_service: TopicContextService
    trustify_port: TrustifyPort
    source_capabilities: tuple[SourceCapability, ...]
    pinned_fight_snapshot: KnownFightSnapshot | None
    evidence_catalog: EvidenceCatalog
    call_runner: ThreadedCallRunner
    wall_clock: Callable[[], datetime]
    monotonic_clock: Callable[[], float]
