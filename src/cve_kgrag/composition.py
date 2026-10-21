"""Composition root: wires adapters into application services. Nothing here runs at import."""

import time
from collections.abc import Callable, Iterable
from datetime import UTC, datetime

from cve_kgrag.adapter_discovery import (
    AdapterEntryPoint,
    InstalledPlanner,
    discover_semantic_retriever,
    find_installed_planner,
    list_installed_adapters,
)
from cve_kgrag.adapters.fight.snapshot_catalog import (
    default_fight_snapshot_catalog_file,
    load_fight_snapshot_catalog,
)
from cve_kgrag.adapters.fixture.fight_fixture import default_fight_fixture_dir, load_fight_fixture
from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.adapters.graph.in_memory_graph import InMemoryRelationGraph
from cve_kgrag.adapters.lexical.bm25_index import Bm25LexicalIndex
from cve_kgrag.adapters.memory.in_memory_evidence_catalog import InMemoryEvidenceCatalog
from cve_kgrag.adapters.memory.in_memory_repository import InMemoryKnowledgeRepository
from cve_kgrag.adapters.structured.in_memory_filter import InMemoryStructuredIndex
from cve_kgrag.adapters.topics.yaml_cards import default_topic_dir, load_topic_cards
from cve_kgrag.adapters.trustify.disabled_trustify_adapter import DisabledTrustifyAdapter
from cve_kgrag.application.deadline_checkpoint import ignore_checkpoint
from cve_kgrag.application.investigate import InvestigationService
from cve_kgrag.application.investigation_deployment import InvestigationDeployment
from cve_kgrag.application.investigation_policy import describe_deterministic_planner
from cve_kgrag.application.investigation_tools import ToolExecutor
from cve_kgrag.application.planner_setup import DeterministicPlanning, PlannerSetup
from cve_kgrag.application.search import SearchService
from cve_kgrag.application.threaded_call_runner import ThreadedCallRunner
from cve_kgrag.application.topic_context import TopicContextService
from cve_kgrag.domain.affectedness import AFFECTEDNESS_DETAILS, AffectednessFailure
from cve_kgrag.domain.evidence_catalog import EvidenceCatalog
from cve_kgrag.domain.hashing import canonical_sha256
from cve_kgrag.domain.investigation import (
    FightUnavailableDetail,
    SourceCapability,
    SourceCapabilityState,
    describe_planner_capability,
)
from cve_kgrag.domain.planning import ModelPlannerUnavailableDetail
from cve_kgrag.domain.threat_context import KnownFightSnapshot
from cve_kgrag.domain.topic_context import KnowledgeSource
from cve_kgrag.interfaces.knowledge_toolbox import KnowledgeToolbox
from cve_kgrag.interfaces.knowledge_tools import ToolLimits
from cve_kgrag.ports.affectedness import TrustifyPort
from cve_kgrag.ports.sources import FightSource
from cve_kgrag.settings import ModelPlannerSettings, SemanticSettings
from cve_kgrag.topics.registry import TopicRegistry

# No model planner configured: the deterministic policy plans every round.
DETERMINISTIC_PLANNING = DeterministicPlanning()
MISDESCRIBED_AFFECTEDNESS = (
    "the configured affectedness port does not give an AffectednessFailure as the reason "
    "affectedness is unavailable"
)


def build_search_service(
    bundle: FixtureBundle, semantic_settings: SemanticSettings | None = None
) -> SearchService:
    """The search channels over ``bundle``, with the semantic channel ``semantic_settings``
    enable (none without them)."""
    repository = InMemoryKnowledgeRepository(bundle.records, bundle.evidence)
    return SearchService(
        cve_repository=repository,
        evidence_catalog=InMemoryEvidenceCatalog(bundle.evidence, bundle.records),
        lexical_retriever=Bm25LexicalIndex(repository.list_cves()),
        structured_retriever=InMemoryStructuredIndex(repository.list_cves()),
        graph_retriever=InMemoryRelationGraph(repository.list_cves()),
        semantic_retriever=discover_semantic_retriever(semantic_settings),
    )


def utc_now() -> datetime:
    """The production clock; tests inject a fixed one instead."""
    return datetime.now(UTC)


def build_topic_registry() -> TopicRegistry:
    """The packaged, reviewed-or-pending topic cards."""
    return TopicRegistry(load_topic_cards(default_topic_dir()))


def load_packaged_fight_source(
    clock: Callable[[], datetime],
) -> tuple[FightSource, KnownFightSnapshot | None]:
    """The packaged FiGHT excerpt and its entry in the packaged reviewed catalog."""
    snapshot_catalog = load_fight_snapshot_catalog(default_fight_snapshot_catalog_file())
    packaged_source = load_fight_fixture(default_fight_fixture_dir(), snapshot_catalog, clock)
    return packaged_source, snapshot_catalog.find(packaged_source.describe().snapshot_sha256)


def build_evidence_catalog(bundle: FixtureBundle, fight_source: FightSource) -> EvidenceCatalog:
    """Everything this deployment serves: the bundle's CVE records and evidence, and the
    FiGHT snapshot's techniques and anchors. Final validation re-checks each served
    anchor, record and technique against it."""
    return InMemoryEvidenceCatalog(
        (*bundle.evidence, *fight_source.list_evidence()),
        bundle.records,
        fight_source.list_techniques(),
    )


def build_topic_context_service(
    bundle: FixtureBundle,
    fight_source: FightSource | None = None,
    pinned_fight_snapshot: KnownFightSnapshot | None = None,
    semantic_settings: SemanticSettings | None = None,
) -> TopicContextService:
    """Packaged topic cards over the bundle's CVEs, whose template searches run the
    semantic channel ``semantic_settings`` enable when a request asks for it.

    Without ``fight_source``, FiGHT is the packaged excerpt, pinned to its entry in
    the packaged reviewed catalog. A caller passing its own source also passes the
    catalog entry it pinned for that source (``None`` when it serves no snapshot).
    """
    if fight_source is None:
        fight_source, pinned_fight_snapshot = load_packaged_fight_source(utc_now)
    return TopicContextService(
        topic_registry=build_topic_registry(),
        search_service=build_search_service(bundle, semantic_settings),
        fight_source=fight_source,
        pinned_fight_snapshot=pinned_fight_snapshot,
        evidence_catalog=build_evidence_catalog(bundle, fight_source),
    )


class AffectednessConfigurationError(ValueError):
    """A configured affectedness port gives no ``AffectednessFailure`` as the reason
    affectedness is unavailable; nothing may be served."""


def describe_affectedness(trustify_port: TrustifyPort) -> SourceCapability:
    """The ``affectedness`` capability every set of the deployment reports: unavailable,
    with the server's sentence for the reason the port gives, read from the port once.

    Raises ``AffectednessConfigurationError`` for a port that gives anything but an
    ``AffectednessFailure``, so no service is built to serve it.
    """
    try:
        # The port is an adapter: its declared return type is a promise, checked here.
        failure = AffectednessFailure(trustify_port.describe())
    except ValueError as error:
        raise AffectednessConfigurationError(MISDESCRIBED_AFFECTEDNESS) from error
    return SourceCapability(
        source=KnowledgeSource.AFFECTEDNESS,
        state=SourceCapabilityState.UNAVAILABLE,
        detail=AFFECTEDNESS_DETAILS[failure],
    )


def describe_source_capabilities(
    bundle: FixtureBundle,
    fight_source: FightSource,
    pinned_fight_snapshot: KnownFightSnapshot | None,
    search_service: SearchService,
    affectedness_capability: SourceCapability,
) -> tuple[SourceCapability, ...]:
    """What each source can serve in this deployment, in ``CAPABILITY_SUBJECTS`` order:
    every subject but ``model_planner``, which the service describes from its planner.
    ``affectedness_capability`` is the one ``describe_affectedness`` read from the port.

    The semantic channel's capability is ``describe_semantic_capability``'s, read from
    ``search_service``.
    """
    manifest = bundle.manifest
    manifest_sha256 = canonical_sha256(manifest.model_dump(mode="json"))
    capabilities = [
        SourceCapability(
            source=KnowledgeSource.CVE_SEARCH,
            state=SourceCapabilityState.AVAILABLE,
            version=f"{manifest.fixture_id}@{manifest.version}+sha256:{manifest_sha256}",
        )
    ]
    if fight_source.describe() is not None and pinned_fight_snapshot is not None:
        capabilities.append(
            SourceCapability(
                source=KnowledgeSource.MITRE_FIGHT,
                state=SourceCapabilityState.AVAILABLE,
                version=pinned_fight_snapshot.source_version,
                coverage=pinned_fight_snapshot.coverage,
            )
        )
    else:
        capabilities.append(
            SourceCapability(
                source=KnowledgeSource.MITRE_FIGHT,
                state=SourceCapabilityState.UNAVAILABLE,
                detail=FightUnavailableDetail.NOT_PINNED,
            )
        )
    capabilities.append(affectedness_capability)
    capabilities.append(describe_semantic_capability(search_service))
    return tuple(capabilities)


def describe_semantic_capability(search_service: SearchService) -> SourceCapability:
    """The ``semantic_channel`` capability of ``search_service``: available with a
    retriever, unavailable with the reason an enabled channel cannot search, otherwise not
    configured. Whether one search of an available channel succeeded shows in that
    search's channel outcome."""
    unavailable_detail = search_service.find_semantic_unavailable_detail()
    if unavailable_detail is not None:
        return SourceCapability(
            source="semantic_channel",
            state=SourceCapabilityState.UNAVAILABLE,
            detail=unavailable_detail,
        )
    if search_service.has_semantic_channel():
        return SourceCapability(source="semantic_channel", state=SourceCapabilityState.AVAILABLE)
    return SourceCapability(source="semantic_channel", state=SourceCapabilityState.NOT_CONFIGURED)


def build_investigation_deployment(
    bundle: FixtureBundle,
    *,
    search_service: SearchService | None = None,
    fight_source: FightSource | None = None,
    pinned_fight_snapshot: KnownFightSnapshot | None = None,
    semantic_settings: SemanticSettings | None = None,
    trustify_port: TrustifyPort | None = None,
    wall_clock: Callable[[], datetime] = utc_now,
    monotonic_clock: Callable[[], float] = time.monotonic,
) -> InvestigationDeployment:
    """One search service shared by the topic-context service and the tool executor, and
    one topic-context service, the tool executor's.

    A caller passing ``search_service`` passes one over ``bundle``: the evidence
    catalog every served anchor and record is re-checked against holds ``bundle``'s
    records and evidence. ``semantic_settings`` configures only the search service built
    here; the ``semantic_channel`` capability reports the service actually used.
    Without ``fight_source``, FiGHT is the packaged excerpt and its catalog pin; a
    caller passing its own source also passes the pin it chose (``None`` for none).
    Without ``trustify_port``, affectedness is the disabled adapter's
    (``DisabledTrustifyAdapter``). The port is described once, here
    (``describe_affectedness``); a port that gives no ``AffectednessFailure`` raises
    ``AffectednessConfigurationError``. Each deployment gets its own call runner, which
    bounds every planner and tool call by the time the run has left.
    """
    if search_service is None:
        search_service = build_search_service(bundle, semantic_settings)
    if fight_source is None:
        fight_source, pinned_fight_snapshot = load_packaged_fight_source(wall_clock)
    if trustify_port is None:
        trustify_port = DisabledTrustifyAdapter()
    affectedness_capability = describe_affectedness(trustify_port)
    topic_registry = build_topic_registry()
    evidence_catalog = build_evidence_catalog(bundle, fight_source)
    topic_context_service = TopicContextService(
        topic_registry=topic_registry,
        search_service=search_service,
        fight_source=fight_source,
        pinned_fight_snapshot=pinned_fight_snapshot,
        evidence_catalog=evidence_catalog,
    )
    return InvestigationDeployment(
        topic_registry=topic_registry,
        tool_executor=ToolExecutor(search_service, topic_context_service, topic_registry),
        search_service=search_service,
        topic_context_service=topic_context_service,
        trustify_port=trustify_port,
        source_capabilities=describe_source_capabilities(
            bundle, fight_source, pinned_fight_snapshot, search_service, affectedness_capability
        ),
        pinned_fight_snapshot=pinned_fight_snapshot,
        evidence_catalog=evidence_catalog,
        call_runner=ThreadedCallRunner(),
        wall_clock=wall_clock,
        monotonic_clock=monotonic_clock,
    )


def build_investigation_service(
    bundle: FixtureBundle,
    *,
    search_service: SearchService | None = None,
    fight_source: FightSource | None = None,
    pinned_fight_snapshot: KnownFightSnapshot | None = None,
    semantic_settings: SemanticSettings | None = None,
    planner_setup: PlannerSetup = DETERMINISTIC_PLANNING,
    trustify_port: TrustifyPort | None = None,
    wall_clock: Callable[[], datetime] = utc_now,
    monotonic_clock: Callable[[], float] = time.monotonic,
) -> InvestigationService:
    """The investigation service running ``planner_setup`` over the deployment
    ``build_investigation_deployment`` wires from the same arguments, on its measured clock.

    By default the deterministic policy plans every round; ``discover_planner_setup``
    gives the planner the settings configure, with the identity it builds once from the
    settings and the installed entry point, so a request calls no adapter method outside
    the call runner. A ``trustify_port`` is described once, when the deployment is built.
    """
    deployment = build_investigation_deployment(
        bundle,
        search_service=search_service,
        fight_source=fight_source,
        pinned_fight_snapshot=pinned_fight_snapshot,
        semantic_settings=semantic_settings,
        trustify_port=trustify_port,
        wall_clock=wall_clock,
        monotonic_clock=monotonic_clock,
    )
    return InvestigationService(deployment, planner_setup, ignore_checkpoint)


def list_accepted_planner_capabilities(
    settings: ModelPlannerSettings | None,
    list_adapters: Callable[[], Iterable[AdapterEntryPoint]] = list_installed_adapters,
) -> tuple[SourceCapability, ...]:
    """The ``model_planner`` capabilities a set sealed under ``settings`` can report, read
    from the settings and the installed adapter's metadata, so verifying a set needs
    neither the key nor loading the adapter.

    The MCP tools always plan with the deterministic policy, so ``not_configured`` is
    always accepted. An enabled planner adds each reason it could not plan, and the
    installed adapter's identity (``find_installed_planner``) as available: whether the
    planner could plan is the health of the service that sealed the set, which the set
    records, while its model, adapter and endpoint are configuration.
    """
    deterministic_planner = describe_deterministic_planner()
    accepted_capabilities = [describe_planner_capability(deterministic_planner)]
    if settings is None:
        return tuple(accepted_capabilities)
    installed_planner = find_installed_planner(settings, list_adapters)
    if isinstance(installed_planner, InstalledPlanner):
        accepted_capabilities.append(describe_planner_capability(installed_planner.identity))
    for unavailable_detail in ModelPlannerUnavailableDetail:
        accepted_capabilities.append(
            describe_planner_capability(deterministic_planner, unavailable_detail)
        )
    return tuple(accepted_capabilities)


def build_knowledge_toolbox(
    bundle: FixtureBundle,
    *,
    search_service: SearchService | None = None,
    fight_source: FightSource | None = None,
    pinned_fight_snapshot: KnownFightSnapshot | None = None,
    trustify_port: TrustifyPort | None = None,
    wall_clock: Callable[[], datetime] = utc_now,
    monotonic_clock: Callable[[], float] = time.monotonic,
    tool_clock: Callable[[], float] = time.monotonic,
    limits: ToolLimits | None = None,
) -> KnowledgeToolbox:
    """The knowledge tools over one deployment of ``bundle``
    (``build_investigation_deployment``): its search service, its FiGHT source (the
    packaged excerpt without ``fight_source``), its affectedness port
    (``DisabledTrustifyAdapter`` without ``trustify_port``), no semantic channel (its
    store cannot be opened read-only, and the tools are read-only) and the deterministic
    planner.

    ``wall_clock`` and ``monotonic_clock`` are the deployment's, which every investigation
    runs on; ``tool_clock`` bounds each tool call, so reading it never moves a run's
    deadline arithmetic. Without ``limits`` every call runs under the default
    ``ToolLimits``. A caller passing ``search_service`` passes one over ``bundle``; one
    passing ``fight_source`` also passes the pin it chose for it (``None`` for none).
    """
    deployment = build_investigation_deployment(
        bundle,
        search_service=search_service,
        fight_source=fight_source,
        pinned_fight_snapshot=pinned_fight_snapshot,
        trustify_port=trustify_port,
        wall_clock=wall_clock,
        monotonic_clock=monotonic_clock,
    )
    return KnowledgeToolbox(
        deployment=deployment,
        investigation_service=InvestigationService(
            deployment, DETERMINISTIC_PLANNING, ignore_checkpoint
        ),
        monotonic_clock=tool_clock,
        limits=limits or ToolLimits(),
    )
