"""Composition root: wires adapters into application services. Nothing here runs at import."""

import time
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from functools import partial
from pathlib import Path

from vulnwitness.adapter_discovery import (
    AdapterEntryPoint,
    InstalledPlanner,
    discover_semantic_retriever,
    find_installed_planner,
    list_installed_adapters,
)
from vulnwitness.adapters.fight.operator_snapshot import (
    load_operator_fight_snapshot,
    read_operator_fight_snapshot,
)
from vulnwitness.adapters.fight.snapshot_catalog import (
    default_fight_snapshot_catalog_file,
    load_fight_snapshot_catalog,
)
from vulnwitness.adapters.fixture.fight_fixture import default_fight_fixture_dir, load_fight_fixture
from vulnwitness.adapters.fixture.synthetic_fixture import (
    FixtureBundle,
    default_fixture_dir,
    load_fixture_bundle,
)
from vulnwitness.adapters.graph.in_memory_graph import InMemoryRelationGraph
from vulnwitness.adapters.lexical.bm25_index import Bm25LexicalIndex
from vulnwitness.adapters.memory.in_memory_evidence_catalog import InMemoryEvidenceCatalog
from vulnwitness.adapters.memory.in_memory_repository import InMemoryKnowledgeRepository
from vulnwitness.adapters.migration.cnvd_snapshot_catalog import (
    default_cnvd_snapshot_catalog_file,
    load_cnvd_snapshot_catalog,
)
from vulnwitness.adapters.mitre.mapping_file import load_weakness_mapping
from vulnwitness.adapters.nvd.normalizer import NvdNormalizer, SourceTerms
from vulnwitness.adapters.provenance.source_registry import (
    default_source_registry_file,
    load_source_registry,
)
from vulnwitness.adapters.store.active_record_writer import OsActiveRecordFiles
from vulnwitness.adapters.store.active_store import (
    ignore_store_name,
    load_active_store,
    read_active_store,
)
from vulnwitness.adapters.store.corpus_store import ignore_model, verify_store_files
from vulnwitness.adapters.store.store_activation import StoreActivation
from vulnwitness.adapters.structured.in_memory_filter import InMemoryStructuredIndex
from vulnwitness.adapters.topics.yaml_cards import default_topic_dir, load_topic_cards
from vulnwitness.adapters.trustify.disabled_trustify_adapter import DisabledTrustifyAdapter
from vulnwitness.application.deadline_checkpoint import ignore_checkpoint
from vulnwitness.application.investigate import InvestigationService
from vulnwitness.application.investigation_deployment import InvestigationDeployment
from vulnwitness.application.investigation_policy import describe_deterministic_planner
from vulnwitness.application.investigation_tools import ToolExecutor
from vulnwitness.application.planner_setup import DeterministicPlanning, PlannerSetup
from vulnwitness.application.product_query import ProductQueryService
from vulnwitness.application.search import SearchService
from vulnwitness.application.serving_data_plane import ServingDataPlane
from vulnwitness.application.threaded_call_runner import ThreadedCallRunner
from vulnwitness.application.topic_context import TopicContextService
from vulnwitness.domain.affectedness import AFFECTEDNESS_DETAILS, AffectednessFailure
from vulnwitness.domain.cnvd_snapshot import CnvdSnapshotCatalog
from vulnwitness.domain.corpus_store_manifest import StoreSource
from vulnwitness.domain.evidence_catalog import EvidenceCatalog
from vulnwitness.domain.hashing import sha256_hex
from vulnwitness.domain.investigation import (
    FightUnavailableDetail,
    SourceCapability,
    SourceCapabilityState,
    describe_planner_capability,
)
from vulnwitness.domain.planning import ModelPlannerUnavailableDetail
from vulnwitness.domain.provenance import SourceRegistry
from vulnwitness.domain.search import SemanticUnavailableDetail
from vulnwitness.domain.served_dataset import ServedDataset, ServedDatasetKind
from vulnwitness.domain.session_record import SessionDatasetIdentity
from vulnwitness.domain.threat_context import KnownFightSnapshot
from vulnwitness.domain.topic_context import KnowledgeSource
from vulnwitness.domain.weakness_mapping import WeaknessMapping
from vulnwitness.evaluation.gold_cases import GoldFileError
from vulnwitness.evaluation.gold_rules import GoldRuleError
from vulnwitness.evaluation.gold_sets import (
    GoldSetCollector,
    format_gold_sets,
    read_technique_subjects,
)
from vulnwitness.evaluation.labelled_cases import GoldFile
from vulnwitness.interfaces.knowledge_toolbox import KnowledgeToolbox
from vulnwitness.interfaces.knowledge_tools import ToolLimits
from vulnwitness.ports.affectedness import TrustifyPort
from vulnwitness.ports.retrieval import SemanticRetriever
from vulnwitness.ports.served_corpus import ServedCorpus
from vulnwitness.ports.sources import FightSource
from vulnwitness.settings import FightSnapshotSettings, ModelPlannerSettings, SemanticSettings
from vulnwitness.topics.registry import TopicRegistry

# No model planner configured: the deterministic policy plans every round.
DETERMINISTIC_PLANNING = DeterministicPlanning()
MISDESCRIBED_AFFECTEDNESS = (
    "the configured affectedness port does not give an AffectednessFailure as the reason "
    "affectedness is unavailable"
)


def load_packaged_fixture() -> FixtureBundle:
    """The packaged synthetic fixture, its checksums verified."""
    return load_fixture_bundle(default_fixture_dir())


def load_served_corpus(
    store_root: Path | None, announce_loading: Callable[[str], None] = ignore_store_name
) -> ServedCorpus:
    """The CVE records and evidence anchors every serving surface serves: the packaged
    fixture when no store root is configured, otherwise the store its ``ACTIVE`` names,
    whose name ``announce_loading`` is told just before it is read
    (``load_active_store``). A configured root that cannot be served raises
    ``StoreUnavailable``; there is no fallback to the fixture (ADR 0009 §9). A process
    builds its services on this one corpus, so no surface serves different records from
    another."""
    if store_root is None:
        return load_packaged_fixture()
    return load_active_store(store_root, announce_loading)


def build_trustify_port() -> TrustifyPort:
    """The affectedness port every surface uses: the disabled adapter, until a verified
    affectedness source exists (ADR 0003)."""
    return DisabledTrustifyAdapter()


def build_store_activation(store_root: Path) -> StoreActivation:
    """The store operations over ``store_root``, on the operating system's files."""
    return StoreActivation(store_root, OsActiveRecordFiles())


def derive_gold_sets(
    gold_file: GoldFile, store_root: Path, fight_snapshot: FightSnapshotSettings
) -> bytes:
    """The sets file of ``gold_file`` (``format_gold_sets``), derived from the store
    ``ACTIVE`` names, read record by record so it is never held in memory, and from the
    operator FiGHT snapshot. Raises ``FightSnapshotUnavailable`` or ``StoreUnavailable``
    for a source that cannot be read, and ``GoldFileError`` when the snapshot or the
    store's corpus is not the one the labels were confirmed against, or a case's sets do
    not support its label."""
    snapshot_catalog = load_fight_snapshot_catalog(default_fight_snapshot_catalog_file())
    snapshot_bytes = read_operator_fight_snapshot(
        fight_snapshot.path, fight_snapshot.sha256, snapshot_catalog
    )
    if sha256_hex(snapshot_bytes) != gold_file.fight_snapshot_sha256:
        raise GoldFileError("the FiGHT snapshot is not the one the gold file was labelled against")
    try:
        techniques = read_technique_subjects(snapshot_bytes)
    except GoldRuleError as error:
        raise GoldFileError(str(error)) from None
    collector = GoldSetCollector(gold_file)
    verified_store = read_active_store(
        store_root,
        partial(verify_store_files, keep_anchor=ignore_model, keep_record=collector.keep_record),
    )
    if verified_store.corpus_content_sha256 != gold_file.corpus_content_sha256:
        raise GoldFileError(
            "the active store's corpus is not the one the gold file was labelled against"
        )
    return format_gold_sets(gold_file, collector.derive(techniques))


def build_search_service(
    served_corpus: ServedCorpus,
    semantic_settings: SemanticSettings | None = None,
    list_adapters: Callable[[], Iterable[AdapterEntryPoint]] = list_installed_adapters,
    weakness_mapping: WeaknessMapping | None = None,
    cnvd_catalog: CnvdSnapshotCatalog | None = None,
) -> SearchService:
    """The search channels over ``served_corpus``, with the semantic channel
    ``semantic_settings`` enable (none without them), found among the adapters
    ``list_adapters`` lists.

    With a corpus store served, a requested semantic channel is unavailable
    (``COLLECTION_NOT_BOUND``) and no adapter is looked up or loaded: no collection
    records the dataset it was built from, and one built from another dataset whose CVE
    IDs overlap the store's would pass every check its hits get (ADR 0009 §14)."""
    if weakness_mapping is None:
        weakness_mapping = load_weakness_mapping()
    repository = InMemoryKnowledgeRepository(served_corpus.records, served_corpus.evidence)
    semantic_retriever: SemanticRetriever | SemanticUnavailableDetail | None = None
    if semantic_settings is not None:
        served_kind = served_corpus.describe_served_dataset().kind
        if served_kind is ServedDatasetKind.CORPUS_STORE:
            semantic_retriever = SemanticUnavailableDetail.COLLECTION_NOT_BOUND
        else:
            semantic_retriever = discover_semantic_retriever(semantic_settings, list_adapters)
    cnvd_language = None
    if cnvd_catalog is None:
        cnvd_catalog = load_cnvd_snapshot_catalog(default_cnvd_snapshot_catalog_file())
    for snapshot in cnvd_catalog.snapshots:
        if snapshot.revision == served_corpus.cnvd_index.imported_revision:
            cnvd_language = snapshot.language
            break
    return SearchService(
        cve_repository=repository,
        evidence_catalog=InMemoryEvidenceCatalog(
            served_corpus.evidence, served_corpus.records, weakness_mapping=weakness_mapping
        ),
        lexical_retriever=Bm25LexicalIndex(repository.list_cves()),
        structured_retriever=InMemoryStructuredIndex(repository.list_cves()),
        graph_retriever=InMemoryRelationGraph(repository.list_cves()),
        semantic_retriever=semantic_retriever,
        weakness_mapping=weakness_mapping,
        cnvd_index=served_corpus.cnvd_index,
        kev_capability=served_corpus.describe_kev(),
        cnvd_language=cnvd_language,
        cnvd_attribution=load_packaged_source_registry().find_source("circl-cnvd").attribution,
    )


def build_product_query_service(served_corpus: ServedCorpus) -> ProductQueryService:
    """The product entry over the same corpus records and evidence every surface serves."""
    return ProductQueryService(
        InMemoryKnowledgeRepository(served_corpus.records, served_corpus.evidence),
        InMemoryEvidenceCatalog(served_corpus.evidence, served_corpus.records),
    )


def utc_now() -> datetime:
    """The production clock; tests inject a fixed one instead."""
    return datetime.now(UTC)


def load_packaged_source_registry() -> SourceRegistry:
    """The packaged source registry (``knowledge/sources.yaml``)."""
    return load_source_registry(default_source_registry_file())


def build_nvd_normalizer(source_registry: SourceRegistry) -> NvdNormalizer:
    """The NVD normalizer citing the NVD and CISA KEV terms ``source_registry`` verifies."""
    return NvdNormalizer(
        SourceTerms(
            nvd=source_registry.require_terms(StoreSource.NVD.value),
            cisa_kev=source_registry.require_terms(StoreSource.CISA_KEV.value),
        )
    )


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


def load_fight_source(
    fight_snapshot: FightSnapshotSettings | None, clock: Callable[[], datetime] = utc_now
) -> tuple[FightSource, KnownFightSnapshot | None]:
    """The FiGHT source the settings configure, and its entry in the packaged reviewed
    catalog: the operator snapshot when a path is set, the packaged excerpt otherwise. A
    configured snapshot that cannot be served raises ``FightSnapshotUnavailable``; there is
    no fallback to the excerpt (ADR 0009 §11)."""
    if fight_snapshot is None:
        return load_packaged_fight_source(clock)
    snapshot_catalog = load_fight_snapshot_catalog(default_fight_snapshot_catalog_file())
    operator_source = load_operator_fight_snapshot(
        fight_snapshot.path, fight_snapshot.sha256, snapshot_catalog, clock
    )
    return operator_source, snapshot_catalog.find(operator_source.describe().snapshot_sha256)


def build_evidence_catalog(
    served_corpus: ServedCorpus,
    fight_source: FightSource,
    weakness_mapping: WeaknessMapping | None = None,
) -> EvidenceCatalog:
    """Everything this deployment serves: the served corpus's CVE records and evidence,
    and the FiGHT snapshot's techniques and anchors. Final validation re-checks each
    served anchor, record and technique against it."""
    if weakness_mapping is None:
        weakness_mapping = load_weakness_mapping()
    return InMemoryEvidenceCatalog(
        (*served_corpus.evidence, *fight_source.list_evidence()),
        served_corpus.records,
        fight_source.list_techniques(),
        weakness_mapping=weakness_mapping,
    )


def build_topic_context_service(
    served_corpus: ServedCorpus,
    fight_source: FightSource | None = None,
    pinned_fight_snapshot: KnownFightSnapshot | None = None,
    semantic_settings: SemanticSettings | None = None,
) -> TopicContextService:
    """Packaged topic cards over the served corpus's CVEs, whose template searches run the
    semantic channel ``semantic_settings`` enable when a request asks for it: the
    topic-context service over a data plane built from these arguments
    (``build_serving_data_plane``), whose rules for ``fight_source`` it follows.
    """
    return assemble_topic_context_service(
        build_serving_data_plane(
            served_corpus,
            fight_source=fight_source,
            pinned_fight_snapshot=pinned_fight_snapshot,
            semantic_settings=semantic_settings,
        )
    )


def assemble_topic_context_service(data_plane: ServingDataPlane) -> TopicContextService:
    """The topic-context service over ``data_plane``'s cards, search service, FiGHT source
    and pin, and evidence catalog."""
    return TopicContextService(
        topic_registry=data_plane.topic_registry,
        search_service=data_plane.search_service,
        fight_source=data_plane.fight_source,
        pinned_fight_snapshot=data_plane.pinned_fight_snapshot,
        evidence_catalog=data_plane.evidence_catalog,
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
    served_dataset: ServedDataset,
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
    capabilities = [
        SourceCapability(
            source=KnowledgeSource.CVE_SEARCH,
            state=SourceCapabilityState.AVAILABLE,
            version=served_dataset.cve_search_version,
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


def build_serving_data_plane(
    served_corpus: ServedCorpus,
    *,
    search_service: SearchService | None = None,
    weakness_mapping: WeaknessMapping | None = None,
    fight_source: FightSource | None = None,
    pinned_fight_snapshot: KnownFightSnapshot | None = None,
    semantic_settings: SemanticSettings | None = None,
    clock: Callable[[], datetime] = utc_now,
) -> ServingDataPlane:
    """The read-only data plane over ``served_corpus`` that every deployment of a process
    shares (ADR 0009 §12): the topic cards, the search service, the FiGHT source and its
    pin, and the evidence catalog, each built once.

    A caller passing ``search_service`` passes one over ``served_corpus``: the evidence
    catalog every served anchor and record is re-checked against holds
    ``served_corpus``'s records and evidence. ``semantic_settings`` configures only the
    search service built here; the ``semantic_channel`` capability reports the service
    actually used. Without ``fight_source``, FiGHT is the packaged excerpt and its catalog
    pin, its anchors stamped by ``clock``; a caller passing its own source also passes the
    pin it chose (``None`` for none).
    """
    if weakness_mapping is None:
        weakness_mapping = load_weakness_mapping()
    if search_service is None:
        search_service = build_search_service(
            served_corpus, semantic_settings, weakness_mapping=weakness_mapping
        )
    if fight_source is None:
        fight_source, pinned_fight_snapshot = load_packaged_fight_source(clock)
    fight_description = fight_source.describe()
    session_dataset = SessionDatasetIdentity(
        **served_corpus.describe_session_corpus().model_dump(),
        fight_snapshot_sha256=(
            fight_description.snapshot_sha256 if fight_description is not None else None
        ),
        mitre_snapshot_sha256=weakness_mapping.describe().snapshot_sha256,
    )
    return ServingDataPlane(
        session_dataset=session_dataset,
        served_dataset=served_corpus.describe_served_dataset(),
        topic_registry=build_topic_registry(),
        search_service=search_service,
        product_query_service=build_product_query_service(served_corpus),
        fight_source=fight_source,
        pinned_fight_snapshot=pinned_fight_snapshot,
        evidence_catalog=build_evidence_catalog(served_corpus, fight_source, weakness_mapping),
    )


def build_investigation_deployment(
    data_plane: ServingDataPlane,
    *,
    trustify_port: TrustifyPort | None = None,
    wall_clock: Callable[[], datetime] = utc_now,
    monotonic_clock: Callable[[], float] = time.monotonic,
    call_runner: ThreadedCallRunner | None = None,
) -> InvestigationDeployment:
    """A deployment over ``data_plane``: one topic-context service over its search
    service and FiGHT source, the tool executor over both, and the deployment's own call
    runner and clocks.

    Without ``trustify_port``, affectedness is the disabled adapter's
    (``DisabledTrustifyAdapter``). The port is described once, here
    (``describe_affectedness``); a port that gives no ``AffectednessFailure`` raises
    ``AffectednessConfigurationError``. Without ``call_runner`` the deployment gets its own
    call runner, which bounds every planner and tool call by the time the run has left; a
    caller passing one shares it, and with it the count of live calls, across deployments.
    """
    if trustify_port is None:
        trustify_port = build_trustify_port()
    if call_runner is None:
        call_runner = ThreadedCallRunner()
    affectedness_capability = describe_affectedness(trustify_port)
    topic_context_service = assemble_topic_context_service(data_plane)
    return InvestigationDeployment(
        served_dataset=data_plane.served_dataset,
        topic_registry=data_plane.topic_registry,
        tool_executor=ToolExecutor(
            data_plane.search_service,
            topic_context_service,
            data_plane.topic_registry,
            data_plane.product_query_service,
            data_plane.evidence_catalog,
        ),
        search_service=data_plane.search_service,
        product_query_service=data_plane.product_query_service,
        topic_context_service=topic_context_service,
        trustify_port=trustify_port,
        source_capabilities=describe_source_capabilities(
            data_plane.served_dataset,
            data_plane.fight_source,
            data_plane.pinned_fight_snapshot,
            data_plane.search_service,
            affectedness_capability,
        ),
        pinned_fight_snapshot=data_plane.pinned_fight_snapshot,
        evidence_catalog=data_plane.evidence_catalog,
        call_runner=call_runner,
        wall_clock=wall_clock,
        monotonic_clock=monotonic_clock,
    )


def build_investigation_service(
    data_plane: ServingDataPlane,
    *,
    planner_setup: PlannerSetup = DETERMINISTIC_PLANNING,
    trustify_port: TrustifyPort | None = None,
    wall_clock: Callable[[], datetime] = utc_now,
    monotonic_clock: Callable[[], float] = time.monotonic,
    call_runner: ThreadedCallRunner | None = None,
) -> InvestigationService:
    """The investigation service running ``planner_setup`` over the deployment
    ``build_investigation_deployment`` wires from the same arguments, on its measured clock.

    By default the deterministic policy plans every round; ``discover_planner_setup``
    gives the planner the settings configure, with the identity it builds once from the
    settings and the installed entry point, so a request calls no adapter method outside
    the call runner. A ``trustify_port`` is described once, when the deployment is built.
    """
    deployment = build_investigation_deployment(
        data_plane,
        trustify_port=trustify_port,
        wall_clock=wall_clock,
        monotonic_clock=monotonic_clock,
        call_runner=call_runner,
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
    data_plane: ServingDataPlane,
    *,
    trustify_port: TrustifyPort | None = None,
    wall_clock: Callable[[], datetime] = utc_now,
    monotonic_clock: Callable[[], float] = time.monotonic,
    tool_clock: Callable[[], float] = time.monotonic,
    limits: ToolLimits | None = None,
) -> KnowledgeToolbox:
    """The knowledge tools over one deployment of ``data_plane``
    (``build_investigation_deployment``): its search service and FiGHT source, its
    affectedness port (``DisabledTrustifyAdapter`` without ``trustify_port``) and the
    deterministic planner. A server passes a data plane built with no semantic channel:
    its Chroma collection cannot be opened read-only, and the tools are read-only.

    ``wall_clock`` and ``monotonic_clock`` are the deployment's, which every investigation
    runs on; ``tool_clock`` bounds each tool call, so reading it never moves a run's
    deadline arithmetic. Without ``limits`` every call runs under the default
    ``ToolLimits``.
    """
    deployment = build_investigation_deployment(
        data_plane,
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
