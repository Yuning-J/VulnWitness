"""The sole dynamic-loading boundary for optional adapters and optional interfaces."""

import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from importlib.metadata import entry_points
from typing import Any, Protocol, cast

from pydantic import SecretStr

from cve_kgrag.adapters.migration.parser_types import MigrationParsers
from cve_kgrag.application.planner_setup import DeterministicPlanning, ModelPlanning, PlannerSetup
from cve_kgrag.domain.evidence_set_verification_report import VerificationReport
from cve_kgrag.domain.planning import (
    ModelPlannerIdentity,
    ModelPlannerUnavailableDetail,
    ModelReply,
    ModelReplyFailureDetail,
    PlannerKind,
    PlanningInput,
)
from cve_kgrag.domain.relevance import RelevanceInput
from cve_kgrag.domain.search import SemanticUnavailableDetail
from cve_kgrag.domain.served_dataset import ServedDatasetKind
from cve_kgrag.domain.taxonomy import BackendStatus
from cve_kgrag.interfaces.knowledge_toolbox import KnowledgeToolbox
from cve_kgrag.ports.planning import ModelPort
from cve_kgrag.ports.retrieval import SemanticRetriever
from cve_kgrag.ports.session_recording import SessionRecording
from cve_kgrag.settings import ModelPlannerSettings, SemanticSettings, fingerprint_endpoint

ADAPTER_ENTRY_POINT_GROUP = "cve_kgrag.adapters"
SEMANTIC_ADAPTER_NAME = "semantic"
MCP_SERVER_ADAPTER_NAME = "mcp_server"
MCP_HTTP_SERVER_ADAPTER_NAME = "mcp_http_server"
MODEL_PLANNER_ADAPTER_NAME = "model_planner"
# The failed reply recorded for an adapter that raised or answered with something other
# than a valid reply; its exception text is never read, since an adapter's error may quote
# its request and so its key.
FAILED_ADAPTER_REPLY = ModelReply(
    status=BackendStatus.ERROR, detail=ModelReplyFailureDetail.ADAPTER_FAILED
)
API_SERVER_ADAPTER_NAME = "api_server"
MIGRATION_PARSERS_ADAPTER_NAME = "migration_parsers"


@dataclass(frozen=True)
class OptionalExtra:
    """An extra an optional interface needs: the top-level modules it installs, and the
    line a user reads when one is missing."""

    modules: frozenset[str]
    missing_detail: str


MCP_EXTRA = OptionalExtra(
    modules=frozenset({"mcp", "anyio", "starlette", "uvicorn"}),
    missing_detail="the 'mcp' extra is not installed: pip install 'cve-kgrag[mcp]'",
)
API_EXTRA = OptionalExtra(
    modules=frozenset({"anyio", "starlette", "uvicorn"}),
    missing_detail="the 'api' extra is not installed: pip install 'cve-kgrag[api]'",
)
MIGRATION_EXTRA = OptionalExtra(
    modules=frozenset({"ijson"}),
    missing_detail="the 'migration' extra is not installed: pip install 'cve-kgrag[migration]'",
)


class AdapterDistribution(Protocol):
    @property
    def version(self) -> str: ...


class AdapterEntryPoint(Protocol):
    """An installed entry point, as ``importlib.metadata`` lists it."""

    @property
    def name(self) -> str: ...

    @property
    def value(self) -> str:
        """The object reference, ``module:attribute``."""
        ...

    @property
    def dist(self) -> AdapterDistribution | None: ...

    def load(self) -> Any: ...


def list_installed_adapters() -> Iterable[AdapterEntryPoint]:
    return entry_points(group=ADAPTER_ENTRY_POINT_GROUP)


def find_single_entry_point(
    adapter_name: str, list_adapters: Callable[[], Iterable[AdapterEntryPoint]]
) -> AdapterEntryPoint | str:
    """The one installed entry point named ``adapter_name``, or why there is not exactly one;
    a registry that cannot be listed is named by its error's type only."""
    named_entry_points: list[AdapterEntryPoint] = []
    try:
        for entry_point in list_adapters():
            if entry_point.name == adapter_name:
                named_entry_points.append(entry_point)
    except Exception as error:  # the installed metadata raises anything
        return f"the adapter registry could not be listed: {type(error).__name__}"
    if not named_entry_points:
        return f"{adapter_name} adapter entry point is not installed"
    if len(named_entry_points) > 1:
        return f"more than one {adapter_name} adapter is installed"
    return named_entry_points[0]


def discover_semantic_retriever(
    settings: SemanticSettings | None,
    list_adapters: Callable[[], Iterable[AdapterEntryPoint]] = list_installed_adapters,
) -> SemanticRetriever | SemanticUnavailableDetail | None:
    """The semantic adapter ``settings`` configure: ``None`` when the channel is not
    enabled; the reason it cannot search when exactly one adapter is not installed, or it
    fails to load or build, logged once by type and never with the adapter's text, which
    may name a local path."""
    if settings is None:
        return None
    logger = logging.getLogger(__name__)
    try:
        semantic_entry_point = find_single_entry_point(SEMANTIC_ADAPTER_NAME, list_adapters)
        if isinstance(semantic_entry_point, str):
            logger.warning("semantic adapter unusable: %s", semantic_entry_point)
            return SemanticUnavailableDetail.ADAPTER_UNUSABLE
        factory = semantic_entry_point.load()
        retriever = factory(
            collection_name=settings.collection_name,
            persist_directory=settings.persist_directory,
            model_name=settings.model_name,
        )
    except KeyboardInterrupt:
        # An interrupt stops the process; it is raised afresh so no adapter text rides on it.
        raise KeyboardInterrupt from None
    except BaseException as error:  # an optional adapter's import or setup raises anything
        logger.warning("semantic adapter raised %s while loading", type(error).__name__)
        return SemanticUnavailableDetail.ADAPTER_UNUSABLE
    return cast(SemanticRetriever, retriever)


class McpServerRunner(Protocol):
    """Loads a toolbox after the MCP handshake and serves until the client disconnects."""

    def __call__(
        self,
        load_toolbox: Callable[[], KnowledgeToolbox],
        *,
        dataset_kind: ServedDatasetKind,
        recorder: SessionRecording | None = None,
    ) -> int: ...


class McpHttpServerRunner(Protocol):
    """Serves a toolbox's tools over MCP Streamable HTTP on ``host`` and ``port``, every
    route but ``/health`` behind ``token``, until the process is interrupted; ``False``
    when it could not start serving, having logged why."""

    def __call__(
        self,
        toolbox: KnowledgeToolbox,
        *,
        host: str,
        port: int,
        token: SecretStr,
        recorder: SessionRecording | None = None,
    ) -> bool: ...


class ApiServerRunner(Protocol):
    """Serves the REST API over a toolbox and an evidence-set check on ``host`` and
    ``port``, every route but ``/health`` behind ``token``, until the process is
    interrupted; ``False`` when it could not start serving, having logged why."""

    def __call__(
        self,
        toolbox: KnowledgeToolbox,
        check_evidence_set: Callable[[bytes], VerificationReport],
        *,
        host: str,
        port: int,
        token: SecretStr,
    ) -> bool: ...


@dataclass(frozen=True)
class InterfaceUnavailable:
    """An optional interface that cannot be used, and why, as one line a user reads and
    without exception text."""

    detail: str


def is_missing_extra(error: Exception, extra: OptionalExtra) -> bool:
    """Whether ``error`` is the import of a top-level module ``extra`` installs.

    Python names the missing top-level module when a dotted import fails for want of its
    package, so a submodule an installed SDK no longer ships (``mcp.server.x``) is not
    mistaken for a missing extra.
    """
    return isinstance(error, ModuleNotFoundError) and error.name in extra.modules


def load_interface(
    adapter_name: str,
    extra: OptionalExtra,
    list_adapters: Callable[[], Iterable[AdapterEntryPoint]],
) -> object | InterfaceUnavailable:
    """The object the one installed ``adapter_name`` entry point names, or why there is
    none: no entry point, more than one, ``extra`` missing, or a load that raised for
    another reason.

    A core install registers the entry point without the extra, so a load that fails on a
    module the extra installs is expected there and logs nothing. Any other failed load,
    such as an SDK release that renamed an import, logs its traceback at warning, because
    there the traceback is the diagnosis.
    """
    runner_entry_point = find_single_entry_point(adapter_name, list_adapters)
    if isinstance(runner_entry_point, str):
        return InterfaceUnavailable(runner_entry_point)
    try:
        runner: object = runner_entry_point.load()
    except Exception as error:  # an optional interface's import raises anything
        if is_missing_extra(error, extra):
            return InterfaceUnavailable(extra.missing_detail)
        logging.getLogger(__name__).warning(
            "%s adapter failed to load", adapter_name, exc_info=True
        )
        return InterfaceUnavailable(
            f"{adapter_name} adapter could not load: {type(error).__name__}"
        )
    return runner


def discover_mcp_server_runner(
    list_adapters: Callable[[], Iterable[AdapterEntryPoint]] = list_installed_adapters,
) -> McpServerRunner | InterfaceUnavailable:
    """The installed stdio MCP server runner, or why there is none (``load_interface``)."""
    runner = load_interface(MCP_SERVER_ADAPTER_NAME, MCP_EXTRA, list_adapters)
    if isinstance(runner, InterfaceUnavailable):
        return runner
    return cast(McpServerRunner, runner)


def discover_mcp_http_server_runner(
    list_adapters: Callable[[], Iterable[AdapterEntryPoint]] = list_installed_adapters,
) -> McpHttpServerRunner | InterfaceUnavailable:
    """The installed MCP Streamable HTTP server runner, or why there is none
    (``load_interface``)."""
    runner = load_interface(MCP_HTTP_SERVER_ADAPTER_NAME, MCP_EXTRA, list_adapters)
    if isinstance(runner, InterfaceUnavailable):
        return runner
    return cast(McpHttpServerRunner, runner)


def discover_api_server_runner(
    list_adapters: Callable[[], Iterable[AdapterEntryPoint]] = list_installed_adapters,
) -> ApiServerRunner | InterfaceUnavailable:
    """The installed REST API server runner, or why there is none (``load_interface``)."""
    runner = load_interface(API_SERVER_ADAPTER_NAME, API_EXTRA, list_adapters)
    if isinstance(runner, InterfaceUnavailable):
        return runner
    return cast(ApiServerRunner, runner)


def discover_migration_parsers(
    list_adapters: Callable[[], Iterable[AdapterEntryPoint]] = list_installed_adapters,
) -> MigrationParsers | InterfaceUnavailable:
    """The parsers the installed ``migration`` extra provides, or why there are none
    (``load_interface``)."""
    build_parsers = load_interface(MIGRATION_PARSERS_ADAPTER_NAME, MIGRATION_EXTRA, list_adapters)
    if isinstance(build_parsers, InterfaceUnavailable):
        return build_parsers
    return cast(Callable[[], MigrationParsers], build_parsers)()


class ModelPortFactory(Protocol):
    """Builds the model planner adapter an enabled planner's settings describe.

    Building it does no network or file I/O. ``propose_plan`` and ``assess_relevance``
    talk to the endpoint within their timeouts. Requests stay under the configured base
    URL: each targets exactly
    ``base_url + "/" + route``, since the settings removed one trailing ``/`` from the
    configured URL and any further trailing ``/`` is part of the path. The adapter follows
    no redirect, ignores proxy settings from the environment, sends ``reasoning_effort``
    only when it is set, and keeps the key a ``SecretStr`` until it builds the request
    header (ADR 0004, ADR 0005).
    """

    def __call__(
        self,
        *,
        base_url: str,
        model_name: str,
        api_key: SecretStr,
        reasoning_effort: str | None,
    ) -> ModelPort: ...


def check_model_reply(model_reply: object) -> ModelReply | None:
    """``model_reply`` validated afresh, or ``None`` when it is not a valid ``ModelReply``.

    An adapter can build a reply without validation (``model_construct``), so its fields
    are read and validated again; they are read as attributes, never serialized, so a
    field of the wrong type is never quoted in a serializer warning. Reading a field can
    run adapter code (a subclass's attribute hook, a field value's ``__hash__`` during
    enum validation), so the caller guards this call.
    """
    if not isinstance(model_reply, ModelReply):
        return None
    try:
        return ModelReply(
            status=model_reply.status, plan_text=model_reply.plan_text, detail=model_reply.detail
        )
    except ValueError:  # pydantic's ValidationError
        return None


class GuardedModelPort:
    """Implements ``ModelPort`` over a discovered adapter: anything its planning or
    assessment call raises or reading its answer raises, and an answer that is not a valid
    ``ModelReply``,
    becomes ``FAILED_ADAPTER_REPLY``, logged without the adapter's text. A valid failed
    reply carries one of the server's sentences, so no exception text and no adapter text,
    which may quote the key, leaves the boundary.

    It catches ``BaseException``: model calls run on a call-runner worker thread,
    where no interrupt signal is delivered, so whatever it raises comes from the adapter.
    """

    def __init__(self, model_port: ModelPort) -> None:
        self._model_port = model_port

    def propose_plan(self, planning_input: PlanningInput, timeout_seconds: float) -> ModelReply:
        logger = logging.getLogger(__name__)
        try:
            # The adapter's declared return type is a promise, checked here.
            model_reply: object = self._model_port.propose_plan(planning_input, timeout_seconds)
            checked_reply = check_model_reply(model_reply)
        except BaseException as error:  # an optional adapter's code raises anything
            logger.warning("model planner adapter raised %s", type(error).__name__)
            return FAILED_ADAPTER_REPLY
        if checked_reply is None:
            logger.warning("model planner adapter answered something other than a valid reply")
            return FAILED_ADAPTER_REPLY
        return checked_reply

    def assess_relevance(
        self, assessment_input: RelevanceInput, timeout_seconds: float
    ) -> ModelReply:
        try:
            model_reply: object = self._model_port.assess_relevance(
                assessment_input, timeout_seconds
            )
            checked_reply = check_model_reply(model_reply)
        except BaseException as error:
            logging.getLogger(__name__).warning(
                "model assessor adapter raised %s", type(error).__name__
            )
            return FAILED_ADAPTER_REPLY
        if checked_reply is None:
            logging.getLogger(__name__).warning("model assessor adapter gave no valid reply")
            return FAILED_ADAPTER_REPLY
        return checked_reply


@dataclass(frozen=True)
class InstalledPlanner:
    """The one installed ``model_planner`` entry point, and the identity of the planner it
    serves under the settings."""

    entry_point: AdapterEntryPoint
    identity: ModelPlannerIdentity


def describe_installed_planner(
    settings: ModelPlannerSettings, entry_point: AdapterEntryPoint
) -> ModelPlannerIdentity | str:
    """The identity of the planner ``entry_point`` serves under ``settings``, read from the
    settings and the entry point's metadata without loading it; or why there is none.
    Raises ``ValueError`` for an object reference or version the identity cannot hold."""
    distribution = entry_point.dist
    if distribution is None:
        return "model planner adapter entry point belongs to no installed distribution"
    return ModelPlannerIdentity(
        kind=PlannerKind.MODEL,
        model_name=settings.model_name,
        adapter=entry_point.value,
        adapter_version=distribution.version,
        endpoint_sha256=fingerprint_endpoint(settings.base_url),
        reasoning_effort=settings.reasoning_effort,
    )


def find_installed_planner(
    settings: ModelPlannerSettings, list_adapters: Callable[[], Iterable[AdapterEntryPoint]]
) -> InstalledPlanner | str:
    """The installed adapter and its identity, or why it is unusable, as a line that quotes
    no adapter text. Listing, reading and describing the entry point run in one guard."""
    try:
        planner_entry_point = find_single_entry_point(MODEL_PLANNER_ADAPTER_NAME, list_adapters)
        if isinstance(planner_entry_point, str):
            return planner_entry_point
        identity = describe_installed_planner(settings, planner_entry_point)
    except KeyboardInterrupt:
        # An interrupt stops the process; it is raised afresh so no adapter text rides on it.
        raise KeyboardInterrupt from None
    except BaseException as error:  # the registry or the entry point raises anything
        return f"model planner adapter entry point raised {type(error).__name__}"
    if isinstance(identity, str):
        return identity
    return InstalledPlanner(planner_entry_point, identity)


def build_model_planning(
    settings: ModelPlannerSettings,
    api_key: SecretStr,
    list_adapters: Callable[[], Iterable[AdapterEntryPoint]],
) -> ModelPlanning | str:
    """The installed adapter, built from ``settings``, with the identity the server built
    for it; or why it is unusable, as a line that quotes no adapter text."""
    installed_planner = find_installed_planner(settings, list_adapters)
    if isinstance(installed_planner, str):
        return installed_planner
    try:
        factory: ModelPortFactory = installed_planner.entry_point.load()
        model_port = factory(
            base_url=settings.base_url,
            model_name=settings.model_name,
            api_key=api_key,
            reasoning_effort=settings.reasoning_effort,
        )
    except KeyboardInterrupt:
        # An interrupt stops the process; it is raised afresh so no adapter text rides on it.
        raise KeyboardInterrupt from None
    except BaseException as error:  # an optional adapter's import or setup raises anything
        return f"model planner adapter raised {type(error).__name__} while loading"
    return ModelPlanning(installed_planner.identity, GuardedModelPort(model_port))


def discover_planner_setup(
    settings: ModelPlannerSettings | None,
    list_adapters: Callable[[], Iterable[AdapterEntryPoint]] = list_installed_adapters,
) -> PlannerSetup:
    """The planner ``settings`` configure: the deterministic policy when none is enabled;
    the installed model planner adapter; or the deterministic policy with the reason the
    enabled planner cannot plan, logged once by reason and never by adapter text.

    An adapter is usable only if exactly one is installed, it belongs to a distribution,
    and it loads and builds. The server builds its identity (``describe_installed_planner``)
    and guards its ``propose_plan`` (``GuardedModelPort``).
    """
    if settings is None:
        return DeterministicPlanning()
    logger = logging.getLogger(__name__)
    if settings.api_key is None:
        logger.warning("model planner unavailable: no API key is configured")
        return DeterministicPlanning(ModelPlannerUnavailableDetail.MISSING_API_KEY)
    model_planning = build_model_planning(settings, settings.api_key, list_adapters)
    if isinstance(model_planning, str):
        logger.warning("model planner unavailable: %s", model_planning)
        return DeterministicPlanning(ModelPlannerUnavailableDetail.ADAPTER_UNUSABLE)
    return model_planning
