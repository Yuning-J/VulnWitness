"""Optional adapters and interfaces load at the one sanctioned entry-point boundary."""

import logging
from collections.abc import Callable, Set
from dataclasses import dataclass, field
from functools import partial
from typing import Any

import pytest
from pydantic import SecretStr

from cve_kgrag.adapter_discovery import (
    MCP_EXTRA_MISSING_DETAIL,
    GuardedModelPort,
    InterfaceUnavailable,
    discover_mcp_http_server_runner,
    discover_mcp_server_runner,
    discover_planner_setup,
    discover_semantic_retriever,
)
from cve_kgrag.application.planner_setup import DeterministicPlanning, ModelPlanning
from cve_kgrag.domain.planning import (
    ModelPlannerIdentity,
    ModelPlannerUnavailableDetail,
    PlannerKind,
    format_planner_version,
)
from cve_kgrag.domain.search import RetrievalOutcome, SemanticUnavailableDetail
from cve_kgrag.domain.taxonomy import BackendStatus
from cve_kgrag.settings import ModelPlannerSettings, SemanticSettings, fingerprint_endpoint
from tests.support.entry_points import (
    FailingRegistry,
    FakeAdapterRegistry,
    FakeDistribution,
    FakeEntryPoint,
)
from tests.support.planners import AdapterAbort, ScriptedModelPort, reconfigure_planner

ENABLED = SemanticSettings(persist_directory="/srv/vectors")
# A local path an adapter's error may quote; no log line may carry it.
LOCAL_PATH = "/opt/private/site-packages/planner"
# The planner tests' key: any text that appears in a log, a reply or an error leaked it.
PLANNER_KEY = "sk-test-planner-key-0123456789"
REGISTRY_FAILURE = f"cannot read {LOCAL_PATH}/entry_points.txt ({PLANNER_KEY})"


class StubSemanticRetriever:
    def search(
        self, query_text: str, limit: int, allowed_cve_ids: Set[str] | None
    ) -> RetrievalOutcome:
        return RetrievalOutcome(status=BackendStatus.OK)


def build_stub_semantic_retriever(**settings: str) -> StubSemanticRetriever:
    return StubSemanticRetriever()


def load_stub_factory() -> object:
    return build_stub_semantic_retriever


def load_with_missing_dependency() -> object:
    raise ModuleNotFoundError(f"No module named 'chromadb' (searched {LOCAL_PATH})")


def record_settings(received_settings: list[dict[str, str]], **settings: str) -> object:
    received_settings.append(settings)
    return StubSemanticRetriever()


def raise_with_a_local_path(**settings: str) -> object:
    raise ValueError(f"Collection cve_documents does not exist in {LOCAL_PATH}")


def load_a_factory_that_raises() -> object:
    return raise_with_a_local_path


def load_with_a_base_exception() -> object:
    raise AdapterAbort(f"interrupted while reading {LOCAL_PATH}")


def serve_nothing(toolbox: object) -> None:
    """A stand-in MCP server runner."""


def load_stub_runner() -> object:
    return serve_nothing


def load_without_the_mcp_sdk() -> object:
    raise ModuleNotFoundError("No module named 'mcp' (searched /opt/site-packages)", name="mcp")


def load_with_a_renamed_sdk_import() -> object:
    raise ImportError("cannot import name 'ServerRequestContext' from 'mcp.server'")


def load_with_a_removed_sdk_submodule() -> object:
    raise ModuleNotFoundError("No module named 'mcp.server.renamed'", name="mcp.server.renamed")


def test_disabled_semantic_channel_does_not_inspect_entry_points() -> None:
    registry = FakeAdapterRegistry([FakeEntryPoint("semantic", load_stub_factory)])

    retriever = discover_semantic_retriever(None, registry.list_adapters)

    assert retriever is None
    assert registry.is_listed is False


def test_installed_semantic_adapter_is_built_from_its_entry_point_and_the_settings() -> None:
    received_settings: list[dict[str, str]] = []
    registry = FakeAdapterRegistry(
        [
            FakeEntryPoint("other"),
            FakeEntryPoint(
                "semantic", partial(return_value, partial(record_settings, received_settings))
            ),
        ]
    )

    retriever = discover_semantic_retriever(ENABLED, registry.list_adapters)

    assert isinstance(retriever, StubSemanticRetriever)
    assert received_settings == [
        {
            "collection_name": "cve_documents",
            "persist_directory": "/srv/vectors",
            "model_name": "sentence-transformers/all-MiniLM-L6-v2",
        }
    ]


@pytest.mark.parametrize(
    "registry",
    [
        FakeAdapterRegistry([FakeEntryPoint("other")]),
        FakeAdapterRegistry(
            [FakeEntryPoint("semantic", load_stub_factory), FakeEntryPoint("semantic")]
        ),
        FakeAdapterRegistry([FakeEntryPoint("semantic", load_with_missing_dependency)]),
        FakeAdapterRegistry([FakeEntryPoint("semantic", load_a_factory_that_raises)]),
        FakeAdapterRegistry([FakeEntryPoint("semantic", load_with_a_base_exception)]),
        FailingRegistry(REGISTRY_FAILURE),
    ],
    ids=[
        "not_installed",
        "installed_twice",
        "optional_dependency_missing",
        "factory_raises",
        "load_raises_a_base_exception",
        "registry_raises",
    ],
)
def test_unusable_semantic_adapter_is_unavailable_and_logs_no_adapter_text(
    caplog: pytest.LogCaptureFixture, registry: FakeAdapterRegistry | FailingRegistry
) -> None:
    with caplog.at_level(logging.DEBUG, logger="cve_kgrag.adapter_discovery"):
        retriever = discover_semantic_retriever(ENABLED, registry.list_adapters)

    logged_text = describe_logged_lines(caplog)
    assert retriever is SemanticUnavailableDetail.ADAPTER_UNUSABLE
    assert len(caplog.records) == 1
    assert caplog.records[0].exc_info is None
    assert LOCAL_PATH not in logged_text


def test_installed_mcp_server_runner_is_loaded_from_its_entry_point() -> None:
    registry = FakeAdapterRegistry(
        [FakeEntryPoint("semantic"), FakeEntryPoint("mcp_server", load_stub_runner)]
    )

    runner = discover_mcp_server_runner(registry.list_adapters)

    assert runner is serve_nothing


def test_missing_mcp_server_entry_point_returns_interface_unavailable() -> None:
    registry = FakeAdapterRegistry([FakeEntryPoint("semantic")])

    runner = discover_mcp_server_runner(registry.list_adapters)

    assert runner == InterfaceUnavailable("mcp_server adapter entry point is not installed")


def test_duplicate_mcp_server_entry_points_return_interface_unavailable() -> None:
    registry = FakeAdapterRegistry(
        [
            FakeEntryPoint("mcp_server", load_stub_runner),
            FakeEntryPoint("mcp_server", load_stub_runner),
        ]
    )

    runner = discover_mcp_server_runner(registry.list_adapters)

    assert runner == InterfaceUnavailable("more than one mcp_server adapter is installed")


def test_mcp_server_load_without_the_sdk_reports_the_missing_extra_and_logs_nothing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    registry = FakeAdapterRegistry([FakeEntryPoint("mcp_server", load_without_the_mcp_sdk)])

    with caplog.at_level(logging.DEBUG, logger="cve_kgrag.adapter_discovery"):
        runner = discover_mcp_server_runner(registry.list_adapters)

    assert runner == InterfaceUnavailable(MCP_EXTRA_MISSING_DETAIL)
    assert caplog.records == []


def test_installed_mcp_http_server_runner_is_loaded_from_its_own_entry_point() -> None:
    registry = FakeAdapterRegistry(
        [FakeEntryPoint("mcp_server"), FakeEntryPoint("mcp_http_server", load_stub_runner)]
    )

    runner = discover_mcp_http_server_runner(registry.list_adapters)

    assert runner is serve_nothing


@pytest.mark.parametrize("missing_module", ["mcp", "anyio", "starlette", "uvicorn"], ids=str)
def test_mcp_http_server_load_without_a_module_of_the_extra_reports_the_missing_extra(
    caplog: pytest.LogCaptureFixture, missing_module: str
) -> None:
    registry = FakeAdapterRegistry(
        [FakeEntryPoint("mcp_http_server", ImportFailure(missing_module).load)]
    )

    with caplog.at_level(logging.DEBUG, logger="cve_kgrag.adapter_discovery"):
        runner = discover_mcp_http_server_runner(registry.list_adapters)

    assert runner == InterfaceUnavailable(MCP_EXTRA_MISSING_DETAIL)
    assert caplog.records == []


class ImportFailure:
    """A load failing on the import of ``module_name``, as a core install's does."""

    def __init__(self, module_name: str) -> None:
        self._module_name = module_name

    def load(self) -> object:
        raise ModuleNotFoundError(f"No module named '{self._module_name}'", name=self._module_name)


@pytest.mark.parametrize(
    ("load_runner", "expected_detail"),
    [
        (load_with_a_renamed_sdk_import, "mcp_server adapter could not load: ImportError"),
        (
            load_with_a_removed_sdk_submodule,
            "mcp_server adapter could not load: ModuleNotFoundError",
        ),
    ],
    ids=["renamed_import", "removed_submodule"],
)
def test_mcp_server_load_failing_with_the_sdk_installed_logs_the_traceback(
    caplog: pytest.LogCaptureFixture,
    load_runner: Callable[[], object],
    expected_detail: str,
) -> None:
    """The detail names the exception type only; the traceback goes to the log."""
    registry = FakeAdapterRegistry([FakeEntryPoint("mcp_server", load_runner)])

    with caplog.at_level(logging.WARNING, logger="cve_kgrag.adapter_discovery"):
        runner = discover_mcp_server_runner(registry.list_adapters)

    logged_warnings: list[tuple[int, str, bool]] = []
    for log_record in caplog.records:
        logged_warnings.append(
            (log_record.levelno, log_record.getMessage(), log_record.exc_info is not None)
        )
    assert runner == InterfaceUnavailable(expected_detail)
    assert logged_warnings == [(logging.WARNING, "mcp_server adapter failed to load", True)]


PLANNER_SETTINGS = ModelPlannerSettings(
    base_url="https://planner.invalid/v1",
    model_name="example-chat",
    api_key=SecretStr(PLANNER_KEY),
)
PLANNER_ADAPTER = "example_planner.adapter:build_model_port"


@dataclass
class PlannerFactory:
    """A model planner adapter factory: records what it was built from and builds
    ``model_port``, or raises ``error`` instead."""

    model_port: object = field(default_factory=lambda: ScriptedModelPort([]))
    error: BaseException | None = None
    received_settings: list[dict[str, object]] = field(default_factory=list)

    def __call__(
        self,
        *,
        base_url: str,
        model_name: str,
        api_key: SecretStr,
        reasoning_effort: str | None,
    ) -> object:
        self.received_settings.append(
            {
                "base_url": base_url,
                "model_name": model_name,
                "api_key": api_key,
                "reasoning_effort": reasoning_effort,
            }
        )
        if self.error is not None:
            raise self.error
        return self.model_port


def return_value(value: object) -> object:
    return value


def raise_on_load() -> object:
    raise ImportError(f"cannot import planner client from {LOCAL_PATH} with {PLANNER_KEY}")


def build_planner_entry_point(factory: PlannerFactory, **entry_point_fields: Any) -> FakeEntryPoint:
    return FakeEntryPoint(
        "model_planner",
        partial(return_value, factory),
        **{"value": PLANNER_ADAPTER, **entry_point_fields},
    )


def build_planner_registry(*planner_entry_points: FakeEntryPoint) -> FakeAdapterRegistry:
    return FakeAdapterRegistry([FakeEntryPoint("semantic"), *planner_entry_points])


def describe_logged_lines(caplog: pytest.LogCaptureFixture) -> str:
    """Every log record as a handler would print it, traceback included."""
    formatter = logging.Formatter("%(levelname)s %(message)s")
    logged_lines: list[str] = []
    for log_record in caplog.records:
        logged_lines.append(formatter.format(log_record))
    return "\n".join(logged_lines)


def test_disabled_planner_plans_deterministically_without_inspecting_entry_points() -> None:
    registry = build_planner_registry(build_planner_entry_point(PlannerFactory()))

    planner_setup = discover_planner_setup(None, registry.list_adapters)

    assert planner_setup == DeterministicPlanning()
    assert registry.is_listed is False


def test_enabled_planner_without_a_key_is_unavailable_without_inspecting_entry_points() -> None:
    registry = build_planner_registry(build_planner_entry_point(PlannerFactory()))
    settings = PLANNER_SETTINGS.model_copy(update={"api_key": None})

    planner_setup = discover_planner_setup(settings, registry.list_adapters)

    assert planner_setup == DeterministicPlanning(ModelPlannerUnavailableDetail.MISSING_API_KEY)
    assert registry.is_listed is False


def test_installed_planner_is_built_from_the_settings_with_a_server_built_identity() -> None:
    factory = PlannerFactory()
    registry = build_planner_registry(
        build_planner_entry_point(factory, dist=FakeDistribution("2.4.1"))
    )

    planner_setup = discover_planner_setup(PLANNER_SETTINGS, registry.list_adapters)

    assert isinstance(planner_setup, ModelPlanning)
    assert planner_setup.identity == ModelPlannerIdentity(
        kind=PlannerKind.MODEL,
        model_name="example-chat",
        adapter=PLANNER_ADAPTER,
        adapter_version="2.4.1",
        endpoint_sha256=fingerprint_endpoint("https://planner.invalid/v1"),
        reasoning_effort=None,
    )
    assert isinstance(planner_setup.model_port, GuardedModelPort)
    assert factory.received_settings == [
        {
            "base_url": PLANNER_SETTINGS.base_url,
            "model_name": PLANNER_SETTINGS.model_name,
            "api_key": PLANNER_SETTINGS.api_key,
            "reasoning_effort": None,
        }
    ]


@pytest.mark.parametrize(
    "changed_setting",
    [
        {"base_url": "https://other-planner.invalid/v1"},
        {"model_name": "other-chat"},
        {"reasoning_effort": "none"},
    ],
    ids=["another_endpoint", "another_model", "another_reasoning_effort"],
)
def test_planner_identity_and_capability_change_with_the_endpoint_model_or_effort(
    changed_setting: dict[str, str],
) -> None:
    registry = build_planner_registry(build_planner_entry_point(PlannerFactory()))
    other_settings = reconfigure_planner(PLANNER_SETTINGS, **changed_setting)

    planner_setup = discover_planner_setup(PLANNER_SETTINGS, registry.list_adapters)
    other_setup = discover_planner_setup(other_settings, registry.list_adapters)

    assert isinstance(planner_setup, ModelPlanning)
    assert isinstance(other_setup, ModelPlanning)
    assert planner_setup.identity != other_setup.identity
    assert format_planner_version(planner_setup.identity) != format_planner_version(
        other_setup.identity
    )


def test_planner_identity_changes_with_the_adapter_or_its_version() -> None:
    adapters = [
        build_planner_entry_point(PlannerFactory()),
        build_planner_entry_point(PlannerFactory(), value="other_planner.adapter:build"),
        build_planner_entry_point(PlannerFactory(), dist=FakeDistribution("9.9.9")),
    ]
    identities: list[ModelPlannerIdentity] = []

    for planner_entry_point in adapters:
        planner_setup = discover_planner_setup(
            PLANNER_SETTINGS, build_planner_registry(planner_entry_point).list_adapters
        )
        assert isinstance(planner_setup, ModelPlanning)
        identities.append(planner_setup.identity)

    assert len(set(identities)) == 3


@pytest.mark.parametrize(
    "registry",
    [
        FakeAdapterRegistry([FakeEntryPoint("semantic")]),
        build_planner_registry(
            build_planner_entry_point(PlannerFactory()),
            build_planner_entry_point(PlannerFactory()),
        ),
        FailingRegistry(REGISTRY_FAILURE),
        build_planner_registry(build_planner_entry_point(PlannerFactory(), dist=None)),
        build_planner_registry(
            build_planner_entry_point(PlannerFactory(), value=f"{LOCAL_PATH} {PLANNER_KEY}")
        ),
        FakeAdapterRegistry(
            [FakeEntryPoint("model_planner", raise_on_load, value=PLANNER_ADAPTER)]
        ),
        build_planner_registry(
            build_planner_entry_point(PlannerFactory(error=ValueError(f"bad key {PLANNER_KEY}")))
        ),
        build_planner_registry(
            build_planner_entry_point(PlannerFactory(error=AdapterAbort(f"bad key {PLANNER_KEY}")))
        ),
    ],
    ids=[
        "not_installed",
        "installed_twice",
        "registry_raises",
        "no_distribution",
        "reference_not_an_object_reference",
        "load_raises",
        "factory_raises",
        "factory_raises_a_base_exception",
    ],
)
def test_unusable_planner_adapter_is_unavailable_and_logs_no_adapter_text(
    caplog: pytest.LogCaptureFixture, registry: FakeAdapterRegistry | FailingRegistry
) -> None:
    with caplog.at_level(logging.DEBUG, logger="cve_kgrag.adapter_discovery"):
        planner_setup = discover_planner_setup(PLANNER_SETTINGS, registry.list_adapters)

    logged_text = describe_logged_lines(caplog)
    assert planner_setup == DeterministicPlanning(ModelPlannerUnavailableDetail.ADAPTER_UNUSABLE)
    assert len(caplog.records) == 1
    assert caplog.records[0].exc_info is None
    assert PLANNER_KEY not in logged_text
    assert LOCAL_PATH not in logged_text


def test_mcp_runner_discovery_over_a_failing_registry_names_only_the_error_type() -> None:
    runner = discover_mcp_server_runner(FailingRegistry(REGISTRY_FAILURE).list_adapters)

    assert runner == InterfaceUnavailable("the adapter registry could not be listed: OSError")


def interrupt_while_loading() -> object:
    raise KeyboardInterrupt(f"interrupted while reading {LOCAL_PATH}")


def test_interrupt_while_loading_the_semantic_adapter_stops_the_process_without_its_text(
    caplog: pytest.LogCaptureFixture,
) -> None:
    registry = FakeAdapterRegistry([FakeEntryPoint("semantic", interrupt_while_loading)])

    with caplog.at_level(logging.DEBUG), pytest.raises(KeyboardInterrupt) as raised:
        discover_semantic_retriever(ENABLED, registry.list_adapters)

    assert raised.value.args == ()
    assert raised.value.__suppress_context__ is True
    assert caplog.records == []
