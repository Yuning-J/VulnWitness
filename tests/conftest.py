"""Shared fixtures for the v2 test tiers. Imports only the core package."""

import os
import socket
import threading
from collections.abc import Iterator
from functools import partialmethod

import pytest

from cve_kgrag.adapters.fixture.synthetic_fixture import (
    FixtureBundle,
    default_fixture_dir,
    load_fixture_bundle,
)
from cve_kgrag.application.search import SearchService
from cve_kgrag.composition import (
    build_evidence_catalog,
    build_search_service,
    build_topic_registry,
    load_packaged_fight_source,
)
from cve_kgrag.domain.evidence_catalog import EvidenceCatalog
from cve_kgrag.domain.threat_context import KnownFightSnapshot
from cve_kgrag.topics.registry import TopicRegistry
from tests.support.clocks import read_fixed_clock
from tests.support.fake_chat_server import FakeChatServers
from tests.support.network_guard import NetworkGuard, guarded_connect, guarded_connect_ex

LIVE_TESTS_VARIABLE = "CVE_KGRAG_LIVE_TESTS"
NETWORK_GUARD_KEY = pytest.StashKey[NetworkGuard]()
NETWORK_GUARD_PATCH_KEY = pytest.StashKey[pytest.MonkeyPatch]()


@pytest.fixture
def fixture_bundle() -> FixtureBundle:
    return load_fixture_bundle(default_fixture_dir())


@pytest.fixture
def search_service(fixture_bundle: FixtureBundle) -> SearchService:
    return build_search_service(fixture_bundle)


@pytest.fixture
def topic_registry() -> TopicRegistry:
    return build_topic_registry()


@pytest.fixture
def packaged_evidence_catalog(fixture_bundle: FixtureBundle) -> EvidenceCatalog:
    """The default deployment's evidence catalog: the fixture's CVE records and anchors,
    and the packaged FiGHT excerpt's techniques and anchors."""
    fight_source, _ = load_packaged_fight_source(read_fixed_clock)
    return build_evidence_catalog(fixture_bundle, fight_source)


@pytest.fixture
def pinned_fight_snapshot() -> KnownFightSnapshot:
    """The catalog entry the default deployment pins for the packaged FiGHT excerpt."""
    _, pinned_snapshot = load_packaged_fight_source(read_fixed_clock)
    assert pinned_snapshot is not None
    return pinned_snapshot


@pytest.fixture
def blocked_call_release() -> Iterator[threading.Event]:
    """An event a blocking fake waits on; set at teardown, so the abandoned thread ends."""
    release = threading.Event()
    yield release
    release.set()


@pytest.fixture
def fake_chat_servers() -> Iterator[FakeChatServers]:
    """Loopback chat-completions servers, released and stopped at teardown."""
    servers = FakeChatServers()
    yield servers
    servers.stop_all()


def pytest_configure(config: pytest.Config) -> None:
    """Refuses every connect outside loopback from before collection to the end of the run.

    Collection imports the test modules, so the guard is in place before any test code
    runs, at module level included. Only an explicitly enabled live run
    (CVE_KGRAG_LIVE_TESTS=1, see tests/live) goes without it.
    """
    if os.environ.get(LIVE_TESTS_VARIABLE) == "1":
        return
    guard = NetworkGuard(
        loopback_connect=socket.socket.connect, loopback_connect_ex=socket.socket.connect_ex
    )
    patch = pytest.MonkeyPatch()
    patch.setattr(socket.socket, "connect", partialmethod(guarded_connect, guard))
    patch.setattr(socket.socket, "connect_ex", partialmethod(guarded_connect_ex, guard))
    config.stash[NETWORK_GUARD_KEY] = guard
    config.stash[NETWORK_GUARD_PATCH_KEY] = patch


def pytest_unconfigure(config: pytest.Config) -> None:
    patch = config.stash.get(NETWORK_GUARD_PATCH_KEY, None)
    if patch is not None:
        patch.undo()


@pytest.fixture
def network_guard(request: pytest.FixtureRequest) -> NetworkGuard:
    """The run's guard, with the addresses refused during the requesting test only."""
    guard = request.config.stash[NETWORK_GUARD_KEY]
    guard.refused_addresses.clear()
    return guard
