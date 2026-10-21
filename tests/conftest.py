"""Shared fixtures for the v2 test tiers. Imports only the core package."""

import threading
from collections.abc import Iterator

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
