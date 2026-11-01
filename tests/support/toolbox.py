"""Knowledge toolboxes over the synthetic fixture, wired like production with a fixed wall
clock, one genuine request per tool, and narrowing helpers for what a tool call returns."""

import threading
import time
from collections.abc import Callable
from typing import Any

from tests.support.affectedness import build_affectedness_request
from tests.support.clocks import ONE_SECOND_RUN_REAL_SECONDS, SteppingClock, read_fixed_clock
from tests.support.corpus_stores import COMPATIBILITY_STORE
from tests.support.services import build_fixture_service
from vulnwitness.adapters.fixture.synthetic_fixture import FixtureBundle
from vulnwitness.adapters.store.corpus_store import load_corpus_store
from vulnwitness.application.threaded_call_runner import CALL_THREAD_NAME
from vulnwitness.composition import (
    build_knowledge_toolbox,
    build_serving_data_plane,
    load_packaged_fight_source,
)
from vulnwitness.domain.affectedness import AffectednessDetail
from vulnwitness.domain.tool_contracts import ToolFailure
from vulnwitness.interfaces.knowledge_toolbox import KnowledgeToolbox
from vulnwitness.interfaces.knowledge_tools import KnowledgeToolName, ToolAnswer, ToolLimits
from vulnwitness.ports.affectedness import TrustifyPort
from vulnwitness.ports.sources import FightSource

# Well formed, but no anchor of the fixture or the FiGHT excerpt has it.
UNKNOWN_EVIDENCE_ID = "ev:" + "0" * 24
FIXTURE_EVIDENCE_ID = "ev:d8097ae9c31b754d26a1ef92"
# Exception text a failing service raises, which no tool answer may carry.
SECRET_ERROR_TEXT = "secret /etc/passwd"
# The affectedness capability the shipped disabled adapter describes, as a tool serves it.
BLOCKED_AFFECTEDNESS_CAPABILITY: dict[str, Any] = {
    "source": "affectedness",
    "state": "unavailable",
    "version": None,
    "coverage": None,
    "detail": AffectednessDetail.BLOCKED_UNVERIFIED.value,
}
# A package URL a fixture record names: a purls filter the fixture executes.
FIXTURE_PURL = "pkg:generic/fictional5g/f5gc"
# One genuine request per tool.
TOOL_ARGUMENTS: dict[KnowledgeToolName, dict[str, Any]] = {
    KnowledgeToolName.GET_KNOWLEDGE_CAPABILITIES: {},
    KnowledgeToolName.RESOLVE_TELECOM_CONCEPT: {"query": "5G-AKA"},
    KnowledgeToolName.LOOKUP_CVE: {"cve_id": "CVE-9999-0003"},
    KnowledgeToolName.SEARCH_VULNERABILITIES: {"query": "ausf crash", "limit": 5},
    KnowledgeToolName.QUERY_PRODUCT_VULNERABILITIES: {"vendor": "democorp", "version": "2.0"},
    KnowledgeToolName.SEARCH_FIGHT: {"query": "5gaka", "limit": 3},
    KnowledgeToolName.CHECK_AFFECTEDNESS: build_affectedness_request().model_dump(mode="json"),
    KnowledgeToolName.GET_EVIDENCE: {"evidence_id": FIXTURE_EVIDENCE_ID},
    KnowledgeToolName.INVESTIGATE_TELECOM_TOPIC: {"query": "5gaka", "scope": "mixed"},
}


def build_test_toolbox(
    bundle: FixtureBundle,
    *,
    fight_source: FightSource | None = None,
    trustify_port: TrustifyPort | None = None,
    tool_clock: Callable[[], float] = time.monotonic,
    monotonic_clock: Callable[[], float] | None = None,
    limits: ToolLimits | None = None,
    **retrievers: Any,
) -> KnowledgeToolbox:
    """The production toolbox over ``bundle``, with the retrievers passed by keyword
    replaced. FiGHT is ``fight_source`` pinned to the packaged excerpt's catalog entry,
    or the packaged excerpt itself. Investigations run on the fixed wall clock and
    ``monotonic_clock``; without it time never advances, so no run reaches its deadline
    and equal requests seal equal sets. Each tool call is bounded on ``tool_clock``."""
    packaged_fight_source, pinned_fight_snapshot = load_packaged_fight_source(read_fixed_clock)
    return build_knowledge_toolbox(
        build_serving_data_plane(
            bundle,
            search_service=build_fixture_service(bundle, **retrievers),
            fight_source=fight_source or packaged_fight_source,
            pinned_fight_snapshot=pinned_fight_snapshot,
        ),
        trustify_port=trustify_port,
        wall_clock=read_fixed_clock,
        monotonic_clock=monotonic_clock or SteppingClock().read,
        tool_clock=tool_clock,
        limits=limits,
    )


def build_compatibility_store_toolbox() -> KnowledgeToolbox:
    """The production toolbox over the format-1 compatibility store, whose records, like an
    NVD import's, name no package URL, so a purls filter cannot be executed on it."""
    return build_knowledge_toolbox(
        build_serving_data_plane(load_corpus_store(COMPATIBILITY_STORE)),
        wall_clock=read_fixed_clock,
        monotonic_clock=SteppingClock().read,
    )


def list_affectedness_capabilities(capabilities: dict[str, Any]) -> list[dict[str, Any]]:
    """The ``affectedness`` entries of a ``get_knowledge_capabilities`` answer."""
    affectedness_capabilities: list[dict[str, Any]] = []
    for capability in capabilities["source_capabilities"]:
        if capability["source"] == "affectedness":
            affectedness_capabilities.append(capability)
    return affectedness_capabilities


def join_abandoned_calls() -> None:
    """Wait until every call thread has finished: run after releasing the blocking fakes,
    so the calls a test abandoned no longer count as live."""
    for thread in threading.enumerate():
        if thread.name == CALL_THREAD_NAME:
            thread.join(timeout=ONE_SECOND_RUN_REAL_SECONDS)
            assert not thread.is_alive()


def require_answer(tool_outcome: ToolAnswer | ToolFailure) -> ToolAnswer:
    assert isinstance(tool_outcome, ToolAnswer), tool_outcome
    return tool_outcome


def require_failure(tool_outcome: ToolAnswer | ToolFailure) -> ToolFailure:
    assert isinstance(tool_outcome, ToolFailure), tool_outcome
    return tool_outcome
