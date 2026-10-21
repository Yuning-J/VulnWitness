"""A set handed back is verified against a deployment and the planners the verifying
settings configure by the validator, then the decision-path audit, then replay: a forged
capability, a planner the verifier does not run or a rewritten decision is rejected before
any source is called again, a step summary rewritten over a real response hash is named by
replay, and a replay that runs out of time says so."""

import threading
import time
from collections.abc import Callable
from dataclasses import replace

import pytest

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.application.evidence_set_verification import verify_evidence_set
from cve_kgrag.application.trajectory_replay import (
    ReplayCompleted,
    ReplayDifference,
    ReplayTimedOut,
)
from cve_kgrag.composition import list_accepted_planner_capabilities
from cve_kgrag.domain.investigation import KnowledgeEvidenceSet, SourceCapability
from cve_kgrag.domain.search import RetrievalOutcome
from cve_kgrag.domain.taxonomy import BackendStatus
from cve_kgrag.domain.validation import EvidenceValidationError
from tests.support.clocks import ONE_SECOND_RUN_REAL_SECONDS
from tests.support.entry_points import FakeAdapterRegistry, FakeDistribution
from tests.support.fakes import BlockingRetriever, RecordingRetriever
from tests.support.investigation import (
    DEPLOYMENT_VIOLATION,
    ONE_SECOND_REQUEST,
    RANKING_VIOLATION,
    build_investigation_request,
    build_test_deployment,
    build_test_investigation_service,
    reseal_evidence_set,
    rewrite_step,
    rewrite_the_ranking,
)
from tests.support.investigation_runs import (
    run_five_g_aka,
    run_five_g_aka_mixed,
    run_model_accepted,
    run_planner_adapter_unusable,
    run_planner_without_a_key,
)
from tests.support.planners import (
    DETERMINISTIC_VERIFIER,
    SCRIPTED_ENTRY_POINT,
    SCRIPTED_MODEL_VERIFIER,
    SCRIPTED_PLANNER_SETTINGS,
    reconfigure_planner,
)

NO_DIFFERENCE = ReplayCompleted(())
SCRIPTED_REGISTRY = FakeAdapterRegistry([SCRIPTED_ENTRY_POINT])
OTHER_MODEL_VERIFIER = list_accepted_planner_capabilities(
    reconfigure_planner(SCRIPTED_PLANNER_SETTINGS, model_name="another-model"),
    SCRIPTED_REGISTRY.list_adapters,
)
# The same model name served from another endpoint: a different planner.
OTHER_ENDPOINT_VERIFIER = list_accepted_planner_capabilities(
    reconfigure_planner(SCRIPTED_PLANNER_SETTINGS, base_url="https://other-planner.invalid/v1"),
    SCRIPTED_REGISTRY.list_adapters,
)
# The configured path with a second trailing slash: configured as "/v1/", which a server
# may route elsewhere than "/v1".
OTHER_PATH_SPELLING_VERIFIER = list_accepted_planner_capabilities(
    reconfigure_planner(SCRIPTED_PLANNER_SETTINGS, base_url="https://planner.invalid/v1//"),
    SCRIPTED_REGISTRY.list_adapters,
)
OTHER_ADAPTER_VERSION_VERIFIER = list_accepted_planner_capabilities(
    SCRIPTED_PLANNER_SETTINGS,
    FakeAdapterRegistry(
        [replace(SCRIPTED_ENTRY_POINT, dist=FakeDistribution("9.9.9"))]
    ).list_adapters,
)
PROTOCOL_CONTEXT_REQUEST = build_investigation_request("5gaka", "protocol_context_only")


def forge_capabilities(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return reseal_evidence_set(evidence_set, source_capabilities=())


@pytest.mark.parametrize(
    ("run", "verifier"),
    [
        (run_five_g_aka, DETERMINISTIC_VERIFIER),
        (run_five_g_aka_mixed, DETERMINISTIC_VERIFIER),
        (run_model_accepted, SCRIPTED_MODEL_VERIFIER),
        (run_five_g_aka, SCRIPTED_MODEL_VERIFIER),
        (run_planner_without_a_key, SCRIPTED_MODEL_VERIFIER),
        (run_planner_adapter_unusable, SCRIPTED_MODEL_VERIFIER),
    ],
    ids=[
        "deterministic_search",
        "deterministic_topic_context",
        "model_planned",
        "deterministic_set_under_an_enabled_planner",
        "planner_missing_its_key",
        "planner_adapter_unusable",
    ],
)
def test_genuine_set_verifies_without_differences(
    fixture_bundle: FixtureBundle,
    run: Callable[[FixtureBundle], KnowledgeEvidenceSet],
    verifier: tuple[SourceCapability, ...],
) -> None:
    """A set verifies under the settings that sealed it: a deterministic set (as the MCP
    tools seal) also under an enabled planner, and a set sealed while the configured planner
    could not plan under those settings, whatever the verifier's own key and adapter."""
    evidence_set = run(fixture_bundle)

    replay_outcome = verify_evidence_set(
        evidence_set, build_test_deployment(fixture_bundle), verifier
    )

    assert replay_outcome == NO_DIFFERENCE


@pytest.mark.parametrize(
    ("run", "verifier"),
    [
        (run_model_accepted, DETERMINISTIC_VERIFIER),
        (run_model_accepted, OTHER_MODEL_VERIFIER),
        (run_model_accepted, OTHER_ENDPOINT_VERIFIER),
        (run_model_accepted, OTHER_PATH_SPELLING_VERIFIER),
        (run_model_accepted, OTHER_ADAPTER_VERSION_VERIFIER),
        (run_planner_without_a_key, DETERMINISTIC_VERIFIER),
    ],
    ids=[
        "model_set_deterministic_verifier",
        "model_set_other_model_verifier",
        "model_set_same_model_other_endpoint_verifier",
        "model_set_endpoint_with_another_trailing_slash_verifier",
        "model_set_other_adapter_version_verifier",
        "unavailable_planner_set_deterministic_verifier",
    ],
)
def test_set_naming_a_planner_the_verifier_does_not_run_raises_deployment_violation(
    fixture_bundle: FixtureBundle,
    run: Callable[[FixtureBundle], KnowledgeEvidenceSet],
    verifier: tuple[SourceCapability, ...],
) -> None:
    evidence_set = run(fixture_bundle)

    with pytest.raises(EvidenceValidationError) as raised:
        verify_evidence_set(evidence_set, build_test_deployment(fixture_bundle), verifier)

    assert DEPLOYMENT_VIOLATION in raised.value.violations


def test_rewritten_step_summary_over_real_hash_reports_replay_difference(
    fixture_bundle: FixtureBundle,
) -> None:
    """The reviewer's forgery: on a deployment whose pinned FiGHT backend is down, the topic
    step keeps the failed response's real hash while its summary and the answer are the ones
    a serving backend gives. The validator and the audit accept it; replay names it."""
    failing_service = build_test_investigation_service(fixture_bundle, fight="failing")
    failed_set = failing_service.investigate(PROTOCOL_CONTEXT_REQUEST)
    served_set = build_test_investigation_service(fixture_bundle).investigate(
        PROTOCOL_CONTEXT_REQUEST
    )
    forged_set = rewrite_step(
        served_set, 1, result_sha256=failed_set.trajectory.steps[0].result_sha256
    )

    replay_outcome = verify_evidence_set(
        forged_set, build_test_deployment(fixture_bundle, fight="failing"), DETERMINISTIC_VERIFIER
    )

    assert isinstance(replay_outcome, ReplayCompleted)
    assert ReplayDifference(1, "answer_ids") in replay_outcome.differences


@pytest.mark.parametrize(
    ("forge", "expected_violation"),
    [(forge_capabilities, DEPLOYMENT_VIOLATION), (rewrite_the_ranking, RANKING_VIOLATION)],
    ids=["forged_capability_fails_the_validator", "rewritten_decision_fails_the_audit"],
)
def test_rejected_set_raises_its_violations_without_calling_a_source_again(
    fixture_bundle: FixtureBundle,
    forge: Callable[[KnowledgeEvidenceSet], KnowledgeEvidenceSet],
    expected_violation: str,
) -> None:
    """The validator rejects the forged capabilities and the audit the rewritten ranking,
    each before replay calls the deployment's lexical channel."""
    forged_set = forge(run_five_g_aka(fixture_bundle))
    lexical_retriever = RecordingRetriever(RetrievalOutcome(status=BackendStatus.OK))
    deployment = build_test_deployment(fixture_bundle, lexical_retriever=lexical_retriever)

    with pytest.raises(EvidenceValidationError) as raised:
        verify_evidence_set(forged_set, deployment, DETERMINISTIC_VERIFIER)

    assert expected_violation in raised.value.violations
    assert lexical_retriever.query_texts == []


def test_blocking_source_reports_replay_timed_out(
    fixture_bundle: FixtureBundle, blocked_call_release: threading.Event
) -> None:
    evidence_set = build_test_investigation_service(fixture_bundle).investigate(ONE_SECOND_REQUEST)
    blocking_deployment = build_test_deployment(
        fixture_bundle,
        monotonic_clock=time.monotonic,
        lexical_retriever=BlockingRetriever(blocked_call_release),
    )

    real_started_at = time.monotonic()
    replay_outcome = verify_evidence_set(evidence_set, blocking_deployment, DETERMINISTIC_VERIFIER)
    real_elapsed_seconds = time.monotonic() - real_started_at

    assert replay_outcome == ReplayTimedOut()
    assert real_elapsed_seconds < ONE_SECOND_RUN_REAL_SECONDS
