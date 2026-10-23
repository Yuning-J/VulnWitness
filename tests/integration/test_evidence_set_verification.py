"""A set handed back is verified against a deployment and the planners the verifying
settings configure by the validator, then the decision-path audit, then replay: a forged
capability, a planner the verifier does not run or a rewritten decision is rejected before
any source is called again, a step summary rewritten over a real response hash is named by
replay, and a replay that runs out of time says so."""

import json
import threading
import time
from collections.abc import Callable
from dataclasses import replace

import pytest

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.application.evidence_set_verification import (
    check_evidence_set,
    verify_evidence_set,
)
from cve_kgrag.application.trajectory_replay import (
    ReplayCompleted,
    ReplayDifference,
    ReplayTimedOut,
)
from cve_kgrag.composition import list_accepted_planner_capabilities
from cve_kgrag.domain.evidence_set_verification_report import (
    MAX_REPORTED_VIOLATIONS,
    ReportedDifference,
    VerificationReport,
    VerificationVerdict,
)
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
    build_test_deployment,
    build_test_investigation_service,
    reseal_evidence_set,
    rewrite_the_ranking,
)
from tests.support.investigation_runs import (
    forge_set_whose_replay_differs,
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
    forged_set = forge_set_whose_replay_differs(fixture_bundle)

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


def test_check_reports_a_genuine_set_verified(fixture_bundle: FixtureBundle) -> None:
    evidence_set_bytes = run_five_g_aka(fixture_bundle).model_dump_json().encode()

    report = check_evidence_set(
        evidence_set_bytes, build_test_deployment(fixture_bundle), DETERMINISTIC_VERIFIER
    )

    assert report == VerificationReport(verdict=VerificationVerdict.VERIFIED)


def test_check_reports_bytes_that_are_not_a_set_malformed(fixture_bundle: FixtureBundle) -> None:
    report = check_evidence_set(b"{", build_test_deployment(fixture_bundle), DETERMINISTIC_VERIFIER)

    assert report.verdict is VerificationVerdict.MALFORMED
    assert report.violations != ()


def test_check_reports_at_most_the_capped_number_of_violations(
    fixture_bundle: FixtureBundle,
) -> None:
    report = check_evidence_set(
        json.dumps({"warnings": [0] * (MAX_REPORTED_VIOLATIONS + 50)}).encode(),
        build_test_deployment(fixture_bundle),
        DETERMINISTIC_VERIFIER,
    )

    assert report.verdict is VerificationVerdict.MALFORMED
    assert len(report.violations) == MAX_REPORTED_VIOLATIONS


def test_check_reports_a_rejected_set_invalid_with_its_violations(
    fixture_bundle: FixtureBundle,
) -> None:
    forged_set = forge_capabilities(run_five_g_aka(fixture_bundle))

    report = check_evidence_set(
        forged_set.model_dump_json().encode(),
        build_test_deployment(fixture_bundle),
        DETERMINISTIC_VERIFIER,
    )

    assert report.verdict is VerificationVerdict.INVALID
    assert DEPLOYMENT_VIOLATION in report.violations


def test_check_reports_each_replay_difference(fixture_bundle: FixtureBundle) -> None:
    forged_set = forge_set_whose_replay_differs(fixture_bundle)

    report = check_evidence_set(
        forged_set.model_dump_json().encode(),
        build_test_deployment(fixture_bundle, fight="failing"),
        DETERMINISTIC_VERIFIER,
    )

    assert report.verdict is VerificationVerdict.REPLAY_DIFFERS
    assert ReportedDifference(step_index=1, part="answer_ids") in report.differences


def test_check_reports_a_replay_past_its_deadline_timed_out(
    fixture_bundle: FixtureBundle, blocked_call_release: threading.Event
) -> None:
    evidence_set = build_test_investigation_service(fixture_bundle).investigate(ONE_SECOND_REQUEST)
    blocking_deployment = build_test_deployment(
        fixture_bundle,
        monotonic_clock=time.monotonic,
        lexical_retriever=BlockingRetriever(blocked_call_release),
    )

    report = check_evidence_set(
        evidence_set.model_dump_json().encode(), blocking_deployment, DETERMINISTIC_VERIFIER
    )

    assert report == VerificationReport(verdict=VerificationVerdict.REPLAY_TIMED_OUT)
