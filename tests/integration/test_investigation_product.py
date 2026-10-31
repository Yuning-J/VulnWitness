"""Named products participate in final answers without asserting component relevance."""

import pytest

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.application.investigation_policy import interpret_request
from cve_kgrag.application.trajectory_replay import ReplayCompleted, replay_evidence_set
from cve_kgrag.domain.planning import ProductQueryCall
from cve_kgrag.domain.result_prefix import measure_response_bytes, slice_response
from cve_kgrag.domain.search import SearchRequest
from tests.support.investigation import (
    build_investigation_request,
    build_test_deployment,
    build_test_investigation_service,
    list_implementation_ids,
    list_need_outcomes,
)
from tests.support.product_investigations import (
    build_lexical_product_bundle,
    build_product_investigation_bundle,
)
from tests.support.services import build_fixture_service


@pytest.fixture
def product_bundle(fixture_bundle: FixtureBundle) -> FixtureBundle:
    return build_product_investigation_bundle(fixture_bundle)


def test_named_product_version_enters_final_top_twenty_without_numeric_search_terms(
    product_bundle: FixtureBundle,
) -> None:
    # Arrange
    request = build_investigation_request(
        "Is Kamailio 5.8.2 affected by known vulnerabilities", "implementation_only"
    )
    service = build_test_investigation_service(product_bundle)

    # Act
    evidence_set = service.investigate(request)

    # Assert
    recognition = evidence_set.interpretation.product_recognition
    assert recognition is not None
    assert recognition.name == "kamailio"
    assert recognition.basis == "affectedness_mention"
    assert recognition.request.vendor == "kamailio"
    assert recognition.request.product is None
    assert recognition.request.version == "5.8.2"
    assert evidence_set.interpretation.search_terms == (
        "kamailio",
        "affected",
        "known",
        "vulnerabilities",
    )
    product_step = evidence_set.trajectory.steps[1]
    assert isinstance(product_step.call, ProductQueryCall)
    assert product_step.backend_requests[0].product_query == recognition.request
    assert set(product_step.answer_ids) <= set(list_implementation_ids(evidence_set))
    assert list_implementation_ids(evidence_set)[:3] == [
        "CVE-9999-7201",
        "CVE-9999-7202",
        "CVE-9999-7300",
    ]
    for candidate in evidence_set.implementation_candidates[:3]:
        assert candidate.nvd_version_notes is not None
        if candidate.candidate.record.cve_id in product_step.answer_ids:
            assert candidate.nvd_version_notes[0].outcome == "hit"
    assert all(outcome != "found" for _, _, outcome in list_need_outcomes(evidence_set))
    assert evidence_set.stop_reason == "needs_unmet"


def test_named_vendor_changes_final_top_twenty_among_generic_network_matches(
    product_bundle: FixtureBundle,
) -> None:
    # Arrange
    query = "OpenAirInterface 5G core network vulnerabilities"
    service = build_test_investigation_service(product_bundle)
    lexical = build_fixture_service(product_bundle).search(SearchRequest(query=query, limit=20))
    lexical_ids = []
    for candidate in lexical.candidates:
        lexical_ids.append(candidate.record.cve_id)

    # Act
    evidence_set = service.investigate(build_investigation_request(query, "implementation_only"))

    # Assert
    recognition = evidence_set.interpretation.product_recognition
    assert recognition is not None
    assert recognition.request.vendor == "openairinterface"
    assert recognition.request.product is None
    assert evidence_set.interpretation.ambiguous_product_names == ()
    product_step = evidence_set.trajectory.steps[1]
    assert isinstance(product_step.call, ProductQueryCall)
    assert set(product_step.answer_ids) == {
        "CVE-9999-7203",
        "CVE-9999-7204",
        "CVE-9999-7210",
    }
    assert list_implementation_ids(evidence_set) != lexical_ids
    assert "CVE-9999-7203" in list_implementation_ids(evidence_set)[:3]
    assert "CVE-9999-7204" in list_implementation_ids(evidence_set)[:4]
    assert len(evidence_set.implementation_candidates) == 20
    assert all(outcome != "found" for _, _, outcome in list_need_outcomes(evidence_set))


def test_product_only_candidates_preserve_full_matching_lexical_top_twenty(
    fixture_bundle: FixtureBundle,
) -> None:
    # Arrange
    bundle = build_lexical_product_bundle(fixture_bundle)
    query = "familydemo vulnerabilities"
    lexical = build_fixture_service(bundle).search(SearchRequest(query=query, limit=20))
    lexical_ids = []
    for candidate in lexical.candidates:
        lexical_ids.append(candidate.record.cve_id)

    # Act
    evidence_set = build_test_investigation_service(bundle).investigate(
        build_investigation_request(query, "implementation_only")
    )

    # Assert
    assert len(lexical_ids) == 20
    assert list_implementation_ids(evidence_set) == lexical_ids
    product_step = evidence_set.trajectory.steps[1]
    assert isinstance(product_step.call, ProductQueryCall)
    assert len(product_step.answer_ids) == 20
    assert set(product_step.answer_ids).isdisjoint(lexical_ids)
    assert all(
        candidate.found_by_steps == (1,) for candidate in evidence_set.implementation_candidates
    )


@pytest.mark.parametrize("name", ("service", "known", "smf"))
def test_collision_name_keeps_lexical_terms_and_omits_product_step(
    product_bundle: FixtureBundle, name: str
) -> None:
    # Arrange
    request = build_investigation_request(f"{name} vulnerabilities", "implementation_only")

    # Act
    evidence_set = build_test_investigation_service(product_bundle).investigate(request)

    # Assert
    assert evidence_set.interpretation.product_recognition is None
    assert name in evidence_set.interpretation.search_terms
    assert all(
        not isinstance(step.call, ProductQueryCall) for step in evidence_set.trajectory.steps
    )


@pytest.mark.parametrize("name", ("sharedname", "vendorcollision"))
def test_ambiguous_product_keeps_lexical_path_and_records_warning(
    product_bundle: FixtureBundle,
    name: str,
) -> None:
    # Arrange
    request = build_investigation_request(f"{name} vulnerabilities", "implementation_only")

    # Act
    evidence_set = build_test_investigation_service(product_bundle).investigate(request)

    # Assert
    assert evidence_set.interpretation.product_recognition is None
    assert evidence_set.interpretation.ambiguous_product_names == (name,)
    assert any(warning.code == "product_name_ambiguous" for warning in evidence_set.warnings)
    assert all(
        not isinstance(step.call, ProductQueryCall) for step in evidence_set.trajectory.steps
    )


def test_component_lexical_candidate_precedes_unmatched_product_candidate(
    product_bundle: FixtureBundle,
) -> None:
    # Arrange
    request = build_investigation_request("Kamailio componentalpha", "implementation_only")

    # Act
    evidence_set = build_test_investigation_service(product_bundle).investigate(request)

    # Assert
    assert list_implementation_ids(evidence_set)[0] == "CVE-9999-7201"
    assert list_implementation_ids(evidence_set).index("CVE-9999-7202") > 0
    assert evidence_set.implementation_candidates[0].found_by_steps == (1, 2)


def test_unrelated_dotted_numbers_stay_in_lexical_search(
    product_bundle: FixtureBundle,
) -> None:
    # Arrange
    deployment = build_test_deployment(product_bundle)
    request = build_investigation_request(
        "Kamailio 5.8.2 affected in release 9.4", "implementation_only"
    )

    # Act
    interpretation = interpret_request(
        request, deployment.topic_registry, deployment.evidence_catalog
    )

    # Assert
    assert "5" not in interpretation.search_terms
    assert "8" not in interpretation.search_terms
    assert "2" not in interpretation.search_terms
    assert "9" in interpretation.search_terms
    assert "4" in interpretation.search_terms


def test_product_candidates_obey_filters(product_bundle: FixtureBundle) -> None:
    # Arrange
    request = build_investigation_request(
        "Kamailio vulnerabilities", "implementation_only", filters={"vendors": ["openairinterface"]}
    )

    # Act
    evidence_set = build_test_investigation_service(product_bundle).investigate(request)

    # Assert
    assert "CVE-9999-7201" not in list_implementation_ids(evidence_set)
    assert "CVE-9999-7202" not in list_implementation_ids(evidence_set)


def test_version_without_affectedness_word_gets_note_without_adding_need(
    product_bundle: FixtureBundle,
) -> None:
    # Arrange
    request = build_investigation_request("Kamailio 5.8.2 vulnerabilities", "implementation_only")

    # Act
    evidence_set = build_test_investigation_service(product_bundle).investigate(request)

    # Assert
    assert evidence_set.interpretation.affectedness_mentions == ()
    assert evidence_set.interpretation.search_terms == ("kamailio", "vulnerabilities")
    assert all(kind != "affectedness" for kind, _, _ in list_need_outcomes(evidence_set))
    assert evidence_set.implementation_candidates[0].nvd_version_notes is not None


def test_product_trajectory_replays_without_differences(product_bundle: FixtureBundle) -> None:
    # Arrange
    request = build_investigation_request("Kamailio componentalpha", "implementation_only")
    evidence_set = build_test_investigation_service(product_bundle).investigate(request)
    deployment = build_test_deployment(product_bundle)

    # Act
    replay = replay_evidence_set(evidence_set, deployment)

    # Assert
    assert replay == ReplayCompleted(())


def test_product_step_respects_call_budget(product_bundle: FixtureBundle) -> None:
    # Arrange
    request = build_investigation_request(
        "Kamailio vulnerabilities", "implementation_only", budget={"max_tool_calls": 1}
    )

    # Act
    evidence_set = build_test_investigation_service(product_bundle).investigate(request)

    # Assert
    assert evidence_set.trajectory.budget_used.tool_calls == 1
    assert all(
        not isinstance(step.call, ProductQueryCall) for step in evidence_set.trajectory.steps
    )


@pytest.mark.parametrize("query", ("prefix-kamailio vulnerabilities", "kamailiox vulnerabilities"))
def test_substrings_do_not_recognize_product(product_bundle: FixtureBundle, query: str) -> None:
    # Arrange
    request = build_investigation_request(query, "implementation_only")

    # Act
    evidence_set = build_test_investigation_service(product_bundle).investigate(request)

    # Assert
    assert evidence_set.interpretation.product_recognition is None


def test_multiple_distinct_names_keep_lexical_path(product_bundle: FixtureBundle) -> None:
    # Arrange
    request = build_investigation_request(
        "Kamailio OpenAirInterface vulnerabilities", "implementation_only"
    )

    # Act
    evidence_set = build_test_investigation_service(product_bundle).investigate(request)

    # Assert
    assert evidence_set.interpretation.product_recognition is None
    assert evidence_set.interpretation.ambiguous_product_names == ("kamailio", "openairinterface")


def test_product_prefix_obeys_context_cap_and_replays(product_bundle: FixtureBundle) -> None:
    # Arrange
    request = build_investigation_request("Kamailio componentalpha", "implementation_only")
    service = build_test_investigation_service(product_bundle)
    complete_set = service.investigate(request)
    product_call = complete_set.trajectory.steps[1].call
    deployment = build_test_deployment(product_bundle)
    product_execution = deployment.tool_executor.execute(product_call, request)
    assert product_execution.search_response is not None
    prefix = slice_response(product_execution.search_response, {"candidates": 1})
    byte_cap = complete_set.trajectory.steps[0].context_bytes + measure_response_bytes(prefix)
    bounded_request = build_investigation_request(
        request.query, "implementation_only", budget={"max_context_bytes": byte_cap}
    )

    # Act
    evidence_set = service.investigate(bounded_request)
    replay = replay_evidence_set(evidence_set, deployment)

    # Assert
    product_step = evidence_set.trajectory.steps[1]
    assert product_step.admission == "admitted_prefix"
    assert product_step.prefix_admission is not None
    assert product_step.prefix_admission.counts[0].kept == 1
    assert product_step.prefix_admission.counts[0].omitted == 1
    assert evidence_set.trajectory.budget_used.context_bytes == byte_cap
    assert replay == ReplayCompleted(())
