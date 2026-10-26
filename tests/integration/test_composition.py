"""The composition root reads the affectedness port once: a port that gives no typed reason
builds no deployment, every set a deployment seals carries the server's sentence for the
port's reason, and an investigation never calls the port."""

import pytest

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.application.investigate import describe_service_capabilities
from cve_kgrag.application.planner_setup import DeterministicPlanning
from cve_kgrag.composition import (
    AffectednessConfigurationError,
    build_investigation_deployment,
    build_serving_data_plane,
)
from cve_kgrag.domain.affectedness import AffectednessDetail, AffectednessFailure
from cve_kgrag.domain.investigation import (
    KnowledgeEvidenceSet,
    SourceCapability,
    SourceCapabilityState,
)
from cve_kgrag.domain.investigation_validation import validate_knowledge_evidence_set
from cve_kgrag.domain.topic_context import KnowledgeSource
from tests.support.fakes import InMemoryTrustifyPort, MisansweringTrustifyPort
from tests.support.investigation import (
    build_investigation_request,
    build_test_deployment,
    build_test_investigation_service,
)

# What a port might give instead of an AffectednessFailure: verdict text, a capability it
# authored, or nothing.
MISDESCRIBED_REASONS = [
    pytest.param("CONFIRMED: pkg is affected by this CVE.", id="verdict_text"),
    pytest.param(
        SourceCapability(
            source=KnowledgeSource.AFFECTEDNESS, state=SourceCapabilityState.AVAILABLE
        ),
        id="adapter_authored_capability",
    ),
    pytest.param(
        {"source": "affectedness", "state": "unavailable", "detail": "not a capability"},
        id="capability_mapping",
    ),
    pytest.param(None, id="none"),
]


def list_affectedness_capabilities(evidence_set: KnowledgeEvidenceSet) -> list[SourceCapability]:
    affectedness_capabilities: list[SourceCapability] = []
    for capability in evidence_set.source_capabilities:
        if capability.source == KnowledgeSource.AFFECTEDNESS:
            affectedness_capabilities.append(capability)
    return affectedness_capabilities


def seal_product_question(
    bundle: FixtureBundle, trustify_port: InMemoryTrustifyPort
) -> KnowledgeEvidenceSet:
    """A product question, which requires affectedness, sealed by a service over
    ``trustify_port``."""
    service = build_test_investigation_service(bundle, trustify_port=trustify_port)
    request = build_investigation_request(
        "5G-AKA", "implementation_only", filters={"products": ["f5gc"]}
    )
    return service.investigate(request)


def build_offline_trustify_port() -> InMemoryTrustifyPort:
    return InMemoryTrustifyPort(
        failure=AffectednessFailure.AUTH_FAILED, described_failure=AffectednessFailure.TIMEOUT
    )


@pytest.mark.parametrize("described_reason", MISDESCRIBED_REASONS)
def test_port_giving_no_typed_reason_raises_configuration_error(
    fixture_bundle: FixtureBundle, described_reason: object
) -> None:
    trustify_port = MisansweringTrustifyPort(
        answer=AffectednessFailure.TIMEOUT, reason=described_reason
    )

    with pytest.raises(AffectednessConfigurationError):
        build_investigation_deployment(
            build_serving_data_plane(fixture_bundle), trustify_port=trustify_port
        )


@pytest.mark.parametrize("described_failure", list(AffectednessFailure), ids=str)
def test_port_reason_publishes_only_the_server_sentence_for_it(
    fixture_bundle: FixtureBundle, described_failure: AffectednessFailure
) -> None:
    trustify_port = InMemoryTrustifyPort(
        failure=AffectednessFailure.SOURCE_UNAVAILABLE, described_failure=described_failure
    )

    deployment = build_investigation_deployment(
        build_serving_data_plane(fixture_bundle), trustify_port=trustify_port
    )

    affectedness_capabilities: list[SourceCapability] = []
    for capability in deployment.source_capabilities:
        if capability.source == KnowledgeSource.AFFECTEDNESS:
            affectedness_capabilities.append(capability)
    assert affectedness_capabilities == [
        SourceCapability(
            source=KnowledgeSource.AFFECTEDNESS,
            state=SourceCapabilityState.UNAVAILABLE,
            detail=AffectednessDetail[described_failure.name],
        )
    ]


def test_deployment_with_fake_port_seals_sets_carrying_the_sentence_for_its_reason(
    fixture_bundle: FixtureBundle,
) -> None:
    trustify_port = build_offline_trustify_port()

    evidence_set = seal_product_question(fixture_bundle, trustify_port)

    affectedness_capabilities = list_affectedness_capabilities(evidence_set)
    assert affectedness_capabilities == [
        SourceCapability(
            source=KnowledgeSource.AFFECTEDNESS,
            state=SourceCapabilityState.UNAVAILABLE,
            detail=AffectednessDetail.TIMEOUT,
        )
    ]


def test_investigation_never_calls_the_affectedness_port(fixture_bundle: FixtureBundle) -> None:
    trustify_port = build_offline_trustify_port()

    seal_product_question(fixture_bundle, trustify_port)

    assert trustify_port.received_checks == []


def test_set_sealed_over_a_fake_port_validates_against_the_test_deployment_of_that_port(
    fixture_bundle: FixtureBundle,
) -> None:
    trustify_port = build_offline_trustify_port()
    evidence_set = seal_product_question(fixture_bundle, trustify_port)

    deployment = build_test_deployment(fixture_bundle, trustify_port=trustify_port)

    validate_knowledge_evidence_set(
        evidence_set,
        deployment.pinned_fight_snapshot,
        deployment.evidence_catalog,
        describe_service_capabilities(deployment, DeterministicPlanning()),
    )
