"""Final validation binds ``source_capabilities`` to the deployment and to the run: a resealed
set that drops, reorders or rewrites a capability, gives one a detail it should not carry
or omits one it should, or contradicts the planner, the FiGHT pin, the semantic channel or
the affectedness outcome, is rejected."""

from collections.abc import Callable, Sequence
from typing import Any

import pytest

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.adapters.trustify.disabled_trustify_adapter import DisabledTrustifyAdapter
from cve_kgrag.application.investigation_policy import describe_deterministic_planner
from cve_kgrag.composition import describe_affectedness, describe_source_capabilities
from cve_kgrag.domain.affectedness import AffectednessDetail
from cve_kgrag.domain.evidence_catalog import EvidenceCatalog
from cve_kgrag.domain.investigation import (
    DecisionBasis,
    FightUnavailableDetail,
    InvestigationRequest,
    KnowledgeEvidenceSet,
    SourceCapability,
    SourceCapabilityState,
    StopReason,
    ToolStep,
    describe_planner_capability,
)
from cve_kgrag.domain.investigation_validation import (
    UNCONFIGURED_SEMANTIC_WARNING,
    validate_knowledge_evidence_set,
)
from cve_kgrag.domain.planning import ModelPlannerUnavailableDetail
from cve_kgrag.domain.search import (
    ChannelOutcome,
    RetrievalOutcome,
    SearchWarning,
    SemanticUnavailableDetail,
)
from cve_kgrag.domain.taxonomy import (
    BackendFailureDetail,
    BackendStatus,
    ResultStatus,
    RetrievalChannel,
)
from cve_kgrag.domain.threat_context import KnownFightSnapshot, SnapshotCoverage
from cve_kgrag.domain.topic_context import KnowledgeSource, SourceOutcome
from cve_kgrag.domain.validation import EvidenceValidationError
from tests.support.fakes import CannedRetriever
from tests.support.investigation import (
    DEPLOYMENT_VIOLATION,
    FightChoice,
    build_investigation_request,
    build_test_investigation_service,
    choose_fight_source,
    label_row,
    load_gold_rows,
    reseal_evidence_set,
    update_trajectory,
)
from tests.support.investigation_runs import run_semantic_hit
from tests.support.planners import ScriptedModelPort, build_plan_reply
from tests.support.services import build_fixture_service

# A genuine set and the FiGHT pin of the deployment that produced it.
PinnedRun = tuple[KnowledgeEvidenceSet, KnownFightSnapshot | None]
Run = Callable[[FixtureBundle], PinnedRun]
Forgery = Callable[[KnowledgeEvidenceSet], KnowledgeEvidenceSet]
GOLD_ROWS = load_gold_rows()
SUBJECT_ORDER_VIOLATION = (
    "source_capabilities must describe cve_search, mitre_fight, affectedness, "
    "semantic_channel, model_planner once each, in that order"
)
OTHER_SNAPSHOT_SHA256 = "e" * 64


def run_on(
    fixture_bundle: FixtureBundle,
    request: InvestigationRequest,
    fight: FightChoice = "packaged",
    **service_parts: Any,
) -> PinnedRun:
    service = build_test_investigation_service(fixture_bundle, fight=fight, **service_parts)
    return service.investigate(request), choose_fight_source(fight)[1]


def run_five_g_aka(fixture_bundle: FixtureBundle) -> PinnedRun:
    """The reviewer's base: ``5G-AKA`` finds both records with one CVE search."""
    return run_on(fixture_bundle, build_investigation_request("5G-AKA", "implementation_only"))


def run_protocol_context(fixture_bundle: FixtureBundle) -> PinnedRun:
    """FiGHT serves the answer from the pinned excerpt."""
    return run_on(fixture_bundle, build_investigation_request("5gaka", "protocol_context_only"))


def run_without_fight(fixture_bundle: FixtureBundle) -> PinnedRun:
    return run_on(fixture_bundle, build_investigation_request("5gaka", "mixed"), "unavailable")


def run_model_planner(fixture_bundle: FixtureBundle) -> PinnedRun:
    model_port = ScriptedModelPort([build_plan_reply({"tool": "cve_search", "query": "ausf suci"})])
    request = build_investigation_request("5G-AKA", "implementation_only")
    return run_on(fixture_bundle, request, model_port=model_port)


def run_planner_without_a_key(fixture_bundle: FixtureBundle) -> PinnedRun:
    """The configured model planner has no key, so the deterministic policy plans."""
    request = build_investigation_request("5G-AKA", "implementation_only")
    return run_on(
        fixture_bundle,
        request,
        planner_unavailable_detail=ModelPlannerUnavailableDetail.MISSING_API_KEY,
    )


def run_pinned_semantic_hit(fixture_bundle: FixtureBundle) -> PinnedRun:
    """``run_semantic_hit`` with the FiGHT pin its deployment serves."""
    return run_semantic_hit(fixture_bundle), choose_fight_source("packaged")[1]


def run_semantic_without_hits(fixture_bundle: FixtureBundle) -> PinnedRun:
    """A wired semantic channel answers, with no match."""
    semantic_retriever = CannedRetriever(RetrievalOutcome(status=BackendStatus.OK))
    request = build_investigation_request("5G-AKA", "implementation_only", semantic=True)
    return run_on(fixture_bundle, request, semantic_retriever=semantic_retriever)


def run_semantic_without_adapter(fixture_bundle: FixtureBundle) -> PinnedRun:
    """A semantic request on a deployment without a semantic adapter: its CVE search runs the
    channel, which reports itself unavailable, so the search is partial."""
    request = build_investigation_request("5G-AKA", "implementation_only", semantic=True)
    return run_on(fixture_bundle, request)


def run_semantic_with_an_unusable_adapter(fixture_bundle: FixtureBundle) -> PinnedRun:
    """A semantic request on a deployment whose enabled semantic adapter could not load:
    the capability is unavailable, and the search runs the channel, which reports itself
    unavailable, so the search is partial."""
    request = build_investigation_request("5G-AKA", "implementation_only", semantic=True)
    return run_on(
        fixture_bundle, request, semantic_retriever=SemanticUnavailableDetail.ADAPTER_UNUSABLE
    )


def run_semantic_topic_without_adapter(fixture_bundle: FixtureBundle) -> PinnedRun:
    """The same for a topic step: every template search runs the missing channel."""
    request = build_investigation_request("5gaka", "mixed", semantic=True)
    return run_on(fixture_bundle, request)


def run_product_question(fixture_bundle: FixtureBundle) -> PinnedRun:
    """A named product requires affectedness, which no adapter serves."""
    request = build_investigation_request(
        "5G-AKA", "implementation_only", filters={"products": ["f5gc"]}
    )
    return run_on(fixture_bundle, request)


def replace_capability(
    evidence_set: KnowledgeEvidenceSet, subject: str, **changes: Any
) -> KnowledgeEvidenceSet:
    """``evidence_set`` with ``changes`` applied to its ``subject`` capability, resealed."""
    forged_capabilities: list[SourceCapability] = []
    for capability in evidence_set.source_capabilities:
        if capability.source == subject:
            forged_capabilities.append(capability.model_copy(update=changes))
        else:
            forged_capabilities.append(capability)
    return reseal_evidence_set(evidence_set, source_capabilities=tuple(forged_capabilities))


def empty_capabilities(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The reviewer's forgery."""
    return reseal_evidence_set(evidence_set, source_capabilities=())


def drop_model_planner(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return reseal_evidence_set(
        evidence_set, source_capabilities=evidence_set.source_capabilities[:-1]
    )


def describe_cve_search_twice(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    cve_search, mitre_fight, _, semantic_channel, model_planner = evidence_set.source_capabilities
    return reseal_evidence_set(
        evidence_set,
        source_capabilities=(cve_search, mitre_fight, cve_search, semantic_channel, model_planner),
    )


def swap_semantic_and_planner(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    cve_search, mitre_fight, affectedness, semantic_channel, model_planner = (
        evidence_set.source_capabilities
    )
    return reseal_evidence_set(
        evidence_set,
        source_capabilities=(
            cve_search,
            mitre_fight,
            affectedness,
            model_planner,
            semantic_channel,
        ),
    )


def claim_affectedness_available(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return replace_capability(
        evidence_set, "affectedness", state=SourceCapabilityState.AVAILABLE, detail=None
    )


def claim_affectedness_unconfigured(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    return replace_capability(
        evidence_set, "affectedness", state=SourceCapabilityState.NOT_CONFIGURED, detail=None
    )


def drop_the_affectedness_detail(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return replace_capability(evidence_set, "affectedness", detail=None)


def drop_the_unavailable_fight_detail(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return replace_capability(evidence_set, "mitre_fight", detail=None)


def give_cve_search_a_detail(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return replace_capability(evidence_set, "cve_search", detail=FightUnavailableDetail.NOT_PINNED)


def give_the_available_fight_a_detail(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return replace_capability(evidence_set, "mitre_fight", detail=FightUnavailableDetail.NOT_PINNED)


def give_the_unconfigured_semantic_channel_a_detail(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    return replace_capability(
        evidence_set, "semantic_channel", detail=AffectednessDetail.SOURCE_UNAVAILABLE
    )


def drop_cve_search_version(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return replace_capability(evidence_set, "cve_search", version=None)


def drop_fight_coverage(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return replace_capability(evidence_set, "mitre_fight", coverage=None)


def version_the_unavailable_fight(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return replace_capability(evidence_set, "mitre_fight", version="fight@forged")


def version_the_semantic_channel(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return replace_capability(evidence_set, "semantic_channel", version="semantic@forged")


def hide_the_model_planner(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return replace_capability(
        evidence_set, "model_planner", state=SourceCapabilityState.NOT_CONFIGURED, version=None
    )


def rename_the_model(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return replace_capability(evidence_set, "model_planner", version="another-model")


def invent_a_model_planner(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return replace_capability(
        evidence_set,
        "model_planner",
        state=SourceCapabilityState.AVAILABLE,
        version="invented-model",
    )


def claim_the_model_planner_unavailable(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return replace_capability(
        evidence_set,
        "model_planner",
        state=SourceCapabilityState.UNAVAILABLE,
        version=None,
        detail=ModelPlannerUnavailableDetail.ADAPTER_UNUSABLE,
    )


def drop_the_planner_detail(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return replace_capability(evidence_set, "model_planner", detail=None)


def give_the_planner_a_fight_sentence(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return replace_capability(
        evidence_set, "model_planner", detail=FightUnavailableDetail.NOT_PINNED
    )


def give_the_unconfigured_planner_a_detail(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    return replace_capability(
        evidence_set, "model_planner", detail=ModelPlannerUnavailableDetail.MISSING_API_KEY
    )


def hide_the_unavailable_planner(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return replace_capability(
        evidence_set, "model_planner", state=SourceCapabilityState.NOT_CONFIGURED, detail=None
    )


def name_another_planner_reason(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return replace_capability(
        evidence_set, "model_planner", detail=ModelPlannerUnavailableDetail.ADAPTER_UNUSABLE
    )


def name_another_snapshot(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    fight_capability = evidence_set.source_capabilities[1]
    assert fight_capability.version is not None
    pinned_sha256 = fight_capability.version.rsplit(":", 1)[1]
    forged_version = fight_capability.version.replace(pinned_sha256, OTHER_SNAPSHOT_SHA256)
    return replace_capability(evidence_set, "mitre_fight", version=forged_version)


def claim_full_fight_coverage(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return replace_capability(evidence_set, "mitre_fight", coverage=SnapshotCoverage.FULL)


def claim_fight_unavailable(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return replace_capability(
        evidence_set,
        "mitre_fight",
        state=SourceCapabilityState.UNAVAILABLE,
        version=None,
        coverage=None,
        detail=FightUnavailableDetail.NOT_PINNED,
    )


def claim_fight_pinned(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The packaged pin's version and coverage on a deployment that pins no snapshot."""
    pinned_fight_snapshot = choose_fight_source("packaged")[1]
    assert pinned_fight_snapshot is not None
    return replace_capability(
        evidence_set,
        "mitre_fight",
        state=SourceCapabilityState.AVAILABLE,
        version=pinned_fight_snapshot.source_version,
        coverage=pinned_fight_snapshot.coverage,
        detail=None,
    )


def drop_the_semantic_detail(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return replace_capability(evidence_set, "semantic_channel", detail=None)


def give_the_semantic_channel_the_fight_sentence(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    return replace_capability(
        evidence_set, "semantic_channel", detail=FightUnavailableDetail.NOT_PINNED
    )


def hide_the_unusable_semantic_adapter(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    return replace_capability(
        evidence_set,
        "semantic_channel",
        state=SourceCapabilityState.NOT_CONFIGURED,
        detail=None,
    )


def unconfigure_the_semantic_channel(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return replace_capability(
        evidence_set, "semantic_channel", state=SourceCapabilityState.NOT_CONFIGURED
    )


def restate_as_sufficient(
    evidence_set: KnowledgeEvidenceSet,
    steps: Sequence[ToolStep],
    coverage_outcomes: Sequence[SourceOutcome],
) -> KnowledgeEvidenceSet:
    """The run presented as answered in full: ``steps`` and ``coverage_outcomes`` replace
    its own, and the stop, status, basis and final assess transition agree; resealed."""
    coverage = evidence_set.coverage.model_copy(
        update={"source_outcomes": tuple(coverage_outcomes), "basis": DecisionBasis.ANSWER_FOUND}
    )
    transitions = list(evidence_set.trajectory.transitions)
    transitions[-2] = transitions[-2].model_copy(update={"basis": DecisionBasis.ANSWER_FOUND})
    trajectory = evidence_set.trajectory.model_copy(
        update={"steps": tuple(steps), "transitions": tuple(transitions)}
    )
    return reseal_evidence_set(
        evidence_set,
        coverage=coverage,
        trajectory=trajectory,
        stop_reason=StopReason.SUFFICIENT,
        status=ResultStatus.OK,
    )


def present_as_sufficient(
    evidence_set: KnowledgeEvidenceSet, **affectedness_changes: Any
) -> KnowledgeEvidenceSet:
    """The product question presented as answered in full: its affectedness outcome
    dropped (no ``affectedness_changes``) or rewritten."""
    forged_outcomes: list[SourceOutcome] = []
    for outcome in evidence_set.coverage.source_outcomes:
        if outcome.source is not KnowledgeSource.AFFECTEDNESS:
            forged_outcomes.append(outcome)
        elif affectedness_changes:
            forged_outcomes.append(outcome.model_copy(update=affectedness_changes))
    return restate_as_sufficient(evidence_set, evidence_set.trajectory.steps, forged_outcomes)


def list_outcomes_without(
    source_outcomes: Sequence[SourceOutcome], dropped_source: KnowledgeSource
) -> list[SourceOutcome]:
    kept_outcomes: list[SourceOutcome] = []
    for outcome in source_outcomes:
        if outcome.source is not dropped_source:
            kept_outcomes.append(outcome)
    return kept_outcomes


def serve_cve_search(source_outcomes: Sequence[SourceOutcome]) -> list[SourceOutcome]:
    """The outcomes with the CVE source's rewritten as served in full."""
    served_outcomes: list[SourceOutcome] = []
    for outcome in source_outcomes:
        if outcome.source is KnowledgeSource.CVE_SEARCH:
            served_outcomes.append(
                outcome.model_copy(update={"status": ResultStatus.OK, "detail": None})
            )
        else:
            served_outcomes.append(outcome)
    return served_outcomes


def relabel_semantic_failures(
    source_outcomes: Sequence[SourceOutcome], detail: BackendFailureDetail
) -> tuple[SourceOutcome, ...]:
    """The outcomes with every semantic channel failure given ``detail``."""
    relabelled_outcomes: list[SourceOutcome] = []
    for outcome in source_outcomes:
        channel_failures: list[ChannelOutcome] = []
        for channel_failure in outcome.channel_failures:
            if channel_failure.channel is RetrievalChannel.SEMANTIC:
                channel_failure = channel_failure.model_copy(update={"detail": detail})
            channel_failures.append(channel_failure)
        relabelled_outcomes.append(
            outcome.model_copy(update={"channel_failures": tuple(channel_failures)})
        )
    return tuple(relabelled_outcomes)


def relabel_the_semantic_failure_as(
    evidence_set: KnowledgeEvidenceSet, detail: BackendFailureDetail
) -> KnowledgeEvidenceSet:
    """``evidence_set`` with every semantic channel failure, in its steps and coverage,
    given ``detail``, resealed."""
    relabelled_steps: list[ToolStep] = []
    for step in evidence_set.trajectory.steps:
        relabelled_steps.append(
            step.model_copy(
                update={"source_outcomes": relabel_semantic_failures(step.source_outcomes, detail)}
            )
        )
    coverage = evidence_set.coverage.model_copy(
        update={
            "source_outcomes": relabel_semantic_failures(
                evidence_set.coverage.source_outcomes, detail
            )
        }
    )
    return reseal_evidence_set(
        evidence_set,
        trajectory=evidence_set.trajectory.model_copy(update={"steps": tuple(relabelled_steps)}),
        coverage=coverage,
    )


def call_the_unusable_adapter_unconfigured(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    return relabel_the_semantic_failure_as(evidence_set, BackendFailureDetail.NOT_CONFIGURED)


def call_the_missing_adapter_unusable(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return relabel_the_semantic_failure_as(evidence_set, BackendFailureDetail.ADAPTER_UNUSABLE)


def drop_the_fight_outcome_to_sufficient(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    """The reviewer's forgery: on a deployment without FiGHT, the topic step's and the
    coverage's unserved FiGHT outcome are dropped and the run presented as sufficient."""
    topic_step = evidence_set.trajectory.steps[0]
    step_outcomes = list_outcomes_without(topic_step.source_outcomes, KnowledgeSource.MITRE_FIGHT)
    forged_step = topic_step.model_copy(update={"source_outcomes": tuple(step_outcomes)})
    coverage_outcomes = list_outcomes_without(
        evidence_set.coverage.source_outcomes, KnowledgeSource.MITRE_FIGHT
    )
    return restate_as_sufficient(evidence_set, [forged_step], coverage_outcomes)


def hide_the_semantic_channel(step: ToolStep) -> ToolStep:
    """The step without the semantic channel or the warning that it is not configured."""
    channels: list[RetrievalChannel] = []
    for channel in step.channels_executed:
        if channel is not RetrievalChannel.SEMANTIC:
            channels.append(channel)
    search_warnings: list[SearchWarning] = []
    for search_warning in step.search_warnings:
        if search_warning != UNCONFIGURED_SEMANTIC_WARNING:
            search_warnings.append(search_warning)
    return step.model_copy(
        update={"channels_executed": tuple(channels), "search_warnings": tuple(search_warnings)}
    )


def hide_the_semantic_search(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """Only the channel and its warning are hidden; the partial outcomes stay."""
    search_step = hide_the_semantic_channel(evidence_set.trajectory.steps[0])
    return update_trajectory(evidence_set, steps=(search_step,))


def hide_the_semantic_search_to_sufficient(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    """The reviewer's forgery: the channel and its warning hidden, the step's and the
    coverage's CVE outcome served in full, and the run presented as sufficient."""
    search_step = hide_the_semantic_channel(evidence_set.trajectory.steps[0])
    forged_step = search_step.model_copy(
        update={"source_outcomes": tuple(serve_cve_search(search_step.source_outcomes))}
    )
    coverage_outcomes = serve_cve_search(evidence_set.coverage.source_outcomes)
    return restate_as_sufficient(evidence_set, [forged_step], coverage_outcomes)


def serve_the_semantic_topic_search(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    topic_step = evidence_set.trajectory.steps[0]
    forged_step = topic_step.model_copy(
        update={"source_outcomes": tuple(serve_cve_search(topic_step.source_outcomes))}
    )
    coverage_outcomes = serve_cve_search(evidence_set.coverage.source_outcomes)
    return restate_as_sufficient(evidence_set, [forged_step], coverage_outcomes)


def rewrite_the_affectedness_outcome_detail(
    evidence_set: KnowledgeEvidenceSet, detail: AffectednessDetail
) -> KnowledgeEvidenceSet:
    """``evidence_set`` with the coverage's affectedness outcome kept unavailable and its
    detail set to ``detail``, resealed."""
    forged_outcomes: list[SourceOutcome] = []
    for outcome in evidence_set.coverage.source_outcomes:
        if outcome.source is KnowledgeSource.AFFECTEDNESS:
            forged_outcomes.append(outcome.model_copy(update={"detail": detail}))
        else:
            forged_outcomes.append(outcome)
    coverage = evidence_set.coverage.model_copy(update={"source_outcomes": tuple(forged_outcomes)})
    return reseal_evidence_set(evidence_set, coverage=coverage)


def reword_the_affectedness_outcome(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The affectedness outcome with another of the server's sentences than the
    capability's."""
    return rewrite_the_affectedness_outcome_detail(evidence_set, AffectednessDetail.TIMEOUT)


def reword_the_affectedness_capability_and_outcome(
    evidence_set: KnowledgeEvidenceSet,
) -> KnowledgeEvidenceSet:
    """The affectedness capability and outcome rewritten to another of the server's
    sentences: the set agrees with itself and every detail is well formed, so only the
    comparison with the deployment's capabilities rejects it."""
    forged_set = replace_capability(
        evidence_set, "affectedness", detail=AffectednessDetail.TOOL_MISMATCH
    )
    return rewrite_the_affectedness_outcome_detail(forged_set, AffectednessDetail.TOOL_MISMATCH)


def drop_affectedness_outcome(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return present_as_sufficient(evidence_set)


def serve_affectedness(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    return present_as_sufficient(evidence_set, status=ResultStatus.OK, detail=None)


CAPABILITY_FORGERIES = [
    pytest.param(run_five_g_aka, empty_capabilities, SUBJECT_ORDER_VIOLATION, id="emptied"),
    pytest.param(run_five_g_aka, drop_model_planner, SUBJECT_ORDER_VIOLATION, id="entry_dropped"),
    pytest.param(
        run_five_g_aka, describe_cve_search_twice, SUBJECT_ORDER_VIOLATION, id="subject_twice"
    ),
    pytest.param(
        run_five_g_aka, swap_semantic_and_planner, SUBJECT_ORDER_VIOLATION, id="out_of_order"
    ),
    pytest.param(
        run_product_question,
        claim_affectedness_available,
        "the affectedness capability cannot be available",
        id="affectedness_available",
    ),
    pytest.param(
        run_product_question,
        claim_affectedness_unconfigured,
        "the affectedness capability cannot be not_configured",
        id="affectedness_unconfigured",
    ),
    pytest.param(
        run_product_question,
        drop_the_affectedness_detail,
        "the affectedness capability names a detail exactly when it is unavailable",
        id="affectedness_without_detail",
    ),
    pytest.param(
        run_without_fight,
        drop_the_unavailable_fight_detail,
        "the mitre_fight capability names a detail exactly when it is unavailable",
        id="unavailable_fight_without_detail",
    ),
    pytest.param(
        run_five_g_aka,
        give_cve_search_a_detail,
        "the cve_search capability names a detail exactly when it is unavailable",
        id="cve_search_with_detail",
    ),
    pytest.param(
        run_protocol_context,
        give_the_available_fight_a_detail,
        "the mitre_fight capability names a detail exactly when it is unavailable",
        id="available_fight_with_detail",
    ),
    pytest.param(
        run_five_g_aka,
        give_the_unconfigured_semantic_channel_a_detail,
        "the semantic_channel capability names a detail exactly when it is unavailable",
        id="semantic_channel_with_detail",
    ),
    pytest.param(
        run_five_g_aka,
        drop_cve_search_version,
        "the cve_search capability names a version exactly when",
        id="cve_search_without_version",
    ),
    pytest.param(
        run_protocol_context,
        drop_fight_coverage,
        "the mitre_fight capability names a coverage exactly when",
        id="fight_without_coverage",
    ),
    pytest.param(
        run_without_fight,
        version_the_unavailable_fight,
        "the mitre_fight capability names a version exactly when",
        id="unavailable_fight_with_version",
    ),
    pytest.param(
        run_five_g_aka,
        version_the_semantic_channel,
        "the semantic_channel capability names a version exactly when",
        id="semantic_channel_with_version",
    ),
    pytest.param(
        run_model_planner,
        hide_the_model_planner,
        "the model_planner capability does not describe the trajectory's model planner",
        id="model_planner_hidden",
    ),
    pytest.param(
        run_model_planner,
        rename_the_model,
        "the model_planner capability does not describe the trajectory's model planner",
        id="model_renamed",
    ),
    pytest.param(
        run_five_g_aka,
        invent_a_model_planner,
        "the model_planner capability does not describe the trajectory's deterministic planner",
        id="model_planner_invented",
    ),
    pytest.param(
        run_model_planner,
        claim_the_model_planner_unavailable,
        "the model_planner capability does not describe the trajectory's model planner",
        id="model_planner_claimed_unavailable",
    ),
    pytest.param(
        run_planner_without_a_key,
        drop_the_planner_detail,
        "the model_planner capability names a detail exactly when it is unavailable",
        id="unavailable_planner_without_detail",
    ),
    pytest.param(
        run_planner_without_a_key,
        give_the_planner_a_fight_sentence,
        "the model_planner capability's detail is not one of its sentences",
        id="unavailable_planner_with_a_fight_sentence",
    ),
    pytest.param(
        run_five_g_aka,
        give_the_unconfigured_planner_a_detail,
        "the model_planner capability names a detail exactly when it is unavailable",
        id="unconfigured_planner_with_detail",
    ),
    pytest.param(
        run_protocol_context,
        name_another_snapshot,
        "the mitre_fight capability names another snapshot than the pinned one",
        id="fight_other_snapshot",
    ),
    pytest.param(
        run_protocol_context,
        claim_full_fight_coverage,
        "the mitre_fight capability names another snapshot than the pinned one",
        id="fight_full_coverage",
    ),
    pytest.param(
        run_without_fight,
        claim_fight_pinned,
        "the mitre_fight capability names another snapshot than the pinned one",
        id="fight_available_without_a_pin",
    ),
    pytest.param(
        run_protocol_context,
        claim_fight_unavailable,
        "FiGHT served this set, but the mitre_fight capability is unavailable",
        id="fight_served_while_unavailable",
    ),
    pytest.param(
        run_pinned_semantic_hit,
        unconfigure_the_semantic_channel,
        "CVE-9999-0003 has a semantic hit, but the semantic channel cannot search",
        id="semantic_hit_without_channel",
    ),
    pytest.param(
        run_semantic_without_hits,
        unconfigure_the_semantic_channel,
        "step 1 ran the semantic channel, which cannot search, without reporting it",
        id="semantic_search_without_channel",
    ),
    pytest.param(
        run_semantic_with_an_unusable_adapter,
        drop_the_semantic_detail,
        "the semantic_channel capability names a detail exactly when it is unavailable",
        id="unavailable_semantic_channel_without_detail",
    ),
    pytest.param(
        run_semantic_with_an_unusable_adapter,
        give_the_semantic_channel_the_fight_sentence,
        "the semantic_channel capability's detail is not one of its sentences",
        id="unavailable_semantic_channel_with_a_fight_sentence",
    ),
]
# Forgeries that agree with themselves: only the comparison with the deployment's
# capabilities rejects them.
DEPLOYMENT_ONLY_FORGERIES = [
    pytest.param(
        run_semantic_with_an_unusable_adapter,
        hide_the_unusable_semantic_adapter,
        DEPLOYMENT_VIOLATION,
        id="unusable_semantic_adapter_hidden",
    ),
    pytest.param(
        run_planner_without_a_key,
        hide_the_unavailable_planner,
        DEPLOYMENT_VIOLATION,
        id="unavailable_planner_hidden",
    ),
    pytest.param(
        run_planner_without_a_key,
        name_another_planner_reason,
        DEPLOYMENT_VIOLATION,
        id="unavailable_planner_reason_changed",
    ),
    pytest.param(
        run_product_question,
        reword_the_affectedness_capability_and_outcome,
        DEPLOYMENT_VIOLATION,
        id="affectedness_capability_and_outcome_reworded",
    ),
]
AFFECTEDNESS_OUTCOME_VIOLATION = (
    "affectedness is unavailable: once a step ran, a required affectedness source is "
    "reported source_unavailable, and never otherwise"
)
AFFECTEDNESS_OUTCOME_FORGERIES = [
    pytest.param(
        run_product_question,
        drop_affectedness_outcome,
        AFFECTEDNESS_OUTCOME_VIOLATION,
        id="affectedness_outcome_dropped",
    ),
    pytest.param(
        run_product_question,
        serve_affectedness,
        AFFECTEDNESS_OUTCOME_VIOLATION,
        id="affectedness_served",
    ),
    pytest.param(
        run_product_question,
        reword_the_affectedness_outcome,
        "the affectedness outcome's detail is not the affectedness capability's detail",
        id="affectedness_outcome_reworded",
    ),
]


SEMANTIC_SERVED_VIOLATION = (
    "step 1 searched under a semantic request without a semantic channel that can search, "
    "but reports cve_search ok"
)
RUN_OBSERVATION_FORGERIES = [
    pytest.param(
        run_without_fight,
        drop_the_fight_outcome_to_sufficient,
        "step 1 records an outcome for other sources than it consulted",
        id="fight_outcome_dropped_to_sufficient",
    ),
    pytest.param(
        run_semantic_without_adapter,
        hide_the_semantic_search,
        "step 1 records the semantic channel where the request does not run it, or omits it "
        "where it does",
        id="semantic_channel_hidden",
    ),
    pytest.param(
        run_semantic_without_adapter,
        hide_the_semantic_search_to_sufficient,
        SEMANTIC_SERVED_VIOLATION,
        id="semantic_channel_hidden_to_sufficient",
    ),
    pytest.param(
        run_semantic_topic_without_adapter,
        serve_the_semantic_topic_search,
        SEMANTIC_SERVED_VIOLATION,
        id="semantic_topic_search_served",
    ),
    pytest.param(
        run_semantic_with_an_unusable_adapter,
        hide_the_semantic_search_to_sufficient,
        SEMANTIC_SERVED_VIOLATION,
        id="unusable_semantic_search_served",
    ),
    pytest.param(
        run_semantic_with_an_unusable_adapter,
        call_the_unusable_adapter_unconfigured,
        "step 1 reports a semantic channel failure that does not match the unavailable "
        "semantic_channel capability",
        id="unusable_semantic_failure_relabelled_unconfigured",
    ),
    pytest.param(
        run_semantic_without_adapter,
        call_the_missing_adapter_unusable,
        "step 1 reports a semantic channel failure that does not match the not_configured "
        "semantic_channel capability",
        id="unconfigured_semantic_failure_relabelled_unusable",
    ),
]


def test_reviewer_emptied_capabilities_are_rejected_after_reseal(
    fixture_bundle: FixtureBundle,
    pinned_fight_snapshot: KnownFightSnapshot,
    packaged_evidence_catalog: EvidenceCatalog,
) -> None:
    evidence_set, _ = run_five_g_aka(fixture_bundle)

    forged_set = empty_capabilities(evidence_set)

    with pytest.raises(EvidenceValidationError) as raised:
        validate_knowledge_evidence_set(
            forged_set,
            pinned_fight_snapshot,
            packaged_evidence_catalog,
            evidence_set.source_capabilities,
        )
    assert raised.value.violations == (DEPLOYMENT_VIOLATION, SUBJECT_ORDER_VIOLATION)


@pytest.mark.parametrize(
    ("run", "forgery", "expected_violation"),
    [*CAPABILITY_FORGERIES, *DEPLOYMENT_ONLY_FORGERIES],
)
def test_forged_capabilities_differ_from_the_deployment(
    fixture_bundle: FixtureBundle,
    packaged_evidence_catalog: EvidenceCatalog,
    run: Run,
    forgery: Forgery,
    expected_violation: str,
) -> None:
    evidence_set, pinned_fight_snapshot = run(fixture_bundle)

    forged_set = forgery(evidence_set)

    with pytest.raises(EvidenceValidationError) as raised:
        validate_knowledge_evidence_set(
            forged_set,
            pinned_fight_snapshot,
            packaged_evidence_catalog,
            evidence_set.source_capabilities,
        )
    assert DEPLOYMENT_VIOLATION in raised.value.violations


@pytest.mark.parametrize(
    ("run", "forgery", "expected_violation"),
    [*CAPABILITY_FORGERIES, *AFFECTEDNESS_OUTCOME_FORGERIES],
)
def test_forged_capabilities_are_rejected_even_as_the_deployment_s_own(
    fixture_bundle: FixtureBundle,
    packaged_evidence_catalog: EvidenceCatalog,
    run: Run,
    forgery: Forgery,
    expected_violation: str,
) -> None:
    """A composition root that described its deployment this way is caught at seal too."""
    evidence_set, pinned_fight_snapshot = run(fixture_bundle)

    forged_set = forgery(evidence_set)

    with pytest.raises(EvidenceValidationError) as raised:
        validate_knowledge_evidence_set(
            forged_set,
            pinned_fight_snapshot,
            packaged_evidence_catalog,
            forged_set.source_capabilities,
        )
    assert any(expected_violation in violation for violation in raised.value.violations)


@pytest.mark.parametrize(("run", "forgery", "expected_violation"), RUN_OBSERVATION_FORGERIES)
def test_run_contradicting_the_deployment_s_capabilities_is_rejected_after_reseal(
    fixture_bundle: FixtureBundle,
    packaged_evidence_catalog: EvidenceCatalog,
    run: Run,
    forgery: Forgery,
    expected_violation: str,
) -> None:
    evidence_set, pinned_fight_snapshot = run(fixture_bundle)

    forged_set = forgery(evidence_set)

    with pytest.raises(EvidenceValidationError) as raised:
        validate_knowledge_evidence_set(
            forged_set,
            pinned_fight_snapshot,
            packaged_evidence_catalog,
            evidence_set.source_capabilities,
        )
    assert any(expected_violation in violation for violation in raised.value.violations)


def list_capability_states(evidence_set: KnowledgeEvidenceSet) -> list[tuple[str, str]]:
    capability_states: list[tuple[str, str]] = []
    for capability in evidence_set.source_capabilities:
        capability_states.append((str(capability.source), capability.state.value))
    return capability_states


@pytest.mark.parametrize(
    ("run", "expected_states"),
    [
        (
            run_five_g_aka,
            ["available", "available", "unavailable", "not_configured", "not_configured"],
        ),
        (
            run_without_fight,
            ["available", "unavailable", "unavailable", "not_configured", "not_configured"],
        ),
        (
            run_pinned_semantic_hit,
            ["available", "available", "unavailable", "available", "not_configured"],
        ),
        (
            run_semantic_with_an_unusable_adapter,
            ["available", "available", "unavailable", "unavailable", "not_configured"],
        ),
        (
            run_model_planner,
            ["available", "available", "unavailable", "not_configured", "available"],
        ),
        (
            run_planner_without_a_key,
            ["available", "available", "unavailable", "not_configured", "unavailable"],
        ),
    ],
    ids=[
        "packaged",
        "fight_unavailable",
        "semantic_channel_wired",
        "semantic_adapter_unusable",
        "model_planner",
        "model_planner_without_a_key",
    ],
)
def test_genuine_run_reports_its_deployment_s_capabilities(
    fixture_bundle: FixtureBundle, run: Run, expected_states: list[str]
) -> None:
    evidence_set, _ = run(fixture_bundle)

    capability_states = list_capability_states(evidence_set)

    subjects = ["cve_search", "mitre_fight", "affectedness", "semantic_channel", "model_planner"]
    assert capability_states == list(zip(subjects, expected_states, strict=True))


def test_semantic_request_without_an_adapter_validates_as_not_configured(
    fixture_bundle: FixtureBundle,
    pinned_fight_snapshot: KnownFightSnapshot,
    packaged_evidence_catalog: EvidenceCatalog,
) -> None:
    request = build_investigation_request("5G-AKA", "implementation_only", semantic=True)
    evidence_set, _ = run_on(fixture_bundle, request)

    validate_knowledge_evidence_set(
        evidence_set,
        pinned_fight_snapshot,
        packaged_evidence_catalog,
        evidence_set.source_capabilities,
    )

    assert ("semantic_channel", "not_configured") in list_capability_states(evidence_set)


@pytest.mark.parametrize("row", GOLD_ROWS, ids=label_row)
def test_gold_row_reports_the_capabilities_its_deployment_is_built_with(
    fixture_bundle: FixtureBundle, packaged_evidence_catalog: EvidenceCatalog, row: dict[str, Any]
) -> None:
    fight_choice: FightChoice = row["sources"]["mitre_fight"]
    fight_source, pinned_fight_snapshot = choose_fight_source(fight_choice)
    deployment_capabilities = (
        *describe_source_capabilities(
            fixture_bundle.describe_served_dataset(),
            fight_source,
            pinned_fight_snapshot,
            build_fixture_service(fixture_bundle),
            describe_affectedness(DisabledTrustifyAdapter()),
        ),
        describe_planner_capability(describe_deterministic_planner()),
    )
    request = InvestigationRequest.model_validate(row["request"])

    evidence_set, _ = run_on(fixture_bundle, request, fight_choice)

    validate_knowledge_evidence_set(
        evidence_set, pinned_fight_snapshot, packaged_evidence_catalog, deployment_capabilities
    )
