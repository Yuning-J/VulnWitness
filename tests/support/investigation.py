"""Investigation services over the synthetic fixture, wired like production with fixed clocks
(or the real monotonic clock around a blocking backend), builders for requests and tool
calls, the gold trajectories, and loop-based extractors for asserting on evidence sets."""

import threading
import time
from collections.abc import Callable
from dataclasses import replace
from typing import Any, Literal

import yaml

from cve_kgrag.adapters.fight.pinned_yaml import UnavailableFightSource
from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.adapters.lexical.bm25_index import Bm25LexicalIndex
from cve_kgrag.adapters.memory.in_memory_evidence_catalog import InMemoryEvidenceCatalog
from cve_kgrag.application.decision_path_audit import audit_decision_path
from cve_kgrag.application.investigate import InvestigationService
from cve_kgrag.application.investigation_deployment import InvestigationDeployment
from cve_kgrag.application.planner_setup import DeterministicPlanning, PlannerSetup
from cve_kgrag.application.serving_data_plane import ServingDataPlane
from cve_kgrag.composition import (
    build_investigation_deployment,
    build_investigation_service,
    build_serving_data_plane,
    load_packaged_fight_source,
)
from cve_kgrag.domain.evidence import EvidenceAnchor
from cve_kgrag.domain.evidence_catalog import EvidenceCatalog
from cve_kgrag.domain.investigation import (
    EvidenceNeedKind,
    InvestigationRequest,
    KnowledgeEvidenceSet,
    NeedOutcome,
    SourceCapability,
    StepReason,
)
from cve_kgrag.domain.investigation_validation import validate_knowledge_evidence_set
from cve_kgrag.domain.planning import (
    CveExactLookupCall,
    CveSearchCall,
    ModelPlannerUnavailableDetail,
    ToolName,
    TopicContextCall,
)
from cve_kgrag.domain.threat_context import KnownFightSnapshot
from cve_kgrag.domain.topic import ReviewStatus, TopicReview
from cve_kgrag.ports.affectedness import TrustifyPort
from cve_kgrag.ports.planning import ModelPort
from cve_kgrag.ports.sources import FightSource
from cve_kgrag.topics.registry import TopicRegistry
from tests.support.clocks import SteppingClock, read_fixed_clock
from tests.support.fakes import (
    BlockingFightSource,
    BlockingRetriever,
    DeadlineNearingRetriever,
    FailingFightSource,
)
from tests.support.paths import GOLD_DIR
from tests.support.planners import plan_with
from tests.support.services import build_fixture_service

FightChoice = Literal["packaged", "unavailable", "failing"]
BlockingBackend = Literal["lexical", "fight"]
FIVE_G_AKA_TOPIC_ID = "3gpp:5g-aka"
# Free text no topic resolves whose words the packaged FiGHT excerpt holds (FGT5019,
# FGT5040, FGT1499.503 and FGT5019.005 name SUCI or discovery) and whose CVE search finds
# CVE-9999-0004: its words may go to FiGHT.
FIGHT_FREE_TEXT_QUERY = "SUCI discovery"
# "5G-AKA", then 72 words written with the ﬃ ligature (one character, "ffi" once
# normalized): 366 characters as typed, whose search terms fill 510 of a search's 512
# characters once normalized, so a search adding a card term to them runs without it.
FILLED_SEARCH_LIMIT_QUERY = "5G-AKA " + " ".join(f"ﬃ{index:03d}" for index in range(72))
# Twenty unknown IDs, then a known one: one more than a lookup takes.
# Spellings of a low-signal word that a search drops whole: a possessive with any
# apostrophe, and an invisible character inside the word. Each is a valid request query.
DISGUISED_LOW_SIGNAL_WORDS = {
    "possessive": "CVE's",
    "possessive_with_a_right_quotation_mark": "CVE\u2019s",
    "possessive_with_a_modifier_apostrophe": "cve\u02bcs",
    "fullwidth_possessive": "\uff23\uff36\uff25\uff07\uff53",
    "zero_width_space_inside": "c\u200bve",
    "variation_selector_inside": "cv\ufe0fe",
    "soft_hyphen_inside_the_plural": "C\u00adVEs",
}
# The same spellings plus a control character inside the word, which no request query
# holds but a model-proposed search may: the text rules read past it as well.
MODEL_DISGUISED_LOW_SIGNAL_WORDS = {
    **DISGUISED_LOW_SIGNAL_WORDS,
    "control_character_inside": "c\x01ve",
}
TWENTY_ONE_IDS = " ".join(f"CVE-9999-{4200 + index}" for index in range(20)) + " CVE-9999-0003"
GOLD_FILE = GOLD_DIR / "m4_trajectories.yaml"
# The validator's violation for a set whose capabilities are not the verifying service's.
DEPLOYMENT_VIOLATION = "source_capabilities differ from the capabilities this service serves"
# The audit's violation for a ranking this code does not apply.
RANKING_VIOLATION = "the trajectory's ranking is not the one this code applies"


def load_gold_rows() -> list[dict[str, Any]]:
    """The hand-labelled gold trajectories."""
    gold_rows: list[dict[str, Any]] = yaml.safe_load(GOLD_FILE.read_text(encoding="utf-8"))[
        "trajectories"
    ]
    return gold_rows


def label_row(row: dict[str, Any]) -> str:
    """A gold row's ID, used as its pytest parameter ID."""
    return str(row["id"])


def build_investigation_request(query: str, scope: str, **fields: Any) -> InvestigationRequest:
    return InvestigationRequest.model_validate({"query": query, "scope": scope, **fields})


# A 5G-AKA question with a one-second wall-time budget: a run that blocks waits out a real
# one-second deadline.
ONE_SECOND_REQUEST = build_investigation_request(
    "5G-AKA", "implementation_only", budget={"max_wall_time_seconds": 1}
)


def build_search_call(query: str) -> CveSearchCall:
    return CveSearchCall(tool=ToolName.CVE_SEARCH, query=query)


def build_topic_call(topic_id: str = FIVE_G_AKA_TOPIC_ID) -> TopicContextCall:
    return TopicContextCall(tool=ToolName.TOPIC_CONTEXT, topic_id=topic_id)


def build_exact_lookup_call(*cve_ids: str) -> CveExactLookupCall:
    return CveExactLookupCall(tool=ToolName.CVE_EXACT_LOOKUP, cve_ids=cve_ids)


def choose_fight_source(fight: FightChoice) -> tuple[FightSource, KnownFightSnapshot | None]:
    """The packaged excerpt with its catalog pin, a source that serves nothing, or the
    pinned packaged excerpt whose every search fails."""
    if fight == "unavailable":
        return UnavailableFightSource(), None
    packaged_fight_source, pinned_fight_snapshot = load_packaged_fight_source(read_fixed_clock)
    if fight == "failing":
        return FailingFightSource(packaged_fight_source), pinned_fight_snapshot
    return packaged_fight_source, pinned_fight_snapshot


def list_packaged_fight_anchors() -> list[EvidenceAnchor]:
    """The anchors of the packaged FiGHT excerpt, as its pinned deployment catalogues them."""
    return list(choose_fight_source("packaged")[0].list_evidence())


def build_test_investigation_service(
    bundle: FixtureBundle,
    *,
    fight: FightChoice = "packaged",
    review_status: ReviewStatus | None = None,
    model_port: ModelPort | None = None,
    planner_unavailable_detail: ModelPlannerUnavailableDetail | None = None,
    trustify_port: TrustifyPort | None = None,
    monotonic_clock: Callable[[], float] | None = None,
    **retrievers: Any,
) -> InvestigationService:
    """The production wiring over ``bundle``, with the retrievers passed by keyword replaced.

    With ``model_port`` the model plans (``plan_with``); without it the deterministic
    policy plans, in place of a configured model planner that cannot plan when
    ``planner_unavailable_detail`` says why. Without ``trustify_port`` affectedness is the
    disabled adapter's. Without ``monotonic_clock`` time never advances, so no deadline is
    ever reached.
    """
    fight_source, pinned_fight_snapshot = choose_fight_source(fight)
    planner_setup: PlannerSetup
    if model_port is None:
        planner_setup = DeterministicPlanning(planner_unavailable_detail)
    else:
        planner_setup = plan_with(model_port)
    data_plane = build_serving_data_plane(
        bundle,
        search_service=build_fixture_service(bundle, **retrievers),
        fight_source=fight_source,
        pinned_fight_snapshot=pinned_fight_snapshot,
        clock=read_fixed_clock,
    )
    if review_status is not None:
        data_plane = with_topic_review(data_plane, review_status)
    return build_investigation_service(
        data_plane,
        planner_setup=planner_setup,
        trustify_port=trustify_port,
        wall_clock=read_fixed_clock,
        monotonic_clock=monotonic_clock or SteppingClock().read,
    )


def with_topic_review(
    data_plane: ServingDataPlane, review_status: ReviewStatus
) -> ServingDataPlane:
    """The fixture data plane with an explicitly synthetic review of its topic."""
    topic = data_plane.topic_registry.list_topics()[0].topic
    review = TopicReview(
        status=review_status,
        reviewer="Synthetic test reviewer" if review_status is ReviewStatus.REVIEWED else None,
        reviewed_on="2026-10-01" if review_status is ReviewStatus.REVIEWED else None,
        basis="Synthetic review for sufficiency tests only.",
    )
    registry = TopicRegistry([topic.model_copy(update={"review": review})])
    return replace(data_plane, topic_registry=registry)


def build_deadline_nearing_service(
    bundle: FixtureBundle,
    model_port: ModelPort | None = None,
    *,
    review_status: ReviewStatus | None = None,
) -> InvestigationService:
    """The production wiring whose first lexical search lands at 29.5 seconds, in time, after
    which every clock read moves on a second, so the next deadline check finds the default
    30-second cap reached."""
    clock = SteppingClock()
    nearing_lexical = DeadlineNearingRetriever(
        Bm25LexicalIndex(bundle.records), clock, seconds=29.5, seconds_per_read=1.0
    )
    return build_test_investigation_service(
        bundle,
        model_port=model_port,
        monotonic_clock=clock.read,
        lexical_retriever=nearing_lexical,
        review_status=review_status,
    )


def build_blocking_investigation_service(
    bundle: FixtureBundle, blocking_backend: BlockingBackend, release: threading.Event
) -> InvestigationService:
    """The production wiring on the real monotonic clock, with the lexical channel or the
    packaged FiGHT source blocking every search until ``release`` is set."""
    packaged_fight_source, pinned_fight_snapshot = load_packaged_fight_source(read_fixed_clock)
    retrievers: dict[str, Any] = {}
    fight_source: FightSource = packaged_fight_source
    if blocking_backend == "lexical":
        retrievers["lexical_retriever"] = BlockingRetriever(release)
    else:
        fight_source = BlockingFightSource(packaged_fight_source, release)
    return build_investigation_service(
        build_serving_data_plane(
            bundle,
            search_service=build_fixture_service(bundle, **retrievers),
            fight_source=fight_source,
            pinned_fight_snapshot=pinned_fight_snapshot,
            clock=read_fixed_clock,
        ),
        wall_clock=read_fixed_clock,
        monotonic_clock=time.monotonic,
    )


def build_test_deployment(
    bundle: FixtureBundle,
    *,
    fight: FightChoice = "packaged",
    review_status: ReviewStatus | None = None,
    trustify_port: TrustifyPort | None = None,
    monotonic_clock: Callable[[], float] | None = None,
    **retrievers: Any,
) -> InvestigationDeployment:
    """The deployment ``build_test_investigation_service`` wires from the same arguments:
    the one a set is replayed against.

    Without ``trustify_port`` affectedness is the disabled adapter's. Without
    ``monotonic_clock`` time never advances, so no deadline is ever reached.
    """
    fight_source, pinned_fight_snapshot = choose_fight_source(fight)
    data_plane = build_serving_data_plane(
        bundle,
        search_service=build_fixture_service(bundle, **retrievers),
        fight_source=fight_source,
        pinned_fight_snapshot=pinned_fight_snapshot,
        clock=read_fixed_clock,
    )
    if review_status is not None:
        data_plane = with_topic_review(data_plane, review_status)
    return build_investigation_deployment(
        data_plane,
        trustify_port=trustify_port,
        wall_clock=read_fixed_clock,
        monotonic_clock=monotonic_clock or SteppingClock().read,
    )


def verify_as_sealed(
    evidence_set: KnowledgeEvidenceSet,
    pinned_fight_snapshot: KnownFightSnapshot | None,
    evidence_catalog: EvidenceCatalog,
    source_capabilities: tuple[SourceCapability, ...],
    topic_registry: TopicRegistry,
) -> None:
    """The checks the service runs on every set it seals, in its order."""
    validate_knowledge_evidence_set(
        evidence_set, pinned_fight_snapshot, evidence_catalog, source_capabilities
    )
    audit_decision_path(evidence_set, topic_registry, evidence_catalog)


def reseal_evidence_set(evidence_set: KnowledgeEvidenceSet, **changes: Any) -> KnowledgeEvidenceSet:
    """``evidence_set`` with ``changes`` applied unvalidated and its hash recomputed, as a
    forger holding the set could do."""
    changed_set = evidence_set.model_copy(update=changes)
    return changed_set.model_copy(update={"result_sha256": changed_set.compute_result_sha256()})


def update_trajectory(evidence_set: KnowledgeEvidenceSet, **changes: Any) -> KnowledgeEvidenceSet:
    """``evidence_set`` with ``changes`` applied to its trajectory, resealed."""
    return reseal_evidence_set(
        evidence_set, trajectory=evidence_set.trajectory.model_copy(update=changes)
    )


def update_interpretation(
    evidence_set: KnowledgeEvidenceSet, **changes: Any
) -> KnowledgeEvidenceSet:
    """``evidence_set`` with ``changes`` applied to its interpretation, resealed."""
    return reseal_evidence_set(
        evidence_set, interpretation=evidence_set.interpretation.model_copy(update=changes)
    )


def rewrite_step(
    evidence_set: KnowledgeEvidenceSet, step_index: int, **changes: Any
) -> KnowledgeEvidenceSet:
    """``evidence_set`` resealed with ``changes`` applied to one step only."""
    steps = list(evidence_set.trajectory.steps)
    steps[step_index - 1] = steps[step_index - 1].model_copy(update=changes)
    return update_trajectory(evidence_set, steps=tuple(steps))


def rewrite_the_ranking(evidence_set: KnowledgeEvidenceSet) -> KnowledgeEvidenceSet:
    """The ranking claims another RRF constant and the tiers in reverse order, resealed: a
    forgery the validator accepts and the decision-path audit rejects."""
    ranking = evidence_set.trajectory.ranking
    forged_ranking = ranking.model_copy(
        update={"rrf_k": 1, "relevance_tier_order": tuple(reversed(ranking.relevance_tier_order))}
    )
    return update_trajectory(evidence_set, ranking=forged_ranking)


def list_step_reasons(evidence_set: KnowledgeEvidenceSet) -> list[StepReason]:
    step_reasons: list[StepReason] = []
    for step in evidence_set.trajectory.steps:
        step_reasons.append(step.reason)
    return step_reasons


def list_step_tools(evidence_set: KnowledgeEvidenceSet) -> list[str]:
    step_tools: list[str] = []
    for step in evidence_set.trajectory.steps:
        step_tools.append(step.call.tool.value)
    return step_tools


def list_transitions(evidence_set: KnowledgeEvidenceSet) -> list[list[str]]:
    """Each transition as ``[from_state, to_state, basis]``."""
    transitions: list[list[str]] = []
    for transition in evidence_set.trajectory.transitions:
        transitions.append(
            [transition.from_state.value, transition.to_state.value, transition.basis.value]
        )
    return transitions


def list_implementation_ids(evidence_set: KnowledgeEvidenceSet) -> list[str]:
    cve_ids: list[str] = []
    for investigation_candidate in evidence_set.implementation_candidates:
        cve_ids.append(investigation_candidate.candidate.record.cve_id)
    return cve_ids


def list_excluded_ids(evidence_set: KnowledgeEvidenceSet) -> list[str]:
    cve_ids: list[str] = []
    for excluded_candidate in evidence_set.excluded_implementation_candidates:
        cve_ids.append(excluded_candidate.candidate.candidate.record.cve_id)
    return cve_ids


def list_warning_codes(evidence_set: KnowledgeEvidenceSet) -> list[str]:
    warning_codes: list[str] = []
    for warning in evidence_set.warnings:
        warning_codes.append(warning.code.value)
    return warning_codes


def list_need_outcomes(
    evidence_set: KnowledgeEvidenceSet,
) -> list[tuple[EvidenceNeedKind, str | None, NeedOutcome]]:
    need_outcomes: list[tuple[EvidenceNeedKind, str | None, NeedOutcome]] = []
    for need in evidence_set.coverage.needs:
        need_outcomes.append((need.kind, need.subject, need.outcome))
    return need_outcomes


def build_productless_catalog() -> InMemoryEvidenceCatalog:
    """A catalog that holds nothing and so names no product: interpreting a query with it
    records no product version, whatever the query asks."""
    return InMemoryEvidenceCatalog((), ())


def build_reviewed_investigation_service(
    bundle: FixtureBundle, **options: Any
) -> InvestigationService:
    """A fixture service with a synthetic reviewed topic for planner behavior tests."""
    return build_test_investigation_service(bundle, review_status=ReviewStatus.REVIEWED, **options)


def build_reviewed_deployment(bundle: FixtureBundle, **options: Any) -> InvestigationDeployment:
    """The deployment matching the explicitly reviewed planner-test service."""
    return build_test_deployment(bundle, review_status=ReviewStatus.REVIEWED, **options)
