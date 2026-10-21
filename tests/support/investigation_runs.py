"""Genuine investigation runs over the synthetic fixture that the validator, the
decision-path audit and replay tests start from, then forge or replay."""

from typing import Any

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.domain.investigation import InvestigationRequest, KnowledgeEvidenceSet
from cve_kgrag.domain.planning import ModelPlannerUnavailableDetail, ModelReply
from cve_kgrag.domain.search import RetrievalOutcome
from cve_kgrag.domain.taxonomy import BackendStatus
from tests.support.clocks import SteppingClock
from tests.support.fakes import CannedRetriever, InventingRetriever, build_lexical_match
from tests.support.investigation import (
    build_deadline_nearing_service,
    build_investigation_request,
    build_test_investigation_service,
)
from tests.support.planners import UNAVAILABLE_REPLY, ScriptedModelPort, build_plan_reply


def investigate(
    fixture_bundle: FixtureBundle, query: str, scope: str, **request_fields: Any
) -> KnowledgeEvidenceSet:
    """The set the deterministic policy seals for the request."""
    request = build_investigation_request(query, scope, **request_fields)
    return build_test_investigation_service(fixture_bundle).investigate(request)


def investigate_with_model_replies(
    fixture_bundle: FixtureBundle, request: InvestigationRequest, *model_replies: ModelReply
) -> KnowledgeEvidenceSet:
    """The set sealed for ``request`` under a model planner that returns ``model_replies``,
    one per round."""
    model_port = ScriptedModelPort(list(model_replies))
    service = build_test_investigation_service(fixture_bundle, model_port=model_port)
    return service.investigate(request)


def build_semantic_hit_retriever() -> CannedRetriever:
    """A wired semantic channel that matches CVE-9999-0003."""
    return CannedRetriever(
        RetrievalOutcome(status=BackendStatus.OK, matches=(build_lexical_match("CVE-9999-0003"),))
    )


def run_semantic_hit(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """A semantic request for 5G-AKA, whose wired semantic channel matches CVE-9999-0003."""
    service = build_test_investigation_service(
        fixture_bundle, semantic_retriever=build_semantic_hit_retriever()
    )
    request = build_investigation_request("5G-AKA", "implementation_only", semantic=True)
    return service.investigate(request)


def run_five_g_aka(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """One ``cve_search("5g aka")`` finds CVE-9999-0003 and CVE-9999-0004."""
    return investigate(fixture_bundle, "5G-AKA", "implementation_only")


def investigate_without_a_usable_planner(
    fixture_bundle: FixtureBundle, unavailable_detail: ModelPlannerUnavailableDetail
) -> KnowledgeEvidenceSet:
    """``5G-AKA`` planned by the deterministic policy in place of a configured model planner
    that cannot plan, for ``unavailable_detail``."""
    service = build_test_investigation_service(
        fixture_bundle, planner_unavailable_detail=unavailable_detail
    )
    return service.investigate(build_investigation_request("5G-AKA", "implementation_only"))


def run_planner_without_a_key(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    return investigate_without_a_usable_planner(
        fixture_bundle, ModelPlannerUnavailableDetail.MISSING_API_KEY
    )


def run_planner_adapter_unusable(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    return investigate_without_a_usable_planner(
        fixture_bundle, ModelPlannerUnavailableDetail.ADAPTER_UNUSABLE
    )


def run_open5gs_product_question(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """A 5G-AKA question about the product open5gs, whose applicability stays unknown."""
    return investigate(
        fixture_bundle, "5gaka", "implementation_only", filters={"products": ["open5gs"]}
    )


def run_five_g_aka_mixed(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """The pending-review card explored with one ``topic_context`` step: a FiGHT search,
    then one CVE search per query template."""
    return investigate(fixture_bundle, "5G-AKA", "mixed")


def run_exact_id(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """One deterministic round: the lookup of CVE-9999-0003 returns it in a 2,513-byte
    response."""
    return investigate(fixture_bundle, "CVE-9999-0003", "implementation_only")


def run_over_the_byte_cap(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """``5G-AKA`` under a byte cap one byte below its one response: the step is discarded
    and the run stops ``budget_exhausted`` on a ``context_bytes`` breach."""
    step_bytes = run_five_g_aka(fixture_bundle).trajectory.steps[0].context_bytes
    return investigate(
        fixture_bundle,
        "5G-AKA",
        "implementation_only",
        budget={"max_context_bytes": step_bytes - 1},
    )


def run_refinement(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """Two deterministic rounds: a literal search for ``5gaka`` finds nothing, so round 2
    explores the topic."""
    return investigate(fixture_bundle, "5gaka", "implementation_only")


def run_cve_under_protocol_scope(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """No round: a CVE ID under ``protocol_context_only`` is blocked at interpretation."""
    return investigate(fixture_bundle, "CVE-9999-0003", "protocol_context_only")


def run_policy_plan_over_budget(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """One deterministic round whose topic call costs more tool calls than the cap allows,
    so the gate rejects the policy's plan and nothing runs."""
    return investigate(
        fixture_bundle, "5gaka", "protocol_context_only", budget={"max_tool_calls": 1}
    )


def run_model_accepted(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """One round whose model plan, ``cve_search("ausf suci")``, passes the gate and runs."""
    return investigate_with_model_replies(
        fixture_bundle,
        build_investigation_request("5G-AKA", "implementation_only"),
        build_plan_reply({"tool": "cve_search", "query": "ausf suci"}),
    )


def run_model_low_signal_search(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """One round whose model plan, ``cve_search("cve ausf suci")``, passes the gate and runs
    as ``cve_search("ausf suci")``."""
    return investigate_with_model_replies(
        fixture_bundle,
        build_investigation_request("5G-AKA", "implementation_only"),
        build_plan_reply({"tool": "cve_search", "query": "cve ausf suci"}),
    )


def run_model_rejected(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """One round whose model plan looks up an ID the caller never named, so the gate
    rejects it and the policy's lookup runs."""
    return investigate_with_model_replies(
        fixture_bundle,
        build_investigation_request("CVE-9999-0003", "implementation_only"),
        build_plan_reply({"tool": "cve_exact_lookup", "cve_ids": ["CVE-9999-0004"]}),
    )


def run_with_invalid_evidence(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """The lexical channel invents a record, so the step's evidence fails integrity and the
    step records no response."""
    service = build_test_investigation_service(
        fixture_bundle, lexical_retriever=InventingRetriever()
    )
    return service.investigate(build_investigation_request("crash", "implementation_only"))


def run_model_unavailable(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """Two rounds whose model planner was unavailable, so the policy's plans ran."""
    model_port = ScriptedModelPort([UNAVAILABLE_REPLY, UNAVAILABLE_REPLY])
    service = build_test_investigation_service(fixture_bundle, model_port=model_port)
    return service.investigate(build_investigation_request("5gaka", "implementation_only"))


def run_model_skipped_at_deadline(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """A model-planned round 1, then a round 2 whose planner the deadline left unconsulted."""
    model_port = ScriptedModelPort([build_plan_reply({"tool": "cve_search", "query": "zzqx"})])
    service = build_deadline_nearing_service(fixture_bundle, model_port)
    return service.investigate(build_investigation_request("zzqx", "implementation_only"))


def run_model_refinement_unavailable(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """The reviewer's run: a model-planned search that found nothing, then a round 2 whose
    consulted planner was unavailable and which had no policy refinement to fall back to."""
    model_port = ScriptedModelPort(
        [build_plan_reply({"tool": "cve_search", "query": "zzqx"}), UNAVAILABLE_REPLY]
    )
    service = build_test_investigation_service(fixture_bundle, model_port=model_port)
    return service.investigate(build_investigation_request("zzqx", "implementation_only"))


def run_model_reply_after_deadline(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    """One round whose model plan landed after the deadline, so nothing ran."""
    clock = SteppingClock()
    model_port = ScriptedModelPort(
        [build_plan_reply({"tool": "cve_search", "query": "ausf suci"})],
        clock=clock,
        seconds_per_call=31,
    )
    service = build_test_investigation_service(
        fixture_bundle, model_port=model_port, monotonic_clock=clock.read
    )
    return service.investigate(build_investigation_request("5G-AKA", "implementation_only"))
