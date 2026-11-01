"""Fixture CVEs and scripted assessor replies for the bounded relevance loop."""

import json
from typing import Any

from tests.support.builders import build_bundle_with
from tests.support.investigation import (
    build_investigation_request,
    build_test_investigation_service,
)
from tests.support.planners import ScriptedModelPort, build_text_reply
from vulnwitness.adapters.fixture.synthetic_fixture import FixtureBundle
from vulnwitness.application.relevance_assessment import build_relevance_input
from vulnwitness.domain.cve import CveRecord
from vulnwitness.domain.investigation import InvestigationRequest, KnowledgeEvidenceSet
from vulnwitness.domain.planning import ModelReply

QUESTION = "gateway"
REFINED_QUERY = "sourced component"
NEW_CVE_ID = "CVE-9999-0300"


def build_relevance_bundle(fixture_bundle: FixtureBundle) -> FixtureBundle:
    bundle = FixtureBundle(fixture_bundle.manifest, (), ())
    for index in range(20):
        bundle = build_bundle_with(
            bundle,
            f"CVE-9999-{100 + index:04d}",
            "[SYNTHETIC] gateway noise",
            affected=[
                {"vendor": "fixturevendor", "product": "sourced_component", "status": "affected"}
            ],
        )
    return build_bundle_with(
        bundle,
        NEW_CVE_ID,
        "[SYNTHETIC] sourced component flaw in sourced component",
        affected=[
            {"vendor": "fixturevendor", "product": "sourced_component", "status": "affected"}
        ],
    )


def build_assessment_reply(
    request: InvestigationRequest,
    records: tuple[CveRecord, ...],
    labels: tuple[str, ...],
    **proposal: Any,
) -> ModelReply:
    _, keys = build_relevance_input(request, records)
    labels_by_cve: dict[str, str] = {}
    for record, label in zip(records, labels, strict=True):
        labels_by_cve[record.cve_id] = label
    labels_by_key: dict[str, str] = {}
    for key, cve_id in keys.items():
        labels_by_key[key] = labels_by_cve[cve_id]
    return build_text_reply(json.dumps({"labels": labels_by_key, **proposal}))


def build_refinement_proposal(
    query: str = REFINED_QUERY, component: str = QUESTION
) -> dict[str, Any]:
    return {
        "gap": {"component": component, "reason": "coverage_unclear", "note": "Check coverage"},
        "search": {"tool": "cve_search", "query": query},
    }


def build_loop_model(bundle: FixtureBundle, request: InvestigationRequest) -> ScriptedModelPort:
    labels = ["relevant", "cannot_tell"]
    for _ in range(18):
        labels.append("not_relevant")
    first = build_assessment_reply(
        request, bundle.records[:20], tuple(labels), **build_refinement_proposal()
    )
    second = build_assessment_reply(request, bundle.records[20:], ("relevant",))
    return ScriptedModelPort([], assessment_replies=[first, second])


def run_relevance_loop(bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    request = build_investigation_request(QUESTION, "implementation_only")
    service = build_test_investigation_service(bundle, model_port=build_loop_model(bundle, request))
    return service.investigate(request)
