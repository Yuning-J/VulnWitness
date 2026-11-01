"""The knowledge tools answer the hand-labelled M5 gold file."""

from typing import Any

import pytest
import yaml

from tests.support.investigation import label_row
from tests.support.paths import GOLD_DIR
from tests.support.toolbox import build_test_toolbox
from vulnwitness.adapters.fixture.synthetic_fixture import FixtureBundle
from vulnwitness.domain.investigation import InvestigationState
from vulnwitness.domain.tool_contracts import ToolFailure
from vulnwitness.interfaces.knowledge_tools import KnowledgeToolName

GOLD_FILE = GOLD_DIR / "m5_tool_queries.yaml"
GOLD_ROWS: list[dict[str, Any]] = yaml.safe_load(GOLD_FILE.read_text(encoding="utf-8"))["rows"]


def summarize_search(search_response: dict[str, Any]) -> dict[str, Any]:
    candidate_ids: list[str] = []
    for candidate in search_response["candidates"]:
        candidate_ids.append(candidate["record"]["cve_id"])
    warnings: list[list[str]] = []
    for warning in search_response["warnings"]:
        warnings.append([warning["code"], warning["subject"]])
    return {
        "status": search_response["status"],
        "channels": search_response["channels_executed"],
        "candidates": candidate_ids,
        "warnings": warnings,
    }


def summarize_resolution(concept_resolution: dict[str, Any]) -> dict[str, Any]:
    matches: list[list[str]] = []
    for match in concept_resolution["resolution"]["matches"]:
        matches.append([match["topic_id"], match["match_kind"]])
    excluded_terms: list[str] = []
    for excluded_term in concept_resolution["resolution"]["excluded_terms"]:
        excluded_terms.append(excluded_term["term"])
    return {"matches": matches, "excluded": excluded_terms}


def summarize_topic_context(topic_context: dict[str, Any]) -> dict[str, Any]:
    technique_ids: list[str] = []
    for technique in topic_context["protocol_context"]:
        technique_ids.append(technique["technique_id"])
    implementation_ids: list[str] = []
    for topic_candidate in topic_context["implementation_candidates"]:
        implementation_ids.append(topic_candidate["candidate"]["record"]["cve_id"])
    excluded_ids: list[str] = []
    for excluded_candidate in topic_context["excluded_implementation_candidates"]:
        excluded_ids.append(excluded_candidate["candidate"]["candidate"]["record"]["cve_id"])
    return {
        "status": topic_context["status"],
        "protocol_context": technique_ids,
        "implementation_candidates": implementation_ids,
        "excluded_implementation_candidates": excluded_ids,
    }


def summarize_capabilities(knowledge_capabilities: dict[str, Any]) -> dict[str, Any]:
    states: dict[str, str] = {}
    for capability in knowledge_capabilities["source_capabilities"]:
        states[capability["source"]] = capability["state"]
    return {"states": states}


def summarize_evidence_set(evidence_set: dict[str, Any]) -> dict[str, Any]:
    validate_basis = None
    for transition in evidence_set["trajectory"]["transitions"]:
        if transition["to_state"] == InvestigationState.VALIDATE.value:
            validate_basis = transition["basis"]
    applicability: list[dict[str, str]] = []
    for product_applicability in evidence_set["product_applicability"]:
        applicability.append(
            {"product": product_applicability["product"], "status": product_applicability["status"]}
        )
    return {
        "stop_reason": evidence_set["stop_reason"],
        "status": evidence_set["status"],
        "validate_basis": validate_basis,
        "applicability": applicability,
    }


def summarize_answer(tool_name: KnowledgeToolName, tool_answer: dict[str, Any]) -> dict[str, Any]:
    """The fields of an answer the gold file labels for ``tool_name``."""
    match tool_name:
        case KnowledgeToolName.SEARCH_VULNERABILITIES | KnowledgeToolName.LOOKUP_CVE:
            return summarize_search(tool_answer)
        case KnowledgeToolName.RESOLVE_TELECOM_CONCEPT:
            return summarize_resolution(tool_answer)
        case KnowledgeToolName.SEARCH_FIGHT:
            return summarize_topic_context(tool_answer)
        case KnowledgeToolName.CHECK_AFFECTEDNESS:
            return {
                "applicability": tool_answer["applicability"],
                "failure": tool_answer["failure"],
            }
        case KnowledgeToolName.GET_KNOWLEDGE_CAPABILITIES:
            return summarize_capabilities(tool_answer)
        case KnowledgeToolName.INVESTIGATE_TELECOM_TOPIC:
            return summarize_evidence_set(tool_answer)
        case KnowledgeToolName.GET_EVIDENCE:
            return {"evidence_id": tool_answer["evidence"]["evidence_id"]}


@pytest.mark.parametrize("row", GOLD_ROWS, ids=label_row)
def test_tool_answers_match_the_labelled_gold(
    fixture_bundle: FixtureBundle, row: dict[str, Any]
) -> None:
    toolbox = build_test_toolbox(fixture_bundle)
    tool_name = KnowledgeToolName(row["tool"])

    tool_outcome = toolbox.call(tool_name, row["request"])

    if isinstance(tool_outcome, ToolFailure):
        answer_summary = {"failure_code": tool_outcome.code.value}
    else:
        answer_summary = summarize_answer(tool_name, tool_outcome.structured_content)
    assert answer_summary == row["expected"]
