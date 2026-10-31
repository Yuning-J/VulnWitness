"""Validate each untrusted assessor reply part independently, without retry."""

import json
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from cve_kgrag.domain.planning import CveSearchCall, ModelReply
from cve_kgrag.domain.relevance import RelevanceGap, RelevanceLabel
from cve_kgrag.domain.relevance_terms import is_question_component
from cve_kgrag.domain.text import list_query_terms


@dataclass(frozen=True)
class ParsedRelevance:
    labels: dict[str, RelevanceLabel]
    gap: RelevanceGap | None
    search: CveSearchCall | None
    issues: tuple[str, ...]


def read_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate keys rather than silently let a later value erase one."""
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate key")
        document[key] = value
    return document


def parse_relevance_reply(
    reply: ModelReply | None, keys: dict[str, str], question: str
) -> ParsedRelevance:
    if reply is None or reply.plan_text is None:
        return ParsedRelevance({}, None, None, ("assessor_unavailable",))
    try:
        document = json.loads(reply.plan_text, object_pairs_hook=read_json_object)
    except (ValueError, RecursionError):
        return ParsedRelevance({}, None, None, ("malformed_reply",))
    if not isinstance(document, dict):
        return ParsedRelevance({}, None, None, ("malformed_reply",))
    issues: list[str] = []
    if set(document) - {"labels", "gap", "search"}:
        issues.append("unexpected_fields")
    labels: dict[str, RelevanceLabel] = {}
    proposed_labels = document.get("labels")
    if not isinstance(proposed_labels, dict):
        issues.append("invalid_labels")
    else:
        if set(proposed_labels) - set(keys):
            issues.append("unknown_label_keys")
        for key in keys:
            try:
                proposed_label = proposed_labels.get(key)
                if not isinstance(proposed_label, str):
                    raise ValueError("invalid label")
                labels[key] = RelevanceLabel(proposed_label)
            except ValueError:
                issues.append("missing_or_invalid_label:" + key)
    gap: RelevanceGap | None = None
    if document.get("gap") is not None:
        try:
            gap = RelevanceGap.model_validate(document["gap"])
        except ValidationError:
            issues.append("invalid_gap")
        if gap is not None and not is_question_component(gap.component, question):
            issues.append("component_outside_question")
            gap = None
        if gap is not None:
            try:
                gap = RelevanceGap(
                    component=" ".join(list_query_terms(gap.component)),
                    reason=gap.reason,
                    note=gap.note,
                )
            except ValidationError:
                issues.append("invalid_gap")
                gap = None
    search: CveSearchCall | None = None
    if document.get("search") is not None:
        try:
            search = CveSearchCall.model_validate(document["search"])
        except ValidationError:
            issues.append("invalid_search")
        if search is not None and not list_query_terms(search.query):
            issues.append("empty_search")
            search = None
    return ParsedRelevance(labels, gap, search, tuple(issues))
