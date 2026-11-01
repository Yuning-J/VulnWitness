"""Derive unfinished triage stages from completed recorded calls, without retrieval."""

from vulnwitness.domain.product_query import ProductQueryResponse
from vulnwitness.domain.session_report import CheckedSession
from vulnwitness.domain.workspace import TriageProductRequest


def remaining_triage_steps(
    contents: CheckedSession, planned_steps: tuple[str, ...], request: TriageProductRequest | None
) -> tuple[str, ...]:
    completed_stages: set[str] = set()
    inventory_count = 0
    inventory_complete = False
    looked_up_ids: set[str] = set()
    for call in contents.calls:
        if call.outcome != "ok":
            continue
        if call.command in {"capabilities", "get_knowledge_capabilities"}:
            completed_stages.add("capabilities")
        answer = contents.responses.get(call.sequence)
        if isinstance(answer, ProductQueryResponse):
            inventory_count += len(answer.items)
            inventory_complete = answer.next_cursor is None
        if call.command in {"lookup", "lookup_cve"} and call.request is not None:
            cve_id = call.request.get("cve_id")
            if isinstance(cve_id, str):
                looked_up_ids.add(cve_id)
    if inventory_complete:
        completed_stages.add("product inventory")
        if request is not None:
            if request.select:
                lookups_complete = all(cve_id in looked_up_ids for cve_id in request.select)
            else:
                lookups_complete = len(looked_up_ids) >= min(request.lookups, inventory_count)
            if lookups_complete:
                completed_stages.add("selected CVE lookups")
    remaining_steps: list[str] = []
    for step in planned_steps:
        if step not in completed_stages:
            remaining_steps.append(step)
    if not remaining_steps:
        remaining_steps.append("workflow: publish completion metadata")
    return tuple(remaining_steps)
