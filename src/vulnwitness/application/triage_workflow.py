"""Bounded composition of capabilities, product paging, lookup and session checking."""

import logging
from collections.abc import Callable
from functools import partial
from typing import Literal

from pydantic import BaseModel

from vulnwitness.application.triage_findings import build_lookup_findings, build_page_findings
from vulnwitness.domain.product_query import (
    ProductQueryRequest,
    ProductQueryResponse,
    ProductVulnerability,
)
from vulnwitness.domain.search import SearchResponse
from vulnwitness.domain.session_record import (
    ProductPaginationProgress,
    SessionCheckReport,
    SessionFinding,
    SessionFindings,
    SessionRecordingError,
    SessionSelections,
)
from vulnwitness.domain.tool_contracts import (
    TOOL_FAILURE_MESSAGES,
    CapabilitiesRequest,
    CveLookupRequest,
    KnowledgeCapabilities,
    ToolFailure,
    ToolFailureCode,
)
from vulnwitness.domain.triage import (
    TriageDeepDive,
    TriageInventory,
    TriageLimits,
    TriageStopReason,
    TriageSummary,
)
from vulnwitness.ports.session_recording import SessionRecording
from vulnwitness.ports.triage_artifacts import TriageArtifacts


def triage_selection_key(vulnerability: ProductVulnerability) -> tuple[int, int, float, str]:
    """Workflow order intentionally prioritizes basis before version-note grouping."""
    basis_order = 0 if vulnerability.basis.kind == "product_field" else 1
    version_order = 1
    if vulnerability.nvd_version_note is not None:
        version_order = ("hit", "unknown", "no_hit").index(vulnerability.nvd_version_note.outcome)
    published = vulnerability.record.published
    publication_order = float("inf") if published is None else -published.timestamp()
    return basis_order, version_order, publication_order, vulnerability.record.cve_id


def plan_triage_calls(
    request: ProductQueryRequest, selected_ids: tuple[str, ...], limits: TriageLimits
) -> int:
    """Reserve the worst case without executing an unrecorded discovery query."""
    if request.cursor is not None:
        raise ValueError("triage must start at the first product page")
    if len(set(selected_ids)) != len(selected_ids):
        raise ValueError("--select IDs must be unique")
    if len(selected_ids) > limits.lookups:
        raise ValueError("--select count exceeds --lookups")
    lookup_budget = len(selected_ids) if selected_ids else limits.lookups
    planned_calls = 1 + limits.max_pages + lookup_budget
    if planned_calls > limits.call_limit:
        raise ValueError(
            f"planned call count {planned_calls} exceeds remaining session call limit "
            f"{limits.call_limit}"
        )
    return planned_calls


class TriageWorkflow:
    """Services own retrieval and comparison; this workflow owns only their sequence.

    The time budget is checked between synchronous service calls. An admitted call is
    allowed to finish and is recorded before the workflow checks the deadline again.
    """

    def __init__(
        self,
        *,
        capabilities: Callable[[], KnowledgeCapabilities],
        query_product: Callable[[ProductQueryRequest], ProductQueryResponse],
        lookup: Callable[[str], SearchResponse],
        recorder: SessionRecording,
        artifacts: TriageArtifacts,
        clock: Callable[[], float],
        limits: TriageLimits,
        encode: Callable[[BaseModel], tuple[bytes, Literal["ok"] | ToolFailureCode, str]],
    ) -> None:
        self._capabilities = capabilities
        self._query_product = query_product
        self._lookup = lookup
        self._recorder = recorder
        self._artifacts = artifacts
        self._clock = clock
        self._limits = limits
        self._encode = encode
        self._sequence = 0

    def run(
        self, request: ProductQueryRequest, selected_ids: tuple[str, ...] = ()
    ) -> tuple[TriageSummary, SessionCheckReport, int]:
        """Record one product traversal and deep dive, then author and check its claims.

        Return the saved scope summary, layered check and CLI-compatible exit code.
        Invalid plans or non-empty directories raise ValueError before any call;
        artifact I/O failures propagate so callers cannot report an unpublished success.
        """
        self._artifacts.require_empty()
        planned_calls = plan_triage_calls(request, selected_ids, self._limits)
        lookup_budget = len(selected_ids) if selected_ids else self._limits.lookups
        self._sequence = 0
        deadline = self._clock() + self._limits.time_limit
        pages: list[ProductQueryResponse] = []
        page_calls: list[int] = []
        inventory: list[ProductVulnerability] = []
        findings: list[SessionFinding] = []
        selection: list[str] = []
        looked_up_ids: list[str] = []
        lookup_calls: list[int] = []
        stop_reason: TriageStopReason = "complete"
        remaining_steps: list[str] = []
        caps_hit: list[Literal["max_pages", "lookups", "time_limit"]] = []
        failure_code = None
        capabilities_done = False
        selection_done = False
        traversal_complete = False
        try:
            capabilities = self._record("capabilities", CapabilitiesRequest(), self._capabilities)
            if isinstance(capabilities, ToolFailure):
                failure_code = capabilities.code
                stop_reason = "call_failed"
            else:
                capabilities_done = True
            while capabilities_done and stop_reason == "complete":
                if self._clock() >= deadline:
                    stop_reason = "time_limit"
                    break
                page = self._record("product", request, partial(self._query_product, request))
                if isinstance(page, ToolFailure):
                    failure_code = page.code
                    stop_reason = "call_failed"
                    break
                assert isinstance(page, ProductQueryResponse)
                pages.append(page)
                page_calls.append(self._sequence)
                inventory.extend(page.items)
                findings.extend(build_page_findings(page, self._sequence))
                if page.next_cursor is None:
                    traversal_complete = True
                    break
                if len(pages) == self._limits.max_pages:
                    caps_hit.append("max_pages")
                    stop_reason = "max_pages"
                    break
                request = request.model_copy(update={"cursor": page.next_cursor})
            if stop_reason in {"complete", "max_pages"}:
                inventory_ids: set[str] = set()
                for vulnerability in inventory:
                    inventory_ids.add(vulnerability.record.cve_id)
                if any(cve_id not in inventory_ids for cve_id in selected_ids):
                    stop_reason = "invalid_selection"
                else:
                    selection_done = True
                    if selected_ids:
                        selection.extend(selected_ids)
                    else:
                        for vulnerability in sorted(inventory, key=triage_selection_key):
                            if len(selection) == lookup_budget:
                                break
                            selection.append(vulnerability.record.cve_id)
                        if len(inventory) > lookup_budget:
                            caps_hit.append("lookups")
                    for cve_id in selection:
                        if self._clock() >= deadline:
                            stop_reason = "time_limit"
                            break
                        lookup = self._record(
                            "lookup", CveLookupRequest(cve_id=cve_id), partial(self._lookup, cve_id)
                        )
                        if isinstance(lookup, ToolFailure):
                            failure_code = lookup.code
                            stop_reason = "call_failed"
                            break
                        assert isinstance(lookup, SearchResponse)
                        looked_up_ids.append(cve_id)
                        lookup_calls.append(self._sequence)
                        lookup_findings = build_lookup_findings(lookup, self._sequence)
                        findings.extend(lookup_findings)
                        if not lookup_findings:
                            stop_reason = "lookup_claim_unavailable"
                            remaining_steps.append(
                                f"findings: lookup call {self._sequence} "
                                "returned no claimable fields"
                            )
                            break
            if stop_reason in {"complete", "max_pages"} and self._clock() >= deadline:
                stop_reason = "time_limit"
        except SessionRecordingError as error:
            failure_code = error.code
            stop_reason = "recording_failed"
        if stop_reason == "time_limit":
            caps_hit.append("time_limit")
        if stop_reason == "complete" and not inventory:
            stop_reason = "no_match"
        if not capabilities_done:
            remaining_steps.append("capabilities")
        if not traversal_complete:
            remaining_steps.append("product: continue inventory traversal")
        if not selection_done:
            remaining_steps.append("select: validate user IDs or take first N by the stated order")
            remaining_steps.append(f"lookup: up to {lookup_budget} selected CVEs")
        else:
            for cve_id in selection:
                if cve_id not in looked_up_ids:
                    remaining_steps.append(f"lookup: {cve_id}")
        pagination = ProductPaginationProgress(
            vendor=request.vendor,
            product=request.product,
            version=request.version,
            calls=tuple(page_calls),
            next_cursor=pages[-1].next_cursor if pages else None,
            complete=traversal_complete,
        )
        self._artifacts.write_findings(
            SessionFindings(
                findings=tuple(findings),
                selections=SessionSelections(
                    cve_ids=tuple(selection), product_queries=(pagination,)
                ),
                open_questions=(),
            )
        )
        check = self._artifacts.check()
        checks_pass = check.record.consistent and check.citations.resolved and check.claims.verified
        if not checks_pass and stop_reason in {"complete", "no_match"}:
            stop_reason = "check_failed"
            remaining_steps.append("session check: resolve reported violations")
        inventory_cve_ids: list[str] = []
        for vulnerability in inventory:
            inventory_cve_ids.append(vulnerability.record.cve_id)
        summary = TriageSummary(
            planned_call_count=planned_calls,
            limits=self._limits,
            inventory=TriageInventory(
                pages_read=len(pages),
                items_seen=len(inventory),
                total_available=pages[-1].total_available if pages else None,
                complete=traversal_complete,
                page_calls=tuple(page_calls),
                cve_ids=tuple(inventory_cve_ids),
            ),
            deep_dive=TriageDeepDive(
                selection_mode="user-chosen IDs" if selected_ids else "first N by the stated order",
                selected_ids=tuple(selection),
                looked_up_ids=tuple(looked_up_ids),
                lookups_completed=len(looked_up_ids),
                lookup_calls=tuple(lookup_calls),
            ),
            stop_reason=stop_reason,
            caps_hit=tuple(caps_hit),
            failure_code=failure_code,
            remaining_steps=tuple(remaining_steps),
        )
        self._artifacts.write_summary(summary)
        if not checks_pass:
            return summary, check, 2
        if stop_reason == "no_match":
            return summary, check, 1
        return summary, check, 0 if stop_reason == "complete" else 2

    def _record(
        self, command: str, request: BaseModel, operation: Callable[[], BaseModel]
    ) -> BaseModel:
        answer = self._recorder.run(
            "cli",
            command,
            request.model_dump(mode="json"),
            partial(self._invoke, operation),
            self._encode,
        )
        self._sequence += 1
        return answer

    def _invoke(self, operation: Callable[[], BaseModel]) -> BaseModel:
        try:
            return operation()
        except Exception:
            logging.getLogger(__name__).error("triage service call failed", exc_info=True)
            return ToolFailure(
                code=ToolFailureCode.INTERNAL_ERROR,
                message=TOOL_FAILURE_MESSAGES[ToolFailureCode.INTERNAL_ERROR],
                invalid_fields=(),
                unexpected_field_count=0,
            )
