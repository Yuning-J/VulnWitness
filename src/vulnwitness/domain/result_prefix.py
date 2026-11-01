"""Whole-result prefixes measured as canonical response JSON, including their anchors.

Topic results interleave each list's head in this order: implementation candidates,
protocol techniques, excluded candidates, then each list's second entry, and so on.
This gives both answer sections a head before either gets a tail; excluded context
comes last at each rank. The first entry that does not fit ends the prefix.
"""

from typing import Literal

from pydantic import Field

from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.evidence import SHA256_PATTERN
from vulnwitness.domain.hashing import canonical_json_bytes
from vulnwitness.domain.search import SearchResponse
from vulnwitness.domain.topic_context import (
    TOPIC_WARNING_ORDER,
    TopicContextResponse,
    TopicContextWarning,
    TopicContextWarningCode,
)

ResultListName = Literal[
    "candidates",
    "implementation_candidates",
    "protocol_context",
    "excluded_implementation_candidates",
]
ToolResponse = SearchResponse | TopicContextResponse


class ResultListCount(ContractModel):
    name: ResultListName
    kept: int = Field(ge=0)
    omitted: int = Field(ge=0)


class PrefixAdmission(ContractModel):
    """Compact witness for a whole-result cut; tool bodies belong to replay's sources.

    The digest uses the complete response's result_sha256 convention. The next-result
    charge is the canonical prefix size with its first omitted entry minus charged_bytes,
    including any added anchors and changed truncation warnings.
    """

    original_result_sha256: str = Field(
        pattern=SHA256_PATTERN,
        description="The complete original response's result_sha256, before context admission.",
    )
    counts: tuple[ResultListCount, ...] = Field(min_length=1, max_length=3)
    charged_bytes: int = Field(ge=1, description="Canonical JSON size of the admitted response.")
    next_result_bytes: int = Field(
        ge=1,
        description=(
            "Additional canonical bytes for the first omitted entry, including added anchors "
            "and changed warnings: size(extended prefix) minus charged_bytes."
        ),
    )


def measure_response_bytes(response: ToolResponse) -> int:
    return len(canonical_json_bytes(response.model_dump(mode="json")))


def list_result_names(response: ToolResponse) -> tuple[ResultListName, ...]:
    if isinstance(response, SearchResponse):
        return ("candidates",)
    return ("implementation_candidates", "protocol_context", "excluded_implementation_candidates")


def slice_response(response: ToolResponse, kept_counts: dict[ResultListName, int]) -> ToolResponse:
    """Keep each list's prefix and exactly the union of the entries' referenced anchors."""
    changes: dict[str, object] = {}
    evidence_ids: set[str] = set()
    for name in list_result_names(response):
        entries = getattr(response, name)[: kept_counts[name]]
        changes[name] = entries
        for entry in entries:
            if name == "candidates":
                evidence_ids.update(entry.record.evidence_ids)
            elif name == "implementation_candidates":
                evidence_ids.update(entry.candidate.record.evidence_ids)
            elif name == "excluded_implementation_candidates":
                evidence_ids.update(entry.candidate.candidate.record.evidence_ids)
            else:
                evidence_ids.update(entry.evidence_ids)
    anchors = []
    for anchor in response.evidence:
        if anchor.evidence_id in evidence_ids:
            anchors.append(anchor)
    changes["evidence"] = tuple(anchors)
    if isinstance(response, TopicContextResponse):
        changes["warnings"] = list_prefix_topic_warnings(response, kept_counts)
    prefix = response.model_copy(update=changes)
    return prefix.model_copy(update={"result_sha256": prefix.compute_result_sha256()})


def list_prefix_topic_warnings(
    response: TopicContextResponse, kept_counts: dict[ResultListName, int]
) -> tuple[TopicContextWarning, ...]:
    """Topic cut counts include exactly the entries the admitted response leaves out."""
    omitted_techniques = len(response.protocol_context) - kept_counts["protocol_context"]
    omitted_candidates = (
        len(response.implementation_candidates)
        - kept_counts["implementation_candidates"]
        + len(response.excluded_implementation_candidates)
        - kept_counts["excluded_implementation_candidates"]
    )
    counts_by_code = {
        TopicContextWarningCode.PROTOCOL_CONTEXT_TRUNCATED: omitted_techniques,
        TopicContextWarningCode.CANDIDATES_TRUNCATED: omitted_candidates,
    }
    warnings: list[TopicContextWarning] = []
    for warning in response.warnings:
        if warning.code in counts_by_code:
            counts_by_code[warning.code] += int(warning.subject)
        else:
            warnings.append(warning)
    for code, count in counts_by_code.items():
        if count:
            warnings.append(TopicContextWarning(code=code, subject=str(count)))
    warnings.sort(key=topic_warning_position)
    return tuple(warnings)


def topic_warning_position(warning: TopicContextWarning) -> int:
    return TOPIC_WARNING_ORDER[warning.code]


def find_longest_prefix(response: ToolResponse, remaining_bytes: int) -> ToolResponse | None:
    """Return the longest nonempty prefix that fits, or None if its first entry does not.

    Each candidate is serialized whole, with all response metadata and referenced
    anchors. No entry after the first non-fitting entry can enter the prefix.
    """
    names = list_result_names(response)
    kept_counts: dict[ResultListName, int] = {}
    for name in names:
        kept_counts[name] = 0
    longest_prefix: ToolResponse | None = None
    while True:
        has_next_entry = False
        for name in names:
            if kept_counts[name] == len(getattr(response, name)):
                continue
            has_next_entry = True
            kept_counts[name] += 1
            prefix = slice_response(response, kept_counts)
            if measure_response_bytes(prefix) > remaining_bytes:
                return longest_prefix
            longest_prefix = prefix
        if not has_next_entry:
            return longest_prefix


def build_prefix_admission(
    original_response: ToolResponse, prefix: ToolResponse
) -> PrefixAdmission:
    counts: list[ResultListCount] = []
    for name in list_result_names(original_response):
        kept_count = len(getattr(prefix, name))
        counts.append(
            ResultListCount(
                name=name,
                kept=kept_count,
                omitted=len(getattr(original_response, name)) - kept_count,
            )
        )
    charged_bytes = measure_response_bytes(prefix)
    next_counts: dict[ResultListName, int] = {}
    for count in counts:
        next_counts[count.name] = count.kept
    # The interleaved prefix's next entry has the lowest (rank, list position).
    next_count = min(
        (count for count in counts if count.omitted),
        key=next_entry_position,
    )
    next_counts[next_count.name] += 1
    extended_prefix = slice_response(original_response, next_counts)
    return PrefixAdmission(
        original_result_sha256=original_response.result_sha256,
        counts=tuple(counts),
        charged_bytes=charged_bytes,
        next_result_bytes=measure_response_bytes(extended_prefix) - charged_bytes,
    )


def next_entry_position(count: ResultListCount) -> tuple[int, int]:
    order = (
        "candidates",
        "implementation_candidates",
        "protocol_context",
        "excluded_implementation_candidates",
    )
    return count.kept, order.index(count.name)
