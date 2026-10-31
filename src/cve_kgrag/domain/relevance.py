"""Candidate relevance, assessor inputs and the recorded refinement gate verdict."""

from enum import StrEnum
from typing import Literal

from pydantic import Field

from cve_kgrag.domain.contract_model import ContractModel
from cve_kgrag.domain.cve import CveId
from cve_kgrag.domain.planning import CveSearchCall, ModelReply, PlanRejection
from cve_kgrag.domain.topic_context import QueryScope

DESCRIPTION_CAP_CHARS = 1000
LABEL_ORDER = ("relevant", "cannot_tell", "not_relevant")


class RelevanceLabel(StrEnum):
    RELEVANT = "relevant"
    NOT_RELEVANT = "not_relevant"
    CANNOT_TELL = "cannot_tell"


class AssessorProduct(ContractModel):
    vendor: str
    product: str


class AssessorCandidate(ContractModel):
    key: str
    description: str = Field(max_length=DESCRIPTION_CAP_CHARS)
    affected_products: tuple[AssessorProduct, ...]
    cwe_ids: tuple[str, ...]


class AssessorQuestion(ContractModel):
    query: str
    scope: QueryScope


class RelevanceInput(ContractModel):
    question: AssessorQuestion
    candidates: tuple[AssessorCandidate, ...]


class RelevanceGap(ContractModel):
    component: str = Field(min_length=1, max_length=512)
    reason: Literal["coverage_unclear"]
    note: str = Field(min_length=1, max_length=512)


class RelevanceProposal(ContractModel):
    """One reply shape; its parts are validated independently at ingress."""

    labels: dict[str, RelevanceLabel]
    gap: RelevanceGap | None = None
    search: CveSearchCall | None = None


class TermSource(ContractModel):
    term: str
    cve_id: CveId | None = None
    field: Literal["question", "vendor", "product", "cpe_product"]


class RelevanceAssessmentRecord(ContractModel):
    """A reply and the decision it supports, re-derived by validation and replay."""

    cve_ids_by_key: dict[str, CveId]
    reply: ModelReply | None
    labels: dict[str, RelevanceLabel]
    gap: RelevanceGap | None
    search: CveSearchCall | None
    term_sources: tuple[TermSource, ...]
    issues: tuple[str, ...]
    rejections: tuple[PlanRejection, ...]
    accepted_search: CveSearchCall | None
    deadline: Literal["before_start", "during_call", "at_finish"] | None = None
