"""Response documents persisted verbatim, without a session envelope."""

from pydantic import BaseModel, RootModel

from vulnwitness.domain.affectedness import AffectednessCheck, AffectednessRequest
from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.cve_lookup import CveLookupResponse
from vulnwitness.domain.evidence_set_verification_report import VerificationReport
from vulnwitness.domain.investigation import KnowledgeEvidenceSet
from vulnwitness.domain.product_query import ProductQueryResponse
from vulnwitness.domain.search import SearchResponse
from vulnwitness.domain.tool_contracts import (
    ConceptResolution,
    EvidenceLookup,
    KnowledgeCapabilities,
    ToolFailure,
)
from vulnwitness.domain.topic_context import TopicContextResponse


class SessionVerificationRequest(ContractModel):
    file: str


class SessionAffectednessRequest(ContractModel):
    checks: tuple[AffectednessRequest, ...]


class SessionAffectednessResponse(RootModel[tuple[AffectednessCheck, ...]]):
    pass


class SessionResponse(
    RootModel[
        CveLookupResponse
        | SearchResponse
        | ProductQueryResponse
        | TopicContextResponse
        | KnowledgeEvidenceSet
        | KnowledgeCapabilities
        | ConceptResolution
        | EvidenceLookup
        | AffectednessCheck
        | ToolFailure
        | VerificationReport
        | tuple[AffectednessCheck, ...]
    ]
):
    """The schema of responses/NNNN.json; call metadata selects its precise contract."""


SESSION_RESPONSE_MODELS: dict[str, type[BaseModel]] = {
    "SearchResponse": SearchResponse,
    "CveLookupResponse": CveLookupResponse,
    "ProductQueryResponse": ProductQueryResponse,
    "TopicContextResponse": TopicContextResponse,
    "KnowledgeEvidenceSet": KnowledgeEvidenceSet,
    "KnowledgeCapabilities": KnowledgeCapabilities,
    "ConceptResolution": ConceptResolution,
    "EvidenceLookup": EvidenceLookup,
    "AffectednessCheck": AffectednessCheck,
    "ToolFailure": ToolFailure,
    "VerificationReport": VerificationReport,
    "SessionAffectednessResponse": SessionAffectednessResponse,
}
