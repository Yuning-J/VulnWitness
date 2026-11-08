"""The command-specific request and response contracts a session checker accepts."""

from pydantic import BaseModel

from vulnwitness.domain.affectedness import AffectednessCheck, AffectednessRequest
from vulnwitness.domain.cve_lookup import CveLookupResponse
from vulnwitness.domain.evidence_set_verification_report import VerificationReport
from vulnwitness.domain.investigation import InvestigationRequest, KnowledgeEvidenceSet
from vulnwitness.domain.product_query import ProductQueryRequest, ProductQueryResponse
from vulnwitness.domain.search import SearchRequest, SearchResponse
from vulnwitness.domain.session_response import (
    SessionAffectednessRequest,
    SessionAffectednessResponse,
    SessionVerificationRequest,
)
from vulnwitness.domain.tool_contracts import (
    CapabilitiesRequest,
    ConceptResolution,
    ConceptResolutionRequest,
    CveLookupRequest,
    EvidenceLookup,
    EvidenceLookupRequest,
    FightSearchRequest,
    KnowledgeCapabilities,
)
from vulnwitness.domain.topic_context import TopicContextRequest, TopicContextResponse

CLI_SESSION_CONTRACTS: dict[str, tuple[type[BaseModel], type[BaseModel]]] = {
    "lookup": (CveLookupRequest, CveLookupResponse),
    "search": (SearchRequest, SearchResponse),
    "product": (ProductQueryRequest, ProductQueryResponse),
    "investigate": (InvestigationRequest, KnowledgeEvidenceSet),
    "topic": (TopicContextRequest, TopicContextResponse),
    "evidence": (EvidenceLookupRequest, EvidenceLookup),
    "affectedness": (SessionAffectednessRequest, SessionAffectednessResponse),
    "capabilities": (CapabilitiesRequest, KnowledgeCapabilities),
    "resolve": (ConceptResolutionRequest, ConceptResolution),
    "verify": (SessionVerificationRequest, VerificationReport),
}
MCP_SESSION_CONTRACTS: dict[str, tuple[type[BaseModel], type[BaseModel]]] = {
    "lookup_cve": (CveLookupRequest, CveLookupResponse),
    "search_vulnerabilities": (SearchRequest, SearchResponse),
    "query_product_vulnerabilities": (ProductQueryRequest, ProductQueryResponse),
    "investigate_telecom_topic": (InvestigationRequest, KnowledgeEvidenceSet),
    "search_fight": (FightSearchRequest, TopicContextResponse),
    "get_evidence": (EvidenceLookupRequest, EvidenceLookup),
    "check_affectedness": (AffectednessRequest, AffectednessCheck),
    "get_knowledge_capabilities": (CapabilitiesRequest, KnowledgeCapabilities),
    "resolve_telecom_concept": (ConceptResolutionRequest, ConceptResolution),
}
