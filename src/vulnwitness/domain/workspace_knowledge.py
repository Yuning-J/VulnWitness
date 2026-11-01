"""MCP-only recording inputs; core requests and REST have no session ID."""

from pydantic import BaseModel, create_model

from vulnwitness.domain.affectedness import AffectednessRequest
from vulnwitness.domain.investigation import InvestigationRequest
from vulnwitness.domain.product_query import ProductQueryRequest
from vulnwitness.domain.search import SearchRequest
from vulnwitness.domain.tool_contracts import (
    CapabilitiesRequest,
    ConceptResolutionRequest,
    CveLookupRequest,
    EvidenceLookupRequest,
    FightSearchRequest,
)
from vulnwitness.domain.workspace import InvestigationId

KNOWLEDGE_REQUEST_MODELS = (
    CapabilitiesRequest,
    ConceptResolutionRequest,
    CveLookupRequest,
    SearchRequest,
    ProductQueryRequest,
    InvestigationRequest,
    FightSearchRequest,
    EvidenceLookupRequest,
    AffectednessRequest,
)
WORKSPACE_KNOWLEDGE_MODELS: dict[type[BaseModel], type[BaseModel]] = {}
for request_model in KNOWLEDGE_REQUEST_MODELS:
    WORKSPACE_KNOWLEDGE_MODELS[request_model] = create_model(
        "Workspace" + request_model.__name__,
        __base__=request_model,
        session_id=(InvestigationId | None, None),
    )
