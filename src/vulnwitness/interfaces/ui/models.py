"""UI-only compositions of existing workspace and report contracts."""

from typing import Literal

from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.investigation import InvestigationRequest as TopicRequest
from vulnwitness.domain.session_record import SessionDatasetIdentity
from vulnwitness.domain.session_report import SessionReport
from vulnwitness.domain.tool_contracts import CveLookupRequest
from vulnwitness.domain.workspace import InvestigationListItem, InvestigationRequest


class LookupRequest(CveLookupRequest, InvestigationRequest):
    pass


class InvestigateRequest(TopicRequest, InvestigationRequest):
    pass


class ListedInvestigation(InvestigationListItem):
    dataset: SessionDatasetIdentity


class InvestigationList(ContractModel):
    status: Literal["loading", "ready"]
    investigations: tuple[ListedInvestigation, ...] = ()


class InvestigationView(ContractModel):
    report: SessionReport
