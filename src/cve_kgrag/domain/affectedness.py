"""The affectedness contract: what a caller asks the affectedness source, why the source
gave no answer, and the check the server publishes.

No field of this contract says that a product is or is not affected. No affectedness
source is verified against a deployed Trustify (ADR 0003), so every check reports
applicability ``unknown`` with the failure that kept it from being established. An
adapter answers with a typed failure only; every published sentence about affectedness
is one of the server's fixed ``AffectednessDetail`` sentences, so no affectedness
adapter's text is ever published.
"""

from enum import StrEnum

from cve_kgrag.domain.contract_model import ContractModel
from cve_kgrag.domain.cve import CveId
from cve_kgrag.domain.search import SCHEMA_VERSION, SchemaVersion, VersionedPackageUrl


class ApplicabilityStatus(StrEnum):
    # No verified affectedness source is available (ADR 0003), so applicability is never
    # established.
    UNKNOWN = "unknown"


class AffectednessFailure(StrEnum):
    """Why the affectedness source gave no answer.

    ``blocked_unverified``: no adapter is verified against a deployed Trustify, so none
    is called; the other members are the failures a verified adapter reports.
    """

    BLOCKED_UNVERIFIED = "blocked_unverified"
    SOURCE_UNAVAILABLE = "source_unavailable"
    TIMEOUT = "timeout"
    AUTH_FAILED = "auth_failed"
    TOOL_MISMATCH = "tool_mismatch"


class AffectednessDetail(StrEnum):
    """The server's sentence for each ``AffectednessFailure``: the ``detail`` of an
    affectedness check and of an unavailable ``affectedness`` capability."""

    BLOCKED_UNVERIFIED = (
        "BLOCKED_UNVERIFIED: no affectedness adapter is verified against a deployed Trustify; "
        "trustify-mcp ac8955f calls /api/v2 routes Trustify removed in v0.5.0 (ADR 0003). "
        "Affectedness is not checked."
    )
    SOURCE_UNAVAILABLE = (
        "The affectedness source could not be reached. Affectedness is not established."
    )
    TIMEOUT = (
        "The affectedness source did not answer within its time limit. Affectedness is not "
        "established."
    )
    AUTH_FAILED = (
        "The affectedness source refused this server's credentials. Affectedness is not "
        "established."
    )
    TOOL_MISMATCH = (
        "The affectedness source's tools differ from the pinned trustify-mcp surface. "
        "Affectedness is not established."
    )


AFFECTEDNESS_DETAILS: dict[AffectednessFailure, AffectednessDetail] = {
    AffectednessFailure.BLOCKED_UNVERIFIED: AffectednessDetail.BLOCKED_UNVERIFIED,
    AffectednessFailure.SOURCE_UNAVAILABLE: AffectednessDetail.SOURCE_UNAVAILABLE,
    AffectednessFailure.TIMEOUT: AffectednessDetail.TIMEOUT,
    AffectednessFailure.AUTH_FAILED: AffectednessDetail.AUTH_FAILED,
    AffectednessFailure.TOOL_MISMATCH: AffectednessDetail.TOOL_MISMATCH,
}


class AffectednessRequest(ContractModel):
    """One CVE against one package version. A product name is not accepted: no Trustify
    tool maps a name to a package."""

    cve_id: CveId
    purl: VersionedPackageUrl


class AffectednessCheck(ContractModel):
    """The published answer to an affectedness check: always ``unknown``, with the failure
    that kept applicability from being established and the server's sentence for it."""

    schema_version: SchemaVersion = SCHEMA_VERSION
    request: AffectednessRequest
    applicability: ApplicabilityStatus
    failure: AffectednessFailure
    detail: AffectednessDetail
