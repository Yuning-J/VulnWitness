"""An explicit affectedness check: one CVE against one package version, through the
affectedness port. Investigations never call it (ADR 0003)."""

from cve_kgrag.domain.affectedness import (
    AFFECTEDNESS_DETAILS,
    AffectednessCheck,
    AffectednessFailure,
    AffectednessRequest,
    ApplicabilityStatus,
)
from cve_kgrag.ports.affectedness import TrustifyPort


def check_affectedness(
    trustify_port: TrustifyPort, request: AffectednessRequest, timeout_seconds: float
) -> AffectednessCheck:
    """The port's failure for ``request``, with the server's sentence for it and
    applicability ``unknown``: the contract has no verdict, so whatever the port answers,
    applicability is never established.

    Raises ``ValueError`` when the port answers anything but an ``AffectednessFailure``
    or the value of one: the port is an adapter, so its declared return type is a
    promise, checked here.
    """
    failure = AffectednessFailure(trustify_port.check_affectedness(request, timeout_seconds))
    return AffectednessCheck(
        request=request,
        applicability=ApplicabilityStatus.UNKNOWN,
        failure=failure,
        detail=AFFECTEDNESS_DETAILS[failure],
    )
