"""The only shipped affectedness source: no adapter is verified against a deployed Trustify
(ADR 0003), so this one describes affectedness as blocked and answers every check
``blocked_unverified`` without calling anything."""

from vulnwitness.domain.affectedness import AffectednessFailure, AffectednessRequest


class DisabledTrustifyAdapter:
    """Affectedness is unavailable, and every check is ``blocked_unverified``."""

    def describe(self) -> AffectednessFailure:
        return AffectednessFailure.BLOCKED_UNVERIFIED

    def check_affectedness(
        self, request: AffectednessRequest, timeout_seconds: float
    ) -> AffectednessFailure:
        return AffectednessFailure.BLOCKED_UNVERIFIED
