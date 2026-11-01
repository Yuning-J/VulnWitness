"""The affectedness source: whether a package version is affected by a CVE."""

from typing import Protocol

from vulnwitness.domain.affectedness import AffectednessFailure, AffectednessRequest


class TrustifyPort(Protocol):
    """A Trustify-backed affectedness source. It answers with a typed failure only: the
    server publishes its own sentence for each (``AffectednessDetail``), never adapter
    text, and a missing answer is never ``not_affected``."""

    def describe(self) -> AffectednessFailure:
        """Why affectedness is unavailable from this source; the composition root publishes
        the ``affectedness`` capability as unavailable with the server's sentence for it
        (``describe_affectedness``).

        Read once, when the composition root builds the deployment; a request never calls
        it, so it is not bounded by any call's time limit.
        """
        ...

    def check_affectedness(
        self, request: AffectednessRequest, timeout_seconds: float
    ) -> AffectednessFailure:
        """Why checking ``request`` established nothing; never raises.

        Returns within ``timeout_seconds``, with ``timeout`` when the source has not
        answered by then: the caller may stop waiting, but only the adapter can end its
        own request.
        """
        ...
