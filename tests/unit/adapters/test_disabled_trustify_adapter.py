"""The shipped affectedness source gives blocked_unverified as its reason and checks nothing."""

from cve_kgrag.adapters.trustify.disabled_trustify_adapter import DisabledTrustifyAdapter
from cve_kgrag.domain.affectedness import AffectednessFailure
from tests.support.affectedness import build_affectedness_request


def test_describe_gives_blocked_unverified_as_the_reason() -> None:
    adapter = DisabledTrustifyAdapter()

    described_failure = adapter.describe()

    assert described_failure is AffectednessFailure.BLOCKED_UNVERIFIED


def test_check_returns_blocked_unverified_failure() -> None:
    adapter = DisabledTrustifyAdapter()
    request = build_affectedness_request()

    failure = adapter.check_affectedness(request, timeout_seconds=8.0)

    assert failure is AffectednessFailure.BLOCKED_UNVERIFIED
