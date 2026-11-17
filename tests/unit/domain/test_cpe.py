"""Named product identities from both CPE bindings."""

import pytest

from vulnwitness.domain.cpe import cpe_product_identity


@pytest.mark.parametrize(
    ("cpe", "identity"),
    [
        ("cpe:/o:redhat:enterprise_linux:9", ("redhat", "enterprise_linux")),
        ("cpe:/a:demo%3acorp:gateway%2bplus", ("demo:corp", "gateway+plus")),
        (r"cpe:2.3:a:demo\:corp:gateway:*:*:*:*:*:*:*:*", ("demo:corp", "gateway")),
        ("cpe:/a:*:gateway", None),
        ("cpe:/a:demo:-", None),
        ("cpe:/a:demo:", None),
        ("cpe:2.3:a:demo:*:*:*:*:*:*:*:*:*", None),
        ("cpe:2.3:a:-:gateway:*:*:*:*:*:*:*:*", None),
        ("cpe:/a:demo", None),
        ("cpe:2.3:a:demo:gateway", None),
        ("other:demo:gateway", None),
    ],
)
def test_cpe_identity_returns_only_a_named_vendor_and_product(
    cpe: str, identity: tuple[str, str] | None
) -> None:
    assert cpe_product_identity(cpe) == identity
