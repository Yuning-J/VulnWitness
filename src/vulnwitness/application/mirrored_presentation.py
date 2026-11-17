"""Source-stated SSVC decisions and version conditions shared by lookup and reports."""

from vulnwitness.domain.cve import SourceAffectedProduct, SourceAffectedVersion, SsvcDecisionPoints


def describe_ssvc_decision_points(points: SsvcDecisionPoints) -> str:
    return (
        f"exploitation {points.exploitation or 'not stated'} · automatable "
        f"{points.automatable or 'not stated'} · technical impact "
        f"{points.technical_impact or 'not stated'}"
    )


def describe_source_version(version: SourceAffectedVersion) -> str:
    """Source-stated bounds and ordered status changes, including any omitted-change count."""
    bounds = version.version
    if version.less_than is not None:
        bounds = f"{version.version} to < {version.less_than}"
    elif version.less_than_or_equal is not None:
        bounds = f"{version.version} to ≤ {version.less_than_or_equal}"
    scheme = f" ({version.version_type})" if version.version_type else ""
    description = f"{version.status} {bounds}{scheme}"
    for change in version.changes:
        description += f"; at {change.at} → {change.status}"
    if version.omitted_changes:
        description += f"; {version.omitted_changes} more status changes not stored"
    return description


def describe_source_product(product: SourceAffectedProduct) -> str:
    """A product's name, purl, default status and source-stated version conditions."""
    name = " ".join(part for part in (product.vendor, product.product) if part)
    name = name or product.package_name or product.package_url or "unnamed product"
    versions = "; ".join(describe_source_version(version) for version in product.versions)
    if product.omitted_versions:
        versions += f"; {product.omitted_versions} more not stored"
    default = f" · default {product.default_status}" if product.default_status else ""
    purl = f" · {product.package_url}" if product.package_url else ""
    return f"{name}{purl}{default} · {versions or 'no versions stated'}"
