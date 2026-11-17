"""Synthetic source blocks shaped like CVE ranges, backports and commit-only records."""

from typing import Any

from tests.support.builders import build_cve_record
from vulnwitness.domain.cve import (
    CveRecord,
    SourceAffected,
    SourceAffectedProduct,
    SourceAffectedVersion,
    SourceVersionChange,
)


def build_source_product(**overrides: Any) -> SourceAffectedProduct:
    fields: dict[str, Any] = {
        "vendor": "Demo Corp",
        "product": "Demo Gateway",
        "versions": (SourceAffectedVersion(version="5.0", less_than="5.4.3", status="affected"),),
    }
    fields.update(overrides)
    return SourceAffectedProduct.model_validate(fields)


def build_source_record(*products: SourceAffectedProduct) -> CveRecord:
    return build_cve_record(
        source_affected=(SourceAffected(source="cna@example.org", products=products),)
    )


def build_backport_product() -> SourceAffectedProduct:
    """A maintained branch with a fix and reintroduction, as CNA backport ranges encode it."""
    return build_source_product(
        versions=(
            SourceAffectedVersion(
                version="5.0",
                less_than="5.4.3",
                version_type="semver",
                status="affected",
                changes=(
                    SourceVersionChange(at="5.4.2", status="affected"),
                    SourceVersionChange(at="5.4.1", status="unaffected"),
                ),
            ),
        )
    )
