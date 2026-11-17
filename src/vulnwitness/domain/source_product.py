"""Shared normalized names from source-stated products and their CPEs (ADR 0023)."""

import re

from vulnwitness.domain.cpe import cpe_product_identity
from vulnwitness.domain.cve import SourceAffectedProduct


def normalize_source_name(name: str) -> str:
    """Case-folded, with runs of spaces, hyphens and underscores read as one underscore."""
    return re.sub(r"[\s_-]+", "_", name.casefold()).strip("_")


def list_entry_names(entry: SourceAffectedProduct) -> list[tuple[str, str]]:
    names: list[tuple[str, str]] = []
    if entry.vendor and entry.product:
        names.append((normalize_source_name(entry.vendor), normalize_source_name(entry.product)))
    for cpe in entry.cpes:
        identity = cpe_product_identity(cpe)
        if identity is not None:
            vendor, product = identity
            names.append((normalize_source_name(vendor), normalize_source_name(product)))
    return names
