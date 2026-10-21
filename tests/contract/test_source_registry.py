"""Every provenance subject the brief names is registered, and unverified terms stay uncommitted."""

from cve_kgrag.adapters.provenance.source_registry import (
    default_source_registry_file,
    load_source_registry,
)
from cve_kgrag.domain.provenance import LocalStoragePolicy, Redistribution

REQUIRED_SOURCES = {
    "nvd",
    "cve-program",
    "cisa-kev",
    "mitre-fight",
    "mitre-attack",
    "mitre-cwe",
    "mitre-capec",
    "trustify-software",
    "trustify-returned-data",
    "trustify-mcp",
}


def test_registry_covers_every_required_provenance_subject() -> None:
    registry = load_source_registry(default_source_registry_file())

    names: set[str] = set()
    for source in registry.sources:
        names.add(source.name)
    assert names >= REQUIRED_SOURCES


def test_sources_with_unverified_terms_commit_nothing_new() -> None:
    registry = load_source_registry(default_source_registry_file())

    for source in registry.sources:
        if source.terms_or_license_url is None:
            assert source.redistribution_allowed is Redistribution.UNKNOWN
            assert source.local_storage_policy is not LocalStoragePolicy.COMMITTED_EXCERPT
