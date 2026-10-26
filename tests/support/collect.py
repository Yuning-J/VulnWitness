"""Small loop-based extractors used in assertions."""

from collections.abc import Iterable, Sequence
from typing import Protocol

from cve_kgrag.domain.investigation import SourceCapability
from cve_kgrag.domain.search import Candidate


class HasCveId(Protocol):
    @property
    def cve_id(self) -> str: ...


def list_cve_ids(items: Iterable[HasCveId]) -> list[str]:
    cve_ids: list[str] = []
    for item in items:
        cve_ids.append(item.cve_id)
    return cve_ids


def list_candidate_cve_ids(candidates: Iterable[Candidate]) -> list[str]:
    cve_ids: list[str] = []
    for candidate in candidates:
        cve_ids.append(candidate.record.cve_id)
    return cve_ids


class HasTechniqueId(Protocol):
    @property
    def technique_id(self) -> str: ...


def list_technique_ids(items: Iterable[HasTechniqueId]) -> list[str]:
    technique_ids: list[str] = []
    for item in items:
        technique_ids.append(item.technique_id)
    return technique_ids


def find_capability(
    source_capabilities: Sequence[SourceCapability], source: str
) -> SourceCapability:
    """The capability of ``source`` (a knowledge source or ``semantic_channel``)."""
    for capability in source_capabilities:
        if capability.source == source:
            return capability
    raise LookupError(source)
