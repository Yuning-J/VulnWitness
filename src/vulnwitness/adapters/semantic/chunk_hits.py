"""Collapse vector-store chunk hits into one ranked match per CVE.

The vector collection CVE-KGRAG's pipeline builds (ADR 0006) holds description chunks with
IDs such as ``CVE-2024-0001_chunk_0``; the CVE ID lives in each chunk's
``cve_id`` metadata. A CVE is ranked by its nearest chunk. Its score is
``1 / (1 + distance)``: monotonic in the store's distance whatever metric the
collection uses (that collection uses Chroma's default squared L2). This module
has no vector-store dependency, so the core lane exercises it.
"""

import math
import re
from collections.abc import Iterable, Mapping, Sequence, Set
from dataclasses import dataclass
from typing import Any, cast

from vulnwitness.domain.cve import CVE_ID_PATTERN, MAX_CVE_ID_CHARS
from vulnwitness.domain.search import RetrievalMatch


class MalformedChunkHitError(ValueError):
    """A vector-store hit lacks a CVE ID or a finite, non-negative distance."""


@dataclass(frozen=True)
class ChunkHit:
    cve_id: str
    distance: float


def read_chunk_hit(metadata: object, distance: object) -> ChunkHit:
    if not isinstance(metadata, Mapping):
        raise MalformedChunkHitError("chunk metadata is not a mapping")
    cve_id = cast(Mapping[str, Any], metadata).get("cve_id")
    # Canonical form only: filters reach the store as an exact ``$in`` on this value.
    if (
        not isinstance(cve_id, str)
        or len(cve_id) > MAX_CVE_ID_CHARS
        or re.fullmatch(CVE_ID_PATTERN, cve_id) is None
    ):
        raise MalformedChunkHitError("chunk metadata has no canonical cve_id")
    if isinstance(distance, bool) or not isinstance(distance, int | float):
        raise MalformedChunkHitError("chunk distance is not a number")
    if not math.isfinite(distance) or distance < 0:
        raise MalformedChunkHitError("chunk distance is not finite and non-negative")
    return ChunkHit(cve_id=cve_id, distance=float(distance))


def read_chroma_query_hits(query_hits: Mapping[str, Any]) -> list[ChunkHit]:
    """Chunk hits from a single-query ``Collection.query`` answer (one row per list)."""
    metadata_rows = query_hits.get("metadatas")
    distance_rows = query_hits.get("distances")
    if not isinstance(metadata_rows, Sequence) or not isinstance(distance_rows, Sequence):
        raise MalformedChunkHitError("query answer lacks metadatas or distances")
    if len(metadata_rows) != 1 or len(distance_rows) != 1:
        raise MalformedChunkHitError("query answer does not hold exactly one query row")
    metadatas = metadata_rows[0]
    distances = distance_rows[0]
    if len(metadatas) != len(distances):
        raise MalformedChunkHitError("metadatas and distances differ in length")
    chunk_hits: list[ChunkHit] = []
    for metadata, distance in zip(metadatas, distances, strict=True):
        chunk_hits.append(read_chunk_hit(metadata, distance))
    return chunk_hits


def collapse_chunk_hits(
    chunk_hits: Iterable[ChunkHit], limit: int, allowed_cve_ids: Set[str] | None
) -> tuple[RetrievalMatch, ...]:
    """Up to ``limit`` CVEs by nearest chunk; ties ordered by ascending CVE ID."""
    nearest_distance_by_cve: dict[str, float] = {}
    for chunk_hit in chunk_hits:
        if allowed_cve_ids is not None and chunk_hit.cve_id not in allowed_cve_ids:
            continue
        nearest_distance = nearest_distance_by_cve.get(chunk_hit.cve_id)
        if nearest_distance is None or chunk_hit.distance < nearest_distance:
            nearest_distance_by_cve[chunk_hit.cve_id] = chunk_hit.distance
    ranked_cves = sorted(nearest_distance_by_cve.items(), key=lambda entry: (entry[1], entry[0]))
    matches: list[RetrievalMatch] = []
    for cve_id, distance in ranked_cves[:limit]:
        matches.append(
            RetrievalMatch(
                cve_id=cve_id,
                score=round(1.0 / (1.0 + distance), 6),
                matched_fields=("semantic.embedding",),
                matched_terms=(),
            )
        )
    return tuple(matches)
