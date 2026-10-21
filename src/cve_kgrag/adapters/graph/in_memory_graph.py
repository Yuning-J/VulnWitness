"""Canonical relation graph without a graph-database dependency."""

from collections import defaultdict
from collections.abc import Iterable, Sequence, Set

from cve_kgrag.domain.cve import CveRecord
from cve_kgrag.domain.relations import Relation, record_relations
from cve_kgrag.domain.search import GraphPath, GraphRelation, RetrievalMatch, RetrievalOutcome
from cve_kgrag.domain.taxonomy import BackendStatus


class InMemoryRelationGraph:
    """Implements ``GraphRetriever`` over an indexed, bidirectional record-relation adjacency."""

    def __init__(self, records: Iterable[CveRecord]) -> None:
        self._relations_by_cve: dict[str, frozenset[Relation]] = {}
        self._cves_by_relation: dict[Relation, set[str]] = defaultdict(set)
        for record in records:
            relations = record_relations(record)
            self._relations_by_cve[record.cve_id] = relations
            for relation in relations:
                self._cves_by_relation[relation].add(record.cve_id)

    def expand(
        self, seed_cve_ids: Sequence[str], limit: int, allowed_cve_ids: Set[str] | None
    ) -> RetrievalOutcome:
        """Score = number of distinct shared relations; every seed-relation path is kept."""
        seeds = set(seed_cve_ids)
        paths_by_candidate: dict[str, set[tuple[str, GraphRelation, str]]] = defaultdict(set)
        for seed_id in seed_cve_ids:
            for relation_kind, value in self._relations_by_cve.get(seed_id, ()):
                for candidate_id in self._cves_by_relation[(relation_kind, value)]:
                    if candidate_id in seeds:
                        continue
                    if allowed_cve_ids is not None and candidate_id not in allowed_cve_ids:
                        continue
                    paths_by_candidate[candidate_id].add((seed_id, relation_kind, value))

        matches: list[RetrievalMatch] = []
        for cve_id, paths in paths_by_candidate.items():
            matches.append(self._build_match(cve_id, sorted(paths)))
        matches.sort(key=lambda match: (-match.score, match.cve_id))
        return RetrievalOutcome(status=BackendStatus.OK, matches=tuple(matches[:limit]))

    def _build_match(
        self, cve_id: str, ordered_paths: list[tuple[str, GraphRelation, str]]
    ) -> RetrievalMatch:
        shared_relations: list[Relation] = []
        graph_paths: list[GraphPath] = []
        for seed_id, relation_kind, value in ordered_paths:
            if (relation_kind, value) not in shared_relations:
                shared_relations.append((relation_kind, value))
            graph_paths.append(GraphPath(seed_cve_id=seed_id, relation=relation_kind, value=value))
        shared_relations.sort()
        matched_fields: list[str] = []
        matched_terms: list[str] = []
        for relation_kind, value in shared_relations:
            matched_fields.append(f"relation.{relation_kind}")
            matched_terms.append(value)
        return RetrievalMatch(
            cve_id=cve_id,
            score=float(len(shared_relations)),
            matched_fields=tuple(matched_fields),
            matched_terms=tuple(matched_terms),
            graph_paths=tuple(graph_paths),
        )
