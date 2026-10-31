"""Build bounded CVE associations with explicit links and marked CWE inference."""

from cve_kgrag.domain.cve import CveRecord
from cve_kgrag.domain.weakness_associations import (
    MAX_WEAKNESS_PATHS,
    AssociationHop,
    CapecMapping,
    MissingAssociationLink,
    WeaknessAssociationPath,
    WeaknessAssociations,
    WeaknessMappingSnapshot,
    WeaknessSnapshotCapability,
)


def path_order(
    path: WeaknessAssociationPath,
) -> tuple[int, str, str, str, str, str, tuple[str, ...]]:
    parents: list[str] = []
    for hop in path.hops:
        if hop.relation in ("capec_child_of", "cwe_child_of"):
            parents.append(hop.to_id)
    if path.terminal_reason is not None:
        category = 3
    elif path.inherited_from_cwe is not None:
        category = 2
    else:
        category = int(path.inherited_from is not None)
    return (
        category,
        path.cwe_id,
        path.capec_id,
        path.technique.technique_id if path.technique is not None else "",
        path.inherited_from or "",
        path.inherited_from_cwe or "",
        tuple(parents),
    )


class WeaknessMapping:
    """A snapshot bound to its computed digest, with explicit comparison status."""

    def __init__(
        self,
        snapshot: WeaknessMappingSnapshot,
        sha256: str,
        *,
        expected_sha256_compared: bool = False,
    ) -> None:
        self._snapshot = snapshot
        self._sha256 = sha256
        self._expected_sha256_compared = expected_sha256_compared

    def describe(self) -> WeaknessSnapshotCapability:
        return WeaknessSnapshotCapability(
            coverage=self._snapshot.coverage,
            integrity=(
                "Compared with expected SHA-256."
                if self._expected_sha256_compared
                else "File identity recorded; no expected SHA-256 supplied."
            ),
            snapshot_sha256=self._sha256,
            sources=self._snapshot.sources,
            counts=self._snapshot.counts,
        )

    def associate(self, record: CveRecord) -> WeaknessAssociations:
        """Paths capped after deterministic ordering; every absent hop is reported."""
        paths: list[WeaknessAssociationPath] = []
        missing_links: list[MissingAssociationLink] = []
        if not record.cwe_ids:
            missing_links.append(
                MissingAssociationLink(subject=record.cve_id, reason="no_specific_cwe")
            )
        for cwe_id in sorted(set(record.cwe_ids)):
            capec_ids = self._snapshot.cwe_capecs.get(cwe_id)
            if capec_ids is None:
                missing_links.append(
                    MissingAssociationLink(subject=cwe_id, reason="cwe_not_in_snapshot")
                )
                continue
            inheritances = self._snapshot.cwe_inheritance.get(cwe_id, ())
            if not capec_ids and not inheritances:
                missing_links.append(
                    MissingAssociationLink(subject=cwe_id, reason="no_related_attack_pattern")
                )
            capec_sources: list[tuple[tuple[str, ...], tuple[str, ...]]] = [(capec_ids, ())]
            for inheritance in inheritances:
                capec_sources.append((inheritance.capec_ids, inheritance.parent_chain))
            for linked_capecs, cwe_parent_chain in capec_sources:
                for capec_id in linked_capecs:
                    capec = self._snapshot.capecs.get(capec_id)
                    if capec is None:
                        missing_links.append(
                            MissingAssociationLink(subject=capec_id, reason="capec_not_in_snapshot")
                        )
                        continue
                    if not capec.mappings:
                        paths.append(
                            self._build_path(record, cwe_id, capec_id, None, cwe_parent_chain)
                        )
                    for parent_id in capec.unavailable_parent_ids:
                        missing_links.append(
                            MissingAssociationLink(
                                subject=parent_id,
                                reason="capec_parent_unavailable",
                            )
                        )
                    for technique_id in capec.unavailable_technique_ids:
                        missing_links.append(
                            MissingAssociationLink(
                                subject=technique_id, reason="attack_technique_unavailable"
                            )
                        )
                    for mapping in capec.mappings:
                        paths.append(
                            self._build_path(record, cwe_id, capec_id, mapping, cwe_parent_chain)
                        )
        paths.sort(key=path_order)
        return WeaknessAssociations(
            paths=tuple(paths[:MAX_WEAKNESS_PATHS]),
            omitted_count=max(0, len(paths) - MAX_WEAKNESS_PATHS),
            missing_links=tuple(missing_links),
            snapshot_sha256=self._sha256,
        )

    def _build_path(
        self,
        record: CveRecord,
        cwe_id: str,
        capec_id: str,
        mapping: CapecMapping | None,
        cwe_parent_chain: tuple[str, ...],
    ) -> WeaknessAssociationPath:
        sources = {}
        for source in self._snapshot.sources:
            sources[source.catalogue] = source
        cwe_source = sources["CWE"]
        capec_source = sources["CAPEC"]
        hops = [
            AssociationHop(
                from_id=record.cve_id,
                to_id=cwe_id,
                relation="nvd_cwe",
                source="NVD record",
                evidence_ids=record.evidence_ids,
            ),
        ]
        linked_cwe = cwe_id
        for parent_cwe in cwe_parent_chain:
            hops.append(
                AssociationHop(
                    from_id=linked_cwe,
                    to_id=parent_cwe,
                    relation="cwe_child_of",
                    source="CWE catalogue",
                    source_version=cwe_source.version,
                    source_sha256=cwe_source.sha256,
                )
            )
            linked_cwe = parent_cwe
        inherited_from_cwe = linked_cwe if cwe_parent_chain else None
        hops.append(
            AssociationHop(
                from_id=linked_cwe,
                to_id=capec_id,
                relation="cwe_related_attack_pattern",
                source="CWE catalogue",
                source_version=cwe_source.version,
                source_sha256=cwe_source.sha256,
            )
        )
        if mapping is None:
            return WeaknessAssociationPath(
                cwe_id=cwe_id,
                capec_id=capec_id,
                terminal_reason="no_attack_mapping",
                inherited_from_cwe=inherited_from_cwe,
                hops=tuple(hops),
            )
        mapping_capec = capec_id
        for parent in mapping.parent_chain:
            hops.append(
                AssociationHop(
                    from_id=mapping_capec,
                    to_id=parent,
                    relation="capec_child_of",
                    source="CAPEC catalogue",
                    source_version=capec_source.version,
                    source_sha256=capec_source.sha256,
                )
            )
            mapping_capec = parent
        hops.append(
            AssociationHop(
                from_id=mapping_capec,
                to_id=mapping.technique.technique_id,
                relation="capec_attack_taxonomy_mapping",
                source="CAPEC catalogue",
                source_version=capec_source.version,
                source_sha256=capec_source.sha256,
            )
        )
        return WeaknessAssociationPath(
            cwe_id=cwe_id,
            capec_id=capec_id,
            technique=mapping.technique,
            technique_source=sources["ATT&CK Enterprise"],
            inherited_from=mapping.inherited_from,
            inherited_from_cwe=inherited_from_cwe,
            hops=tuple(hops),
        )
