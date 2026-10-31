"""Build bounded CVE associations using only explicit snapshot links."""

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


def path_order(path: WeaknessAssociationPath) -> tuple[int, str, str, str, str, tuple[str, ...]]:
    parents: list[str] = []
    for hop in path.hops:
        if hop.relation == "capec_child_of":
            parents.append(hop.to_id)
    return (
        2 if path.terminal_reason is not None else int(path.inherited_from is not None),
        path.cwe_id,
        path.capec_id,
        path.technique.technique_id if path.technique is not None else "",
        path.inherited_from or "",
        tuple(parents),
    )


class WeaknessMapping:
    """A digest-verified snapshot, read without modifying its catalogue links."""

    def __init__(self, snapshot: WeaknessMappingSnapshot, sha256: str) -> None:
        self._snapshot = snapshot
        self._sha256 = sha256

    def describe(self) -> WeaknessSnapshotCapability:
        return WeaknessSnapshotCapability(
            coverage=self._snapshot.coverage,
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
            if not capec_ids:
                missing_links.append(
                    MissingAssociationLink(subject=cwe_id, reason="no_related_attack_pattern")
                )
            for capec_id in capec_ids:
                capec = self._snapshot.capecs.get(capec_id)
                if capec is None:
                    missing_links.append(
                        MissingAssociationLink(subject=capec_id, reason="capec_not_in_snapshot")
                    )
                    continue
                if not capec.mappings:
                    paths.append(self._build_path(record, cwe_id, capec_id, None))
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
                    paths.append(self._build_path(record, cwe_id, capec_id, mapping))
        paths.sort(key=path_order)
        return WeaknessAssociations(
            paths=tuple(paths[:MAX_WEAKNESS_PATHS]),
            omitted_count=max(0, len(paths) - MAX_WEAKNESS_PATHS),
            missing_links=tuple(missing_links),
            snapshot_sha256=self._sha256,
        )

    def _build_path(
        self, record: CveRecord, cwe_id: str, capec_id: str, mapping: CapecMapping | None
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
            AssociationHop(
                from_id=cwe_id,
                to_id=capec_id,
                relation="cwe_related_attack_pattern",
                source="CWE catalogue",
                source_version=cwe_source.version,
                source_sha256=cwe_source.sha256,
            ),
        ]
        if mapping is None:
            return WeaknessAssociationPath(
                cwe_id=cwe_id,
                capec_id=capec_id,
                terminal_reason="no_attack_mapping",
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
            hops=tuple(hops),
        )
