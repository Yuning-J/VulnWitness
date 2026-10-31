"""Parse official CWE, CAPEC and Enterprise ATT&CK files without network access."""

import json
import re
from typing import Any
from xml.etree import ElementTree

from cve_kgrag.adapters.mitre.cwe_inheritance import collect_cwe_inheritance, read_cwe_parents
from cve_kgrag.domain.hashing import sha256_hex
from cve_kgrag.domain.weakness_associations import (
    AttackTechnique,
    CapecAssociations,
    CapecMapping,
    CatalogueSource,
    CweCapecInheritance,
    MappingCounts,
    WeaknessMappingSnapshot,
)


def normalize_technique_id(entry_id: str) -> str:
    """CAPEC writes ATT&CK numeric IDs with or without the T prefix."""
    technique_id = entry_id.strip()
    if not technique_id.startswith("T"):
        technique_id = "T" + technique_id
    if not re.fullmatch(r"T[0-9]{4}(\.[0-9]{3})?", technique_id):
        raise ValueError("CAPEC contains an invalid ATT&CK technique ID")
    return technique_id


def read_attack_techniques(
    attack_bytes: bytes,
) -> tuple[dict[str, AttackTechnique], str, int, int]:
    """Active attack-pattern objects, their release version, and excluded object counts."""
    bundle = json.loads(attack_bytes)
    tactics: dict[str, str] = {}
    versions: set[str] = set()
    deprecated_count = 0
    revoked_count = 0
    for attack_object in bundle["objects"]:
        if attack_object.get("x_mitre_deprecated", False):
            deprecated_count += 1
        if attack_object.get("revoked", False):
            revoked_count += 1
        if (
            attack_object["type"] == "x-mitre-collection"
            and attack_object["name"] == "Enterprise ATT&CK"
        ):
            versions.add(attack_object["x_mitre_version"])
        if attack_object.get("x_mitre_deprecated", False) or attack_object.get("revoked", False):
            continue
        if attack_object["type"] == "x-mitre-tactic":
            tactics[attack_object["x_mitre_shortname"]] = attack_object["name"]
    if len(versions) != 1:
        raise ValueError("ATT&CK requires one Enterprise collection release version")
    techniques: dict[str, AttackTechnique] = {}
    for attack_object in bundle["objects"]:
        if attack_object["type"] != "attack-pattern":
            continue
        if attack_object.get("x_mitre_deprecated", False) or attack_object.get("revoked", False):
            continue
        technique_id = read_attack_external_id(attack_object)
        if technique_id is None:
            continue
        tactic_names: set[str] = set()
        for phase in attack_object.get("kill_chain_phases", []):
            if phase["kill_chain_name"] == "mitre-attack":
                phase_name = phase["phase_name"]
                # An absent tactic object leaves the authoritative phase spelling intact.
                tactic_names.add(tactics.get(phase_name, phase_name))
        is_subtechnique = "." in technique_id
        techniques[technique_id] = AttackTechnique(
            technique_id=technique_id,
            name=attack_object["name"],
            kind="subtechnique" if is_subtechnique else "technique",
            parent_technique_id=technique_id.split(".")[0] if is_subtechnique else None,
            tactics=tuple(sorted(tactic_names)),
        )
    return techniques, versions.pop(), deprecated_count, revoked_count


def read_attack_external_id(attack_object: dict[str, Any]) -> str | None:
    for reference in attack_object.get("external_references", []):
        if reference["source_name"] == "mitre-attack":
            return normalize_technique_id(reference["external_id"])
    return None


def collect_capec_mappings(
    capec_id: str,
    direct_mappings: dict[str, tuple[AttackTechnique, ...]],
    parents: dict[str, tuple[str, ...]],
    unavailable_ids: dict[str, tuple[str, ...]],
) -> tuple[tuple[CapecMapping, ...], tuple[str, ...], tuple[str, ...]]:
    """Every direct and inherited mapping, retaining each explicit ChildOf chain.

    Deprecated parents are absent from the index and cannot bridge a chain. Cycles
    refuse the build rather than silently dropping or inventing an inheritance hop.
    """
    mappings: list[CapecMapping] = []
    missing_techniques: set[str] = set()
    missing_parents: set[str] = set()
    pending: list[tuple[str, tuple[str, ...]]] = [(capec_id, ())]
    while pending:
        ancestor_id, chain = pending.pop()
        missing_techniques.update(unavailable_ids[ancestor_id])
        for technique in direct_mappings[ancestor_id]:
            mappings.append(
                CapecMapping(
                    technique=technique,
                    inherited_from=ancestor_id if chain else None,
                    parent_chain=chain,
                )
            )
        for parent_id in reversed(parents[ancestor_id]):
            if parent_id == capec_id or parent_id in chain:
                raise ValueError("CAPEC ChildOf chain contains a cycle")
            if parent_id in direct_mappings:
                pending.append((parent_id, (*chain, parent_id)))
            else:
                missing_parents.add(parent_id)
    return tuple(mappings), tuple(sorted(missing_techniques)), tuple(sorted(missing_parents))


def build_mapping_snapshot(
    cwe_bytes: bytes,
    capec_bytes: bytes,
    attack_bytes: bytes,
    cwe_ids: tuple[str, ...] = (),
) -> WeaknessMappingSnapshot:
    """Derive catalogue links and marked CWE inference; CWE IDs select an excerpt.

    Raises XML, JSON or validation errors for malformed catalogues and ValueError for
    invalid technique IDs, missing release metadata or cyclic CWE/CAPEC inheritance.
    """
    cwe_catalogue = ElementTree.fromstring(cwe_bytes)
    capec_catalogue = ElementTree.fromstring(capec_bytes)
    techniques, attack_version, deprecated_attack, revoked_attack = read_attack_techniques(
        attack_bytes
    )
    direct_mappings: dict[str, tuple[AttackTechnique, ...]] = {}
    parents: dict[str, tuple[str, ...]] = {}
    unavailable_ids: dict[str, tuple[str, ...]] = {}
    capec_names: dict[str, str] = {}
    deprecated_capecs: set[str] = set()
    for pattern in capec_catalogue.findall("./{*}Attack_Patterns/{*}Attack_Pattern"):
        capec_id = "CAPEC-" + pattern.attrib["ID"]
        if pattern.attrib.get("Status") == "Deprecated":
            deprecated_capecs.add(capec_id)
            continue
        capec_names[capec_id] = pattern.attrib["Name"]
        technique_ids: set[str] = set()
        for taxonomy in pattern.findall("./{*}Taxonomy_Mappings/{*}Taxonomy_Mapping"):
            if taxonomy.attrib["Taxonomy_Name"] == "ATTACK":
                technique_ids.add(normalize_technique_id(taxonomy.findtext("{*}Entry_ID", "")))
        mapped_techniques: list[AttackTechnique] = []
        missing_techniques: list[str] = []
        for technique_id in sorted(technique_ids):
            if technique_id in techniques:
                mapped_techniques.append(techniques[technique_id])
            else:
                missing_techniques.append(technique_id)
        direct_mappings[capec_id] = tuple(mapped_techniques)
        unavailable_ids[capec_id] = tuple(missing_techniques)
        parent_ids: set[str] = set()
        for relation in pattern.findall("./{*}Related_Attack_Patterns/{*}Related_Attack_Pattern"):
            if relation.attrib["Nature"] == "ChildOf":
                parent_ids.add("CAPEC-" + relation.attrib["CAPEC_ID"])
        parents[capec_id] = tuple(sorted(parent_ids))
    all_cwe_capecs: dict[str, tuple[str, ...]] = {}
    cwe_parents: dict[str, tuple[str, ...]] = {}
    cwes_with_direct_links: set[str] = set()
    for weakness in cwe_catalogue.findall("./{*}Weaknesses/{*}Weakness"):
        cwe_id = "CWE-" + weakness.attrib["ID"]
        cwe_parents[cwe_id] = read_cwe_parents(weakness)
        linked_capecs: set[str] = set()
        for relation in weakness.findall("./{*}Related_Attack_Patterns/{*}Related_Attack_Pattern"):
            cwes_with_direct_links.add(cwe_id)
            capec_id = "CAPEC-" + relation.attrib["CAPEC_ID"]
            if capec_id not in deprecated_capecs:
                linked_capecs.add(capec_id)
        all_cwe_capecs[cwe_id] = tuple(sorted(linked_capecs))
    cwe_capecs: dict[str, tuple[str, ...]] = {}
    cwe_inheritance: dict[str, tuple[CweCapecInheritance, ...]] = {}
    for cwe_id, linked_capecs_tuple in all_cwe_capecs.items():
        if cwe_ids and cwe_id not in cwe_ids:
            continue
        cwe_capecs[cwe_id] = linked_capecs_tuple
        inheritances = collect_cwe_inheritance(
            cwe_id, all_cwe_capecs, cwes_with_direct_links, cwe_parents
        )
        if inheritances:
            cwe_inheritance[cwe_id] = inheritances
    if cwe_ids and set(cwe_ids) != set(cwe_capecs):
        raise ValueError("selected CWE IDs are absent from the CWE catalogue")
    included_capecs = set(capec_names)
    if cwe_ids:
        included_capecs = set()
        for cwe_links in cwe_capecs.values():
            included_capecs.update(cwe_links)
        for inheritances in cwe_inheritance.values():
            for inheritance in inheritances:
                included_capecs.update(inheritance.capec_ids)
    capecs: dict[str, CapecAssociations] = {}
    direct_count = 0
    inherited_count = 0
    mapped_capec_count = 0
    for capec_id in sorted(included_capecs):
        if capec_id not in capec_names:
            continue
        mappings, missing_ids, missing_parents = collect_capec_mappings(
            capec_id, direct_mappings, parents, unavailable_ids
        )
        capecs[capec_id] = CapecAssociations(
            name=capec_names[capec_id],
            mappings=mappings,
            unavailable_technique_ids=missing_ids,
            unavailable_parent_ids=missing_parents,
        )
        if mappings:
            mapped_capec_count += 1
        for mapping in mappings:
            if mapping.inherited_from is None:
                direct_count += 1
            else:
                inherited_count += 1
    return WeaknessMappingSnapshot(
        coverage="excerpt" if cwe_ids else "full",
        sources=(
            CatalogueSource(
                catalogue="CWE",
                version=cwe_catalogue.attrib["Version"],
                sha256=sha256_hex(cwe_bytes),
            ),
            CatalogueSource(
                catalogue="CAPEC",
                version=capec_catalogue.attrib["Version"],
                sha256=sha256_hex(capec_bytes),
            ),
            CatalogueSource(
                catalogue="ATT&CK Enterprise",
                version=attack_version,
                sha256=sha256_hex(attack_bytes),
            ),
        ),
        cwe_capecs=cwe_capecs,
        cwe_inheritance=cwe_inheritance,
        capecs=capecs,
        counts=MappingCounts(
            cwes_with_capec_links=sum(bool(links) for links in cwe_capecs.values()),
            cwes_with_inherited_capec_links=len(cwe_inheritance),
            capecs_with_attack_links=mapped_capec_count,
            direct_mappings=direct_count,
            inherited_mappings=inherited_count,
            deprecated_capecs_skipped=len(deprecated_capecs),
            deprecated_attack_objects_skipped=deprecated_attack,
            revoked_attack_objects_skipped=revoked_attack,
        ),
    )


def serialize_mapping_snapshot(snapshot: WeaknessMappingSnapshot) -> bytes:
    """Stable, compact UTF-8 encoding whose bytes the operator pins."""
    return (
        json.dumps(
            snapshot.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n"
    ).encode()
