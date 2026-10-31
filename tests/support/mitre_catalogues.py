"""Small offline XML/STIX inputs for explicit catalogue association cases."""

import json
from pathlib import Path
from typing import Any

from cve_kgrag.adapters.mitre.catalogue_parser import (
    build_mapping_snapshot,
    serialize_mapping_snapshot,
)
from cve_kgrag.domain.hashing import sha256_hex
from cve_kgrag.domain.search import Candidate
from cve_kgrag.domain.weakness_mapping import WeaknessMapping

CWE_XML = b"""<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-8" Version="5.0">
<Weaknesses><Weakness ID="79"><Related_Attack_Patterns>
<Related_Attack_Pattern CAPEC_ID="10"/><Related_Attack_Pattern CAPEC_ID="11"/>
<Related_Attack_Pattern CAPEC_ID="12"/><Related_Attack_Pattern CAPEC_ID="13"/>
</Related_Attack_Patterns></Weakness>
<Weakness ID="119"><Related_Attack_Patterns>
<Related_Attack_Pattern CAPEC_ID="10"/><Related_Attack_Pattern CAPEC_ID="12"/>
<Related_Attack_Pattern CAPEC_ID="13"/>
</Related_Attack_Patterns></Weakness>
<Weakness ID="787"><Related_Weaknesses>
<Related_Weakness Nature="ChildOf" CWE_ID="119" View_ID="1000" Ordinal="Primary"/>
</Related_Weaknesses></Weakness><Weakness ID="788"/></Weaknesses>
</Weakness_Catalog>"""
CAPEC_XML = b"""<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3" Version="3.9">
<Attack_Patterns>
<Attack_Pattern ID="10" Name="Child" Status="Stable"><Related_Attack_Patterns>
<Related_Attack_Pattern Nature="ChildOf" CAPEC_ID="20"/>
</Related_Attack_Patterns><Taxonomy_Mappings><Taxonomy_Mapping Taxonomy_Name="ATTACK">
<Entry_ID>1548.004</Entry_ID></Taxonomy_Mapping>
<Taxonomy_Mapping Taxonomy_Name="WASC"><Entry_ID>9999</Entry_ID></Taxonomy_Mapping>
</Taxonomy_Mappings></Attack_Pattern>
<Attack_Pattern ID="11" Name="Retired" Status="Deprecated"><Taxonomy_Mappings>
<Taxonomy_Mapping Taxonomy_Name="ATTACK"><Entry_ID>1548</Entry_ID></Taxonomy_Mapping>
</Taxonomy_Mappings></Attack_Pattern>
<Attack_Pattern ID="12" Name="Retired techniques" Status="Stable"><Taxonomy_Mappings>
<Taxonomy_Mapping Taxonomy_Name="ATTACK"><Entry_ID>2001</Entry_ID></Taxonomy_Mapping>
<Taxonomy_Mapping Taxonomy_Name="ATTACK"><Entry_ID>2002</Entry_ID></Taxonomy_Mapping>
</Taxonomy_Mappings></Attack_Pattern>
<Attack_Pattern ID="13" Name="Grandchild" Status="Stable"><Related_Attack_Patterns>
<Related_Attack_Pattern Nature="ChildOf" CAPEC_ID="10"/>
</Related_Attack_Patterns></Attack_Pattern>
<Attack_Pattern ID="20" Name="Parent" Status="Stable"><Taxonomy_Mappings>
<Taxonomy_Mapping Taxonomy_Name="ATTACK"><Entry_ID>T1548</Entry_ID></Taxonomy_Mapping>
</Taxonomy_Mappings></Attack_Pattern>
</Attack_Patterns></Attack_Pattern_Catalog>"""


def build_attack_object(technique_id: str, **fields: Any) -> dict[str, Any]:
    attack_object: dict[str, Any] = {
        "type": "attack-pattern",
        "name": "Technique " + technique_id,
        "external_references": [{"source_name": "mitre-attack", "external_id": technique_id}],
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "impact"}],
    }
    attack_object.update(fields)
    return attack_object


def build_attack_json(extra_techniques: int = 0) -> bytes:
    objects = [
        {"type": "x-mitre-collection", "name": "Enterprise ATT&CK", "x_mitre_version": "20.0"},
        {"type": "x-mitre-tactic", "name": "Impact", "x_mitre_shortname": "impact"},
        build_attack_object("T1548"),
        build_attack_object("T1548.004"),
        build_attack_object("T2001", x_mitre_deprecated=True),
        build_attack_object("T2002", revoked=True),
    ]
    for number in range(extra_techniques):
        objects.append(build_attack_object(f"T{3000 + number}"))
    return json.dumps({"type": "bundle", "objects": objects}).encode()


def build_snippet_mapping(extra_techniques: int = 0) -> WeaknessMapping:
    capec_xml = CAPEC_XML
    if extra_techniques:
        taxonomy_mappings = []
        for number in range(extra_techniques):
            taxonomy_mappings.append(
                '<Taxonomy_Mapping Taxonomy_Name="ATTACK">'
                f"<Entry_ID>{3000 + number}</Entry_ID></Taxonomy_Mapping>"
            )
        capec_xml = capec_xml.replace(
            b"</Taxonomy_Mappings>",
            ("".join(taxonomy_mappings) + "</Taxonomy_Mappings>").encode(),
            1,
        )
    snapshot = build_mapping_snapshot(CWE_XML, capec_xml, build_attack_json(extra_techniques))
    return WeaknessMapping(snapshot, sha256_hex(serialize_mapping_snapshot(snapshot)))


def write_snippet_catalogues(directory: Path) -> list[str]:
    directory.mkdir(exist_ok=True)
    arguments = []
    for name, content in (("cwe", CWE_XML), ("capec", CAPEC_XML), ("attack", build_attack_json())):
        path = directory / name
        path.write_bytes(content)
        arguments.extend(("--" + name, str(path)))
    return arguments


def forge_capec_hop(candidate: Candidate) -> Candidate:
    """A consumer-supplied candidate with a CAPEC hop absent from the served snapshot."""
    associations = candidate.weakness_associations
    assert associations is not None
    path = associations.paths[0]
    forged_hop = path.hops[1].model_copy(update={"to_id": "CAPEC-9999"})
    forged_path = path.model_copy(
        update={"capec_id": "CAPEC-9999", "hops": (path.hops[0], forged_hop, *path.hops[2:])}
    )
    forged_associations = associations.model_copy(
        update={"paths": (forged_path, *associations.paths[1:])}
    )
    return candidate.model_copy(update={"weakness_associations": forged_associations})
