"""Explicit links, inheritance, exclusions and fan-out on small offline inputs."""

import pytest

from tests.support.builders import build_cve_record
from tests.support.mitre_catalogues import (
    CAPEC_XML,
    CWE_XML,
    build_attack_json,
    build_snippet_mapping,
)
from vulnwitness.adapters.mitre.catalogue_parser import build_mapping_snapshot
from vulnwitness.domain.weakness_associations import MAX_WEAKNESS_PATHS


def test_direct_path_retains_every_hop_source() -> None:
    # Arrange
    mapping = build_snippet_mapping()
    record = build_cve_record(cwe_ids=["CWE-79"])

    # Act
    associations = mapping.associate(record)
    path = associations.paths[0]

    # Assert
    assert path.cwe_id == "CWE-79"
    assert path.capec_id == "CAPEC-10"
    assert path.technique.technique_id == "T1548.004"
    assert path.inherited_from is None
    assert path.derived is True
    assert path.hops[0].source == "NVD record"
    assert path.hops[0].evidence_ids == record.evidence_ids
    assert path.hops[1].relation == "cwe_related_attack_pattern"
    assert path.hops[1].source_version == "5.0"
    assert path.hops[2].relation == "capec_attack_taxonomy_mapping"
    assert path.hops[2].source_version == "3.9"
    assert path.technique_source.version == "20.0"


def test_inherited_mapping_retains_the_complete_parent_chain() -> None:
    # Arrange
    mapping = build_snippet_mapping()

    # Act
    paths = mapping.associate(build_cve_record(cwe_ids=["CWE-79"])).paths
    inherited_path = next(
        path for path in paths if path.capec_id == "CAPEC-13" and path.inherited_from == "CAPEC-20"
    )

    # Assert
    assert inherited_path.capec_id == "CAPEC-13"
    assert inherited_path.inherited_from == "CAPEC-20"
    assert inherited_path.technique.technique_id == "T1548"
    assert inherited_path.hops[2].from_id == "CAPEC-13"
    assert inherited_path.hops[2].to_id == "CAPEC-10"
    assert inherited_path.hops[3].to_id == "CAPEC-20"
    assert inherited_path.hops[4].from_id == "CAPEC-20"


def test_deprecated_capecs_and_inactive_attack_objects_are_counted_and_excluded() -> None:
    # Arrange
    snapshot = build_mapping_snapshot(CWE_XML, CAPEC_XML, build_attack_json())

    # Act
    capec_ids = snapshot.cwe_capecs["CWE-79"]
    unavailable_ids = snapshot.capecs["CAPEC-12"].unavailable_technique_ids

    # Assert
    assert "CAPEC-11" not in snapshot.capecs
    assert "CAPEC-11" not in capec_ids
    assert snapshot.capecs["CAPEC-12"].mappings == ()
    assert unavailable_ids == ("T2001", "T2002")
    assert snapshot.counts.deprecated_capecs_skipped == 1
    assert snapshot.counts.deprecated_attack_objects_skipped == 1
    assert snapshot.counts.revoked_attack_objects_skipped == 1


def test_subtechnique_parent_is_a_technique_and_tactics_come_from_phases() -> None:
    # Arrange
    mapping = build_snippet_mapping()

    # Act
    paths = mapping.associate(build_cve_record(cwe_ids=["CWE-79"])).paths
    subtechnique = paths[0].technique
    parent = paths[1].technique

    # Assert
    assert subtechnique.technique_id == "T1548.004"
    assert subtechnique.kind == "subtechnique"
    assert subtechnique.parent_technique_id == "T1548"
    assert parent.technique_id == "T1548"
    assert parent.kind == "technique"
    assert parent.parent_technique_id is None
    assert subtechnique.tactics == ("Impact",)
    assert parent.tactics == ("Impact",)


@pytest.mark.parametrize("extra_techniques", [0, 7, 8, 25])
def test_full_and_capec_terminal_paths_share_the_cap_and_exact_omitted_count(
    extra_techniques: int,
) -> None:
    # Arrange
    mapping = build_snippet_mapping(extra_techniques=extra_techniques)
    record = build_cve_record(cwe_ids=["CWE-79"])

    # Act
    associations = mapping.associate(record)
    repeated_associations = mapping.associate(record)

    # Assert
    # One direct, three inherited, one terminal; each extra technique adds two full paths.
    total_paths = 5 + 2 * extra_techniques
    assert len(associations.paths) == min(MAX_WEAKNESS_PATHS, total_paths)
    assert associations.omitted_count == max(0, total_paths - MAX_WEAKNESS_PATHS)
    assert associations.paths[0].technique.technique_id == "T1548.004"
    path_kinds = []
    for path in associations.paths:
        if path.terminal_reason is not None:
            path_kinds.append(2)
        else:
            path_kinds.append(int(path.inherited_from is not None))
    assert path_kinds == sorted(path_kinds)
    assert (2 in path_kinds) == (total_paths <= MAX_WEAKNESS_PATHS)
    assert repeated_associations == associations
    assert associations.ordering == (
        "direct_then_capec_inherited_then_cwe_inherited_then_capec_terminal_then_id_not_importance"
    )
    assert associations.missing_links[0].reason == "attack_technique_unavailable"


def test_missing_catalogue_hops_remain_empty_and_are_reported() -> None:
    # Arrange
    mapping = build_snippet_mapping()

    # Act
    associations = mapping.associate(build_cve_record(cwe_ids=["CWE-788", "CWE-999"]))

    # Assert
    assert associations.paths == ()
    assert associations.missing_links[0].reason == "no_related_attack_pattern"
    assert associations.missing_links[1].reason == "cwe_not_in_snapshot"


def test_cyclic_capec_parent_chain_refuses_the_build() -> None:
    # Arrange
    capec_xml = CAPEC_XML.replace(b'CAPEC_ID="20"', b'CAPEC_ID="13"')

    # Act / Assert
    with pytest.raises(ValueError, match="cycle"):
        build_mapping_snapshot(CWE_XML, capec_xml, build_attack_json())


def test_absent_parent_is_reported_without_filling_the_mapping() -> None:
    # Arrange
    capec_xml = CAPEC_XML.replace(b'CAPEC_ID="20"', b'CAPEC_ID="999"')

    # Act
    snapshot = build_mapping_snapshot(CWE_XML, capec_xml, build_attack_json())
    child = snapshot.capecs["CAPEC-10"]

    # Assert
    assert child.unavailable_parent_ids == ("CAPEC-999",)
    assert len(child.mappings) == 1
    assert child.mappings[0].inherited_from is None


def test_unknown_excerpt_cwe_refuses_an_empty_excerpt() -> None:
    # Arrange
    selected_cwes = ("CWE-999999",)

    # Act / Assert
    with pytest.raises(ValueError, match="selected CWE IDs are absent"):
        build_mapping_snapshot(CWE_XML, CAPEC_XML, build_attack_json(), selected_cwes)


def test_cwe_inheritance_keeps_both_hierarchies_and_terminal_paths() -> None:
    # Arrange
    mapping = build_snippet_mapping()

    # Act
    associations = mapping.associate(build_cve_record(cwe_ids=["CWE-787"]))
    full_path = next(path for path in associations.paths if path.inherited_from is None)
    combined_path = next(path for path in associations.paths if path.inherited_from is not None)
    terminal_path = associations.paths[-1]

    # Assert
    assert len(associations.paths) == 5
    assert associations.missing_links[0].reason == "attack_technique_unavailable"
    assert full_path.inherited_from_cwe == "CWE-119"
    assert full_path.inherited_from is None
    assert full_path.hops[1].relation == "cwe_child_of"
    assert full_path.hops[1].from_id == "CWE-787"
    assert full_path.hops[1].to_id == "CWE-119"
    assert full_path.hops[1].source == "CWE catalogue"
    assert full_path.hops[1].source_version == "5.0"
    assert full_path.hops[1].source_sha256 == mapping.describe().sources[0].sha256
    assert full_path.hops[2].from_id == "CWE-119"
    assert full_path.hops[2].relation == "cwe_related_attack_pattern"
    assert combined_path.inherited_from_cwe == "CWE-119"
    assert combined_path.inherited_from == "CAPEC-20"
    assert terminal_path.inherited_from_cwe == "CWE-119"
    assert terminal_path.terminal_reason == "no_attack_mapping"
    assert len(terminal_path.hops) == 3
    assert "inference along the CWE hierarchy, not a catalogue link" in associations.note


def test_cwe_inherited_paths_share_the_cap_after_direct_and_capec_inherited_paths() -> None:
    # Arrange
    mapping = build_snippet_mapping(extra_techniques=7)

    # Act
    associations = mapping.associate(build_cve_record(cwe_ids=["CWE-79", "CWE-787"]))

    # Assert
    assert len(associations.paths) == MAX_WEAKNESS_PATHS
    assert associations.omitted_count == 18
    assert all(path.cwe_id == "CWE-79" for path in associations.paths[:18])
    assert all(path.inherited_from_cwe == "CWE-119" for path in associations.paths[18:])
    assert all(path.terminal_reason is None for path in associations.paths)


def test_excerpt_resolves_cwe_ancestors_against_the_full_input() -> None:
    # Arrange
    selected_cwes = ("CWE-787",)

    # Act
    snapshot = build_mapping_snapshot(CWE_XML, CAPEC_XML, build_attack_json(), selected_cwes)

    # Assert
    assert snapshot.coverage == "excerpt"
    assert snapshot.cwe_capecs == {"CWE-787": ()}
    assert snapshot.cwe_inheritance["CWE-787"][0].inherited_from_cwe == "CWE-119"
    assert set(snapshot.capecs) == {"CAPEC-10", "CAPEC-12", "CAPEC-13"}
    assert snapshot.counts.cwes_with_capec_links == 0
    assert snapshot.counts.cwes_with_inherited_capec_links == 1
