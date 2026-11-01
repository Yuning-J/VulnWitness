"""CWE hierarchy selection and nearest-ancestor inference on offline XML."""

from xml.etree import ElementTree

import pytest

from tests.support.mitre_catalogues import CAPEC_XML, CWE_XML, build_attack_json
from vulnwitness.adapters.mitre.catalogue_parser import build_mapping_snapshot
from vulnwitness.adapters.mitre.cwe_inheritance import read_cwe_parents


@pytest.mark.parametrize(
    "relations,expected_parents",
    [
        (
            '<Related_Weakness Nature="ChildOf" CWE_ID="119" View_ID="1000" Ordinal="Primary"/>'
            '<Related_Weakness Nature="ChildOf" CWE_ID="79" View_ID="1000"/>'
            '<Related_Weakness Nature="ChildOf" CWE_ID="20" View_ID="700" Ordinal="Primary"/>'
            '<Related_Weakness Nature="CanPrecede" CWE_ID="120" View_ID="1000"/>',
            ("CWE-119",),
        ),
        (
            '<Related_Weakness Nature="ChildOf" CWE_ID="119" View_ID="1000"/>'
            '<Related_Weakness Nature="ChildOf" CWE_ID="79" View_ID="1000"/>',
            ("CWE-119", "CWE-79"),
        ),
        ('<Related_Weakness Nature="ChildOf" CWE_ID="119" View_ID="700"/>', ()),
    ],
    ids=["primary-parent-in-view-1000", "all-parents-without-primary", "other-view-excluded"],
)
def test_only_selected_view_childof_parents_are_followed(
    relations: str, expected_parents: tuple[str, ...]
) -> None:
    # Arrange
    weakness = ElementTree.fromstring(
        '<Weakness ID="787"><Related_Weaknesses>' + relations + "</Related_Weaknesses></Weakness>"
    )

    # Act
    parent_ids = read_cwe_parents(weakness)

    # Assert
    assert parent_ids == expected_parents


@pytest.mark.parametrize("capec_id", ["10", "11"], ids=["active-link", "deprecated-link"])
def test_a_direct_catalogue_link_prevents_cwe_inheritance(capec_id: str) -> None:
    # Arrange
    cwe_xml = CWE_XML.replace(
        b'<Weakness ID="787">',
        (
            '<Weakness ID="787"><Related_Attack_Patterns>'
            f'<Related_Attack_Pattern CAPEC_ID="{capec_id}"/></Related_Attack_Patterns>'
        ).encode(),
    )

    # Act
    snapshot = build_mapping_snapshot(cwe_xml, CAPEC_XML, build_attack_json())

    # Assert
    assert "CWE-787" not in snapshot.cwe_inheritance
    assert snapshot.counts.cwes_with_inherited_capec_links == 0


@pytest.mark.parametrize(
    "second_parent,expected_chains",
    [
        ("79", (("CWE-119",), ("CWE-79",))),
        ("788", (("CWE-119",),)),
    ],
    ids=["tied-nearest-ancestors", "farther-linked-ancestor-excluded"],
)
def test_inheritance_uses_all_and_only_the_nearest_linked_ancestors(
    second_parent: str, expected_chains: tuple[tuple[str, ...], ...]
) -> None:
    # Arrange
    cwe_xml = (
        CWE_XML.replace(b' Ordinal="Primary"', b"")
        .replace(
            b'<Weakness ID="788"/>',
            b'<Weakness ID="788"><Related_Weaknesses>'
            b'<Related_Weakness Nature="ChildOf" CWE_ID="79" View_ID="1000"/>'
            b"</Related_Weaknesses></Weakness>",
        )
        .replace(
            b'<Related_Weakness Nature="ChildOf" CWE_ID="119" View_ID="1000"/>',
            (
                f'<Related_Weakness Nature="ChildOf" CWE_ID="{second_parent}" View_ID="1000"/>'
            ).encode()
            + b'<Related_Weakness Nature="ChildOf" CWE_ID="119" View_ID="1000"/>',
        )
    )

    # Act
    snapshot = build_mapping_snapshot(cwe_xml, CAPEC_XML, build_attack_json())

    # Assert
    chains = []
    for inheritance in snapshot.cwe_inheritance["CWE-787"]:
        chains.append(inheritance.parent_chain)
    assert tuple(chains) == expected_chains


def test_multilevel_cwe_inheritance_retains_every_parent() -> None:
    # Arrange
    cwe_xml = CWE_XML.replace(
        b'<Weakness ID="788"/>',
        b'<Weakness ID="788"><Related_Weaknesses>'
        b'<Related_Weakness Nature="ChildOf" CWE_ID="787" View_ID="1000"/>'
        b"</Related_Weaknesses></Weakness>",
    )

    # Act
    snapshot = build_mapping_snapshot(cwe_xml, CAPEC_XML, build_attack_json())

    # Assert
    inheritance = snapshot.cwe_inheritance["CWE-788"][0]
    assert inheritance.parent_chain == ("CWE-787", "CWE-119")
    assert inheritance.inherited_from_cwe == "CWE-119"


def test_a_cwe_cycle_refuses_the_build() -> None:
    # Arrange
    cwe_xml = CWE_XML.replace(b'CWE_ID="119"', b'CWE_ID="787"')

    # Act / Assert
    with pytest.raises(ValueError, match="CWE ChildOf chain contains a cycle"):
        build_mapping_snapshot(cwe_xml, CAPEC_XML, build_attack_json())


def test_an_absent_cwe_parent_does_not_invent_links() -> None:
    # Arrange
    cwe_xml = CWE_XML.replace(b'CWE_ID="119"', b'CWE_ID="999"')

    # Act
    snapshot = build_mapping_snapshot(cwe_xml, CAPEC_XML, build_attack_json())

    # Assert
    assert "CWE-787" not in snapshot.cwe_inheritance
