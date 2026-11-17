"""NVD 2.0 configurations that say more than the affected products are kept as given."""

from typing import Any

from tests.unit.adapters.test_nvd_normalizer import (
    NVD_SNAPSHOT,
    build_cpe_match,
    build_normalizer,
    build_v2,
)
from vulnwitness.domain.cve import MAX_CONFIGURATIONS, VersionRange, find_range_gaps
from vulnwitness.domain.nvd_version_note import NvdVersionHit, build_nvd_version_note
from vulnwitness.interfaces.lookup_summary import render_mirrored_lines

ROUTER = "cpe:2.3:o:democorp:router_firmware:*:*:*:*:*:*:*:*"
HARDWARE = "cpe:2.3:h:democorp:router:-:*:*:*:*:*:*:*"


def and_configuration(firmware: str = ROUTER) -> dict[str, Any]:
    return {
        "operator": "AND",
        "nodes": [
            {
                "operator": "OR",
                "negate": False,
                "cpeMatch": [build_cpe_match(firmware, True, versionEndExcluding="2.0")],
            },
            {"operator": "OR", "negate": False, "cpeMatch": [build_cpe_match(HARDWARE, False)]},
        ],
    }


def normalize(configurations: list[dict[str, Any]]) -> Any:
    return (
        build_normalizer()
        .normalize_v2(build_v2(configurations=configurations), NVD_SNAPSHOT)
        .record
    )


def test_an_and_configuration_keeps_its_running_on_platform() -> None:
    record = normalize([and_configuration()])

    assert [product.cpe for product in record.affected] == [ROUTER]
    (configuration,) = record.configurations
    assert configuration.operator == "AND"
    assert [match.vulnerable for node in configuration.nodes for match in node.matches] == [
        True,
        False,
    ]
    assert configuration.nodes[0].matches[0].version_range == VersionRange(end_excluding="2.0")
    assert record.list_platforms(ROUTER) == (HARDWARE,)
    assert record.has_format4_fields()


def test_a_plain_or_of_vulnerable_products_is_not_repeated() -> None:
    record = normalize(
        [{"nodes": [{"operator": "OR", "cpeMatch": [build_cpe_match(ROUTER, True)]}]}]
    )

    assert record.configurations == ()
    assert record.list_platforms(ROUTER) == ()


def test_an_unnamed_cpe_keeps_the_record_and_moves_to_configurations() -> None:
    unnamed = "cpe:2.3:h:qualcomm:-:-:*:*:*:*:*:*:*"
    record = normalize(
        [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "cpeMatch": [
                            build_cpe_match(unnamed, True),
                            build_cpe_match(ROUTER, True),
                        ],
                    }
                ]
            }
        ]
    )

    assert [product.cpe for product in record.affected] == [ROUTER]
    assert [match.cpe for match in record.configurations[0].nodes[0].matches] == [
        unnamed,
        ROUTER,
    ]


def test_configurations_beyond_the_cap_are_counted() -> None:
    record = normalize([and_configuration()] * (MAX_CONFIGURATIONS + 3))

    assert len(record.configurations) == MAX_CONFIGURATIONS
    assert record.omitted_configurations == 3


def test_range_gaps_name_the_open_side() -> None:
    assert find_range_gaps(VersionRange(end_excluding="2.0")) == ("no_lower_bound",)
    assert find_range_gaps(VersionRange(start_including="1.0")) == ("no_upper_bound",)
    assert find_range_gaps(VersionRange(start_including="1.0", end_excluding="2.0")) == ()
    assert find_range_gaps(VersionRange(exact="1.0")) == ()


def test_a_version_hit_names_the_open_range_and_the_platform() -> None:
    record = normalize([and_configuration()])

    note = build_nvd_version_note(record, "router_firmware 1.5")

    assert isinstance(note, NvdVersionHit)
    assert note.range_gaps == ("no_lower_bound",)
    assert note.required_platforms == (HARDWARE,)
    assert "no lower bound" in note.wording
    assert f"running-on platform: {HARDWARE}" in note.wording
    text = "\n".join(render_mirrored_lines(record, 200))
    assert f"vulnerable {ROUTER} < 2.0 AND running on {HARDWARE}" in text
