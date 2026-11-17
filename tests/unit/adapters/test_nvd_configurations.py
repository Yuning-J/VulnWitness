"""NVD 2.0 configurations that say more than the affected products are kept as given."""

from typing import Any

import pytest

from tests.unit.adapters.test_nvd_normalizer import (
    NVD_SNAPSHOT,
    build_cpe_match,
    build_normalizer,
    build_v1,
    build_v2,
)
from vulnwitness.adapters.nvd.normalizer import NvdNormalizationError
from vulnwitness.domain.cve import (
    MAX_CONFIGURATION_MATCHES,
    MAX_CONFIGURATION_NODES,
    MAX_CONFIGURATIONS,
    CveRecord,
    VersionRange,
    find_range_gaps,
)
from vulnwitness.domain.normalization import NormalizationFailureCode
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

    product_cpes: list[str | None] = []
    for product in record.affected:
        product_cpes.append(product.cpe)
    assert product_cpes == [ROUTER]
    (configuration,) = record.configurations
    assert configuration.operator == "AND"
    vulnerable_flags: list[bool] = []
    for node in configuration.nodes:
        for match in node.matches:
            vulnerable_flags.append(match.vulnerable)
    assert vulnerable_flags == [True, False]
    assert configuration.nodes[0].matches[0].version_range == VersionRange(end_excluding="2.0")
    condition = record.find_platform_condition(ROUTER, VersionRange(end_excluding="2.0"))
    assert condition is not None
    assert condition.platforms == (HARDWARE,)
    assert record.has_format4_fields()


def test_a_plain_or_of_vulnerable_products_is_not_repeated() -> None:
    record = normalize(
        [{"nodes": [{"operator": "OR", "cpeMatch": [build_cpe_match(ROUTER, True)]}]}]
    )

    assert record.configurations == ()
    assert record.find_platform_condition(ROUTER, VersionRange(exact="1.0")) is None


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

    product_cpes: list[str | None] = []
    for product in record.affected:
        product_cpes.append(product.cpe)
    configuration_cpes: list[str] = []
    for match in record.configurations[0].nodes[0].matches:
        configuration_cpes.append(match.cpe)
    assert product_cpes == [ROUTER]
    assert configuration_cpes == [unnamed, ROUTER]


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


def test_a_platform_for_another_range_is_not_attached_to_the_hit() -> None:
    standalone = {
        "nodes": [{"cpeMatch": [build_cpe_match(ROUTER, True, versionEndExcluding="1.0")]}]
    }
    record = normalize([standalone, and_configuration()])

    note = build_nvd_version_note(record, "router_firmware 0.5")

    assert isinstance(note, NvdVersionHit)
    assert note.required_platforms == ()
    assert "running-on platform" not in note.wording


@pytest.mark.parametrize("standalone_first", [True, False])
def test_a_condition_also_standing_alone_does_not_claim_a_platform_is_required(
    standalone_first: bool,
) -> None:
    standalone = {
        "nodes": [{"cpeMatch": [build_cpe_match(ROUTER, True, versionEndExcluding="2.0")]}]
    }
    configurations = [standalone, and_configuration()]
    if not standalone_first:
        configurations.reverse()
    record = normalize(configurations)

    note = build_nvd_version_note(record, "router_firmware 1.5")

    assert isinstance(note, NvdVersionHit)
    assert note.required_platforms == (HARDWARE,)
    assert "only together with" not in note.wording
    assert "lists it without one in others" in note.wording


@pytest.mark.parametrize("negation_level", ["configuration", "node"])
def test_a_negated_occurrence_does_not_claim_the_condition_can_stand_without_a_platform(
    negation_level: str,
) -> None:
    standalone = {
        "nodes": [{"cpeMatch": [build_cpe_match(ROUTER, True, versionEndExcluding="2.0")]}]
    }
    if negation_level == "configuration":
        standalone["negate"] = True
    else:
        standalone["nodes"][0]["negate"] = True
    record = normalize([standalone, and_configuration()])

    note = build_nvd_version_note(record, "router_firmware 1.5")

    assert isinstance(note, NvdVersionHit)
    assert note.required_platforms == (HARDWARE,)
    assert "only together with" in note.wording


def test_platforms_for_distinct_ranges_of_the_same_cpe_stay_separate() -> None:
    later = and_configuration()
    later["nodes"][0]["cpeMatch"][0]["versionEndExcluding"] = "3.0"
    later["nodes"][0]["cpeMatch"][0]["versionStartIncluding"] = "2.0"
    other_hardware = HARDWARE.replace(":router:", ":other_router:")
    later["nodes"][1]["cpeMatch"][0]["criteria"] = other_hardware
    record = normalize([and_configuration(), later])

    early_note = build_nvd_version_note(record, "router_firmware 1.5")
    later_note = build_nvd_version_note(record, "router_firmware 2.5")

    assert isinstance(early_note, NvdVersionHit)
    assert isinstance(later_note, NvdVersionHit)
    assert early_note.required_platforms == (HARDWARE,)
    assert later_note.required_platforms == (other_hardware,)


def test_an_and_node_over_vulnerable_matches_is_kept_and_rendered_as_a_conjunction() -> None:
    companion = ROUTER.replace(":router_firmware:", ":companion:")
    record = normalize(
        [
            {
                "nodes": [
                    {
                        "operator": "AND",
                        "cpeMatch": [
                            build_cpe_match(ROUTER, True),
                            build_cpe_match(companion, True),
                        ],
                    }
                ]
            }
        ]
    )

    text = "\n".join(render_mirrored_lines(record, 200))

    assert len(record.configurations) == 1
    assert f"vulnerable {ROUTER} AND vulnerable {companion}" in text


def test_a_platform_in_an_and_node_is_attached_to_its_condition() -> None:
    configuration = and_configuration()
    node = configuration["nodes"][0]
    node["operator"] = "AND"
    node["cpeMatch"].extend(configuration["nodes"][1]["cpeMatch"])
    record = normalize([{"nodes": [node]}])

    note = build_nvd_version_note(record, "router_firmware 1.5")

    assert isinstance(note, NvdVersionHit)
    assert note.required_platforms == (HARDWARE,)
    assert "only together with" in note.wording


def test_a_vulnerable_match_beyond_the_node_cap_still_gets_its_platform_note() -> None:
    configuration = and_configuration()
    filler = build_cpe_match(ROUTER.replace(":router_firmware:", ":other:"), True)
    configuration["nodes"][0]["cpeMatch"] = [filler] * MAX_CONFIGURATION_MATCHES + configuration[
        "nodes"
    ][0]["cpeMatch"]
    record = normalize([configuration])

    note = build_nvd_version_note(record, "router_firmware 1.5")

    assert record.configurations[0].nodes[0].omitted_matches == 1
    assert isinstance(note, NvdVersionHit)
    assert note.required_platforms == (HARDWARE,)


def test_platforms_beyond_the_node_match_cap_are_included_in_the_omitted_count() -> None:
    configuration = and_configuration()
    platform_matches: list[dict[str, Any]] = []
    for number in range(MAX_CONFIGURATION_MATCHES + 2):
        hardware = HARDWARE.replace(":router:", f":router_{number}:")
        platform_matches.append(build_cpe_match(hardware, False))
    configuration["nodes"][1]["cpeMatch"] = platform_matches
    record = normalize([configuration])

    note = build_nvd_version_note(record, "router_firmware 1.5")

    assert record.configurations[0].nodes[1].omitted_matches == 2
    assert isinstance(note, NvdVersionHit)
    assert len(note.required_platforms) == 16
    assert note.omitted_platforms == 114
    assert "and 114 more" in note.wording


def test_platforms_beyond_the_node_count_cap_are_retained_in_the_summary() -> None:
    configuration = and_configuration()
    configuration["nodes"] = (
        configuration["nodes"][:1] * MAX_CONFIGURATION_NODES + configuration["nodes"][1:]
    )
    record = normalize([configuration])

    note = build_nvd_version_note(record, "router_firmware 1.5")

    assert record.configurations[0].omitted_nodes == 1
    assert isinstance(note, NvdVersionHit)
    assert note.required_platforms == (HARDWARE,)


def test_platforms_beyond_the_configuration_cap_are_retained_in_the_summary() -> None:
    other = and_configuration(ROUTER.replace(":router_firmware:", ":other:"))
    record = normalize([other] * MAX_CONFIGURATIONS + [and_configuration()])

    note = build_nvd_version_note(record, "router_firmware 1.5")

    assert record.omitted_configurations == 1
    assert isinstance(note, NvdVersionHit)
    assert note.required_platforms == (HARDWARE,)


def test_platform_summary_and_standalone_wording_survive_record_serialization() -> None:
    standalone = {
        "nodes": [{"cpeMatch": [build_cpe_match(ROUTER, True, versionEndExcluding="2.0")]}]
    }
    record = normalize([standalone, and_configuration()])

    restored = CveRecord.model_validate_json(record.model_dump_json())

    assert build_nvd_version_note(restored, "router_firmware 1.5") == build_nvd_version_note(
        record, "router_firmware 1.5"
    )


def test_nvd_11_refuses_an_unnamed_vulnerable_cpe_instead_of_losing_it() -> None:
    entry = build_v1()
    entry["configurations"] = {
        "nodes": [
            {
                "cpe_match": [
                    {"cpe23Uri": "cpe:2.3:h:qualcomm:-:-:*:*:*:*:*:*:*", "vulnerable": True}
                ]
            }
        ]
    }

    with pytest.raises(NvdNormalizationError) as failure:
        build_normalizer().normalize_v1(entry, NVD_SNAPSHOT)

    assert failure.value.code == NormalizationFailureCode.INVALID_CPE
