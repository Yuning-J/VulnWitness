"""NVD 1.1/2.0 and CISA KEV entries become canonical records with their own evidence."""

from datetime import UTC, date, datetime
from typing import Any

import pytest

from vulnwitness.adapters.nvd.normalizer import (
    KevSource,
    NvdNormalizationError,
    NvdNormalizer,
    RejectedCveError,
    SourceSnapshot,
)
from vulnwitness.composition import build_nvd_normalizer, load_packaged_source_registry
from vulnwitness.domain.normalization import NormalizationFailureCode
from vulnwitness.domain.taxonomy import SourceType, TrustLevel


def build_normalizer() -> NvdNormalizer:
    """The normalizer composition builds, citing the packaged registry's terms."""
    return build_nvd_normalizer(load_packaged_source_registry())


NVD_SNAPSHOT = SourceSnapshot(
    source_uri="https://services.nvd.nist.gov/rest/json/cves/2.0",
    retrieved_at=datetime(2026, 10, 13, tzinfo=UTC),
    source_version="etag-1",
)
KEV_SNAPSHOT = SourceSnapshot(
    source_uri="urn:test:kev-catalog",
    retrieved_at=datetime(2026, 10, 12, tzinfo=UTC),
    source_version="2026.10.12",
)


def build_cpe_match(cpe: str, is_vulnerable: bool, **bounds: str) -> dict[str, Any]:
    return {"criteria": cpe, "vulnerable": is_vulnerable, **bounds}


def build_v2(**overrides: Any) -> dict[str, Any]:
    vulnerability: dict[str, Any] = {
        "id": "CVE-9999-0201",
        "sourceIdentifier": "psirt@democorp.example",
        "vulnStatus": "Analyzed",
        "published": "2099-01-02T03:04:05.000",
        "lastModified": "2099-01-03T03:04:05Z",
        "descriptions": [
            {"lang": "es", "value": "Descripcion sintetica."},
            {"lang": "en", "value": "SYNTHETIC: democorp gateway mishandles input."},
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N",
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                    },
                },
                {
                    "source": "psirt@democorp.example",
                    "type": "Secondary",
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:L",
                        "baseScore": 5.9,
                        "baseSeverity": "MEDIUM",
                    },
                },
            ]
        },
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-787"}]}],
        "references": [
            {"url": "https://democorp.example/advisory/1", "source": "psirt@democorp.example"}
        ],
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            build_cpe_match(
                                "cpe:2.3:a:democorp:tcp\\/ip_stack:*:*:*:*:*:*:*:*",
                                True,
                                versionEndExcluding="2.0.1",
                            ),
                            build_cpe_match("cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*", False),
                        ]
                    }
                ]
            }
        ],
    }
    vulnerability.update(overrides)
    return vulnerability


def build_v1(**cve_overrides: Any) -> dict[str, Any]:
    cve: dict[str, Any] = {
        "CVE_data_meta": {"ID": "CVE-9999-0202", "ASSIGNER": "cna@example.test"},
        "description": {"description_data": [{"lang": "en", "value": "SYNTHETIC record."}]},
        "problemtype": {"problemtype_data": [{"description": [{"value": "CWE-20"}]}]},
        "references": {
            "reference_data": [
                {
                    "url": "https://example.test/advisory",
                    "name": "https://example.test/advisory",
                    "refsource": "CONFIRM",
                    "tags": ["Vendor Advisory"],
                }
            ]
        },
    }
    cve.update(cve_overrides)
    return {
        "cve": cve,
        "impact": {
            "baseMetricV3": {
                "cvssV3": {
                    "version": "3.0",
                    "vectorString": "CVSS:3.1/AV:N",
                    "baseScore": 9.8,
                    "baseSeverity": "CRITICAL",
                }
            },
            "baseMetricV2": {
                "cvssV2": {"version": "2.0", "vectorString": "AV:N/AC:L", "baseScore": 7.5},
                "severity": "HIGH",
            },
        },
        "configurations": {"nodes": []},
    }


def test_v2_keeps_every_cvss_scorer_vendor_and_version_range() -> None:
    normalized = build_normalizer().normalize_v2(build_v2(), NVD_SNAPSHOT)

    record = normalized.record
    assert [metric.scorer for metric in record.cvss] == [
        "nvd@nist.gov",
        "psirt@democorp.example",
    ]
    assert record.affected[0].vendor == "democorp"
    assert record.affected[0].product == "tcp/ip_stack"
    assert record.affected[0].version_ranges[0].end_excluding == "2.0.1"
    assert record.cwe_ids == ("CWE-787",)
    assert normalized.evidence[0].source_type is SourceType.NVD_API_2
    assert normalized.evidence[0].source_version == "etag-1"


def test_v2_platform_cpe_not_marked_vulnerable_is_not_an_affected_product() -> None:
    record = build_normalizer().normalize_v2(build_v2(), NVD_SNAPSHOT).record

    vendors: list[str] = []
    for affected_product in record.affected:
        vendors.append(affected_product.vendor)
    assert vendors == ["democorp"]


def test_v2_descriptions_are_attributed_to_the_source_identifier() -> None:
    record = build_normalizer().normalize_v2(build_v2(), NVD_SNAPSHOT).record

    assert record.descriptions[0].source == "psirt@democorp.example"


def test_v2_evidence_hash_covers_the_configurations() -> None:
    other_configurations = [
        {
            "nodes": [
                {
                    "cpeMatch": [
                        build_cpe_match("cpe:2.3:a:othercorp:portal:1.0:*:*:*:*:*:*:*", True)
                    ]
                }
            ]
        }
    ]

    first = build_normalizer().normalize_v2(build_v2(), NVD_SNAPSHOT)
    second = build_normalizer().normalize_v2(
        build_v2(configurations=other_configurations), NVD_SNAPSHOT
    )

    assert first.record.affected != second.record.affected
    assert first.evidence[0].evidence_id != second.evidence[0].evidence_id


def test_v2_rejected_status_raises_rejected_error() -> None:
    with pytest.raises(RejectedCveError, match="CVE-9999-0201"):
        build_normalizer().normalize_v2(build_v2(vulnStatus="Rejected"), NVD_SNAPSHOT)


def test_v2_inline_cisa_listing_becomes_kev_entry_without_ransomware_claim() -> None:
    vulnerability = build_v2(cisaExploitAdd="2026-01-02", cisaActionDue="2026-01-23")

    normalized = build_normalizer().normalize_v2(vulnerability, NVD_SNAPSHOT)

    kev = normalized.record.kev
    assert kev is not None
    assert kev.date_added == date(2026, 1, 2)
    assert kev.due_date == date(2026, 1, 23)
    assert kev.known_ransomware_campaign_use is None
    assert len(normalized.evidence) == 1


@pytest.mark.parametrize(
    "vulnerability",
    [
        build_v2(
            metrics={
                "cvssMetricV31": [
                    {
                        "source": "nvd@nist.gov",
                        "cvssData": {"vectorString": "CVSS:3.1/AV:N", "baseScore": "9.8"},
                    }
                ]
            }
        ),
        build_v2(
            metrics={
                "cvssMetricV31": [
                    {
                        "source": "nvd@nist.gov",
                        "cvssData": {"vectorString": "CVSS:3.1/AV:N", "baseScore": True},
                    }
                ]
            }
        ),
        build_v2(configurations={"nodes": []}),
        build_v2(
            configurations=[
                {"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:x", "vulnerable": True}]}]}
            ]
        ),
        build_v2(
            configurations=[
                {"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*"}]}]}
            ]
        ),
        build_v2(descriptions=[]),
        build_v2(published="yesterday"),
        build_v2(
            configurations=[
                {
                    "nodes": [
                        {
                            "negate": "true",
                            "cpeMatch": [
                                build_cpe_match("cpe:2.3:a:acme:app:*:*:*:*:*:*:*:*", True)
                            ],
                        }
                    ]
                }
            ]
        ),
    ],
    ids=[
        "string_base_score",
        "boolean_base_score",
        "configurations_object",
        "truncated_cpe",
        "cpe_match_without_vulnerable_flag",
        "no_description",
        "unparseable_timestamp",
        "string_negate_flag",
    ],
)
def test_v2_malformed_entry_raises_instead_of_dropping_fields(
    vulnerability: dict[str, Any],
) -> None:
    with pytest.raises(NvdNormalizationError):
        build_normalizer().normalize_v2(vulnerability, NVD_SNAPSHOT)


def test_v1_derives_cvss_31_from_the_vector_when_the_version_says_30() -> None:
    record = build_normalizer().normalize_v1(build_v1(), NVD_SNAPSHOT).record

    assert record.cvss[0].version == "3.1"
    assert record.cvss[0].scorer == "NVD"


def test_v1_cvss_v2_severity_comes_from_base_metric_v2() -> None:
    record = build_normalizer().normalize_v1(build_v1(), NVD_SNAPSHOT).record

    assert record.cvss[1].version == "2.0"
    assert record.cvss[1].base_severity == "HIGH"


def test_v1_reference_source_is_the_refsource_not_the_name_url() -> None:
    record = build_normalizer().normalize_v1(build_v1(), NVD_SNAPSHOT).record

    assert record.references[0].source == "CONFIRM"
    assert record.references[0].tags == ("Vendor Advisory",)


def test_v1_reject_marker_raises_rejected_error() -> None:
    rejected_description = {
        "description_data": [{"lang": "en", "value": "** REJECT ** DO NOT USE THIS CANDIDATE."}]
    }

    with pytest.raises(RejectedCveError):
        build_normalizer().normalize_v1(build_v1(description=rejected_description), NVD_SNAPSHOT)


def test_v1_description_mentioning_withdrawn_is_not_rejected() -> None:
    description = {
        "description_data": [{"lang": "en", "value": "SYNTHETIC: a withdrawn token is reused."}]
    }

    record = build_normalizer().normalize_v1(build_v1(description=description), NVD_SNAPSHOT).record

    assert record.cve_id == "CVE-9999-0202"


def test_kev_entry_adds_an_anchor_with_the_catalog_snapshot_identity() -> None:
    kev = KevSource(
        entry={
            "cveID": "CVE-9999-0201",
            "dateAdded": "2026-01-02",
            "dueDate": "2026-01-23",
            "knownRansomwareCampaignUse": "Known",
        },
        snapshot=KEV_SNAPSHOT,
    )

    normalized = build_normalizer().normalize_v2(build_v2(metrics={}), NVD_SNAPSHOT, kev)

    kev_anchor = normalized.evidence[1]
    assert normalized.record.cvss == ()
    assert normalized.record.kev is not None
    assert normalized.record.kev.known_ransomware_campaign_use == "known"
    assert kev_anchor.source_type is SourceType.CISA_KEV
    assert kev_anchor.trust_level is TrustLevel.AUTHORITATIVE
    assert kev_anchor.source_uri == "urn:test:kev-catalog"
    assert kev_anchor.retrieved_at == KEV_SNAPSHOT.retrieved_at
    assert kev_anchor.source_version == "2026.10.12"


def test_kev_entry_for_another_cve_is_rejected() -> None:
    kev = KevSource(
        entry={"cveID": "CVE-9999-0999", "dateAdded": "2026-01-02"}, snapshot=KEV_SNAPSHOT
    )

    with pytest.raises(NvdNormalizationError, match="does not match"):
        build_normalizer().normalize_v2(build_v2(), NVD_SNAPSHOT, kev)


def build_v1_configurations() -> dict[str, Any]:
    return {
        "nodes": [
            {
                "operator": "AND",
                "children": [
                    {
                        "operator": "OR",
                        "cpe_match": [
                            {
                                "vulnerable": True,
                                "cpe23Uri": "cpe:2.3:a:democorp:legacy_gateway:1.4:*:*:*:*:*:*:*",
                            }
                        ],
                    },
                    {
                        "operator": "OR",
                        "cpe_match": [
                            {
                                "vulnerable": False,
                                "cpe23Uri": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*",
                            }
                        ],
                    },
                ],
            }
        ]
    }


def test_v1_nested_cpe_matches_become_affected_products_with_exact_versions() -> None:
    cve_item = build_v1()
    cve_item["configurations"] = build_v1_configurations()

    record = build_normalizer().normalize_v1(cve_item, NVD_SNAPSHOT).record

    assert len(record.affected) == 1
    assert record.affected[0].product == "legacy_gateway"
    assert record.affected[0].version_ranges[0].exact == "1.4"


def test_normalizing_the_same_entry_twice_yields_identical_output() -> None:
    first = build_normalizer().normalize_v2(build_v2(), NVD_SNAPSHOT)
    second = build_normalizer().normalize_v2(build_v2(), NVD_SNAPSHOT)

    assert first == second


def test_v2_matches_under_a_negated_node_are_not_affected_products() -> None:
    negated_node = {
        "negate": True,
        "cpeMatch": [build_cpe_match("cpe:2.3:a:democorp:gateway_lts:*:*:*:*:*:*:*:*", True)],
    }
    configurations = build_v2()["configurations"]
    configurations[0]["nodes"].append(negated_node)

    record = (
        build_normalizer()
        .normalize_v2(build_v2(configurations=configurations), NVD_SNAPSHOT)
        .record
    )

    products: list[str] = []
    for affected_product in record.affected:
        products.append(affected_product.product)
    assert products == ["tcp/ip_stack"]


def test_v2_scorer_type_is_case_folded() -> None:
    record = build_normalizer().normalize_v2(build_v2(), NVD_SNAPSHOT).record

    assert record.cvss[0].scorer_type == "primary"
    assert record.cvss[1].scorer_type == "secondary"


@pytest.mark.parametrize(
    "vulnerability",
    [
        build_v2(descriptions=[{"lang": "EN", "value": "SYNTHETIC"}]),
        build_v2(
            metrics={
                "cvssMetricV31": [
                    {
                        "source": "nvd@nist.gov",
                        "cvssData": {"vectorString": "CVSS:3.1/AV:N", "baseScore": 11.0},
                    }
                ]
            }
        ),
        build_v2(id="CVE-99-1"),
        build_v2(
            configurations=[
                {"nodes": [{"cpeMatch": [build_cpe_match("cpe:2.3:a:*:*:*:*:*:*:*:*:*:*", True)]}]}
            ]
        ),
    ],
    ids=["upper_case_language", "score_above_ten", "malformed_cve_id", "wildcard_vendor"],
)
def test_v2_contract_violation_raises_the_normalization_error(
    vulnerability: dict[str, Any],
) -> None:
    with pytest.raises(NvdNormalizationError):
        build_normalizer().normalize_v2(vulnerability, NVD_SNAPSHOT)


def test_explicit_kev_entry_supersedes_the_listing_nvd_mirrors() -> None:
    kev = KevSource(
        entry={
            "cveID": "CVE-9999-0201",
            "dateAdded": "2026-02-01",
            "knownRansomwareCampaignUse": "Unknown",
        },
        snapshot=KEV_SNAPSHOT,
    )
    vulnerability = build_v2(cisaExploitAdd="2026-01-02")

    record = build_normalizer().normalize_v2(vulnerability, NVD_SNAPSHOT, kev).record

    assert record.kev is not None
    assert record.kev.date_added == date(2026, 2, 1)
    assert record.kev.known_ransomware_campaign_use == "unknown"


def test_v2_negated_configuration_contributes_no_affected_product() -> None:
    configurations = build_v2()["configurations"]
    configurations.append(
        {
            "negate": True,
            "nodes": [{"cpeMatch": [build_cpe_match("cpe:2.3:a:acme:app:*:*:*:*:*:*:*:*", True)]}],
        }
    )

    record = (
        build_normalizer()
        .normalize_v2(build_v2(configurations=configurations), NVD_SNAPSHOT)
        .record
    )

    assert len(record.affected) == 1
    assert record.affected[0].vendor == "democorp"


def test_v2_configuration_with_string_negate_flag_is_rejected() -> None:
    configurations = [{"negate": "true", "nodes": []}]

    with pytest.raises(NvdNormalizationError, match="negate"):
        build_normalizer().normalize_v2(build_v2(configurations=configurations), NVD_SNAPSHOT)


@pytest.mark.parametrize(
    ("vulnerability", "expected_code"),
    [
        (build_v2(id=None), NormalizationFailureCode.MISSING_FIELD),
        (build_v2(configurations={"nodes": []}), NormalizationFailureCode.WRONG_JSON_TYPE),
        (build_v2(published="yesterday"), NormalizationFailureCode.INVALID_TIMESTAMP),
        (build_v2(cisaExploitAdd="soon"), NormalizationFailureCode.INVALID_DATE),
        (
            build_v2(configurations=[{"nodes": [{"negate": "true", "cpeMatch": []}]}]),
            NormalizationFailureCode.INVALID_CONFIGURATION,
        ),
        (
            build_v2(
                configurations=[
                    {"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:x", "vulnerable": True}]}]}
                ]
            ),
            NormalizationFailureCode.INVALID_CPE,
        ),
        (
            build_v2(references=[{"url": "https://example.invalid/", "tags": [1]}]),
            NormalizationFailureCode.INVALID_REFERENCE,
        ),
        (
            build_v2(
                metrics={
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "cvssData": {"vectorString": "CVSS:3.1/AV:N", "baseScore": "9.8"},
                        }
                    ]
                }
            ),
            NormalizationFailureCode.INVALID_CVSS,
        ),
        (build_v2(descriptions=[]), NormalizationFailureCode.NO_DESCRIPTION),
        (build_v2(id="not-a-cve-id"), NormalizationFailureCode.CONTRACT_VIOLATION),
        (build_v2(vulnStatus="Rejected"), NormalizationFailureCode.REJECTED_BY_SOURCE),
    ],
    ids=[
        "missing_id",
        "configurations_object",
        "unparseable_timestamp",
        "unparseable_cisa_date",
        "string_negate_flag",
        "truncated_cpe",
        "non_string_reference_tag",
        "string_base_score",
        "no_description",
        "malformed_cve_id",
        "rejected",
    ],
)
def test_every_normalization_error_names_its_reason_by_code(
    vulnerability: dict[str, Any], expected_code: NormalizationFailureCode
) -> None:
    with pytest.raises(NvdNormalizationError) as raised:
        build_normalizer().normalize_v2(vulnerability, NVD_SNAPSHOT)

    assert raised.value.code is expected_code


def test_kev_entry_for_another_cve_names_its_reason_by_code() -> None:
    kev = KevSource(
        entry={"cveID": "CVE-9999-0999", "dateAdded": "2026-01-02"}, snapshot=KEV_SNAPSHOT
    )

    with pytest.raises(NvdNormalizationError) as raised:
        build_normalizer().normalize_v2(build_v2(), NVD_SNAPSHOT, kev)

    assert raised.value.code is NormalizationFailureCode.INVALID_KEV_ENTRY


def test_anchors_cite_the_terms_the_source_registry_verifies() -> None:
    source_registry = load_packaged_source_registry()
    kev = KevSource(
        entry={"cveID": "CVE-9999-0201", "dateAdded": "2026-01-02"}, snapshot=KEV_SNAPSHOT
    )

    nvd_anchor, kev_anchor = (
        build_nvd_normalizer(source_registry).normalize_v2(build_v2(), NVD_SNAPSHOT, kev).evidence
    )

    assert nvd_anchor.license_or_terms_ref == source_registry.require_terms("nvd")
    assert kev_anchor.license_or_terms_ref == source_registry.require_terms("cisa-kev")
