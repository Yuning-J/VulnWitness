"""Writes the inputs of the format-1 compatibility store and imports them (ADR 0009 §15).

The store beside this file was written once by this script with the importer at commit
28e5b4d (contract version 2.0.0-dev.25), and its bytes are pinned by
``tests/contract/test_store_format_compatibility.py``. Never run it to refresh the store:
a store written by a later importer proves nothing about reading what 28e5b4d wrote.

The inputs are authored with the importer's test helpers so that, for each field the
store persists, it holds every value the importer at 28e5b4d can write, a KEV entry
included, and nothing that importer could not write.

Usage, from a checkout of 28e5b4d: ``python build_store.py WORK_DIR``; the store is
written to ``WORK_DIR/stores/store``.
"""

import sys
from pathlib import Path
from typing import Any

from tests.support.legacy_inputs import (
    build_declaration,
    build_kev_row,
    build_v1_feed,
    build_v1_item,
    build_v2_entry,
    build_v2_feed,
    run_test_migration,
    write_gzip_feed,
    write_inputs_manifest,
    write_kev_csv,
    write_plain_feed,
    write_zip_feed,
)

GATEWAY_ANY = "cpe:2.3:a:democorp:gateway:*:*:*:*:*:*:*:*"


def cvss(version: str, vector: str, score: float, severity: str | None = None) -> dict[str, Any]:
    data: dict[str, Any] = {"version": version, "vectorString": vector, "baseScore": score}
    if severity is not None:
        data["baseSeverity"] = severity
    return data


def write_inputs(inputs_dir: Path) -> Path:
    """Write every input and the input manifest naming them; the manifest's path."""
    # F1: NVD 2.0 year feed 2099, plain; its timestamp has a fraction.
    entry_1 = build_v2_entry(
        1,
        descriptions=[
            {"lang": "en", "value": "SYNTHETIC: democorp gateway mishandles input."},
            {"lang": "es", "value": "SINTETICO: la pasarela de democorp maneja mal la entrada."},
            {"lang": "en"},  # dropped: no value
        ],
        metrics={
            "cvssMetricV40": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": cvss(
                        "4.0",
                        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                        9.3,
                        "CRITICAL",
                    ),
                }
            ],
            "cvssMetricV31": [
                {
                    "source": "cna@democorp.example",
                    "type": "Secondary",
                    "cvssData": cvss(
                        "3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", 8.2, "HIGH"
                    ),
                }
            ],
            "cvssMetricV30": [
                {
                    "source": "nvd@nist.gov",
                    "cvssData": cvss(
                        "3.0", "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L", 5.0, "MEDIUM"
                    ),
                }
            ],
            "cvssMetricV2": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "baseSeverity": "LOW",
                    "cvssData": cvss("2.0", "AV:L/AC:H/Au:N/C:P/I:N/A:N", 1.2),
                }
            ],
        },
        weaknesses=[
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "description": [
                    {"lang": "en", "value": "CWE-79"},
                    {"lang": "en", "value": "NVD-CWE-noinfo"},
                    {"lang": "en", "value": "cwe-20"},
                ],
            }
        ],
        configurations=[
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "negate": False,
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:democorp:gateway:1.0:*:*:*:*:*:*:*",
                            },
                            {
                                "vulnerable": True,
                                "criteria": GATEWAY_ANY,
                                "versionStartIncluding": "2.0",
                                "versionEndExcluding": "2.5",
                            },
                            {
                                "vulnerable": True,
                                "criteria": GATEWAY_ANY,
                                "versionStartExcluding": "3.0",
                                "versionEndIncluding": "3.4",
                            },
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:democorp:agent:*:*:*:*:*:*:*:*",
                                "versionEndExcluding": "4.0",
                            },
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:democorp:console:*:*:*:*:*:*:*:*",
                            },
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:o:democorp:firmware:-:*:*:*:*:*:*:*",
                            },
                            {
                                "vulnerable": False,
                                "criteria": "cpe:2.3:h:democorp:board:-:*:*:*:*:*:*:*",
                            },
                        ],
                    },
                    {
                        "operator": "OR",
                        "negate": True,
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:democorp:excluded:1.0:*:*:*:*:*:*:*",
                            }
                        ],
                    },
                ]
            }
        ],
        references=[
            {
                "url": "https://democorp.example/advisory/1",
                "source": "cna@democorp.example",
                "tags": ["Vendor Advisory", "Patch"],
            },
            {"url": "https://democorp.example/notes/1"},
            {"url": "https://democorp.example/notes/2", "source": "nvd@nist.gov"},
            {"url": "https://democorp.example/notes/3", "tags": ["Third Party Advisory"]},
        ],
        cisaExploitAdd="2099-01-04",
        cisaActionDue="2099-01-25",
    )
    entry_2 = build_v2_entry(
        2,
        last_modified=None,
        published=None,
        sourceIdentifier=None,
        configurations=[],
        weaknesses=[
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "description": [{"lang": "en", "value": "NVD-CWE-Other"}],
            }
        ],
        cisaExploitAdd="2099-01-06",
    )
    entry_3 = build_v2_entry(
        3,
        published="2099-01-02T05:04:05.123+02:00",
        descriptions=[{"lang": "en-US", "value": "SYNTHETIC: democorp gateway leaks nothing."}],
        metrics={
            "cvssMetricV40": [
                {
                    "source": "cna@democorp.example",
                    "type": "Secondary",
                    "cvssData": cvss(
                        "4.0",
                        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
                        0.0,
                    ),
                }
            ],
            "cvssMetricV31": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": cvss(
                        "3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "NONE"
                    ),
                }
            ],
        },
        cisaExploitAdd="2099-01-07",
        cisaActionDue="2099-01-28",
    )
    entry_4_old = build_v2_entry(4)
    write_plain_feed(
        inputs_dir / "nvdcve-2.0-2099.json",
        build_v2_feed(
            [entry_1, entry_2, entry_3, entry_4_old], timestamp="2026-10-20T00:00:00.250"
        ),
    )

    # F2: NVD 1.1 year feed 2098, gzipped.
    item_10 = build_v1_item(10)
    item_10["cve"]["problemtype"] = {
        "problemtype_data": [{"description": [{"lang": "en", "value": "CWE-787"}]}]
    }
    item_10["cve"]["references"] = {
        "reference_data": [
            {
                "url": "https://democorp.example/advisory/10",
                "name": "ADV-10",
                "refsource": "CONFIRM",
                "tags": ["Vendor Advisory"],
            },
            {"url": "https://democorp.example/notes/10", "name": "notes-10"},
        ]
    }
    item_10["configurations"]["nodes"][0]["cpe_match"] = [
        {
            "vulnerable": True,
            "cpe23Uri": "cpe:2.3:a:democorp:gateway:*:*:*:*:*:*:*:*",
            "versionEndExcluding": "1.5",
        }
    ]
    item_10["impact"] = {
        "baseMetricV3": {
            "cvssV3": cvss("3.0", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL")
        },
        "baseMetricV2": {
            "cvssV2": cvss("2.0", "AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5),
            "severity": "HIGH",
        },
    }
    item_11 = build_v1_item(11, last_modified=None)
    del item_11["cve"]["CVE_data_meta"]["ASSIGNER"]
    item_11["impact"] = {
        "baseMetricV3": {
            "cvssV3": cvss("3.0", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, "MEDIUM")
        },
        "baseMetricV2": {"cvssV2": cvss("2.0", "AV:N/AC:L/Au:N/C:N/I:P/A:N", 5.0)},
    }
    write_gzip_feed(inputs_dir / "nvdcve-1.1-2098.json.gz", build_v1_feed([item_10, item_11]))

    # F3: NVD 2.0 recent feed, zipped: a later version of CVE-9999-0004 that supersedes F1's.
    entry_4_new = build_v2_entry(
        4,
        last_modified="2099-02-01T00:00:00.000",
        description="SYNTHETIC: democorp gateway mishandles input, revised.",
    )
    write_zip_feed(
        inputs_dir / "nvdcve-2.0-recent.json.zip",
        build_v2_feed([entry_4_new], timestamp="2026-10-21T00:00:00.000"),
    )

    # F4: NVD 1.1 modified feed, plain, with no timestamp.
    write_plain_feed(
        inputs_dir / "nvdcve-1.1-modified.json", build_v1_feed([build_v1_item(12)], timestamp=None)
    )

    # The KEV catalog: one row per ransomware value, with and without a due date.
    write_kev_csv(
        inputs_dir / "known_exploited_vulnerabilities.csv",
        [
            build_kev_row(1, knownRansomwareCampaignUse="Known"),
            build_kev_row(4, knownRansomwareCampaignUse="", dueDate="2099-02-15"),
            build_kev_row(10, knownRansomwareCampaignUse="Unknown", dueDate=""),
        ],
    )
    return write_inputs_manifest(
        inputs_dir,
        [
            build_declaration("nvdcve-2.0-2099.json", retrieved_at="2026-10-24T10:30:00.5+02:00"),
            build_declaration("nvdcve-1.1-2098.json.gz"),
            build_declaration("nvdcve-2.0-recent.json.zip"),
            build_declaration("nvdcve-1.1-modified.json"),
            build_declaration("known_exploited_vulnerabilities.csv", source="cisa-kev"),
        ],
    )


def main(work_dir: Path) -> None:
    inputs_dir = work_dir / "inputs"
    stores_dir = work_dir / "stores"
    inputs_dir.mkdir(parents=True)
    stores_dir.mkdir()
    report = run_test_migration(write_inputs(inputs_dir), stores_dir / "store")
    print(report.model_dump_json(indent=2))


if __name__ == "__main__":
    main(Path(sys.argv[1]))
