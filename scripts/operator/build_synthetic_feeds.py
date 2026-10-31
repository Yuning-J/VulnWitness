"""Write synthetic NVD 2.0 year feeds, a KEV catalog and an input manifest for the
importer's scale run (ADR 0008 §8). Every record is a CVE-9999-* ID describing no real
product. Usage: build_synthetic_feeds.py DIR RECORD_COUNT [--feed-count N] [--plain]"""

import argparse
import csv
import gzip
import json
from pathlib import Path

FEED_COUNT = 10
KEV_EVERY = 250
RETRIEVED_AT = "2026-10-24T08:30:00Z"
FEED_TIMESTAMP = "2026-10-20T00:00:00.000"
KEV_COLUMNS = [
    "cveID",
    "vendorProject",
    "product",
    "vulnerabilityName",
    "dateAdded",
    "shortDescription",
    "requiredAction",
    "dueDate",
    "knownRansomwareCampaignUse",
    "notes",
    "cwes",
]


def build_entry(number: int) -> dict[str, object]:
    cve_id = f"CVE-9999-{number:06d}"
    product_cpe = f"cpe:2.3:a:democorp:component{number % 500}:1.0:*:*:*:*:*:*:*"
    return {
        "cve": {
            "id": cve_id,
            "sourceIdentifier": "cna@democorp.example",
            "vulnStatus": "Analyzed",
            "published": "2099-01-02T03:04:05.000",
            "lastModified": "2099-01-03T00:00:00.000",
            "descriptions": [
                {"lang": "en", "value": f"SYNTHETIC: democorp component {number} mishandles input."}
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "cvssData": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                        },
                    }
                ]
            },
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-20"}]}],
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": product_cpe,
                                }
                            ]
                        }
                    ]
                }
            ],
            "references": [{"url": f"https://democorp.example/advisories/{number}"}],
        }
    }


def write_feed(path: Path, first_number: int, entry_count: int, is_plain: bool = False) -> None:
    # A whole feed, as NVD publishes one: a single result starting at 0.
    feed = {
        "resultsPerPage": entry_count,
        "startIndex": 0,
        "totalResults": entry_count,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": FEED_TIMESTAMP,
    }
    # Stream one entry at a time so a feed near the file cap need not fit in memory.
    feed_prefix = json.dumps(feed)[:-1] + ', "vulnerabilities": ['
    with (
        path.open("wb") if is_plain else gzip.GzipFile(filename=path, mode="wb", mtime=0)
    ) as feed_file:
        feed_file.write(feed_prefix.encode())
        for number in range(first_number, first_number + entry_count):
            if number > first_number:
                feed_file.write(b", ")
            feed_file.write(json.dumps(build_entry(number)).encode())
        feed_file.write(b"]}")


def write_kev(path: Path, record_count: int) -> None:
    with path.open("w", encoding="utf-8", newline="") as kev_file:
        writer = csv.writer(kev_file, dialect="excel")
        writer.writerow(KEV_COLUMNS)
        for number in range(1, record_count + 1, KEV_EVERY):
            writer.writerow(
                [
                    f"CVE-9999-{number:06d}",
                    "Democorp",
                    "Component",
                    "Input flaw",
                    "2099-01-05",
                    "SYNTHETIC: exploited.",
                    "Update.",
                    "2099-01-26",
                    "Unknown",
                    "",
                    "",
                ]
            )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("record_count", type=int)
    parser.add_argument("--feed-count", type=int, default=FEED_COUNT, choices=range(1, 129))
    parser.add_argument("--plain", action="store_true", help="write uncompressed JSON feeds")
    arguments = parser.parse_args()
    output_dir = arguments.output_dir
    record_count = arguments.record_count
    output_dir.mkdir(parents=True, exist_ok=True)
    per_feed = -(-record_count // arguments.feed_count)
    manifest_lines = ["format_version: 1", "inputs:"]
    for feed_index in range(arguments.feed_count):
        first_number = feed_index * per_feed + 1
        entry_count = min(per_feed, record_count - feed_index * per_feed)
        if entry_count <= 0:
            break
        suffix = ".json" if arguments.plain else ".json.gz"
        file_name = f"nvdcve-2.0-{2002 + feed_index}{suffix}"
        write_feed(output_dir / file_name, first_number, entry_count, arguments.plain)
        manifest_lines.append(
            f'  - {{source: nvd, path: {file_name}, retrieved_at: "{RETRIEVED_AT}"}}'
        )
    write_kev(output_dir / "known_exploited_vulnerabilities.csv", record_count)
    kev_path = "known_exploited_vulnerabilities.csv"
    manifest_lines.append(
        f'  - {{source: cisa-kev, path: {kev_path}, retrieved_at: "{RETRIEVED_AT}"}}'
    )
    (output_dir / "inputs.yaml").write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
