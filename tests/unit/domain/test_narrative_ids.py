"""Identifiers named in statements are matched exactly against recorded responses."""

from vulnwitness.domain.narrative_ids import (
    check_narrative_identifiers,
    collect_recorded_identifiers,
    extract_identifiers,
)


def test_identifiers_are_exact_bounded_tokens() -> None:
    text = (
        "cve-2026-1234 and CVE-2026-12345, CWE-79; CNVD-2026-123456 but not "
        "XCVE-2026-9999 nor CVE-2026-1234567x nor CWE-"
    )

    assert extract_identifiers(text) == (
        "CVE-2026-1234",
        "CVE-2026-12345",
        "CWE-79",
        "CNVD-2026-123456",
        "CVE-2026-1234567",
    )


def test_unrecorded_identifiers_are_listed_by_finding() -> None:
    recorded = collect_recorded_identifiers(['{"cve_id":"CVE-2026-0001","cwe_ids":["CWE-79"]}'])

    check = check_narrative_identifiers(
        (
            ("f1", "CVE-2026-0001 is an XSS (CWE-79)."),
            ("f2", "Also see CVE-2026-0999 and CVE-2026-0001."),
        ),
        recorded,
    )

    assert (check.identifiers_checked, check.recorded, check.unrecorded_count) == (4, 3, 1)
    (unrecorded,) = check.unrecorded
    assert (unrecorded.finding_id, unrecorded.identifier, unrecorded.kind) == (
        "f2",
        "CVE-2026-0999",
        "cve",
    )


def test_a_longer_recorded_id_does_not_record_its_prefix() -> None:
    recorded = collect_recorded_identifiers(["CVE-2026-12345"])

    check = check_narrative_identifiers((("f", "CVE-2026-1234"),), recorded)

    assert check.unrecorded_count == 1
