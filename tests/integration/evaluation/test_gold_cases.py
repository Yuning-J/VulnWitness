"""The evaluation reads only investigation gold files, refusing any other without quoting
it, and names each case by its request and FiGHT source."""

from collections.abc import Sequence
from typing import Any

import pytest
import yaml

from cve_kgrag.domain.evidence_set_verification_report import (
    MAX_REPORTED_VIOLATIONS,
    MAX_VIOLATION_CHARS,
)
from cve_kgrag.evaluation.gold_cases import (
    MAX_GOLD_CASES,
    MAX_GOLD_FILE_BYTES,
    GoldCase,
    GoldFileError,
    load_gold_cases,
)
from tests.support.evaluation import build_gold_row, encode_gold
from tests.support.investigation import GOLD_FILE

GOLD_MARKER = "gold-marker-91c2"


def build_distinct_rows(row_count: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index in range(row_count):
        rows.append(build_gold_row(f"query {index}"))
    return rows


def list_case_hashes(cases: Sequence[GoldCase]) -> list[str]:
    case_hashes: list[str] = []
    for case in cases:
        case_hashes.append(case.case_sha256)
    return case_hashes


def test_investigation_gold_file_loads_every_case_with_its_fight_source() -> None:
    gold_rows = yaml.safe_load(GOLD_FILE.read_text(encoding="utf-8"))["trajectories"]

    cases = load_gold_cases(GOLD_FILE.read_bytes())

    assert len(cases) == len(gold_rows)
    for case, row in zip(cases, gold_rows, strict=True):
        assert case.request.query == row["request"]["query"]
        assert case.fight == row["sources"]["mitre_fight"]
    assert len(set(list_case_hashes(cases))) == len(cases)


def test_case_hash_names_the_request_and_fight_source_not_the_row_id() -> None:
    renamed_row = {"id": "another-name", **build_gold_row("5G-AKA")}

    (case,) = load_gold_cases(encode_gold([build_gold_row("5G-AKA")]))
    (renamed_case,) = load_gold_cases(encode_gold([renamed_row]))
    (unavailable_case,) = load_gold_cases(encode_gold([build_gold_row("5G-AKA", "unavailable")]))

    assert case.case_sha256 == renamed_case.case_sha256
    assert case.case_sha256 != unavailable_case.case_sha256


@pytest.mark.parametrize(
    ("gold_bytes", "expected_message"),
    [
        (b"\xff" + GOLD_MARKER.encode(), "the gold file is not UTF-8 YAML a strict loader accepts"),
        (
            f"trajectories: [{GOLD_MARKER}".encode(),
            "the gold file is not UTF-8 YAML a strict loader accepts",
        ),
        (
            f"trajectories: []\ntrajectories: [{GOLD_MARKER}]\n".encode(),
            "the gold file is not UTF-8 YAML a strict loader accepts",
        ),
        (
            yaml.safe_dump({"queries": [GOLD_MARKER]}).encode(),
            "the gold file holds no trajectories list",
        ),
        (encode_gold([]), "the gold file holds no trajectories list"),
        (encode_gold([GOLD_MARKER]), "case 1 is not a mapping"),
        (
            encode_gold([build_gold_row("5G-AKA", GOLD_MARKER)]),
            "case 1: sources.mitre_fight is not packaged or unavailable",
        ),
        (
            encode_gold([build_gold_row("5G-AKA"), build_gold_row("5G-AKA", scope=GOLD_MARKER)]),
            "case 2: request: scope: Input should be 'protocol_context_only', "
            "'implementation_only' or 'mixed'",
        ),
        (
            encode_gold([build_gold_row("5G-AKA", **{GOLD_MARKER: True})]),
            "case 1: request: 1 unexpected field",
        ),
        (
            encode_gold(
                [
                    build_gold_row("5G-AKA"),
                    build_gold_row("CVE-9999-0003"),
                    build_gold_row("5G-AKA"),
                ]
            ),
            "case 3 repeats an earlier case",
        ),
        (
            encode_gold(build_distinct_rows(MAX_GOLD_CASES + 1)),
            f"the gold file holds more than {MAX_GOLD_CASES} cases",
        ),
        (
            b"#" * MAX_GOLD_FILE_BYTES + GOLD_MARKER.encode(),
            f"the gold file is larger than {MAX_GOLD_FILE_BYTES} bytes",
        ),
        (
            encode_gold([{"request": {}, "sources": {"mitre_fight": [GOLD_MARKER]}}]),
            "case 1: sources.mitre_fight is not packaged or unavailable",
        ),
        (
            encode_gold([{"request": {}, "sources": {"mitre_fight": {GOLD_MARKER: 1}}}]),
            "case 1: sources.mitre_fight is not packaged or unavailable",
        ),
        (
            f"trajectories: []\n{GOLD_MARKER}: 2024-02-30\n".encode(),
            "the gold file is not UTF-8 YAML a strict loader accepts",
        ),
        (
            f"trajectories: []\n{GOLD_MARKER}: {'9' * 5000}\n".encode(),
            "the gold file is not UTF-8 YAML a strict loader accepts",
        ),
    ],
    ids=[
        "not_utf8",
        "not_yaml",
        "duplicate_key",
        "no_trajectories",
        "empty_trajectories",
        "row_not_a_mapping",
        "unknown_fight_source",
        "invalid_request",
        "unexpected_request_field",
        "repeated_case",
        "too_many_cases",
        "too_large",
        "list_fight_source",
        "mapping_fight_source",
        "impossible_date",
        "integer_too_long",
    ],
)
def test_file_that_is_no_investigation_gold_file_is_refused_without_quoting_it(
    gold_bytes: bytes, expected_message: str
) -> None:
    with pytest.raises(GoldFileError) as raised:
        load_gold_cases(gold_bytes)

    assert str(raised.value) == expected_message
    assert GOLD_MARKER not in str(raised.value)
    assert raised.value.__cause__ is None


def test_request_with_many_problems_is_refused_with_a_bounded_message() -> None:
    gold_row = build_gold_row("5G-AKA", filters={"vendors": [1] * 50_000})

    with pytest.raises(GoldFileError) as raised:
        load_gold_cases(encode_gold([gold_row]))

    assert str(raised.value).startswith("case 1: request: filters.vendors")
    assert len(str(raised.value)) <= MAX_REPORTED_VIOLATIONS * (MAX_VIOLATION_CHARS + 2) + 64
