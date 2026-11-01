"""CLI text views over the packaged synthetic corpus, with unchanged JSON bytes."""

import pytest

from vulnwitness.adapters.fixture.synthetic_fixture import FixtureBundle
from vulnwitness.cli import main
from vulnwitness.composition import build_search_service
from vulnwitness.domain.search import SearchRequest
from vulnwitness.domain.weakness_associations import DERIVED_ASSOCIATION_NOTE


def test_lookup_text_shows_paths_missing_reasons_and_catalogue_limits_before_anchors(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Arrange
    arguments = ["lookup", "CVE-9999-0003", "--format", "text"]

    # Act
    exit_code = main(arguments, environment={})

    # Assert
    summary = capsys.readouterr().out
    assert exit_code == 0
    assert "Published: 2026-03-05" in summary
    assert "CVSS: HIGH 7.5 v3.1" in summary
    assert "CWEs: CWE-20" in summary
    assert "Products: fictional5g/f5gc" in summary
    assert "KEV: not listed" in summary
    assert "CWE-20 → CAPEC-13 → T1574.006 Dynamic Linker Hijacking" in summary
    assert "Omitted paths: 36" in summary
    assert "T1562.003: ATT&CK technique unavailable in this snapshot" in summary
    assert "[attack_technique_unavailable]" in summary
    assert DERIVED_ASSOCIATION_NOTE in " ".join(summary.split())
    anchors = summary.split("Source anchors:\n", 1)[1].splitlines()
    assert anchors == ["ev:1e1f09d19e41dd7e27b364ff"]


@pytest.mark.parametrize(
    ("cve_id", "expected_path"),
    [
        (
            "CVE-9999-0002",
            "CWE-79 → CAPEC-85 → CAPEC-580 [CAPEC inheritance] → "
            "CAPEC-169 [CAPEC inheritance] → T1217 Browser Information Discovery",
        ),
        (
            "CVE-9999-0006",
            "CWE-787 → CWE-119 [CWE inheritance inference] → CAPEC-10 "
            "(no ATT&CK mapping in this snapshot)",
        ),
    ],
)
def test_lookup_text_marks_catalogue_inheritance_and_snapshot_only_terminals(
    cve_id: str, expected_path: str, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    arguments = ["lookup", cve_id, "--format", "text"]

    # Act
    exit_code = main(arguments, environment={})

    # Assert
    assert exit_code == 0
    assert expected_path in capsys.readouterr().out.splitlines()


def test_lookup_text_explains_missing_cwe_snapshot_link(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Arrange
    arguments = ["lookup", "CVE-9999-0001", "--format", "text"]

    # Act
    exit_code = main(arguments, environment={})

    # Assert
    summary = capsys.readouterr().out
    assert exit_code == 0
    assert "Weakness paths (catalogue associations):\nNone recorded." in summary
    assert "CWE-89: CWE absent from this snapshot [cwe_not_in_snapshot]" in summary
    assert "Omitted paths: 0" in summary


def test_lookup_description_wraps_to_terminal_columns(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    monkeypatch.setenv("COLUMNS", "42")
    arguments = ["lookup", "CVE-9999-0001", "--format", "text"]

    # Act
    exit_code = main(arguments, environment={})

    # Assert
    summary = capsys.readouterr().out
    description = summary.split("KEV: not listed\n", 1)[1].split("\n\n", 1)[0]
    assert exit_code == 0
    assert len(description.splitlines()) > 1
    assert all(len(line) <= 42 for line in description.splitlines())


def test_search_text_shows_word_match_ranks_channels_and_limit_warning(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Arrange
    arguments = ["search", "gateway", "--limit", "2", "--format", "text"]

    # Act
    exit_code = main(arguments, environment={})

    # Assert
    summary = capsys.readouterr().out
    assert exit_code == 0
    assert "Ranks are word matches" in summary
    table = summary.split("Rank  CVE ID", 1)[1].split("\n\nChannel outcomes:", 1)[0]
    rows = table.splitlines()[1:]
    assert len(rows) == 2
    assert rows[0].split()[:3] == ["1", "CVE-9999-0001", "2026-01-15"]
    assert rows[1].split()[:3] == ["2", "CVE-9999-0002", "2026-02-10"]
    assert "CRITICAL 9.8 v3.1" in rows[0]
    assert "[SYNTHETIC]" in rows[0]
    assert "Channel outcomes:\nlexical: ok" in summary
    assert "[result_limit_reached] Subject: 2" in summary


@pytest.mark.parametrize("command,query", [("lookup", "CVE-9999-4242"), ("search", "   ")])
def test_empty_text_view_keeps_nonzero_exit_and_warning(
    command: str, query: str, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    arguments = [command, query, "--format", "text"]

    # Act
    exit_code = main(arguments, environment={})

    # Assert
    summary = capsys.readouterr().out
    assert exit_code == 1
    assert "Status: no_match" in summary
    assert "unknown_cve_id" in summary or "no_searchable_terms" in summary


@pytest.mark.parametrize(
    ("command", "query"),
    [
        ("lookup", "CVE-9999-0001"),
        ("lookup", "CVE-9999-4242"),
        ("search", "authentication bypass"),
        ("search", "   "),
    ],
)
@pytest.mark.parametrize("format_arguments", [[], ["--format", "json"]])
def test_default_and_explicit_json_print_the_unmodified_service_bytes(
    fixture_bundle: FixtureBundle,
    command: str,
    query: str,
    format_arguments: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Arrange
    service = build_search_service(fixture_bundle)
    search = (
        service.lookup(query) if command == "lookup" else service.search(SearchRequest(query=query))
    )
    expected_bytes = search.model_dump_json(indent=2) + "\n"

    # Act
    exit_code = main([command, query, *format_arguments], environment={})

    # Assert
    assert exit_code == (0 if search.status == "ok" else 1)
    assert capsys.readouterr().out == expected_bytes
