"""Plain-text investigation answers retain evidence and uncertainty without inference."""

import pytest

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.domain.investigation import InvestigationWarning
from cve_kgrag.interfaces.investigation_summary import render_investigation_summary
from tests.support.builders import build_cve_record, build_threat_context_item
from tests.support.investigation import reseal_evidence_set
from tests.support.investigation_runs import (
    investigate,
    run_exact_id,
    run_five_g_aka_mixed,
    run_open5gs_product_question,
)


def test_topic_summary_shows_found_needs_candidates_and_protocol_context(
    fixture_bundle: FixtureBundle,
) -> None:
    # Arrange
    evidence_set = run_five_g_aka_mixed(fixture_bundle)

    # Act
    summary = render_investigation_summary(evidence_set)

    # Assert
    assert summary.startswith("Investigation: 5G-AKA\nScope: mixed\n")
    assert (
        "Status: Every evidence need was met; that does not show the list is complete." in summary
    )
    assert (
        "Stop reason: Each need was met through an exact lookup or the reviewed topic." in summary
    )
    assert "Implementation CVEs: found through the reviewed topic." in summary
    assert "Protocol context: found through the reviewed topic." in summary
    assert "Rank  CVE ID" in summary
    assert "CVE-9999-0003   HIGH 7.5 v3.1" in summary
    assert "CVE-9999-0004   HIGH 8.2 v3.1" in summary
    assert "fictional5g/f5gc  topic card" in summary
    assert "FGT1499.503: DOS A UE Via gNB Or NF Signaling" in summary
    assert "[topic_pending_review]" in summary
    assert "Subject: 3gpp:5g-aka" in summary
    assert "Full evidence set: --format json" in summary
    assert f"Example: cve-kgrag evidence {evidence_set.evidence[0].evidence_id}" in summary


def test_free_text_summary_says_match_relevance_was_not_assessed(
    fixture_bundle: FixtureBundle,
) -> None:
    # Arrange
    evidence_set = investigate(fixture_bundle, "sql injection gateway", "implementation_only")

    # Act
    summary = render_investigation_summary(evidence_set)

    # Assert
    assert "matches found; their relevance was not assessed" in summary
    assert "no relevant" not in summary.lower()
    assert "not affected" not in summary.lower()
    assert "word match" in summary
    assert "Stop reason: Matches were found but not every need was met." in summary
    unknowns = summary.split("Could not be judged:\n", 1)[1].split("\n\nWarnings:", 1)[0]
    assert "matches found; their relevance was not assessed" in unknowns


def test_named_cve_summary_identifies_the_exact_lookup(fixture_bundle: FixtureBundle) -> None:
    # Arrange
    evidence_set = run_exact_id(fixture_bundle)

    # Act
    summary = render_investigation_summary(evidence_set)

    # Assert
    assert "Named CVE (CVE-9999-0003): found through an exact lookup." in summary
    assert "exact lookup" in summary.split("CVE candidates:\n", 1)[1]
    assert "Protocol context:" not in summary


def test_affectedness_need_says_version_affectedness_was_not_assessed(
    fixture_bundle: FixtureBundle,
) -> None:
    # Arrange
    evidence_set = run_open5gs_product_question(fixture_bundle)

    # Act
    summary = render_investigation_summary(evidence_set)

    # Assert
    assert "Affectedness (open5gs): the required source was unavailable." in summary
    assert "Version affectedness was not assessed." in summary
    assert "[applicability_unknown]" in summary
    assert "Subject: open5gs" in summary
    assert "not affected" not in summary.lower()


def test_product_applicability_alone_reports_unassessed_version_affectedness(
    fixture_bundle: FixtureBundle,
) -> None:
    # Arrange
    evidence_set = run_open5gs_product_question(fixture_bundle)
    evidence_set = reseal_evidence_set(
        evidence_set, coverage=evidence_set.coverage.model_copy(update={"needs": ()})
    )

    # Act
    summary = render_investigation_summary(evidence_set)

    # Assert
    assert "open5gs: version affectedness was not assessed." in summary


def test_unknown_warning_is_printed_as_its_code_alone(fixture_bundle: FixtureBundle) -> None:
    # Arrange
    warning = InvestigationWarning.model_construct(code="future_warning", subject="some subject")
    evidence_set = run_exact_id(fixture_bundle).model_copy(update={"warnings": (warning,)})

    # Act
    summary = render_investigation_summary(evidence_set)

    # Assert
    assert "Warnings:\nfuture_warning\n\nWhere the evidence is:" in summary
    assert "some subject" not in summary


@pytest.mark.parametrize(
    ("metrics", "expected_severity"),
    [
        ([], "unknown"),
        (
            [
                {"version": "4.0", "base_score": 10.0, "base_severity": "CRITICAL"},
                {
                    "version": "3.1",
                    "base_score": 7.5,
                    "base_severity": "HIGH",
                    "scorer_type": "primary",
                },
                {
                    "version": "3.0",
                    "base_score": 8.2,
                    "base_severity": "HIGH",
                    "scorer_type": "primary",
                },
            ],
            "HIGH 8.2 v3.0",
        ),
        (
            [
                {"version": "3.1", "base_score": 8.2, "base_severity": "HIGH"},
                {"version": "4.0", "base_score": 9.8, "base_severity": "CRITICAL"},
            ],
            "CRITICAL 9.8 v4.0",
        ),
        ([{"version": "2.0", "base_score": 7.5}], "unknown 7.5 v2.0"),
        (
            [
                {"version": "3.1", "base_score": 8.2, "base_severity": "HIGH"},
                {"version": "4.0", "base_score": 9.8},
            ],
            "HIGH 8.2 v3.1",
        ),
    ],
    ids=[
        "missing_cvss",
        "highest_primary_score",
        "highest_score_without_primary",
        "missing_severity",
        "highest_supplied_severity",
    ],
)
def test_candidate_severity_preserves_the_preferred_metric(
    fixture_bundle: FixtureBundle, metrics: list[dict[str, object]], expected_severity: str
) -> None:
    # Arrange
    for metric in metrics:
        metric.update(vector_string="test-vector", scorer="test-scorer")
    evidence_set = run_exact_id(fixture_bundle)
    candidate = evidence_set.implementation_candidates[0]
    record = build_cve_record(cvss=metrics)
    candidate = candidate.model_copy(
        update={"candidate": candidate.candidate.model_copy(update={"record": record})}
    )
    evidence_set = reseal_evidence_set(evidence_set, implementation_candidates=(candidate,))

    # Act
    summary = render_investigation_summary(evidence_set)

    # Assert
    assert expected_severity in summary


def test_candidate_table_shows_kev_date_and_at_most_two_distinct_products(
    fixture_bundle: FixtureBundle,
) -> None:
    # Arrange
    products = []
    for product_name in ("one", "two", "one", "three"):
        products.append({"vendor": "vendor", "product": product_name, "status": "unknown"})
    record = build_cve_record(affected=products, kev={"date_added": "2026-10-01"})
    evidence_set = run_exact_id(fixture_bundle)
    candidate = evidence_set.implementation_candidates[0]
    candidate = candidate.model_copy(
        update={"candidate": candidate.candidate.model_copy(update={"record": record})}
    )
    evidence_set = reseal_evidence_set(evidence_set, implementation_candidates=(candidate,))

    # Act
    summary = render_investigation_summary(evidence_set)

    # Assert
    assert "yes 2026-10-01" in summary
    assert "vendor/one," in summary
    assert "vendor/two +1" in summary
    assert "vendor/three" not in summary
    assert "unknown" in summary
    assert all(len(line) <= 100 for line in summary.splitlines())


def test_summary_caps_candidates_and_techniques_and_reports_the_omissions(
    fixture_bundle: FixtureBundle,
) -> None:
    # Arrange
    evidence_set = run_exact_id(fixture_bundle)
    candidates = []
    for rank in range(1, 22):
        candidate = evidence_set.implementation_candidates[0]
        record = build_cve_record(cve_id=f"CVE-9999-{rank:04}")
        candidates.append(
            candidate.model_copy(
                update={
                    "rank": rank,
                    "candidate": candidate.candidate.model_copy(update={"record": record}),
                }
            )
        )
    techniques = []
    for technique_number in range(1, 12):
        techniques.append(build_threat_context_item(technique_id=f"FGT{technique_number:04}"))
    evidence_set = reseal_evidence_set(
        evidence_set,
        implementation_candidates=tuple(candidates),
        protocol_context=tuple(techniques),
    )

    # Act
    summary = render_investigation_summary(evidence_set)

    # Assert
    assert "CVE-9999-0020" in summary
    assert "CVE-9999-0021" not in summary
    assert "+1 more CVEs in --format json." in summary
    assert "FGT0010:" in summary
    assert "FGT0011:" not in summary
    assert "+1 more\n" in summary


def test_search_limit_warning_says_more_matches_may_exist(fixture_bundle: FixtureBundle) -> None:
    # Arrange
    evidence_set = investigate(
        fixture_bundle, "5G-AKA", "mixed", budget={"max_results_per_call": 1}
    )

    # Act
    summary = render_investigation_summary(evidence_set)

    # Assert
    assert (
        "[result_limit_reached] A search reached its result limit; more CVE matches may exist."
        in summary
    )
    assert "[answer_truncated]" in summary
    assert "The evidence set omits additional CVEs or techniques because of a limit." in summary


def test_long_source_fields_wrap_within_100_columns(fixture_bundle: FixtureBundle) -> None:
    # Arrange
    evidence_set = run_five_g_aka_mixed(fixture_bundle)
    request = evidence_set.request.model_copy(update={"query": "long-query " * 50})
    technique = build_threat_context_item(name="long technique name " * 25)
    warning = InvestigationWarning(code="topic_pending_review", subject="long-subject" * 30)
    evidence_set = reseal_evidence_set(
        evidence_set, request=request, protocol_context=(technique,), warnings=(warning,)
    )

    # Act
    summary = render_investigation_summary(evidence_set)

    # Assert
    assert all(len(line) <= 100 for line in summary.splitlines())
    assert "\x1b" not in summary
