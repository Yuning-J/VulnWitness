"""Source notes travel through queries, investigations, claims, reports and old stores."""

import csv
import io
import json
from dataclasses import replace
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from tests.support.builders import build_bundle_with
from tests.support.corpus_stores import COMPATIBILITY_STORE
from tests.support.investigation import build_investigation_request, reseal_evidence_set
from tests.support.paths import REPOSITORY_SCHEMA_DIR
from tests.support.source_version_notes import build_backport_product, build_source_product
from vulnwitness.adapters.fixture.synthetic_fixture import FixtureBundle
from vulnwitness.adapters.store.corpus_store import load_corpus_store
from vulnwitness.application.investigation_report import build_investigation_report
from vulnwitness.application.session_report import build_source_version_facts
from vulnwitness.application.triage_findings import build_page_findings
from vulnwitness.composition import (
    build_investigation_service,
    build_product_query_service,
    build_serving_data_plane,
)
from vulnwitness.domain.cve import SourceAffected
from vulnwitness.domain.investigation import KnowledgeEvidenceSet
from vulnwitness.domain.investigation_validation import validate_knowledge_evidence_set
from vulnwitness.domain.product_query import ProductQueryRequest
from vulnwitness.domain.session_claim import SourceVersionNoteClaim
from vulnwitness.domain.session_claim_check import check_session_claim
from vulnwitness.domain.validation import EvidenceValidationError
from vulnwitness.interfaces.investigation_summary import render_investigation_summary
from vulnwitness.interfaces.product_query_output import write_export_rows
from vulnwitness.interfaces.product_query_summary import render_product_query_summary
from vulnwitness.interfaces.report_html import render_html_section
from vulnwitness.interfaces.report_markdown import render_markdown_section


@pytest.fixture
def source_note_bundle(fixture_bundle: FixtureBundle) -> FixtureBundle:
    record = fixture_bundle.records[0]
    blocks = (
        SourceAffected(
            source="cna@example.org",
            products=(build_backport_product().model_copy(update={"vendor": "Democorp"}),),
        ),
        SourceAffected(
            source="adp@example.org",
            products=(
                build_source_product(
                    vendor="Democorp",
                    versions=(),
                    default_status="affected",
                ),
            ),
        ),
    )
    amended = record.model_copy(update={"source_affected": blocks})
    records = []
    for candidate in fixture_bundle.records:
        records.append(amended if candidate.cve_id == record.cve_id else candidate)
    bundle = replace(fixture_bundle, records=tuple(records))
    return build_bundle_with(
        bundle, "CVE-9999-8080", "[SYNTHETIC] unrelated description", source_affected=blocks
    )


@pytest.mark.parametrize("version", [None, "5.4.1"], ids=["without_version", "with_version"])
def test_product_notes_preserve_inventory_order_and_candidate_boundary(
    source_note_bundle: FixtureBundle, fixture_bundle: FixtureBundle, version: str | None
) -> None:
    request = ProductQueryRequest(product="demo_gateway", version=version)
    page = build_product_query_service(source_note_bundle).query(request)
    baseline = build_product_query_service(fixture_bundle).query(request)
    identities = []
    baseline_identities = []
    for vulnerability in page.items:
        identities.append(vulnerability.record.cve_id)
    for vulnerability in baseline.items:
        baseline_identities.append(vulnerability.record.cve_id)
    assert identities == baseline_identities
    assert page.total_available == baseline.total_available
    assert page.source_named_total == 1
    assert page.source_named_candidates[0].cve_id == "CVE-9999-8080"
    assert "source_version_notes" not in page.source_named_candidates[0].model_dump()
    vulnerability = None
    for entry in page.items:
        if entry.record.cve_id == "CVE-9999-0001":
            vulnerability = entry
    assert vulnerability is not None
    if version is None:
        assert vulnerability.source_version_notes is None
        assert "source_version_notes" not in vulnerability.model_dump(mode="json")
    else:
        assert vulnerability.source_version_notes is not None
        outcomes = []
        for note in vulnerability.source_version_notes:
            outcomes.append(note.outcome)
        assert outcomes == ["states_unaffected", "states_affected"]
        assert vulnerability.applicability == "unknown"
        text = " ".join(render_product_query_summary(page).split())
        assert text.index(vulnerability.nvd_version_note.wording) < text.index(
            vulnerability.source_version_notes[0].wording
        )
        facts = build_source_version_facts(vulnerability)
        assert facts[0].detail == vulnerability.source_version_notes[0].wording
        findings = build_page_findings(page, 1)
        source_claims = []
        for finding in findings:
            if isinstance(finding.claim, SourceVersionNoteClaim):
                source_claims.append(finding.claim)
                assert check_session_claim(finding.id, finding.claim, page).status == "verified"
        assert len(source_claims) == 2
    schema = json.loads((REPOSITORY_SCHEMA_DIR / "product_query_response.schema.json").read_text())
    Draft202012Validator(schema).validate(page.model_dump(mode="json"))


@pytest.mark.parametrize("export", ["csv", "jsonl"], ids=["csv", "jsonl"])
def test_versioned_exports_keep_attributed_source_notes(
    source_note_bundle: FixtureBundle, export: str
) -> None:
    page = build_product_query_service(source_note_bundle).query(
        ProductQueryRequest(product="demo_gateway", version="5.4.1")
    )
    export_file = io.StringIO()
    write_export_rows(export_file, [page], export)
    if export == "csv":
        rows = list(csv.DictReader(io.StringIO(export_file.getvalue())))
        for row in rows:
            if row["cve_id"] == "CVE-9999-0001":
                break
        notes = json.loads(row["source_version_notes"])
    else:
        for line in export_file.getvalue().splitlines():
            row = json.loads(line)
            if row["cve_id"] == "CVE-9999-0001":
                break
        notes = row["source_version_notes"]
    assert notes[0]["source"] == "cna@example.org"
    assert notes[0]["outcome"] == "states_unaffected"
    assert notes[1]["outcome"] == "states_affected"


def run_source_investigation(bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    service = build_investigation_service(build_serving_data_plane(bundle))
    return service.investigate(
        build_investigation_request(
            "Is democorp 5.4.1 affected by CVE-9999-0001?", "implementation_only"
        )
    )


def test_investigation_renders_source_statements_beside_nvd_and_checks_claims(
    source_note_bundle: FixtureBundle,
) -> None:
    answer = run_source_investigation(source_note_bundle)
    candidate = answer.implementation_candidates[0]
    assert candidate.source_version_notes is not None
    assert len(candidate.source_version_notes) == 2
    assert candidate.source_version_notes[0].outcome == "states_unaffected"
    assert candidate.source_version_notes[1].outcome == "states_affected"
    text = " ".join(render_investigation_summary(answer).split())
    assert candidate.nvd_version_notes is not None
    assert text.index("NVD (democorp 5.4.1)") < text.index(
        candidate.source_version_notes[0].wording
    )
    section = build_investigation_report(answer, 1, set())
    for document in (render_markdown_section(section, 1), render_html_section(section, 1)):
        assert "cna@example.org" in document
        assert "adp@example.org" in document
        assert "VulnWitness has not set applicability." in document
    assert all(entry.status == "unknown" for entry in answer.product_applicability)
    affectedness_needs = []
    for need in answer.coverage.needs:
        if need.kind == "affectedness":
            affectedness_needs.append(need.outcome)
    assert affectedness_needs == ["source_unavailable"]
    claim = SourceVersionNoteClaim(
        kind="source_version_note",
        call=1,
        cve_id=candidate.candidate.record.cve_id,
        mention="democorp 5.4.1",
        source="adp@example.org",
        outcome="states_affected",
    )
    assert check_session_claim("source-note", claim, answer).status == "verified"


@pytest.mark.parametrize(
    "forgery",
    ["missing", "wording", "source", "outcome", "product", "entry", "changes", "extra"],
    ids=["missing", "wording", "source", "outcome", "product", "entry", "changes", "extra"],
)
def test_investigation_validation_recomputes_every_source_note(
    source_note_bundle: FixtureBundle, forgery: str
) -> None:
    data_plane = build_serving_data_plane(source_note_bundle)
    answer = build_investigation_service(data_plane).investigate(
        build_investigation_request(
            "Is democorp 5.4.1 affected by CVE-9999-0001?", "implementation_only"
        )
    )
    candidate = answer.implementation_candidates[0]
    notes = candidate.source_version_notes
    assert notes is not None
    note = notes[0]
    updates: dict[str, Any] = {}
    if forgery == "wording":
        updates["wording"] = "VulnWitness has set applicability."
    elif forgery == "source":
        updates["source"] = "imposter"
    elif forgery == "outcome":
        updates["outcome"] = "states_affected"
    elif forgery == "product":
        updates["matched_products"] = (build_source_product(),)
    elif forgery in ("entry", "changes"):
        match = note.covering_entries[0]
        if forgery == "entry":
            match = match.model_copy(update={"entry": build_source_product().versions[0]})
        else:
            match = match.model_copy(update={"applied_changes": ()})
        updates["covering_entries"] = (match,)
    amended_notes = (note.model_copy(update=updates), *notes[1:])
    if forgery == "missing":
        amended_notes = None
    elif forgery == "extra":
        amended_notes = (*notes, notes[0])
    amended = candidate.model_copy(update={"source_version_notes": amended_notes})
    forged = reseal_evidence_set(answer, implementation_candidates=(amended,))
    with pytest.raises(EvidenceValidationError, match="source version notes"):
        validate_knowledge_evidence_set(
            forged,
            data_plane.pinned_fight_snapshot,
            data_plane.evidence_catalog,
            answer.source_capabilities,
        )


@pytest.mark.parametrize(
    "field,value,status",
    [
        ("mention", "different 5.4.1", "contradicted"),
        ("source", "imposter", "contradicted"),
        ("outcome", "states_affected", "contradicted"),
    ],
    ids=["wrong_mention", "wrong_source", "wrong_outcome"],
)
def test_source_claim_checks_mention_source_and_outcome(
    source_note_bundle: FixtureBundle, field: str, value: str, status: str
) -> None:
    page = build_product_query_service(source_note_bundle).query(
        ProductQueryRequest(product="demo_gateway", version="5.4.1")
    )
    claim = SourceVersionNoteClaim(
        kind="source_version_note",
        call=1,
        cve_id="CVE-9999-0001",
        mention="demo_gateway 5.4.1",
        source="cna@example.org",
        outcome="states_unaffected",
    )
    altered = claim.model_copy(update={field: value})
    assert check_session_claim("source-note", altered, page).status == status


@pytest.mark.parametrize("format_version", [1, 2, 3, 4], ids=["v1", "v2", "v3", "v4"])
def test_store_format_controls_empty_notes_in_query_and_investigation(format_version: int) -> None:
    store = load_corpus_store(COMPATIBILITY_STORE)
    store = replace(
        store, manifest=store.manifest.model_copy(update={"store_format_version": format_version})
    )
    page = build_product_query_service(store).query(
        ProductQueryRequest(vendor="democorp", version="2.0")
    )
    for vulnerability in page.items:
        assert vulnerability.source_version_notes == (() if format_version == 4 else None)
        assert ("source_version_notes" in vulnerability.model_dump()) == (format_version == 4)
    service = build_investigation_service(build_serving_data_plane(store))
    answer = service.investigate(
        build_investigation_request(
            "Is democorp 2.0 affected by CVE-9999-0001?", "implementation_only"
        )
    )
    candidate = answer.implementation_candidates[0]
    assert candidate.source_version_notes == (() if format_version == 4 else None)
    assert ("source_version_notes" in candidate.model_dump()) == (format_version == 4)
    claim = SourceVersionNoteClaim(
        kind="source_version_note",
        call=1,
        cve_id="CVE-9999-0001",
        mention="democorp 2.0",
        source="cna@example.org",
        outcome="states_affected",
    )
    assert check_session_claim("source-note", claim, page).status == "unverifiable"
