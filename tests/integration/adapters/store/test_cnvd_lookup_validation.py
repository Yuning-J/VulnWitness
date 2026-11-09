"""Lookup views preserve source content and never persist derived comparisons."""

from pathlib import Path

import pytest

from tests.support.cnvd_inputs import import_cnvd_lookup_corpus
from vulnwitness.adapters.store.corpus_store import load_corpus_store
from vulnwitness.composition import build_serving_data_plane
from vulnwitness.domain.validation import EvidenceValidationError, validate_search_response
from vulnwitness.interfaces.lookup_summary import render_lookup_summary


@pytest.mark.parametrize(
    "identifier", ["CVE-9999-0001", "CVE-9999-0004"], ids=["merged", "pending"]
)
def test_lookup_comparisons_validate_without_changing_stored_content(
    tmp_path: Path,
    identifier: str,
) -> None:
    corpus = import_cnvd_lookup_corpus(tmp_path)
    data_plane = build_serving_data_plane(corpus)

    lookup = data_plane.search_service.lookup(identifier)
    validate_search_response(lookup, data_plane.evidence_catalog)
    reloaded = load_corpus_store(tmp_path / "stores" / corpus.store_name)

    assert reloaded.records == corpus.records
    assert reloaded.cnvd_index == corpus.cnvd_index
    for record in reloaded.records:
        for entry in record.cnvd:
            assert "source_comparison" not in entry.model_dump()
            assert "name_check" not in entry.model_dump()
    for pending in reloaded.cnvd_index.pending_by_cnvd_id.values():
        assert "source_comparison" not in pending.entry.model_dump()
        assert "name_check" not in pending.entry.model_dump()


@pytest.mark.parametrize(
    "label_field,changes,violation",
    [
        (
            "source_comparison",
            {"grade_relative": "higher"},
            "source comparison differs from the rule",
        ),
        ("name_check", {"cnvd_name": "Altered"}, "name check differs from the rule"),
    ],
    ids=["severity-comparison", "name-check"],
)
@pytest.mark.parametrize("is_pending", [False, True], ids=["merged", "pending"])
def test_lookup_validator_rejects_a_comparison_that_differs_from_the_rule(
    tmp_path: Path,
    is_pending: bool,
    label_field: str,
    changes: dict[str, str],
    violation: str,
) -> None:
    data_plane = build_serving_data_plane(import_cnvd_lookup_corpus(tmp_path))
    identifier = "CVE-9999-0004" if is_pending else "CVE-9999-0001"
    lookup = data_plane.search_service.lookup(identifier)
    if is_pending:
        entry = lookup.pending_cnvd[0]
        forged_entry = entry.model_copy(
            update={
                label_field: getattr(entry, label_field).model_copy(update=changes),
            }
        )
        forged_lookup = lookup.model_copy(update={"pending_cnvd": (forged_entry,)})
    else:
        candidate = lookup.candidates[0]
        entry = candidate.record.cnvd[0]
        forged_entry = entry.model_copy(
            update={
                label_field: getattr(entry, label_field).model_copy(update=changes),
            }
        )
        forged_record = candidate.record.model_copy(update={"cnvd": (forged_entry,)})
        forged_lookup = lookup.model_copy(
            update={"candidates": (candidate.model_copy(update={"record": forged_record}),)}
        )
    forged_lookup = forged_lookup.model_copy(
        update={"result_sha256": forged_lookup.compute_result_sha256()}
    )

    with pytest.raises(EvidenceValidationError, match=violation):
        validate_search_response(forged_lookup, data_plane.evidence_catalog)


@pytest.mark.parametrize("is_pending", [False, True], ids=["linked", "pending"])
def test_lookup_serves_name_check_and_summarises_names(tmp_path: Path, is_pending: bool) -> None:
    corpus = import_cnvd_lookup_corpus(tmp_path, cnvd_title="Democorp Gateway漏洞")
    data_plane = build_serving_data_plane(corpus)
    identifier = "CVE-9999-0004" if is_pending else "CVE-9999-0001"

    lookup = data_plane.search_service.lookup(identifier)
    summary = render_lookup_summary(lookup)
    served = lookup.model_dump(mode="json")

    if is_pending:
        label = served["pending_cnvd"][0]["name_check"]
        assert label["result"] == "uncheckable"
        assert label["uncheckable_reason"] == "no_nvd_record"
        assert label["nvd_pair"] is None
        assert "Name check: uncheckable (no_nvd_record) · CNVD name: Democorp Gateway" in summary
    else:
        label = served["candidates"][0]["record"]["cnvd"][0]["name_check"]
        assert label["result"] == "vendor_product_overlap"
        assert "uncheckable_reason" not in label
        assert label["nvd_pair"] == {"vendor": "democorp", "product": "gateway"}
        assert (
            "Name check: vendor_product_overlap · CNVD name: Democorp Gateway "
            "· NVD: democorp/gateway" in summary
        )
        assert lookup.candidates[0].record.to_source_record() == corpus.records[0]
    assert label["cnvd_name"] == "Democorp Gateway"
