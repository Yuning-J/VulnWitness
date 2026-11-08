"""Lookup views preserve source content and never persist derived comparisons."""

from pathlib import Path

import pytest

from tests.support.cnvd_inputs import import_cnvd_lookup_corpus
from vulnwitness.adapters.store.corpus_store import load_corpus_store
from vulnwitness.composition import build_serving_data_plane
from vulnwitness.domain.validation import EvidenceValidationError, validate_search_response


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
    for pending in reloaded.cnvd_index.pending_by_cnvd_id.values():
        assert "source_comparison" not in pending.entry.model_dump()


@pytest.mark.parametrize("is_pending", [False, True], ids=["merged", "pending"])
def test_lookup_validator_rejects_a_comparison_that_differs_from_the_rule(
    tmp_path: Path,
    is_pending: bool,
) -> None:
    data_plane = build_serving_data_plane(import_cnvd_lookup_corpus(tmp_path))
    identifier = "CVE-9999-0004" if is_pending else "CVE-9999-0001"
    lookup = data_plane.search_service.lookup(identifier)
    if is_pending:
        entry = lookup.pending_cnvd[0]
        forged_entry = entry.model_copy(
            update={
                "source_comparison": entry.source_comparison.model_copy(
                    update={"grade_relative": "higher"}
                ),
            }
        )
        forged_lookup = lookup.model_copy(update={"pending_cnvd": (forged_entry,)})
    else:
        candidate = lookup.candidates[0]
        entry = candidate.record.cnvd[0]
        forged_entry = entry.model_copy(
            update={
                "source_comparison": entry.source_comparison.model_copy(
                    update={"grade_relative": "higher"}
                ),
            }
        )
        forged_record = candidate.record.model_copy(update={"cnvd": (forged_entry,)})
        forged_lookup = lookup.model_copy(
            update={"candidates": (candidate.model_copy(update={"record": forged_record}),)}
        )
    forged_lookup = forged_lookup.model_copy(
        update={"result_sha256": forged_lookup.compute_result_sha256()}
    )

    with pytest.raises(EvidenceValidationError, match="source comparison differs from the rule"):
        validate_search_response(forged_lookup, data_plane.evidence_catalog)
