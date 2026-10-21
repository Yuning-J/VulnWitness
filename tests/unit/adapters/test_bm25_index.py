"""BM25 lexical channel: ranking, match reasons, determinism."""

from cve_kgrag.adapters.lexical.bm25_index import Bm25LexicalIndex
from cve_kgrag.domain.cve import CveRecord
from tests.support.builders import build_cve_record
from tests.support.collect import list_cve_ids


def build_record(cve_id: str, description: str, product: str = "demo") -> CveRecord:
    return build_cve_record(
        cve_id=cve_id,
        descriptions=[{"lang": "en", "value": description, "source": "test"}],
        affected=[{"vendor": "democorp", "product": product, "status": "affected"}],
        cwe_ids=["CWE-89"],
    )


INDEX = Bm25LexicalIndex(
    [
        build_record("CVE-9999-0003", "buffer overflow in parser"),
        build_record("CVE-9999-0001", "sql injection sql injection in login"),
        build_record("CVE-9999-0002", "sql injection in report export module page"),
    ]
)


def test_search_ranks_higher_term_frequency_first() -> None:
    matches = INDEX.search("sql injection", limit=10, allowed_cve_ids=None).matches

    assert list_cve_ids(matches) == ["CVE-9999-0001", "CVE-9999-0002"]
    assert matches[0].score > matches[1].score


def test_search_reports_matched_fields_and_terms() -> None:
    matches = INDEX.search("injection democorp", limit=10, allowed_cve_ids=None).matches

    assert matches[0].matched_fields == ("description", "vendor")
    assert matches[0].matched_terms == ("democorp", "injection")


def test_search_breaks_score_ties_by_cve_id() -> None:
    tied_index = Bm25LexicalIndex(
        [
            build_record("CVE-9999-0002", "heap overflow"),
            build_record("CVE-9999-0001", "heap overflow"),
        ]
    )

    matches = tied_index.search("overflow", limit=10, allowed_cve_ids=None).matches

    assert matches[0].score == matches[1].score
    assert list_cve_ids(matches) == ["CVE-9999-0001", "CVE-9999-0002"]


def test_search_with_unindexed_term_returns_no_matches() -> None:
    assert INDEX.search("bluetooth", limit=10, allowed_cve_ids=None).matches == ()


def test_search_respects_limit() -> None:
    assert len(INDEX.search("democorp", limit=2, allowed_cve_ids=None).matches) == 2


def test_search_applies_allowed_ids_before_the_limit() -> None:
    matches = INDEX.search(
        "sql injection", limit=1, allowed_cve_ids=frozenset({"CVE-9999-0002"})
    ).matches

    assert list_cve_ids(matches) == ["CVE-9999-0002"]


def test_unaffected_product_names_are_not_indexed_as_vendor_or_product() -> None:
    record = build_cve_record(
        cve_id="CVE-9999-0004",
        descriptions=[{"lang": "en", "value": "overflow in parser", "source": "test"}],
        affected=[
            {"vendor": "democorp", "product": "parser", "status": "affected"},
            {"vendor": "microsoft", "product": "windows", "status": "unaffected"},
        ],
    )

    matches = Bm25LexicalIndex([record]).search("microsoft windows", 10, None).matches

    assert matches == ()
