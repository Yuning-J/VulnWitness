"""BM25 lexical channel: ranking, match reasons, determinism."""

import pytest

from cve_kgrag.adapters.lexical.bm25_index import Bm25LexicalIndex
from cve_kgrag.domain.cve import CveRecord
from tests.support.builders import build_cve_record
from tests.support.collect import list_cve_ids


def build_record(
    cve_id: str,
    description: str,
    product: str = "demo",
    vendor: str = "democorp",
    cwe_id: str = "CWE-89",
) -> CveRecord:
    return build_cve_record(
        cve_id=cve_id,
        descriptions=[{"lang": "en", "value": description, "source": "test"}],
        affected=[{"vendor": vendor, "product": product, "status": "affected"}],
        cwe_ids=[cwe_id],
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


def test_search_names_query_terms_no_record_holds_beside_its_matches() -> None:
    outcome = INDEX.search("sql zzqx", limit=10, allowed_cve_ids=None)

    assert list_cve_ids(outcome.matches) == ["CVE-9999-0001", "CVE-9999-0002"]
    assert outcome.unindexed_terms == ("zzqx",)


def test_search_respects_limit() -> None:
    assert len(INDEX.search("democorp", limit=2, allowed_cve_ids=None).matches) == 2


def test_search_applies_allowed_ids_before_the_limit() -> None:
    matches = INDEX.search(
        "sql injection", limit=1, allowed_cve_ids=frozenset({"CVE-9999-0002"})
    ).matches

    assert list_cve_ids(matches) == ["CVE-9999-0002"]


def test_index_of_records_without_indexed_terms_returns_no_matches() -> None:
    record = build_cve_record(
        cve_id="CVE-9999-0004",
        descriptions=[{"lang": "en", "value": "the of", "source": "test"}],
        affected=[],
        cwe_ids=[],
    )

    matches = Bm25LexicalIndex([record]).search("the", 10, None).matches

    assert matches == ()


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


# Scores, order and match reasons recorded from the index; a change to how the index stores
# or scores records must leave every one of them unchanged.
RECORDED_INDEX = Bm25LexicalIndex(
    [
        build_record(
            "CVE-9999-0005",
            "kamailio sip proxy crash via crafted sip message",
            product="kamailio",
            vendor="kamailio",
            cwe_id="CWE-125",
        ),
        build_record(
            "CVE-9999-0001", "sql injection sql injection in login form", product="portal"
        ),
        build_record(
            "CVE-9999-0004",
            "denial of service in sip parser of the proxy",
            product="sip-proxy",
            vendor="acme",
            cwe_id="CWE-400",
        ),
        build_record(
            "CVE-9999-0002", "sql injection in report export module page", product="reports"
        ),
        build_record(
            "CVE-9999-0003",
            "buffer overflow in sip parser",
            product="parser",
            vendor="acme",
            cwe_id="CWE-120",
        ),
    ]
)
DESCRIPTION = ("description",)
DESCRIPTION_PRODUCT = ("description", "product")
DESCRIPTION_VENDOR_CWE = ("description", "vendor", "cwe_ids")
SQL_TERMS = ("89", "cwe", "democorp", "injection", "sql")


@pytest.mark.parametrize(
    ("query", "limit", "allowed_cve_ids", "expected_matches"),
    [
        (
            "sip proxy crash",
            10,
            None,
            [
                ("CVE-9999-0005", 2.870316, DESCRIPTION, ("crash", "proxy", "sip")),
                ("CVE-9999-0004", 1.93379, DESCRIPTION_PRODUCT, ("proxy", "sip")),
                ("CVE-9999-0003", 0.582787, DESCRIPTION, ("sip",)),
            ],
        ),
        (
            "democorp sql injection cwe 89",
            10,
            None,
            [
                ("CVE-9999-0001", 4.21653, DESCRIPTION_VENDOR_CWE, SQL_TERMS),
                ("CVE-9999-0002", 3.559172, DESCRIPTION_VENDOR_CWE, SQL_TERMS),
                ("CVE-9999-0003", 0.094081, ("cwe_ids",), ("cwe",)),
                ("CVE-9999-0004", 0.086291, ("cwe_ids",), ("cwe",)),
                ("CVE-9999-0005", 0.082861, ("cwe_ids",), ("cwe",)),
            ],
        ),
        (
            "sip parser",
            2,
            None,
            [
                ("CVE-9999-0003", 1.852128, DESCRIPTION_PRODUCT, ("parser", "sip")),
                ("CVE-9999-0004", 1.605111, DESCRIPTION_PRODUCT, ("parser", "sip")),
            ],
        ),
        (
            "sip proxy",
            10,
            frozenset({"CVE-9999-0004", "CVE-9999-0003"}),
            [
                ("CVE-9999-0004", 1.93379, DESCRIPTION_PRODUCT, ("proxy", "sip")),
                ("CVE-9999-0003", 0.582787, DESCRIPTION, ("sip",)),
            ],
        ),
        (
            "injection SQL injection",
            10,
            None,
            [
                ("CVE-9999-0001", 2.393799, DESCRIPTION, ("injection", "sql")),
                ("CVE-9999-0002", 1.73644, DESCRIPTION, ("injection", "sql")),
            ],
        ),
    ],
    ids=["three_terms", "every_field", "limit_cuts", "allowed_ids", "repeated_term"],
)
def test_search_returns_the_recorded_scores_order_and_reasons(
    query: str,
    limit: int,
    allowed_cve_ids: frozenset[str] | None,
    expected_matches: list[tuple[str, float, tuple[str, ...], tuple[str, ...]]],
) -> None:
    matches = RECORDED_INDEX.search(query, limit, allowed_cve_ids).matches

    match_summaries: list[tuple[str, float, tuple[str, ...], tuple[str, ...]]] = []
    for match in matches:
        match_summaries.append(
            (match.cve_id, match.score, match.matched_fields, match.matched_terms)
        )
    assert match_summaries == expected_matches


FILLER_WORDS = ("alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel")


def build_sip_record(cve_id: str, sip_count: int, filler_count: int) -> CveRecord:
    words = ["sip"] * sip_count
    for word_number in range(filler_count):
        words.append(FILLER_WORDS[word_number % len(FILLER_WORDS)])
    return build_cve_record(
        cve_id=cve_id,
        descriptions=[{"lang": "en", "value": " ".join(words), "source": "test"}],
        affected=[],
        cwe_ids=[],
    )


def test_search_orders_scores_equal_to_six_decimals_by_cve_id() -> None:
    # CVE-9999-0004 scores about 3e-17 above CVE-9999-0001 before rounding; the ranking
    # compares the reported, rounded scores, so the lower CVE ID comes first.
    index = Bm25LexicalIndex(
        [
            build_sip_record("CVE-9999-0001", sip_count=4, filler_count=18),
            build_sip_record("CVE-9999-0002", sip_count=4, filler_count=0),
            build_sip_record("CVE-9999-0003", sip_count=1, filler_count=37),
            build_sip_record("CVE-9999-0004", sip_count=2, filler_count=6),
        ]
    )

    matches = index.search("sip", limit=10, allowed_cve_ids=None).matches

    assert list_cve_ids(matches) == [
        "CVE-9999-0002",
        "CVE-9999-0001",
        "CVE-9999-0004",
        "CVE-9999-0003",
    ]
    assert matches[1].score == matches[2].score
