"""Filter values are bounded and validated at the request boundary."""

import pytest
from pydantic import ValidationError

from cve_kgrag.domain.search import MAX_FILTER_VALUES, SearchFilters


def list_distinct_vendors(count: int) -> list[str]:
    vendors: list[str] = []
    for index in range(count):
        vendors.append(f"vendor{index}")
    return vendors


def test_filter_values_are_kept_exactly_as_sent() -> None:
    filters = SearchFilters.model_validate(
        {"vendors": ["DemoCorp", "democorp"], "purls": ["pkg:PyPI/Example-Parser"]}
    )

    assert filters.vendors == ("DemoCorp", "democorp")
    assert filters.purls == ("pkg:PyPI/Example-Parser",)


def test_filter_field_accepts_its_maximum_number_of_values() -> None:
    filters = SearchFilters(vendors=tuple(list_distinct_vendors(MAX_FILTER_VALUES)))

    assert len(filters.vendors) == MAX_FILTER_VALUES


@pytest.mark.parametrize(
    "filter_values",
    [
        {"vendors": ["democorp", "democorp"]},
        {"vendors": [""]},
        {"vendors": list_distinct_vendors(MAX_FILTER_VALUES + 1)},
        {"cwe_ids": ["89"]},
        {"cwe_ids": ["cwe-89"]},
        {"cwe_ids": ["CWE-" + "9" * 1000]},
        {"cwe_ids": ["CWE-٧٩"]},
        {"severities": ["SEVERE"]},
        {"severities": ["high"]},
        {"purls": ["pkg:pypi/example-parser@4.1.2"]},
        {"purls": ["PKG:pypi/example-parser"]},
        {"purls": ["pypi/example-parser"]},
        {"published_years": [1998]},
        {"published_years": ["2020"]},
        {"kev_only": "false"},
    ],
    ids=[
        "exact_duplicate",
        "empty_value",
        "too_many_values",
        "malformed_cwe",
        "lower_case_cwe",
        "unbounded_cwe",
        "non_ascii_cwe_digits",
        "unknown_severity",
        "lower_case_severity",
        "versioned_purl",
        "upper_case_purl_scheme",
        "not_a_purl",
        "year_before_cve",
        "year_as_string",
        "kev_only_as_string",
    ],
)
def test_invalid_filter_values_are_rejected(filter_values: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        SearchFilters.model_validate(filter_values)
