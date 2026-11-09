"""ADR 0017's title/CPE name rule labels evidence for review deterministically."""

import pytest
from pydantic import ValidationError

from tests.support.builders import build_cnvd_entry, build_cve_record, build_versioned_product
from vulnwitness.domain.name_check import NAME_CHECK_STATEMENT, CnvdNameCheck, check_cnvd_name


@pytest.mark.parametrize(
    "title,nvd_pairs,expected,reason,cnvd_name,overlapping_pair",
    [
        pytest.param(
            "Google Chrome漏洞",
            (("google", "chrome"),),
            "vendor_product_overlap",
            None,
            "Google Chrome",
            ("google", "chrome"),
            id="chrome",
        ),
        pytest.param(
            "GE Healthcare漏洞",
            (("gehealthcare", "*"),),
            "vendor_overlap",
            None,
            "GE Healthcare",
            ("gehealthcare", "*"),
            id="ge-healthcare-joined",
        ),
        pytest.param(
            "Internet Explorer漏洞",
            (("microsoft", "internet_explorer"),),
            "product_overlap",
            None,
            "Internet Explorer",
            ("microsoft", "internet_explorer"),
            id="internet-explorer-product-only",
        ),
        pytest.param(
            "Google Pixel漏洞",
            (("google", "android"),),
            "vendor_overlap",
            None,
            "Google Pixel",
            ("google", "android"),
            id="pixel-vs-android",
        ),
        pytest.param(
            "Tableau漏洞",
            (("haier", "p10_firmware"),),
            "no_overlap",
            None,
            "Tableau",
            None,
            id="tableau-vs-haier",
        ),
        pytest.param(
            "多款Google Chrome漏洞",
            (("google", "chrome"),),
            "vendor_product_overlap",
            None,
            "Google Chrome",
            ("google", "chrome"),
            id="multiple-models-prefix",
        ),
        pytest.param(
            "多个Google Chrome漏洞",
            (("google", "chrome"),),
            "vendor_product_overlap",
            None,
            "Google Chrome",
            ("google", "chrome"),
            id="multiple-items-prefix",
        ),
        pytest.param(
            "中文标题",
            (("google", "chrome"),),
            "uncheckable",
            "no_extractable_name",
            None,
            None,
            id="chinese-only",
        ),
        pytest.param(
            "Google Chrome漏洞",
            (),
            "uncheckable",
            "no_affected_products",
            "Google Chrome",
            None,
            id="no-affected-products",
        ),
        pytest.param(
            "Google Chrome漏洞",
            None,
            "uncheckable",
            "no_nvd_record",
            "Google Chrome",
            None,
            id="pending",
        ),
        pytest.param(
            "Google Chrome漏洞",
            (("google", "android"), ("other", "chrome")),
            "product_overlap",
            None,
            "Google Chrome",
            ("other", "chrome"),
            id="cross-pair-product-precedence",
        ),
        pytest.param(
            "Project漏洞",
            (("foo_project", "other"),),
            "no_overlap",
            None,
            "Project",
            None,
            id="organisation-project-excluded",
        ),
        pytest.param(
            "Google:Chrome!漏洞",
            (("google", "chrome"),),
            "vendor_product_overlap",
            None,
            "Google:Chrome!",
            ("google", "chrome"),
            id="colon-and-exclamation",
        ),
        pytest.param(
            "Foo Bar漏洞",
            (("other", "foobar"),),
            "product_overlap",
            None,
            "Foo Bar",
            ("other", "foobar"),
            id="product-joined-words",
        ),
        pytest.param(
            "Foo Extra Bar漏洞",
            (("foobar", "foobar"),),
            "no_overlap",
            None,
            "Foo Extra Bar",
            None,
            id="joined-words-must-be-consecutive",
        ),
        pytest.param(
            "Windows漏洞",
            (("microsoft", "windows_10"),),
            "product_overlap",
            None,
            "Windows",
            ("microsoft", "windows_10"),
            id="first-product-token-family",
        ),
        pytest.param(
            "Explorer漏洞",
            (("microsoft", "internet_explorer"),),
            "no_overlap",
            None,
            "Explorer",
            None,
            id="later-product-token-excluded",
        ),
        pytest.param(
            "Chrome漏洞",
            (("z_vendor", "chrome"), ("a_vendor", "chrome_z"), ("a_vendor", "chrome_a")),
            "product_overlap",
            None,
            "Chrome",
            ("a_vendor", "chrome_a"),
            id="pair-sorted-by-vendor-then-product",
        ),
        pytest.param(
            "Google Chrome漏洞",
            (("a_vendor", "chrome"), ("google", "chrome")),
            "vendor_product_overlap",
            None,
            "Google Chrome",
            ("google", "chrome"),
            id="both-precede-earlier-product-only",
        ),
        pytest.param(
            "中文标题",
            (),
            "uncheckable",
            "no_affected_products",
            None,
            None,
            id="empty-affected-before-missing-name",
        ),
        pytest.param(
            "中文标题",
            None,
            "uncheckable",
            "no_nvd_record",
            None,
            None,
            id="pending-before-missing-name",
        ),
        pytest.param(
            "Google\tChrome漏洞",
            (("google", "chrome"),),
            "vendor_overlap",
            None,
            "Google",
            ("google", "chrome"),
            id="extraction-stops-at-tab",
        ),
        pytest.param(
            "Google@Chrome漏洞",
            (("google", "chrome"),),
            "vendor_overlap",
            None,
            "Google",
            ("google", "chrome"),
            id="extraction-stops-at-unlisted-punctuation",
        ),
        pytest.param(
            " ._+-/&, '():!Google Chrome 123漏洞",
            (("google", "chrome"),),
            "vendor_product_overlap",
            None,
            "._+-/&, '():!Google Chrome 123",
            ("google", "chrome"),
            id="all-allowed-name-characters",
        ),
    ],
)
def test_name_check_follows_the_fixed_rule(
    title: str,
    nvd_pairs: tuple[tuple[str, str], ...] | None,
    expected: str,
    reason: str | None,
    cnvd_name: str | None,
    overlapping_pair: tuple[str, str] | None,
) -> None:
    entry = build_cnvd_entry(title=title)
    record = None
    if nvd_pairs is not None:
        affected = []
        for vendor, product in nvd_pairs:
            affected.append(build_versioned_product(vendor=vendor, product=product))
        record = build_cve_record(affected=tuple(affected))

    label = check_cnvd_name(entry, record)

    assert label.result == expected
    assert label.uncheckable_reason == reason
    assert ("uncheckable_reason" in label.model_dump()) == (reason is not None)
    assert label.cnvd_name == cnvd_name
    if overlapping_pair is None:
        assert label.nvd_pair is None
    else:
        assert label.nvd_pair is not None
        assert (label.nvd_pair.vendor, label.nvd_pair.product) == overlapping_pair
    assert label.rule == "cnvd_title_vs_nvd_cpe_names"
    assert label.statement == NAME_CHECK_STATEMENT


@pytest.mark.parametrize("status", ["affected", "unaffected", "unknown"])
def test_all_affected_pair_statuses_participate(status: str) -> None:
    record = build_cve_record(
        affected=(build_versioned_product(vendor="google", product="chrome", status=status),)
    )

    label = check_cnvd_name(build_cnvd_entry(title="Google Chrome漏洞"), record)

    assert label.result == "vendor_product_overlap"


@pytest.mark.parametrize(
    "suffix", ["project", "inc", "llc", "corporation", "foundation", "software", "technologies"]
)
def test_organisation_suffix_tokens_do_not_overlap(suffix: str) -> None:
    record = build_cve_record(
        affected=(build_versioned_product(vendor=f"foo_{suffix}", product="other"),)
    )

    label = check_cnvd_name(build_cnvd_entry(title=suffix.title() + "漏洞"), record)

    assert label.result == "no_overlap"


def test_name_check_serialises_identically_twice() -> None:
    entry = build_cnvd_entry(title="Google Chrome漏洞")
    record = build_cve_record(
        affected=(build_versioned_product(vendor="google", product="chrome"),)
    )

    first = check_cnvd_name(entry, record).model_dump_json()
    second = check_cnvd_name(entry, record).model_dump_json()

    assert first == second


@pytest.mark.parametrize(
    "changes,violation",
    [
        ({"result": "no_overlap"}, "a reason is required exactly"),
        ({"uncheckable_reason": None}, "a reason is required exactly"),
        (
            {"nvd_pair": {"vendor": "google", "product": "chrome"}},
            "an NVD pair is required exactly",
        ),
        ({"rule": "another_rule"}, "Input should be"),
        ({"statement": "the link is wrong"}, "Input should be"),
    ],
    ids=[
        "reason-on-checkable",
        "missing-reason",
        "pair-without-overlap",
        "fixed-rule",
        "fixed-statement",
    ],
)
def test_name_check_rejects_inconsistent_contract_fields(
    changes: dict[str, object], violation: str
) -> None:
    label = check_cnvd_name(build_cnvd_entry(), None).model_dump()
    label.update(changes)

    with pytest.raises(ValidationError, match=violation):
        CnvdNameCheck.model_validate(label)
