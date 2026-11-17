"""Source version readings preserve attribution, exceptions and conservative unknowns."""

import pytest

from tests.support.source_version_notes import (
    build_backport_product,
    build_source_product,
    build_source_record,
)
from vulnwitness.domain.cve import (
    SourceAffected,
    SourceAffectedProduct,
    SourceAffectedVersion,
    SourceVersionChange,
)
from vulnwitness.domain.source_version_note import (
    SourceVersionUnknown,
    build_source_version_notes,
    list_source_version_notes,
)


@pytest.mark.parametrize(
    "version,outcome,applied",
    [
        ("4.9", "no_statement", ()),
        ("5.0", "states_affected", ()),
        ("5.4.1", "states_unaffected", ("5.4.1",)),
        ("5.4.2", "states_affected", ("5.4.1", "5.4.2")),
        ("5.4.3", "no_statement", ()),
    ],
    ids=["before_range", "inclusive_start", "backport", "reintroduced", "exclusive_end"],
)
def test_backport_changes_apply_in_version_order(
    version: str, outcome: str, applied: tuple[str, ...]
) -> None:
    record = build_source_record(build_backport_product())
    notes = list_source_version_notes(record, (f"demo_gateway {version}",), 4)

    assert notes is not None and len(notes) == 1
    note = notes[0]
    assert note.outcome == outcome
    assert note.source == "cna@example.org"
    assert note.matched_products == record.source_affected[0].products
    product = note.matched_products[0]
    assert product.vendor == "Demo Corp"
    assert product.product == "Demo Gateway"
    changes = []
    for match in note.covering_entries:
        assert match.entry in product.versions
        for change in match.applied_changes:
            changes.append(change.at)
    assert tuple(changes) == applied
    assert note.wording.startswith("CNA/ADP cna@example.org ")
    assert note.wording.endswith(
        "This is cna@example.org's statement; VulnWitness has not set applicability."
    )
    if outcome == "states_affected":
        assert f"states version {version} is affected: range 5.0 to below 5.4.3" in note.wording


@pytest.mark.parametrize(
    "product,version,outcome,reason",
    [
        (
            build_source_product(
                vendor="Linux",
                product="Linux",
                versions=(
                    SourceAffectedVersion(
                        version="a12bc",
                        less_than="fc879",
                        version_type="git",
                        status="affected",
                    ),
                ),
            ),
            "6.1",
            "unknown",
            "no_version_data",
        ),
        (
            build_source_product(
                versions=(
                    SourceAffectedVersion(
                        version="1.0",
                        less_than="2.0",
                        version_type="original_commit_for_fix",
                        status="affected",
                    ),
                )
            ),
            "1.5",
            "unknown",
            "no_version_data",
        ),
        (
            build_source_product(
                default_status="unaffected",
                versions=(
                    SourceAffectedVersion(
                        version="9ec19493fb86",
                        less_than="cbb425f62df9",
                        version_type="custom",
                        status="affected",
                    ),
                ),
            ),
            "5.10.150",
            "unknown",
            "no_version_data",
        ),
        (build_source_product(default_status="unaffected"), "6.0", "states_unaffected", None),
        (build_source_product(default_status="affected"), "6.0", "states_affected", None),
        (build_source_product(default_status="unknown"), "6.0", "no_statement", None),
        (
            build_source_product(versions=(), default_status="unaffected"),
            "6.0",
            "states_unaffected",
            None,
        ),
        (build_source_product(versions=()), "5.2", "unknown", "no_version_data"),
        (build_source_product(omitted_versions=1), "5.2", "unknown", "truncated"),
        (
            build_source_product(
                versions=(
                    SourceAffectedVersion(
                        version="11.2.7-h8",
                        status="affected",
                    ),
                )
            ),
            "11.2.7-h8",
            "unknown",
            "version_not_comparable",
        ),
        (build_source_product(), "5.2-h8", "unknown", "version_not_comparable"),
        (
            build_source_product(
                versions=(
                    SourceAffectedVersion(
                        version="5.0",
                        less_than="5.5",
                        status="affected",
                        changes=(SourceVersionChange(at="5.3-rc1", status="unaffected"),),
                    ),
                )
            ),
            "5.2",
            "unknown",
            "version_not_comparable",
        ),
        (
            build_source_product(
                versions=(
                    SourceAffectedVersion(
                        version="5.0",
                        less_than="5.5",
                        status="affected",
                        omitted_changes=1,
                    ),
                )
            ),
            "5.2",
            "unknown",
            "truncated",
        ),
        (
            build_source_product(
                versions=(
                    SourceAffectedVersion(
                        version="5.0",
                        status="unknown",
                    ),
                )
            ),
            "5.0",
            "no_statement",
            None,
        ),
    ],
    ids=[
        "kernel_git",
        "numeric_commit_type",
        "custom_commit_only_even_with_default",
        "default_unaffected",
        "default_affected",
        "default_unknown",
        "default_without_entries",
        "no_version_data",
        "truncated_product",
        "hotfix_entry",
        "hotfix_mention",
        "uncomparable_future_change",
        "truncated_changes",
        "covering_unknown_status",
    ],
)
def test_real_feed_shapes_and_unknown_reasons(
    product: SourceAffectedProduct, version: str, outcome: str, reason: str | None
) -> None:
    record = build_source_record(product)
    notes = build_source_version_notes(
        record,
        f"{product.product} {version}",
        version,
        product=product.product,
        store_format_version=4,
    )

    assert notes is not None and len(notes) == 1
    assert notes[0].outcome == outcome
    if reason is not None:
        assert isinstance(notes[0], SourceVersionUnknown)
        assert notes[0].reason_code == reason


@pytest.mark.parametrize(
    "version,outcome,covering_version",
    [
        ("5.10.150", "states_unaffected", "5.10.46"),
        ("5.10.20", "no_statement", None),
        ("5.1", "states_affected", "5.1"),
    ],
    ids=["fixed_backport", "before_backport", "affected_exact"],
)
@pytest.mark.parametrize("wildcard_upper", [False, True], ids=["exclusive", "linux_wildcard"])
def test_linux_cve_2021_47230_mirrored_products_are_read_together(
    version: str, outcome: str, covering_version: str | None, wildcard_upper: bool
) -> None:
    """NVD splits Linux release and custom commit ranges into single-version products."""
    entries = []
    for commit_upper in ("cbb425f62df9", "a12bc34de567", "bc234de56789", "cd345ef67890"):
        entries.append(
            SourceAffectedVersion(
                version="9ec19493fb86",
                less_than=commit_upper,
                version_type="custom",
                status="affected",
            )
        )
    for lower, upper in (("0", "5.1"), ("5.4.128", "5.5"), ("5.12.13", "5.13")):
        entries.append(SourceAffectedVersion(version=lower, less_than=upper, status="unaffected"))
    backport = SourceAffectedVersion(
        version="5.10.46",
        less_than=None if wildcard_upper else "5.11",
        less_than_or_equal="5.10.*" if wildcard_upper else None,
        status="unaffected",
    )
    entries.extend(
        (
            backport,
            SourceAffectedVersion(version="5.13", status="unaffected"),
            SourceAffectedVersion(version="5.1", status="affected"),
        )
    )
    products = []
    for entry in entries:
        products.append(
            build_source_product(
                vendor="linux", product="linux_kernel", default_status="unknown", versions=(entry,)
            )
        )
    record = build_source_record(*products).model_copy(update={"cve_id": "CVE-2021-47230"})
    notes = build_source_version_notes(
        record,
        f"linux_kernel {version}",
        version,
        vendor="linux",
        product="linux_kernel",
        store_format_version=4,
    )
    assert notes is not None and len(notes) == 1
    note = notes[0]
    assert note.outcome == outcome
    assert note.matched_products == tuple(products)
    if covering_version is None:
        assert note.covering_entries == ()
    else:
        assert len(note.covering_entries) == 1
        assert note.covering_entries[0].entry.version == covering_version
        if covering_version == "5.10.46":
            assert note.covering_entries[0].entry == backport
    assert note.wording.startswith("CNA/ADP cna@example.org ")


@pytest.mark.parametrize(
    "sibling",
    [
        build_source_product(versions=()),
        build_source_product(
            default_status="unaffected",
            versions=(SourceAffectedVersion(version="6.0", status="unaffected"),),
        ),
        build_source_product(
            versions=(
                SourceAffectedVersion(version="git-hash", version_type="git", status="affected"),
            )
        ),
    ],
    ids=["missing_versions", "noncovering_with_different_default", "commit_only"],
)
def test_covering_release_is_not_overridden_by_matching_siblings(
    sibling: SourceAffectedProduct,
) -> None:
    product = build_source_product()
    notes = list_source_version_notes(
        build_source_record(product, sibling), ("Demo Gateway 5.2",), 4
    )
    assert notes is not None and len(notes) == 1
    assert notes[0].outcome == "states_affected"
    assert notes[0].matched_products == (product, sibling)
    assert len(notes[0].covering_entries) == 1
    assert notes[0].covering_entries[0].entry == product.versions[0]


@pytest.mark.parametrize(
    "condition,version,outcome",
    [
        (
            SourceAffectedVersion(version="0", less_than="*", status="affected"),
            "99999.4",
            "states_affected",
        ),
        (
            SourceAffectedVersion(version="0", less_than_or_equal="*", status="affected"),
            "0.0.1",
            "states_affected",
        ),
        (
            SourceAffectedVersion(version="0", less_than="5.0", status="affected"),
            "0.0.1",
            "states_affected",
        ),
        (
            SourceAffectedVersion(version="5.0", less_than="*", status="affected"),
            "4.9",
            "no_statement",
        ),
        (
            SourceAffectedVersion(version="5.0", less_than_or_equal="5.2", status="affected"),
            "5.2.0",
            "states_affected",
        ),
        (
            SourceAffectedVersion(version="5.0", less_than="5.2", status="affected"),
            "5.2.0",
            "no_statement",
        ),
        (
            SourceAffectedVersion(version="5.9", less_than="5.11", status="affected"),
            "5.10",
            "states_affected",
        ),
        (SourceAffectedVersion(version="5.2", status="affected"), "5.2.0", "states_affected"),
        (SourceAffectedVersion(version="0", status="affected"), "0.1", "no_statement"),
        (
            SourceAffectedVersion(version="unspecified", less_than="115.0", status="affected"),
            "102.4",
            "states_affected",
        ),
        (
            SourceAffectedVersion(version="*", less_than="5.0", status="affected"),
            "0.0.1",
            "states_affected",
        ),
        (
            SourceAffectedVersion(version="1234567", less_than="1234569", status="affected"),
            "1234568",
            "states_affected",
        ),
        (
            SourceAffectedVersion(
                version="5.10.150", less_than_or_equal="5.10.*", status="unaffected"
            ),
            "5.10.200",
            "states_unaffected",
        ),
        (
            SourceAffectedVersion(
                version="5.10.150", less_than_or_equal="5.10.*", status="unaffected"
            ),
            "5.11",
            "no_statement",
        ),
        (
            SourceAffectedVersion(version="5.0", less_than="5.10.*", status="affected"),
            "5.10.1",
            "no_statement",
        ),
        (SourceAffectedVersion(version="2.4.*", status="affected"), "2.4.7", "states_affected"),
    ],
    ids=[
        "both_open_exclusive",
        "both_open_inclusive",
        "open_lower",
        "open_upper_miss",
        "inclusive_upper",
        "exclusive_upper",
        "numeric_segments",
        "exact_trailing_zeros",
        "zero_exact_is_not_open",
        "unspecified_lower_is_open",
        "wildcard_lower_is_open",
        "all_digit_bounds_are_release_versions",
        "wildcard_upper_inclusive_covers_prefix",
        "wildcard_upper_inclusive_ends_at_prefix",
        "wildcard_upper_exclusive_excludes_prefix",
        "wildcard_exact_covers_prefix",
    ],
)
def test_ranges_open_sides_and_exact_versions(
    condition: SourceAffectedVersion, version: str, outcome: str
) -> None:
    notes = list_source_version_notes(
        build_source_record(build_source_product(versions=(condition,))),
        (f"Demo Gateway {version}",),
        4,
    )
    assert notes is not None and notes[0].outcome == outcome


@pytest.mark.parametrize(
    "products,reason",
    [
        (
            (
                build_source_product(default_status="affected", versions=(), omitted_versions=1),
                build_source_product(default_status="unaffected", versions=()),
            ),
            "conflicting",
        ),
        (
            (
                build_source_product(versions=(), omitted_versions=1),
                build_source_product(versions=()),
            ),
            "truncated",
        ),
        (
            (
                build_source_product(),
                build_source_product(
                    versions=(
                        SourceAffectedVersion(
                            version="5.2-rc1",
                            status="affected",
                            version_type="custom",
                        ),
                    )
                ),
            ),
            "version_not_comparable",
        ),
        (
            (build_source_product(versions=()), build_source_product(versions=())),
            "no_version_data",
        ),
        (
            (
                build_source_product(default_status="affected", versions=()),
                build_source_product(default_status="unknown", versions=()),
            ),
            "conflicting",
        ),
        (
            (
                build_source_product(
                    versions=(
                        SourceAffectedVersion(version="5.0", less_than="6.0", status="affected"),
                        SourceAffectedVersion(version="5.2", status="unaffected"),
                    ),
                    omitted_versions=1,
                ),
            ),
            "conflicting",
        ),
    ],
    ids=[
        "conflict_before_truncation",
        "truncation_before_missing",
        "uncomparable_sibling",
        "no_release_data",
        "conflicting_defaults",
        "overlapping_entries",
    ],
)
def test_block_unknown_precedence_and_matching_siblings(
    products: tuple[SourceAffectedProduct, ...], reason: str
) -> None:
    notes = list_source_version_notes(build_source_record(*products), ("Demo Gateway 5.2",), 4)
    assert notes is not None and len(notes) == 1
    assert isinstance(notes[0], SourceVersionUnknown)
    assert notes[0].reason_code == reason
    assert notes[0].matched_products == products


def test_disagreeing_sources_keep_separate_notes_in_feed_order() -> None:
    record = build_source_record(build_source_product())
    record = record.model_copy(
        update={
            "source_affected": (
                SourceAffected(source="z-cna", products=(build_source_product(),)),
                SourceAffected(
                    source="a-adp",
                    products=(
                        build_source_product(
                            default_status="unaffected",
                            versions=(),
                        ),
                    ),
                ),
            )
        }
    )
    notes = list_source_version_notes(record, ("Demo Gateway 5.2",), 4)
    assert notes is not None
    source_outcomes = []
    for note in notes:
        source_outcomes.append((note.source, note.outcome))
    assert source_outcomes == [
        ("z-cna", "states_affected"),
        ("a-adp", "states_unaffected"),
    ]


@pytest.mark.parametrize(
    "vendor,product,expected_count",
    [
        ("demo_corp", "DEMO-gateway", 1),
        (None, "demo gateway", 1),
        ("demo corp", None, 1),
        ("different", "demo gateway", 0),
        ("demo corp", "different", 0),
    ],
    ids=["normalized_pair", "product_only", "vendor_only", "wrong_vendor", "wrong_product"],
)
def test_source_names_reuse_candidate_normalization(
    vendor: str | None, product: str | None, expected_count: int
) -> None:
    notes = build_source_version_notes(
        build_source_record(build_source_product()),
        "query 5.2",
        "5.2",
        vendor=vendor,
        product=product,
        store_format_version=4,
    )
    assert notes is not None and len(notes) == expected_count


@pytest.mark.parametrize(
    "cpe",
    ["cpe:/a:demo_corp:demo_gateway", "cpe:2.3:a:demo_corp:demo_gateway:*:*:*:*:*:*:*:*"],
    ids=["cpe22", "cpe23"],
)
def test_cpe_names_supply_an_independent_pair(cpe: str) -> None:
    product = build_source_product(vendor="n/a", product="Unknown", cpes=(cpe,))
    notes = build_source_version_notes(
        build_source_record(product),
        "demo 5.2",
        "5.2",
        vendor="Demo Corp",
        product="demo gateway",
        store_format_version=4,
    )
    assert notes is not None and notes[0].outcome == "states_affected"
    assert notes[0].matched_products == (product,)
    assert notes[0].matched_products[0].vendor == "n/a"


@pytest.mark.parametrize("format_version", [1, 2, 3, 4], ids=["v1", "v2", "v3", "v4"])
def test_no_match_is_empty_only_when_the_store_can_hold_source_data(format_version: int) -> None:
    record = build_source_record(build_source_product())
    notes = list_source_version_notes(record, ("unrelated 5.2",), format_version)
    assert notes == (() if format_version == 4 else None)
    assert list_source_version_notes(record, (), format_version) is None
