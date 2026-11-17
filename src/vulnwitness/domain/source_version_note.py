"""Pure readings of each CNA/ADP's version statements; never applicability verdicts."""

import re
from collections.abc import Sequence
from functools import cmp_to_key
from typing import Annotated, Literal

from pydantic import Field

from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.cve import (
    AffectedStatus,
    CveRecord,
    SourceAffectedProduct,
    SourceAffectedVersion,
    SourceVersionChange,
)
from vulnwitness.domain.nvd_version_note import compare_numeric_versions, parse_numeric_version
from vulnwitness.domain.source_product import list_entry_names, normalize_source_name

SourceVersionOutcome = Literal["states_affected", "states_unaffected", "no_statement", "unknown"]
SourceVersionReason = Literal[
    "conflicting", "truncated", "version_not_comparable", "no_version_data"
]
REASON_WORDING: dict[SourceVersionReason, str] = {
    "conflicting": "its entries state different statuses for this version",
    "truncated": "some of its versions or status changes were not stored",
    "version_not_comparable": "a version cannot be compared by the numeric dotted-segment rule",
    "no_version_data": "it states no release versions",
}
REASON_ORDER: tuple[SourceVersionReason, ...] = (
    "conflicting",
    "truncated",
    "version_not_comparable",
    "no_version_data",
)


class SourceVersionMatch(ContractModel):
    entry: SourceAffectedVersion
    applied_changes: tuple[SourceVersionChange, ...] = ()
    status: AffectedStatus


class SourceVersionStatement(ContractModel):
    mention: str
    source: str
    outcome: Literal["states_affected", "states_unaffected", "no_statement"]
    matched_products: tuple[SourceAffectedProduct, ...] = Field(min_length=1)
    covering_entries: tuple[SourceVersionMatch, ...] = ()
    wording: str


class SourceVersionUnknown(ContractModel):
    mention: str
    source: str
    outcome: Literal["unknown"] = "unknown"
    reason_code: SourceVersionReason
    matched_products: tuple[SourceAffectedProduct, ...] = Field(min_length=1)
    covering_entries: tuple[SourceVersionMatch, ...] = ()
    wording: str


SourceVersionNote = Annotated[
    SourceVersionStatement | SourceVersionUnknown, Field(discriminator="outcome")
]


def source_product_matches(
    entry: SourceAffectedProduct, vendor: str | None, product: str | None, name: str | None
) -> bool:
    """Explicit product queries require a same-entry pair; mentions name either component.

    Source text can supply a single requested name even when its other component is absent.
    CPE pairs independently supply either or both requested components.
    """
    names = list_entry_names(entry)
    if entry.vendor is not None or entry.product is not None:
        names.append(
            (normalize_source_name(entry.vendor or ""), normalize_source_name(entry.product or ""))
        )
    for entry_vendor, entry_product in names:
        if name is not None:
            if normalize_source_name(name) in (entry_vendor, entry_product):
                return True
        elif (vendor is None or normalize_source_name(vendor) == entry_vendor) and (
            product is None or normalize_source_name(product) == entry_product
        ):
            return True
    return False


def compare_change_points(left: SourceVersionChange, right: SourceVersionChange) -> int:
    comparison = compare_numeric_versions(left.at, right.at)
    assert comparison is not None  # Every change point is checked before sorting.
    return comparison


# CNAs write an open lower bound as "0" (the CVE format's convention), "unspecified" or "*".
OPEN_LOWER_BOUNDS = ("0", "unspecified", "*")
OPEN_UPPER_BOUND = "*"
COMMIT_VERSION_TYPES = ("git", "original_commit_for_fix")
COMMIT_IDENTIFIER = re.compile(r"[0-9a-f]{7,40}")
WILDCARD_SUFFIX = ".*"


def compare_to_bound(version: str, bound: str) -> int | None:
    """Compare with a bound; a trailing ``.*`` (e.g. ``5.10.*``) stands for every version
    sharing that prefix, so only the version's leading segments are compared."""
    if not bound.endswith(WILDCARD_SUFFIX):
        return compare_numeric_versions(version, bound)
    prefix_segments = parse_numeric_version(bound.removesuffix(WILDCARD_SUFFIX))
    version_segments = parse_numeric_version(version)
    if prefix_segments is None or version_segments is None:
        return None
    padded_segments = version_segments + (0,) * len(prefix_segments)
    leading_segments = padded_segments[: len(prefix_segments)]
    if leading_segments < prefix_segments:
        return -1
    if leading_segments > prefix_segments:
        return 1
    return 0


def is_commit_entry(entry: SourceAffectedVersion) -> bool:
    """Commit-identified entries state the same range in commits, not releases.

    The Linux CNA publishes each range twice, once by commit and once by release; NVD's
    mirror labels many commit ranges ``custom``, so abbreviated hashes are recognised too.
    """
    if entry.version_type in COMMIT_VERSION_TYPES:
        return True
    for bound in (entry.version, entry.less_than, entry.less_than_or_equal):
        if bound is None or bound == OPEN_UPPER_BOUND:
            continue
        if bound.isdigit() or COMMIT_IDENTIFIER.fullmatch(bound) is None:
            return False
    return True


def is_comparable_bound(bound: str) -> bool:
    return compare_to_bound("0", bound) is not None


def read_source_entry(
    entry: SourceAffectedVersion, version: str
) -> SourceVersionMatch | Literal["not_covered", "version_not_comparable"]:
    """Read a covering entry with sorted applied changes, or explain why none is read."""
    is_range = entry.less_than is not None or entry.less_than_or_equal is not None
    has_lower_bound = not is_range or entry.version not in OPEN_LOWER_BOUNDS
    bounds: list[str] = []
    if has_lower_bound:
        bounds.append(entry.version)
    for bound in (entry.less_than, entry.less_than_or_equal):
        if bound is not None and bound != OPEN_UPPER_BOUND:
            bounds.append(bound)
    if not all(is_comparable_bound(bound) for bound in bounds):
        return "version_not_comparable"
    if any(parse_numeric_version(change.at) is None for change in entry.changes):
        return "version_not_comparable"
    if not is_range:
        comparison = compare_to_bound(version, entry.version)
        if comparison is None:
            return "version_not_comparable"
        if comparison != 0:
            return "not_covered"
        return SourceVersionMatch(entry=entry, status=entry.status)
    if has_lower_bound:
        comparison = compare_to_bound(version, entry.version)
        assert comparison is not None
        if comparison < 0:
            return "not_covered"
    for bound, inclusive in ((entry.less_than, False), (entry.less_than_or_equal, True)):
        if bound is None or bound == OPEN_UPPER_BOUND:
            continue
        comparison = compare_to_bound(version, bound)
        assert comparison is not None
        if comparison > 0 or (comparison == 0 and not inclusive):
            return "not_covered"
    applied_changes: list[SourceVersionChange] = []
    status = entry.status
    for change in sorted(entry.changes, key=cmp_to_key(compare_change_points)):
        comparison = compare_numeric_versions(version, change.at)
        assert comparison is not None
        if comparison >= 0:
            applied_changes.append(change)
            status = change.status
    return SourceVersionMatch(entry=entry, applied_changes=tuple(applied_changes), status=status)


def find_source_reason(reasons: set[SourceVersionReason]) -> SourceVersionReason | None:
    """The first applicable unknown reason in the ADR's precedence order."""
    for reason in REASON_ORDER:
        if reason in reasons:
            return reason
    return None


def read_source_products(
    products: Sequence[SourceAffectedProduct], version: str
) -> tuple[tuple[SourceVersionMatch, ...], AffectedStatus | None, SourceVersionReason | None]:
    """Read one source's matching products as a single product.

    NVD's mirror splits one product's versions over many entries, so a version one entry
    does not cover says nothing against another entry that covers it. Returns the covering
    entries, the stated status (None when the source states none) and the unknown reason.
    """
    reasons: set[SourceVersionReason] = set()
    covering_entries: list[SourceVersionMatch] = []
    default_statuses: set[AffectedStatus] = set()
    has_release_entries = False
    has_commit_entries = False
    for product in products:
        if product.omitted_versions:
            reasons.add("truncated")
        if product.default_status is not None:
            default_statuses.add(product.default_status)
        for condition in product.versions:
            if condition.omitted_changes:
                reasons.add("truncated")
            if is_commit_entry(condition):
                has_commit_entries = True
                continue
            has_release_entries = True
            if parse_numeric_version(version) is None:
                reasons.add("version_not_comparable")
                continue
            reading = read_source_entry(condition, version)
            if isinstance(reading, SourceVersionMatch):
                covering_entries.append(reading)
            elif reading == "version_not_comparable":
                reasons.add("version_not_comparable")
    stated_statuses: set[AffectedStatus] = set()
    for covering in covering_entries:
        stated_statuses.add(covering.status)
    if not covering_entries:
        stated_statuses = default_statuses
    if len(stated_statuses) > 1:
        reasons.add("conflicting")
    if not has_release_entries and (has_commit_entries or not default_statuses):
        reasons.add("no_version_data")
    status = next(iter(stated_statuses)) if len(stated_statuses) == 1 else None
    return tuple(covering_entries), status, find_source_reason(reasons)


def describe_source_match(match: SourceVersionMatch) -> str:
    entry = match.entry
    if entry.less_than is None and entry.less_than_or_equal is None:
        description = f"exact version {entry.version}"
    else:
        if entry.less_than is not None:
            upper = "" if entry.less_than == OPEN_UPPER_BOUND else f"below {entry.less_than}"
        else:
            bound = entry.less_than_or_equal
            upper = "" if bound == OPEN_UPPER_BOUND else f"up to and including {bound}"
        if entry.version in OPEN_LOWER_BOUNDS:
            description = f"every version {upper}" if upper else "every version"
        elif upper:
            description = f"range {entry.version} to {upper}"
        else:
            description = f"range {entry.version} onward"
    if match.applied_changes:
        description += "; changes " + ", ".join(
            f"at {change.at} to {change.status}" for change in match.applied_changes
        )
    return description


def build_source_note(
    source: str, mention: str, version: str, products: Sequence[SourceAffectedProduct]
) -> SourceVersionNote:
    covering_entries, status, reason = read_source_products(products, version)
    ending = f"This is {source}'s statement; VulnWitness has not set applicability."
    if reason is not None:
        return SourceVersionUnknown(
            mention=mention,
            source=source,
            reason_code=reason,
            matched_products=tuple(products),
            covering_entries=covering_entries,
            wording=(
                f"CNA/ADP {source}: statement on version {version} unknown; "
                f"{REASON_WORDING[reason]}. {ending}"
            ),
        )
    if status in ("affected", "unaffected"):
        descriptions: list[str] = []
        for match in covering_entries:
            descriptions.append(describe_source_match(match))
        if not descriptions:
            descriptions.append(f"default status {status}")
        return SourceVersionStatement(
            mention=mention,
            source=source,
            outcome="states_affected" if status == "affected" else "states_unaffected",
            matched_products=tuple(products),
            covering_entries=covering_entries,
            wording=(
                f"CNA/ADP {source} states version {version} is {status}: "
                f"{'; '.join(descriptions)}. {ending}"
            ),
        )
    return SourceVersionStatement(
        mention=mention,
        source=source,
        outcome="no_statement",
        matched_products=tuple(products),
        covering_entries=covering_entries,
        wording=f"CNA/ADP {source} gives no statement for version {version}. {ending}",
    )


def build_source_version_notes(
    record: CveRecord,
    mention: str,
    version: str,
    *,
    vendor: str | None = None,
    product: str | None = None,
    name: str | None = None,
    store_format_version: int,
) -> tuple[SourceVersionNote, ...] | None:
    """One note per matching source block in feed order; absent before store format 4."""
    if store_format_version < 4:
        return None
    notes: list[SourceVersionNote] = []
    for block in record.source_affected:
        matched_products: list[SourceAffectedProduct] = []
        for entry in block.products:
            if source_product_matches(entry, vendor, product, name):
                matched_products.append(entry)
        if matched_products:
            notes.append(build_source_note(block.source, mention, version, matched_products))
    return tuple(notes)


def list_source_version_notes(
    record: CveRecord, mentions: Sequence[str], store_format_version: int
) -> tuple[SourceVersionNote, ...] | None:
    """Mention order, then feed order, using the investigation's whole-name matching rule."""
    if not mentions or store_format_version < 4:
        return None
    notes: list[SourceVersionNote] = []
    for mention in mentions:
        name, version = mention.rsplit(" ", 1)
        notes.extend(
            build_source_version_notes(
                record,
                mention,
                version,
                name=name,
                store_format_version=store_format_version,
            )
            or ()
        )
    return tuple(notes)
