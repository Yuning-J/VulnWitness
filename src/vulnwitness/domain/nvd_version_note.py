"""Annotations over a record's retained version conditions, never affectedness findings.

Versions are split on dots into ASCII numeric segments and compared numerically,
with missing trailing segments equal to zero: 5.10 > 5.9 and 2.7 == 2.7.0.
Any non-digit segment is uncomparable; an exact condition alone may also match by
trimmed string equality. No SemVer or configuration/environment evaluation is done.
For each mention, the first hit in record order wins. Without a hit, any missing
condition or uncomparable version keeps the note unknown rather than asserting a miss.
"""

from collections.abc import Sequence
from itertools import zip_longest
from typing import Annotated, Literal

from pydantic import Field

from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.cve import AffectedProduct, CveRecord, VersionRange

UnknownVersionReason = Literal[
    "no_matching_product",
    "no_version_condition",
    "version_not_comparable",
    "description_mention_only",
]


class NvdVersionHit(ContractModel):
    mention: str
    outcome: Literal["hit"] = "hit"
    wording: str
    matched_entry: AffectedProduct
    matched_condition: VersionRange


class NvdVersionNoHit(ContractModel):
    mention: str
    outcome: Literal["no_hit"] = "no_hit"
    wording: str


class NvdVersionUnknown(ContractModel):
    mention: str
    outcome: Literal["unknown"] = "unknown"
    wording: str
    reason_code: UnknownVersionReason


NvdVersionNote = Annotated[
    NvdVersionHit | NvdVersionNoHit | NvdVersionUnknown, Field(discriminator="outcome")
]


def parse_numeric_version(version: str) -> tuple[int, ...] | None:
    """Return numeric segments, or None for any segment outside ASCII digits."""
    segments: list[int] = []
    for segment in version.split("."):
        if not segment.isascii() or not segment.isdigit():
            return None
        segments.append(int(segment))
    return tuple(segments)


def compare_numeric_versions(version: str, condition_version: str) -> int | None:
    """Return -1, 0 or 1 using numeric dot segments, or None when uncomparable."""
    segments = parse_numeric_version(version)
    condition_segments = parse_numeric_version(condition_version)
    if segments is None or condition_segments is None:
        return None
    for segment, condition_segment in zip_longest(segments, condition_segments, fillvalue=0):
        if segment < condition_segment:
            return -1
        if segment > condition_segment:
            return 1
    return 0


def matches_version_condition(version: str, condition: VersionRange) -> bool | None:
    """True for a hit, False for a comparable miss, None for an unsupported version."""
    if condition.exact is not None:
        if version.strip() == condition.exact.strip():
            return True
        comparison = compare_numeric_versions(version, condition.exact)
        return None if comparison is None else comparison == 0
    satisfies_bounds = True
    for bound_name, allowed_comparisons in (
        ("start_including", (0, 1)),
        ("start_excluding", (1,)),
        ("end_including", (-1, 0)),
        ("end_excluding", (-1,)),
    ):
        bound = getattr(condition, bound_name)
        if bound is None:
            continue
        comparison = compare_numeric_versions(version, bound)
        if comparison is None:
            return None
        if comparison not in allowed_comparisons:
            satisfies_bounds = False
    return satisfies_bounds


def build_nvd_version_note(record: CveRecord, mention: str) -> NvdVersionNote:
    """Compare one 'product version' mention with matching implicated entries only.

    Vendor and product names match as whole names, case-insensitively. No-hit wording
    lists each matching vendor:product once, in record order. A hit overrides unknowns;
    otherwise uncomparable versions take precedence over missing version conditions.
    """
    product_name, version = mention.rsplit(" ", 1)
    matching_entries: list[AffectedProduct] = []
    for entry in record.list_implicated_products():
        if product_name.casefold() in (entry.vendor.casefold(), entry.product.casefold()):
            matching_entries.append(entry)
    return build_nvd_version_note_for_entries(matching_entries, mention, version)


def build_nvd_version_note_for_entries(
    entries: Sequence[AffectedProduct], mention: str, version: str
) -> NvdVersionNote:
    """Apply the NVD condition rule and wording to explicitly matched product entries.

    Entries retain record order. The caller supplies the version separately so an
    explicit field is not parsed as a natural-language product/version mention.
    """
    product_identities: list[str] = []
    has_missing_condition = False
    has_uncomparable_version = False
    for entry in entries:
        product_identity = f"{entry.vendor}:{entry.product}"
        if product_identity not in product_identities:
            product_identities.append(product_identity)
        if not entry.version_ranges:
            has_missing_condition = True
        for condition in entry.version_ranges:
            matches_condition = matches_version_condition(version, condition)
            if matches_condition:
                return NvdVersionHit(
                    mention=mention,
                    wording=(
                        f"Version {version} matches an NVD CPE version condition for "
                        f"{product_identity}; the full configuration and environment "
                        "conditions were not evaluated."
                    ),
                    matched_entry=entry,
                    matched_condition=condition,
                )
            if matches_condition is None:
                has_uncomparable_version = True
    reason_code: UnknownVersionReason | None = None
    if not product_identities:
        reason_code = "no_matching_product"
        reason = "no affected entry matches the mentioned product"
    elif has_uncomparable_version:
        reason_code = "version_not_comparable"
        reason = "a version cannot be compared by the numeric dotted-segment rule"
    elif has_missing_condition:
        reason_code = "no_version_condition"
        reason = "a matching entry carries no version condition"
    if reason_code is not None:
        return NvdVersionUnknown(
            mention=mention,
            wording=f"Version {version}: NVD CPE version condition unknown; {reason}.",
            reason_code=reason_code,
        )
    return NvdVersionNoHit(
        mention=mention,
        wording=(
            f"Version {version} matches none of the NVD CPE version conditions listed for "
            f"{', '.join(product_identities)}; this does not show the version is unaffected."
        ),
    )


def list_nvd_version_notes(
    record: CveRecord, mentions: Sequence[str]
) -> tuple[NvdVersionNote, ...] | None:
    """One note per interpretation mention, in mention order; absent without mentions."""
    if not mentions:
        return None
    notes: list[NvdVersionNote] = []
    for mention in mentions:
        notes.append(build_nvd_version_note(record, mention))
    return tuple(notes)
