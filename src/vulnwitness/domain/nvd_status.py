"""NVD's vulnerability statuses: the API value, NVD's displayed label and what it means.

Since 2026-04-15 NVD shows its statuses under new labels while the 2.0 API and feeds keep
the old values, so a record whose ``vulnStatus`` is ``Deferred`` is the one NVD's site
calls "Not Scheduled". Labels and meanings follow NVD's vulnerability-status page as read
on 2026-11-16 (https://nvd.nist.gov/vuln/vulnerability-status). A value not listed there is
kept verbatim and described as unrecognised, never mapped to a guess.
"""

from dataclasses import dataclass
from typing import Final, Literal

NvdEnrichment = Literal["enriched", "pending", "not_scheduled", "rejected", "unrecognised"]


@dataclass(frozen=True)
class NvdStatus:
    """One NVD status: the 2.0 API value, the label NVD displays and its enrichment class."""

    api_value: str
    display_label: str
    enrichment: NvdEnrichment
    meaning: str


def build_nvd_statuses() -> dict[str, NvdStatus]:
    statuses: dict[str, NvdStatus] = {}
    for status in (
        NvdStatus(
            "Received",
            "Received",
            "pending",
            "recently published to the CVE List; NVD has not enriched it",
        ),
        NvdStatus(
            "Awaiting Analysis",
            "Awaiting Enrichment",
            "pending",
            "marked for NVD enrichment; NVD CPE, CVSS and CWE may not yet exist",
        ),
        NvdStatus(
            "Undergoing Analysis",
            "Undergoing Enrichment",
            "pending",
            "being enriched by NVD; NVD CPE, CVSS and CWE may not yet exist",
        ),
        NvdStatus("Analyzed", "Enriched", "enriched", "NVD's enrichment is complete"),
        NvdStatus(
            "Modified",
            "Modified After Enrichment",
            "enriched",
            "changed after NVD's enrichment; NVD's data may need amendment and is not "
            "routinely reviewed",
        ),
        NvdStatus(
            "Deferred",
            "Not Scheduled",
            "not_scheduled",
            "not scheduled for NVD enrichment; NVD CPE, CVSS and CWE are not expected",
        ),
        NvdStatus("Rejected", "Rejected", "rejected", "rejected in the CVE List"),
    ):
        statuses[status.api_value] = status
    return statuses


NVD_STATUSES: Final = build_nvd_statuses()


def find_nvd_status(api_value: str | None) -> NvdStatus | None:
    """The listed status for an API ``vulnStatus``, or ``None`` when absent or unlisted."""
    if api_value is None:
        return None
    return NVD_STATUSES.get(api_value)


def describe_nvd_status(api_value: str | None) -> str:
    """One line naming NVD's displayed label beside the API value, e.g.
    ``Not Scheduled (API: Deferred)``; the API value alone when unlisted."""
    if api_value is None:
        return "not recorded"
    status = find_nvd_status(api_value)
    if status is None:
        return f"{api_value} (unrecognised NVD status)"
    if status.display_label == status.api_value:
        return status.display_label
    return f"{status.display_label} (API: {status.api_value})"


def classify_nvd_enrichment(api_value: str | None) -> NvdEnrichment | None:
    """The enrichment class of a recorded status; ``None`` when no status was recorded."""
    if api_value is None:
        return None
    status = find_nvd_status(api_value)
    return "unrecognised" if status is None else status.enrichment
