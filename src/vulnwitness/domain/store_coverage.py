"""What a corpus store's records carry, by publication month, and how two stores differ in
meaning rather than in bytes.

Coverage counts what NVD enrichment supplies and VulnWitness relies on: vulnerable CPE
matches, NVD's own CVSS v3 metric, CWE IDs and ``Exploit``-tagged references, beside NVD's
status. Since NVD's 2026-04-15 change most new records stay "Not Scheduled", so these
counts say how much of a store exact CPE matching and NVD-score rules can see at all.

A record's semantic digest hashes its content without ``last_modified`` and without
evidence IDs, which hash the source bytes. NVD rewrote ``lastModified`` on about 95% of
records on 2026-06-17 with no change of content; the semantic diff tells such a refresh
from a real one. Both are deterministic over the store's records.
"""

from collections import Counter
from collections.abc import Iterable
from typing import Final, Literal

from pydantic import Field

from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.cve import CveId, CveRecord
from vulnwitness.domain.evidence import SHA256_PATTERN
from vulnwitness.domain.hashing import canonical_sha256
from vulnwitness.domain.nvd_metrics import is_nvd_own_metric
from vulnwitness.domain.nvd_status import classify_nvd_enrichment
from vulnwitness.domain.search import SCHEMA_VERSION, SchemaVersion
from vulnwitness.domain.source_comparison import select_nvd_cvss3

EXPLOIT_REFERENCE_TAG: Final = "Exploit"
SEMANTIC_DIGEST_VERSION: Final = 1
# Fields that change when a source re-serialises a record without changing its meaning.
VOLATILE_RECORD_FIELDS: Final = frozenset({"last_modified", "evidence_ids"})
MAX_LISTED_CHANGES = 200
COVERAGE_STATEMENT: Final = (
    "Counts of what each record carries in this store, by publication month. A missing CPE, "
    "score or CWE says NVD supplied none in the imported snapshot; it never says the CVE "
    "affects nothing or is not severe."
)
DIFF_STATEMENT: Final = (
    "Records are compared by semantic digest, which leaves out last_modified and evidence "
    "IDs. metadata_only counts records whose last_modified or evidence IDs changed while "
    "their content did not."
)


def semantic_record_payload(record: CveRecord) -> dict[str, object]:
    """The record as JSON without volatile fields; CNVD entries lose their evidence IDs."""
    payload = record.model_dump(mode="json", exclude=set(VOLATILE_RECORD_FIELDS))
    cnvd_entries = payload.get("cnvd")
    if isinstance(cnvd_entries, list):
        semantic_entries = []
        for entry in cnvd_entries:
            if not isinstance(entry, dict):
                continue
            semantic_entry = {}
            for key, value in entry.items():
                if key != "evidence_id":
                    semantic_entry[key] = value
            semantic_entries.append(semantic_entry)
        payload["cnvd"] = semantic_entries
    return payload


def semantic_record_sha256(record: CveRecord) -> str:
    return canonical_sha256(
        {"version": SEMANTIC_DIGEST_VERSION, "record": semantic_record_payload(record)}
    )


def semantic_content_sha256(record_digests: dict[str, str]) -> str:
    """One digest over every record's semantic digest, in CVE ID order."""
    ordered_digests = []
    for cve_id in sorted(record_digests):
        ordered_digests.append([cve_id, record_digests[cve_id]])
    return canonical_sha256({"version": SEMANTIC_DIGEST_VERSION, "records": ordered_digests})


class EnrichmentCounts(ContractModel):
    enriched: int = Field(ge=0)
    pending: int = Field(ge=0)
    not_scheduled: int = Field(ge=0)
    rejected: int = Field(ge=0)
    unrecognised: int = Field(ge=0)
    not_recorded: int = Field(ge=0)


class MonthCoverage(ContractModel):
    month: str = Field(
        pattern=r"^([0-9]{4}-[0-9]{2}|unpublished|all)$",
        description=(
            "Publication month (UTC); unpublished when the record has no date; all for "
            "the store's total."
        ),
    )
    records: int = Field(ge=0)
    nvd_status: dict[str, int] = Field(description="Verbatim NVD 2.0 API vulnStatus counts.")
    enrichment: EnrichmentCounts
    with_vulnerable_cpe: int = Field(ge=0)
    with_nvd_own_cvss3: int = Field(ge=0)
    with_any_cvss: int = Field(ge=0)
    with_cvss4: int = Field(ge=0)
    with_cwe: int = Field(ge=0)
    with_exploit_reference: int = Field(ge=0)
    kev_listed: int = Field(ge=0)
    with_cnvd: int = Field(ge=0)
    with_source_cvss: int = Field(ge=0, description="Records with a CVSS metric not NVD's own.")
    with_source_affected: int = Field(
        ge=0, description="Records carrying CNA or ADP affected data (store format 4)."
    )
    with_source_affected_versions: int = Field(
        ge=0, description="Records whose CNA or ADP affected data names a version or range."
    )
    with_source_affected_purl: int = Field(ge=0)
    with_ssvc: int = Field(ge=0)
    ssvc_exploitation_poc: int = Field(ge=0)
    ssvc_exploitation_active: int = Field(ge=0)


class StoreCoverage(ContractModel):
    schema_version: SchemaVersion = SCHEMA_VERSION
    store_name: str
    corpus_content_sha256: str = Field(pattern=SHA256_PATTERN)
    semantic_content_sha256: str = Field(pattern=SHA256_PATTERN)
    records: int = Field(ge=0)
    months: tuple[MonthCoverage, ...]
    total: MonthCoverage
    statement: Literal[
        "Counts of what each record carries in this store, by publication month. A missing "
        "CPE, score or CWE says NVD supplied none in the imported snapshot; it never says "
        "the CVE affects nothing or is not severe."
    ] = COVERAGE_STATEMENT


class StoreSemanticDiff(ContractModel):
    schema_version: SchemaVersion = SCHEMA_VERSION
    old_store_name: str
    new_store_name: str
    old_semantic_content_sha256: str = Field(pattern=SHA256_PATTERN)
    new_semantic_content_sha256: str = Field(pattern=SHA256_PATTERN)
    added: int = Field(ge=0)
    removed: int = Field(ge=0)
    changed: int = Field(ge=0)
    metadata_only: int = Field(ge=0)
    unchanged: int = Field(ge=0)
    changed_fields: dict[str, int] = Field(
        description="Top-level record fields that differ, counted over changed records."
    )
    added_ids: tuple[CveId, ...] = Field(max_length=MAX_LISTED_CHANGES)
    removed_ids: tuple[CveId, ...] = Field(max_length=MAX_LISTED_CHANGES)
    changed_ids: tuple[CveId, ...] = Field(max_length=MAX_LISTED_CHANGES)
    lists_truncated: bool
    statement: Literal[
        "Records are compared by semantic digest, which leaves out last_modified and "
        "evidence IDs. metadata_only counts records whose last_modified or evidence IDs "
        "changed while their content did not."
    ] = DIFF_STATEMENT


def publication_month(record: CveRecord) -> str:
    if record.published is None:
        return "unpublished"
    return record.published.strftime("%Y-%m")


def has_nvd_own_cvss3(record: CveRecord) -> bool:
    return select_nvd_cvss3(record) is not None


def has_ssvc_exploitation(record: CveRecord, value: str) -> bool:
    return any(assessment.decision_points.exploitation == value for assessment in record.ssvc)


def count_month(month: str, records: list[CveRecord]) -> MonthCoverage:
    statuses: Counter[str] = Counter()
    enrichment: Counter[str] = Counter()
    for record in records:
        if record.nvd_status is not None:
            statuses[record.nvd_status] += 1
        enrichment[classify_nvd_enrichment(record.nvd_status) or "not_recorded"] += 1
    return MonthCoverage(
        month=month,
        records=len(records),
        nvd_status=dict(sorted(statuses.items())),
        enrichment=EnrichmentCounts(
            enriched=enrichment["enriched"],
            pending=enrichment["pending"],
            not_scheduled=enrichment["not_scheduled"],
            rejected=enrichment["rejected"],
            unrecognised=enrichment["unrecognised"],
            not_recorded=enrichment["not_recorded"],
        ),
        with_vulnerable_cpe=sum(
            any(product.cpe is not None for product in record.list_implicated_products())
            for record in records
        ),
        with_nvd_own_cvss3=sum(has_nvd_own_cvss3(record) for record in records),
        with_any_cvss=sum(bool(record.cvss) for record in records),
        with_cvss4=sum(any(m.version == "4.0" for m in record.cvss) for record in records),
        with_cwe=sum(bool(record.cwe_ids) for record in records),
        with_exploit_reference=sum(
            any(EXPLOIT_REFERENCE_TAG in reference.tags for reference in record.references)
            for record in records
        ),
        kev_listed=sum(record.kev is not None for record in records),
        with_cnvd=sum(bool(record.cnvd) for record in records),
        with_source_cvss=sum(
            any(not is_nvd_own_metric(metric) for metric in record.cvss) for record in records
        ),
        with_source_affected=sum(bool(record.source_affected) for record in records),
        with_source_affected_versions=sum(
            any(product.versions for block in record.source_affected for product in block.products)
            for record in records
        ),
        with_source_affected_purl=sum(
            any(
                product.package_url is not None
                for block in record.source_affected
                for product in block.products
            )
            for record in records
        ),
        with_ssvc=sum(bool(record.ssvc) for record in records),
        ssvc_exploitation_poc=sum(has_ssvc_exploitation(record, "poc") for record in records),
        ssvc_exploitation_active=sum(has_ssvc_exploitation(record, "active") for record in records),
    )


def measure_store_coverage(
    store_name: str, corpus_content_sha256: str, records: Iterable[CveRecord]
) -> StoreCoverage:
    by_month: dict[str, list[CveRecord]] = {}
    all_records: list[CveRecord] = []
    digests: dict[str, str] = {}
    for record in records:
        by_month.setdefault(publication_month(record), []).append(record)
        all_records.append(record)
        digests[record.cve_id] = semantic_record_sha256(record)
    months = []
    for month in sorted(by_month):
        months.append(count_month(month, by_month[month]))
    return StoreCoverage(
        store_name=store_name,
        corpus_content_sha256=corpus_content_sha256,
        semantic_content_sha256=semantic_content_sha256(digests),
        records=len(all_records),
        months=tuple(months),
        total=count_month("all", all_records),
    )


def diff_store_semantics(
    old_store_name: str,
    old_records: Iterable[CveRecord],
    new_store_name: str,
    new_records: Iterable[CveRecord],
) -> StoreSemanticDiff:
    old_by_id = {}
    old_digests = {}
    for record in old_records:
        old_by_id[record.cve_id] = record
        old_digests[record.cve_id] = semantic_record_sha256(record)
    new_by_id = {}
    new_digests = {}
    for record in new_records:
        new_by_id[record.cve_id] = record
        new_digests[record.cve_id] = semantic_record_sha256(record)
    added = sorted(new_by_id.keys() - old_by_id.keys())
    removed = sorted(old_by_id.keys() - new_by_id.keys())
    changed: list[str] = []
    changed_fields: Counter[str] = Counter()
    metadata_only = 0
    unchanged = 0
    for cve_id in sorted(old_by_id.keys() & new_by_id.keys()):
        old_record = old_by_id[cve_id]
        new_record = new_by_id[cve_id]
        if old_digests[cve_id] != new_digests[cve_id]:
            changed.append(cve_id)
            old_payload = semantic_record_payload(old_record)
            new_payload = semantic_record_payload(new_record)
            for field in sorted(old_payload.keys() | new_payload.keys()):
                if old_payload.get(field) != new_payload.get(field):
                    changed_fields[field] += 1
        elif old_record != new_record:
            metadata_only += 1
        else:
            unchanged += 1
    truncated = any(len(ids) > MAX_LISTED_CHANGES for ids in (added, removed, changed))
    return StoreSemanticDiff(
        old_store_name=old_store_name,
        new_store_name=new_store_name,
        old_semantic_content_sha256=semantic_content_sha256(old_digests),
        new_semantic_content_sha256=semantic_content_sha256(new_digests),
        added=len(added),
        removed=len(removed),
        changed=len(changed),
        metadata_only=metadata_only,
        unchanged=unchanged,
        changed_fields=dict(sorted(changed_fields.items())),
        added_ids=tuple(added[:MAX_LISTED_CHANGES]),
        removed_ids=tuple(removed[:MAX_LISTED_CHANGES]),
        changed_ids=tuple(changed[:MAX_LISTED_CHANGES]),
        lists_truncated=truncated,
    )
