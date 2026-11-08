"""Normalize NVD JSON 1.1 and API 2.0 records into the canonical contract.

The normalizer is pure: callers supply each source's identity, retrieval time and terms,
and no network or filesystem access occurs here. Input is validated at this
boundary. A field present with the wrong JSON type raises
``NvdNormalizationError`` rather than being dropped; an absent field stays absent.
Every error carries a ``NormalizationFailureCode``; its message may quote the entry, so
only the code may be reported to anyone but the developer.

Only CPE matches NVD marks ``vulnerable`` become affected products. The other
matches in a configuration name the platform a vulnerable product runs on, and
NVD states nothing about whether that platform is affected. Matches under a
``negate`` node are a NOT condition and are skipped too.
"""

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any, cast

from pydantic import ValidationError

from vulnwitness.domain.cpe import split_cpe
from vulnwitness.domain.cve import (
    CWE_ID_PATTERN,
    AffectedProduct,
    CveRecord,
    CvssMetric,
    KevEntry,
    LocalizedText,
    Reference,
    VersionRange,
)
from vulnwitness.domain.evidence import UNSEALED_EVIDENCE_ID, EvidenceAnchor, seal_evidence_anchor
from vulnwitness.domain.hashing import canonical_sha256
from vulnwitness.domain.normalization import NormalizationFailureCode
from vulnwitness.domain.taxonomy import (
    AssertionKind,
    KnowledgeScope,
    SourceType,
    TrustLevel,
)

# NVD JSON 1.1 has no status field; rejected entries carry this description prefix.
V1_REJECTED_PREFIX = "** REJECT **"
UNSPECIFIED_CPE_VERSIONS = frozenset({"", "*", "-"})
# CPE logical values ANY and NA; neither names a vendor or product.
CPE_LOGICAL_VALUES = frozenset({"", "*", "-"})
RANSOMWARE_USE = {"known": "known", "unknown": "unknown"}


class NvdNormalizationError(ValueError):
    """An NVD or KEV entry is malformed or lacks the identity the contract needs;
    ``code`` says why."""

    def __init__(self, code: NormalizationFailureCode, message: str) -> None:
        super().__init__(message)
        self.code = code


class RejectedCveError(NvdNormalizationError):
    """The source marks the CVE rejected, so it describes no vulnerability."""

    def __init__(self, cve_id: str) -> None:
        super().__init__(NormalizationFailureCode.REJECTED_BY_SOURCE, f"{cve_id} is rejected")


@dataclass(frozen=True)
class SourceTerms:
    """The terms each source's anchors cite, read from the source registry."""

    nvd: str
    cisa_kev: str


@dataclass(frozen=True)
class SourceSnapshot:
    """Where and when one source document was fetched."""

    source_uri: str
    retrieved_at: datetime
    source_version: str | None = None


@dataclass(frozen=True)
class KevSource:
    """One CISA KEV catalog entry and the catalog snapshot it came from."""

    entry: Mapping[str, Any]
    snapshot: SourceSnapshot


@dataclass(frozen=True)
class NormalizedCve:
    record: CveRecord
    evidence: tuple[EvidenceAnchor, ...]


def _optional_mapping(container: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = container.get(key)
    if value is None:
        return {}
    return _as_mapping(value, key)


def _as_mapping(value: object, what: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise NvdNormalizationError(
            NormalizationFailureCode.WRONG_JSON_TYPE, f"{what} is not a JSON object"
        )
    return cast(Mapping[str, Any], value)


def _optional_list(container: Mapping[str, Any], key: str) -> list[Any]:
    value = container.get(key)
    if value is None:
        return []
    if not isinstance(value, list):
        raise NvdNormalizationError(
            NormalizationFailureCode.WRONG_JSON_TYPE, f"{key} is not a JSON array"
        )
    return value


def _optional_text(container: Mapping[str, Any], key: str) -> str | None:
    value = container.get(key)
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise NvdNormalizationError(
            NormalizationFailureCode.WRONG_JSON_TYPE, f"{key} is not a string"
        )
    return value


def _required_text(container: Mapping[str, Any], key: str) -> str:
    value = _optional_text(container, key)
    if value is None:
        raise NvdNormalizationError(NormalizationFailureCode.MISSING_FIELD, f"{key} is missing")
    return value


def _optional_datetime(container: Mapping[str, Any], key: str) -> datetime | None:
    text = _optional_text(container, key)
    if text is None:
        return None
    try:
        timestamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise NvdNormalizationError(
            NormalizationFailureCode.INVALID_TIMESTAMP, f"{key} is not an ISO 8601 timestamp"
        ) from error
    # NVD API 2.0 timestamps carry no offset and are UTC.
    return timestamp.replace(tzinfo=UTC) if timestamp.tzinfo is None else timestamp


def _optional_date(container: Mapping[str, Any], key: str) -> date | None:
    text = _optional_text(container, key)
    if text is None:
        return None
    try:
        return date.fromisoformat(text)
    except ValueError as error:
        raise NvdNormalizationError(
            NormalizationFailureCode.INVALID_DATE, f"{key} is not an ISO 8601 date"
        ) from error


def _walk_cpe_matches(nodes: Iterable[object]) -> Iterable[Mapping[str, Any]]:
    """Every CPE match in NVD configuration nodes (2.0 ``cpeMatch``, 1.1 ``cpe_match``).

    A ``negate`` node and everything under it is skipped: its matches state what a
    configuration must not contain.
    """
    for node_value in nodes:
        node = _as_mapping(node_value, "configuration node")
        is_negated = node.get("negate", False)
        if not isinstance(is_negated, bool):
            raise NvdNormalizationError(
                NormalizationFailureCode.INVALID_CONFIGURATION,
                "configuration node negate is not a boolean",
            )
        if is_negated:
            continue
        for cpe_match in _optional_list(node, "cpeMatch") + _optional_list(node, "cpe_match"):
            yield _as_mapping(cpe_match, "CPE match")
        yield from _walk_cpe_matches(_optional_list(node, "nodes"))
        yield from _walk_cpe_matches(_optional_list(node, "children"))


def _version_range(cpe_match: Mapping[str, Any], cpe_version: str) -> VersionRange | None:
    start_including = _optional_text(cpe_match, "versionStartIncluding")
    start_excluding = _optional_text(cpe_match, "versionStartExcluding")
    end_including = _optional_text(cpe_match, "versionEndIncluding")
    end_excluding = _optional_text(cpe_match, "versionEndExcluding")
    if start_including or start_excluding or end_including or end_excluding:
        return VersionRange(
            start_including=start_including,
            start_excluding=start_excluding,
            end_including=end_including,
            end_excluding=end_excluding,
        )
    if cpe_version not in UNSPECIFIED_CPE_VERSIONS:
        return VersionRange(exact=cpe_version)
    return None


def _affected_products(nodes: Iterable[object]) -> tuple[AffectedProduct, ...]:
    affected_products: list[AffectedProduct] = []
    known_products: set[AffectedProduct] = set()
    for cpe_match in _walk_cpe_matches(nodes):
        is_vulnerable = cpe_match.get("vulnerable")
        if not isinstance(is_vulnerable, bool):
            raise NvdNormalizationError(
                NormalizationFailureCode.INVALID_CPE, "CPE match lacks a boolean vulnerable flag"
            )
        if not is_vulnerable:
            continue
        cpe = _optional_text(cpe_match, "criteria") or _required_text(cpe_match, "cpe23Uri")
        components = split_cpe(cpe)
        if not cpe.startswith("cpe:2.3:") or len(components) != 11:
            raise NvdNormalizationError(
                NormalizationFailureCode.INVALID_CPE, f"not a CPE 2.3 formatted string: {cpe!r}"
            )
        if components[1] in CPE_LOGICAL_VALUES or components[2] in CPE_LOGICAL_VALUES:
            raise NvdNormalizationError(
                NormalizationFailureCode.INVALID_CPE,
                f"CPE names no concrete vendor and product: {cpe!r}",
            )
        version_range = _version_range(cpe_match, components[3])
        affected_product = AffectedProduct(
            vendor=components[1],
            product=components[2],
            cpe=cpe,
            status="affected",
            version_ranges=(version_range,) if version_range else (),
        )
        if affected_product not in known_products:
            known_products.add(affected_product)
            affected_products.append(affected_product)
    return tuple(affected_products)


def _descriptions(entries: Iterable[object], source: str) -> tuple[LocalizedText, ...]:
    descriptions: list[LocalizedText] = []
    for entry in entries:
        description = _as_mapping(entry, "description")
        language = _optional_text(description, "lang")
        text = _optional_text(description, "value")
        if language and text:
            descriptions.append(LocalizedText(lang=language, value=text, source=source))
    return tuple(descriptions)


def _cwe_ids(weaknesses: Iterable[object]) -> tuple[str, ...]:
    """Exact CWE IDs; NVD placeholders such as ``NVD-CWE-noinfo`` are not CWE IDs."""
    cwe_ids: list[str] = []
    for weakness in weaknesses:
        for entry in _optional_list(_as_mapping(weakness, "weakness"), "description"):
            description = _as_mapping(entry, "weakness description")
            value = (_optional_text(description, "value") or "").upper()
            is_cwe_id = re.fullmatch(CWE_ID_PATTERN, value) is not None
            if is_cwe_id and value not in cwe_ids:
                cwe_ids.append(value)
    return tuple(cwe_ids)


def _references(entries: Iterable[object], source_key: str) -> tuple[Reference, ...]:
    references: list[Reference] = []
    for entry in entries:
        reference = _as_mapping(entry, "reference")
        url = _optional_text(reference, "url")
        if url is None:
            continue
        tags: list[str] = []
        for tag in _optional_list(reference, "tags"):
            if not isinstance(tag, str):
                raise NvdNormalizationError(
                    NormalizationFailureCode.INVALID_REFERENCE, "reference tag is not a string"
                )
            tags.append(tag)
        references.append(
            Reference(url=url, source=_optional_text(reference, source_key), tags=tuple(tags))
        )
    return tuple(references)


def _cvss_metric(
    cvss_data: Mapping[str, Any],
    severity: str | None,
    default_version: str,
    scorer: str,
    scorer_type: str | None,
) -> CvssMetric:
    vector = _required_text(cvss_data, "vectorString")
    base_score = cvss_data.get("baseScore")
    if isinstance(base_score, bool) or not isinstance(base_score, int | float):
        raise NvdNormalizationError(
            NormalizationFailureCode.INVALID_CVSS, "CVSS baseScore is not a number"
        )
    version = _optional_text(cvss_data, "version") or default_version
    # NVD JSON 1.1 files CVSS 3.1 vectors under baseMetricV3 labelled 3.0.
    if vector.startswith("CVSS:3.1/"):
        version = "3.1"
    elif vector.startswith("CVSS:3.0/"):
        version = "3.0"
    normalized_scorer_type = scorer_type.casefold() if scorer_type else None
    return CvssMetric.model_validate(
        {
            "version": version,
            "vector_string": vector,
            "base_score": float(base_score),
            "base_severity": severity.upper() if severity else None,
            "scorer": scorer,
            "scorer_type": normalized_scorer_type,
        }
    )


def _v2_metrics(metrics: Mapping[str, Any]) -> tuple[CvssMetric, ...]:
    cvss_metrics: list[CvssMetric] = []
    for key, default_version in (
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        for entry in _optional_list(metrics, key):
            metric = _as_mapping(entry, key)
            cvss_data = _as_mapping(metric.get("cvssData"), "cvssData")
            cvss_metrics.append(
                _cvss_metric(
                    cvss_data,
                    # CVSS 2.0 entries carry severity beside cvssData, not inside it.
                    _optional_text(cvss_data, "baseSeverity")
                    or _optional_text(metric, "baseSeverity"),
                    default_version,
                    _required_text(metric, "source"),
                    _optional_text(metric, "type"),
                )
            )
    return tuple(cvss_metrics)


def _v1_metrics(impact: Mapping[str, Any]) -> tuple[CvssMetric, ...]:
    """NVD JSON 1.1 metrics are NVD's own; v3 severity sits in cvssV3, v2 severity beside it."""
    cvss_metrics: list[CvssMetric] = []
    base_metric_v3 = _optional_mapping(impact, "baseMetricV3")
    if base_metric_v3:
        cvss_v3 = _as_mapping(base_metric_v3.get("cvssV3"), "cvssV3")
        cvss_metrics.append(
            _cvss_metric(cvss_v3, _optional_text(cvss_v3, "baseSeverity"), "3.0", "NVD", None)
        )
    base_metric_v2 = _optional_mapping(impact, "baseMetricV2")
    if base_metric_v2:
        cvss_v2 = _as_mapping(base_metric_v2.get("cvssV2"), "cvssV2")
        cvss_metrics.append(
            _cvss_metric(cvss_v2, _optional_text(base_metric_v2, "severity"), "2.0", "NVD", None)
        )
    return tuple(cvss_metrics)


def _inline_kev(vulnerability: Mapping[str, Any]) -> KevEntry | None:
    """The KEV listing NVD 2.0 mirrors into ``cisaExploitAdd``/``cisaActionDue``."""
    date_added = _optional_date(vulnerability, "cisaExploitAdd")
    if date_added is None:
        return None
    return KevEntry(date_added=date_added, due_date=_optional_date(vulnerability, "cisaActionDue"))


def _anchor(
    source_type: SourceType,
    cve_id: str,
    snapshot: SourceSnapshot,
    content_sha256: str,
    locator: str,
    terms: str,
    trust_level: TrustLevel,
) -> EvidenceAnchor:
    source_name = source_type.value
    unsealed_anchor = EvidenceAnchor(
        evidence_id=UNSEALED_EVIDENCE_ID,
        source_name=source_name,
        source_type=source_type,
        authoritative_record_id=cve_id,
        source_uri=snapshot.source_uri,
        source_version=snapshot.source_version,
        retrieved_at=snapshot.retrieved_at,
        content_sha256=content_sha256,
        locator=locator,
        scope=KnowledgeScope.IMPLEMENTATION_VULNERABILITY,
        assertion_kind=AssertionKind.ASSERTED,
        license_or_terms_ref=terms,
        trust_level=trust_level,
    )
    return seal_evidence_anchor(unsealed_anchor)


def _kev_entry(cve_id: str, kev: KevSource, terms: str) -> tuple[KevEntry, EvidenceAnchor]:
    kev_id = _optional_text(kev.entry, "cveID")
    if kev_id != cve_id:
        raise NvdNormalizationError(
            NormalizationFailureCode.INVALID_KEV_ENTRY,
            f"KEV entry {kev_id!r} does not match {cve_id}",
        )
    date_added = _optional_date(kev.entry, "dateAdded")
    if date_added is None:
        raise NvdNormalizationError(
            NormalizationFailureCode.INVALID_KEV_ENTRY, "KEV entry needs dateAdded"
        )
    ransomware_text = _optional_text(kev.entry, "knownRansomwareCampaignUse")
    ransomware_use: str | None = None
    if ransomware_text is not None:
        ransomware_use = RANSOMWARE_USE.get(ransomware_text.casefold())
        if ransomware_use is None:
            raise NvdNormalizationError(
                NormalizationFailureCode.INVALID_KEV_ENTRY,
                "knownRansomwareCampaignUse is neither Known nor Unknown",
            )
    kev_entry = KevEntry.model_validate(
        {
            "date_added": date_added,
            "due_date": _optional_date(kev.entry, "dueDate"),
            "known_ransomware_campaign_use": ransomware_use,
        }
    )
    anchor = _anchor(
        SourceType.CISA_KEV,
        cve_id,
        kev.snapshot,
        canonical_sha256(kev.entry),
        f"vulnerabilities/{cve_id}",
        terms,
        TrustLevel.AUTHORITATIVE,
    )
    return kev_entry, anchor


def _assemble(
    cve_id: str,
    record_fields: dict[str, object],
    nvd_anchor: EvidenceAnchor,
    kev: KevSource | None,
    kev_terms: str,
) -> NormalizedCve:
    """Attach evidence; an explicit KEV catalog entry supersedes NVD's mirrored listing."""
    if not record_fields["descriptions"]:
        raise NvdNormalizationError(
            NormalizationFailureCode.NO_DESCRIPTION, f"{cve_id} has no description"
        )
    anchors = [nvd_anchor]
    if kev is not None:
        kev_entry, kev_anchor = _kev_entry(cve_id, kev, kev_terms)
        record_fields["kev"] = kev_entry
        anchors.append(kev_anchor)
    evidence_ids: list[str] = []
    for anchor in anchors:
        evidence_ids.append(anchor.evidence_id)
    record = CveRecord.model_validate(
        {**record_fields, "cve_id": cve_id, "evidence_ids": evidence_ids}
    )
    return NormalizedCve(record, tuple(anchors))


class NvdNormalizer:
    """Every malformed entry raises ``NvdNormalizationError``, including values the
    canonical models reject, so a batch import can skip one entry and continue. Each
    anchor cites ``terms``, which composition reads from the source registry."""

    def __init__(self, terms: SourceTerms) -> None:
        self._terms = terms

    def normalize_v2(
        self,
        vulnerability: Mapping[str, Any],
        snapshot: SourceSnapshot,
        kev: KevSource | None = None,
    ) -> NormalizedCve:
        """Normalize one ``vulnerabilities[].cve`` object of the NVD CVE API 2.0.

        Raises ``RejectedCveError`` when ``vulnStatus`` is ``Rejected``.
        """
        try:
            return self._normalize_v2(vulnerability, snapshot, kev)
        except ValidationError as error:
            raise NvdNormalizationError(
                NormalizationFailureCode.CONTRACT_VIOLATION,
                f"NVD 2.0 entry breaks the contract: {error}",
            ) from error

    def normalize_v1(
        self,
        cve_item: Mapping[str, Any],
        snapshot: SourceSnapshot,
        kev: KevSource | None = None,
    ) -> NormalizedCve:
        """Normalize one ``CVE_Items[]`` entry of an NVD JSON 1.1 feed.

        Raises ``RejectedCveError`` when a description starts with ``** REJECT **``.
        """
        try:
            return self._normalize_v1(cve_item, snapshot, kev)
        except ValidationError as error:
            raise NvdNormalizationError(
                NormalizationFailureCode.CONTRACT_VIOLATION,
                f"NVD 1.1 entry breaks the contract: {error}",
            ) from error

    def _normalize_v2(
        self,
        vulnerability: Mapping[str, Any],
        snapshot: SourceSnapshot,
        kev: KevSource | None,
    ) -> NormalizedCve:
        cve_id = _required_text(vulnerability, "id")
        if _optional_text(vulnerability, "vulnStatus") == "Rejected":
            raise RejectedCveError(cve_id)
        nvd_anchor = _anchor(
            SourceType.NVD_API_2,
            cve_id,
            snapshot,
            canonical_sha256(vulnerability),
            f"vulnerabilities/{cve_id}",
            self._terms.nvd,
            TrustLevel.SECONDARY,
        )
        # Descriptions come from the CNA named in sourceIdentifier.
        description_source = _optional_text(vulnerability, "sourceIdentifier") or "NVD"
        record_fields: dict[str, object] = {
            "descriptions": _descriptions(
                _optional_list(vulnerability, "descriptions"), description_source
            ),
            "published": _optional_datetime(vulnerability, "published"),
            "last_modified": _optional_datetime(vulnerability, "lastModified"),
            "cvss": _v2_metrics(_optional_mapping(vulnerability, "metrics")),
            "cwe_ids": _cwe_ids(_optional_list(vulnerability, "weaknesses")),
            # A 2.0 configuration has the node shape (negate, nodes), so it is walked as one.
            "affected": _affected_products(_optional_list(vulnerability, "configurations")),
            "references": _references(_optional_list(vulnerability, "references"), "source"),
            "kev": _inline_kev(vulnerability),
            "nvd_status": vulnerability.get("vulnStatus"),
        }
        return _assemble(cve_id, record_fields, nvd_anchor, kev, self._terms.cisa_kev)

    def _normalize_v1(
        self,
        cve_item: Mapping[str, Any],
        snapshot: SourceSnapshot,
        kev: KevSource | None,
    ) -> NormalizedCve:
        cve = _optional_mapping(cve_item, "cve")
        metadata = _optional_mapping(cve, "CVE_data_meta")
        cve_id = _required_text(metadata, "ID")
        description_source = _optional_text(metadata, "ASSIGNER") or "NVD"
        descriptions = _descriptions(
            _optional_list(_optional_mapping(cve, "description"), "description_data"),
            description_source,
        )
        if any(description.value.startswith(V1_REJECTED_PREFIX) for description in descriptions):
            raise RejectedCveError(cve_id)
        nvd_anchor = _anchor(
            SourceType.NVD_JSON_11,
            cve_id,
            snapshot,
            canonical_sha256(cve_item),
            f"CVE_Items/{cve_id}",
            self._terms.nvd,
            TrustLevel.SECONDARY,
        )
        problem_types = _optional_list(_optional_mapping(cve, "problemtype"), "problemtype_data")
        references = _optional_list(_optional_mapping(cve, "references"), "reference_data")
        configurations = _optional_mapping(cve_item, "configurations")
        record_fields: dict[str, object] = {
            "descriptions": descriptions,
            "published": _optional_datetime(cve_item, "publishedDate"),
            "last_modified": _optional_datetime(cve_item, "lastModifiedDate"),
            "cvss": _v1_metrics(_optional_mapping(cve_item, "impact")),
            "cwe_ids": _cwe_ids(problem_types),
            "affected": _affected_products(_optional_list(configurations, "nodes")),
            "references": _references(references, "refsource"),
            "kev": None,
        }
        return _assemble(cve_id, record_fields, nvd_anchor, kev, self._terms.cisa_kev)
