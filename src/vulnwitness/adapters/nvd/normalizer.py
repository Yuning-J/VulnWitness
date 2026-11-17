"""Normalize NVD JSON 1.1 and API 2.0 records into the canonical contract.

The normalizer is pure: callers supply each source's identity, retrieval time and terms,
and no network or filesystem access occurs here. Input is validated at this
boundary. A field present with the wrong JSON type raises
``NvdNormalizationError`` rather than being dropped; an absent field stays absent.
Every error carries a ``NormalizationFailureCode``; its message may quote the entry, so
only the code may be reported to anyone but the developer.

Only CPE matches NVD marks ``vulnerable`` and that name a vendor and product become
affected products. The other matches in a configuration name the platform a vulnerable
product runs on, and NVD states nothing about whether that platform is affected. Matches
under a ``negate`` node are a NOT condition and are skipped too. For NVD 2.0, every
configuration that says more than those products (AND, negation, platforms, unnamed CPEs)
is also kept verbatim under ``configurations``; nothing evaluates it.
"""

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any, cast

from pydantic import ValidationError

from vulnwitness.domain.cpe import cpe_product_identity, split_cpe
from vulnwitness.domain.cve import (
    CWE_ID_PATTERN,
    MAX_CONFIGURATION_MATCHES,
    MAX_CONFIGURATION_NODES,
    MAX_CONFIGURATIONS,
    MAX_NOTED_PLATFORMS,
    MAX_SOURCE_AFFECTED_NAMES,
    MAX_SOURCE_AFFECTED_PRODUCTS,
    MAX_SOURCE_AFFECTED_VERSIONS,
    AffectedProduct,
    CveRecord,
    CveTag,
    CvssMetric,
    KevEntry,
    LocalizedText,
    PlatformCondition,
    Reference,
    SourceAffected,
    SsvcAssessment,
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


def _affected_products(
    nodes: Iterable[object], *, keeps_configurations: bool
) -> tuple[AffectedProduct, ...]:
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
        identity = cpe_product_identity(cpe)
        if identity is None:
            if keeps_configurations:
                # NVD 2.0 retains unnamed matches under configurations.
                continue
            raise NvdNormalizationError(
                NormalizationFailureCode.INVALID_CPE,
                "NVD 1.1 cannot retain a vulnerable CPE without a vendor and product",
            )
        vendor, product = identity
        version_range = _version_range(cpe_match, components[3])
        affected_product = AffectedProduct(
            vendor=vendor,
            product=product,
            cpe=cpe,
            status="affected",
            version_ranges=(version_range,) if version_range else (),
        )
        if affected_product not in known_products:
            known_products.add(affected_product)
            affected_products.append(affected_product)
    return tuple(affected_products)


def _negate(node: Mapping[str, Any]) -> bool:
    negate = node.get("negate", False)
    if not isinstance(negate, bool):
        raise NvdNormalizationError(
            NormalizationFailureCode.INVALID_CONFIGURATION,
            "configuration node negate is not a boolean",
        )
    return negate


def _operator(node: Mapping[str, Any], default: str) -> str:
    operator = node.get("operator", default)
    if operator not in ("AND", "OR"):
        raise NvdNormalizationError(
            NormalizationFailureCode.INVALID_CONFIGURATION,
            "configuration operator is not AND or OR",
        )
    return cast(str, operator)


def _configuration_node(node: Mapping[str, Any]) -> tuple[dict[str, object], bool]:
    """A stored node and whether it holds anything ``affected`` lacks."""
    matches: list[dict[str, object]] = []
    omitted = 0
    negate = _negate(node)
    operator = _operator(node, "OR")
    match_entries = _optional_list(node, "cpeMatch")
    says_more = negate or (operator == "AND" and len(match_entries) > 1)
    for value in match_entries:
        cpe_match = _as_mapping(value, "CPE match")
        is_vulnerable = cpe_match.get("vulnerable")
        cpe = _optional_text(cpe_match, "criteria")
        if not isinstance(is_vulnerable, bool) or cpe is None or not cpe.startswith("cpe:2.3:"):
            raise NvdNormalizationError(
                NormalizationFailureCode.INVALID_CPE, "CPE match lacks a criteria or flag"
            )
        says_more = says_more or not is_vulnerable or cpe_product_identity(cpe) is None
        if len(matches) == MAX_CONFIGURATION_MATCHES:
            omitted += 1
            continue
        components = split_cpe(cpe)
        version = components[3] if len(components) == 11 else ""
        matches.append(
            {
                "cpe": cpe,
                "vulnerable": is_vulnerable,
                "version_range": _version_range(cpe_match, version),
            }
        )
    stored: dict[str, object] = {
        "operator": operator,
        "negate": negate,
        "matches": matches,
        "omitted_matches": omitted,
    }
    return stored, says_more


def _configurations(entries: Iterable[object]) -> dict[str, object]:
    """NVD 2.0 configurations that say more than ``affected``, capped and counted. A plain
    OR of vulnerable, named CPEs is already ``affected`` and is not repeated here."""
    kept: list[dict[str, object]] = []
    omitted = 0
    for entry in entries:
        configuration = _as_mapping(entry, "configuration")
        operator = _operator(configuration, "OR")
        negate = _negate(configuration)
        says_more = operator == "AND" or negate
        nodes: list[dict[str, object]] = []
        node_entries = _optional_list(configuration, "nodes")
        for value in node_entries:
            node, node_says_more = _configuration_node(_as_mapping(value, "configuration node"))
            says_more = says_more or node_says_more
            nodes.append(node)
        if not says_more or not nodes:
            continue
        if len(kept) == MAX_CONFIGURATIONS:
            omitted += 1
            continue
        kept.append(
            {
                "operator": operator,
                "negate": negate,
                "nodes": nodes[:MAX_CONFIGURATION_NODES],
                "omitted_nodes": max(0, len(nodes) - MAX_CONFIGURATION_NODES),
            }
        )
    return {"configurations": kept, "omitted_configurations": omitted}


def _platform_match_groups(
    configuration: Mapping[str, Any],
) -> Iterable[list[Mapping[str, Any]]]:
    """Positive matches joined by an AND, or individual alternatives under an OR."""
    if _negate(configuration):
        return
    if _operator(configuration, "OR") == "AND":
        yield list(_walk_cpe_matches([configuration]))
        return
    for value in _optional_list(configuration, "nodes"):
        node = _as_mapping(value, "configuration node")
        if _negate(node):
            continue
        matches = list(_walk_cpe_matches([node]))
        if _operator(node, "OR") == "AND":
            yield matches
        else:
            for match in matches:
                yield [match]


def _platform_conditions(entries: Iterable[object]) -> tuple[PlatformCondition, ...]:
    """Summarize all CPE/range pairings before configuration, node and match caps."""
    platforms_by_condition: dict[tuple[str, VersionRange | None], dict[str, None]] = {}
    platform_free_conditions: set[tuple[str, VersionRange | None]] = set()
    for entry in entries:
        configuration = _as_mapping(entry, "configuration")
        for matches in _platform_match_groups(configuration):
            platforms: dict[str, None] = {}
            for match in matches:
                if not match["vulnerable"]:
                    platforms[_required_text(match, "criteria")] = None
            for match in matches:
                if not match["vulnerable"]:
                    continue
                cpe = _required_text(match, "criteria")
                version_range = _version_range(match, split_cpe(cpe)[3])
                condition_key = (cpe, version_range)
                if not platforms:
                    platform_free_conditions.add(condition_key)
                platforms_by_condition.setdefault(condition_key, {}).update(platforms)
    conditions: list[PlatformCondition] = []
    for (cpe, version_range), platforms in platforms_by_condition.items():
        if platforms:
            conditions.append(
                PlatformCondition(
                    cpe=cpe,
                    version_range=version_range,
                    platforms=tuple(platforms)[:MAX_NOTED_PLATFORMS],
                    omitted_platforms=max(0, len(platforms) - MAX_NOTED_PLATFORMS),
                    has_platform_free_match=(cpe, version_range) in platform_free_conditions,
                )
            )
    return tuple(conditions)


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


def _text_list(container: Mapping[str, Any], key: str) -> tuple[str, ...]:
    """A list of strings; empty strings are dropped and at most the stored cap is kept."""
    values: list[str] = []
    for value in _optional_list(container, key):
        if not isinstance(value, str):
            raise NvdNormalizationError(
                NormalizationFailureCode.WRONG_JSON_TYPE, f"{key} item is not a string"
            )
        if value and value not in values:
            values.append(value)
    return tuple(values[:MAX_SOURCE_AFFECTED_NAMES])


def _status(container: Mapping[str, Any], key: str) -> str | None:
    """A CVE-format product status; the format allows only these three."""
    text = _optional_text(container, key)
    if text is None:
        return None
    status = text.casefold()
    if status not in ("affected", "unaffected", "unknown"):
        raise NvdNormalizationError(
            NormalizationFailureCode.WRONG_JSON_TYPE, f"{key} is not a CVE affected status"
        )
    return status


def _required_status(version: Mapping[str, Any]) -> str:
    status = _status(version, "status")
    if status is None:
        raise NvdNormalizationError(NormalizationFailureCode.MISSING_FIELD, "status is missing")
    return status


def _source_affected(entries: Iterable[object]) -> tuple[SourceAffected, ...]:
    """NVD 2.0 ``affected[]``: each CNA or ADP block of ``affectedData`` products, capped,
    with the products and versions beyond the caps counted. ``changes``, ``programFiles``
    and ``programRoutines`` are not kept."""
    blocks: list[SourceAffected] = []
    for entry in entries:
        block = _as_mapping(entry, "affected")
        products: list[dict[str, object]] = []
        affected_data = _optional_list(block, "affectedData")
        for item in affected_data[:MAX_SOURCE_AFFECTED_PRODUCTS]:
            product = _as_mapping(item, "affectedData")
            versions: list[dict[str, object]] = []
            version_entries = _optional_list(product, "versions")
            for version_item in version_entries[:MAX_SOURCE_AFFECTED_VERSIONS]:
                version = _as_mapping(version_item, "versions")
                versions.append(
                    {
                        "version": _required_text(version, "version"),
                        "status": _required_status(version),
                        "version_type": _optional_text(version, "versionType"),
                        "less_than": _optional_text(version, "lessThan"),
                        "less_than_or_equal": _optional_text(version, "lessThanOrEqual"),
                    }
                )
            products.append(
                {
                    "vendor": _optional_text(product, "vendor"),
                    "product": _optional_text(product, "product"),
                    "package_name": _optional_text(product, "packageName"),
                    "collection_url": _optional_text(product, "collectionURL"),
                    "repo": _optional_text(product, "repo"),
                    "package_url": _optional_text(product, "packageURL"),
                    "cpes": _text_list(product, "cpes"),
                    "modules": _text_list(product, "modules"),
                    "platforms": _text_list(product, "platforms"),
                    "default_status": _status(product, "defaultStatus"),
                    "versions": versions,
                    "omitted_versions": max(0, len(version_entries) - len(versions)),
                }
            )
        blocks.append(
            SourceAffected.model_validate(
                {
                    "source": _required_text(block, "source"),
                    "products": products,
                    "omitted_products": max(0, len(affected_data) - len(products)),
                }
            )
        )
    return tuple(blocks)


SSVC_DECISION_POINTS = {
    "exploitation": "exploitation",
    "automatable": "automatable",
    "technicalimpact": "technical_impact",
}


def _ssvc(metrics: Mapping[str, Any]) -> tuple[SsvcAssessment, ...]:
    """NVD 2.0 ``metrics.ssvcV203``; decision points other than the three SSVC names CISA
    scores are not kept, and a repeated point is a malformed entry."""
    assessments: list[SsvcAssessment] = []
    for entry in _optional_list(metrics, "ssvcV203"):
        metric = _as_mapping(entry, "ssvcV203")
        data = _optional_mapping(metric, "ssvcData")
        points: dict[str, str] = {}
        for option in _optional_list(data, "options"):
            for name, value in _as_mapping(option, "options").items():
                field = SSVC_DECISION_POINTS.get(str(name).casefold())
                if field is None:
                    continue
                if not isinstance(value, str) or field in points:
                    raise NvdNormalizationError(
                        NormalizationFailureCode.WRONG_JSON_TYPE, f"SSVC {name} is malformed"
                    )
                points[field] = value.casefold()
        assessments.append(
            SsvcAssessment.model_validate(
                {
                    "source": _required_text(metric, "source"),
                    "role": _optional_text(data, "role"),
                    "version": _optional_text(data, "version"),
                    "assessed_at": _optional_datetime(data, "timestamp"),
                    "decision_points": points,
                }
            )
        )
    return tuple(assessments)


def _cve_tags(entries: Iterable[object]) -> tuple[CveTag, ...]:
    tags: list[CveTag] = []
    for entry in entries:
        tag = _as_mapping(entry, "cveTags")
        values = _text_list(tag, "tags")
        if values:
            tags.append(
                CveTag(source=_optional_text(tag, "sourceIdentifier") or "unknown", tags=values)
            )
    return tuple(tags)


def _kev_cwe_ids(text: str | None) -> tuple[str, ...]:
    """CISA's ``cwes`` column: comma-separated CWE IDs; anything else is not kept."""
    cwe_ids: list[str] = []
    for part in (text or "").split(","):
        value = part.strip().upper()
        if re.fullmatch(CWE_ID_PATTERN, value) is not None and value not in cwe_ids:
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
    return KevEntry(
        date_added=date_added,
        due_date=_optional_date(vulnerability, "cisaActionDue"),
        vulnerability_name=_optional_text(vulnerability, "cisaVulnerabilityName"),
        required_action=_optional_text(vulnerability, "cisaRequiredAction"),
    )


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
            "vulnerability_name": _optional_text(kev.entry, "vulnerabilityName"),
            "required_action": _optional_text(kev.entry, "requiredAction"),
            "notes": _optional_text(kev.entry, "notes"),
            "cwe_ids": _kev_cwe_ids(_optional_text(kev.entry, "cwes")),
            "forensic_triage": (_optional_text(kev.entry, "forensicTriage") or "").casefold()
            or None,
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
            "affected": _affected_products(
                _optional_list(vulnerability, "configurations"), keeps_configurations=True
            ),
            "references": _references(_optional_list(vulnerability, "references"), "source"),
            "kev": _inline_kev(vulnerability),
            "nvd_status": vulnerability.get("vulnStatus"),
            "source_affected": _source_affected(_optional_list(vulnerability, "affected")),
            "ssvc": _ssvc(_optional_mapping(vulnerability, "metrics")),
            "cve_tags": _cve_tags(_optional_list(vulnerability, "cveTags")),
            **_configurations(_optional_list(vulnerability, "configurations")),
            "platform_conditions": _platform_conditions(
                _optional_list(vulnerability, "configurations")
            ),
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
            "affected": _affected_products(
                _optional_list(configurations, "nodes"), keeps_configurations=False
            ),
            "references": _references(references, "refsource"),
            "kev": None,
        }
        return _assemble(cve_id, record_fields, nvd_anchor, kev, self._terms.cisa_kev)
