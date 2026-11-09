"""Canonical CVE record.

Structured values stay structured: every CVSS metric is kept with its version and
scorer, affected products keep vendor, product, identifiers and version ranges.
A field no source supplied is left empty — never filled with a guess.
"""

from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, JsonValue, model_validator
from pydantic.config import JsonDict

from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.evidence import EvidenceId
from vulnwitness.domain.taxonomy import VulnerabilityOrigin
from vulnwitness.domain.timestamps import CalendarDate, Timestamp

# [0-9], not \d: Python and pydantic read \d as any Unicode digit, JSON Schema as ASCII.
CVE_ID_PATTERN = r"^CVE-[0-9]{4}-[0-9]{4,}$"
CNVD_ID_PATTERN = r"^CNVD-[0-9]{4}-[0-9]{4,6}$"
CWE_ID_PATTERN = r"^CWE-[0-9]+$"
PURL_PATTERN = r"^pkg:"

# The CVE and CWE programs assign numbers far shorter than these bounds.
MAX_CVE_ID_CHARS = 32
MAX_CWE_ID_CHARS = 16

CveId = Annotated[str, Field(pattern=CVE_ID_PATTERN, max_length=MAX_CVE_ID_CHARS)]
CweId = Annotated[str, Field(pattern=CWE_ID_PATTERN, max_length=MAX_CWE_ID_CHARS)]
Severity = Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def purl_package_identity(purl: str) -> str:
    """The package a purl names, without version, qualifiers or subpath, case-folded.

    Per the purl spec an ``@`` inside the namespace or name is percent-encoded, so
    the last ``@`` after the last ``/`` starts the version.
    """
    identity = purl.split("#", 1)[0].split("?", 1)[0]
    version_separator_index = identity.rfind("@")
    if version_separator_index > identity.rfind("/"):
        identity = identity[:version_separator_index]
    return identity.casefold()


class LocalizedText(ContractModel):
    lang: str = Field(pattern=r"^[a-z]{2,3}(-[A-Za-z0-9]+)*$")
    value: str = Field(min_length=1, max_length=8000)
    source: str = Field(min_length=1, description="Who authored this text, e.g. a CNA.")


class CvssMetric(ContractModel):
    version: Literal["2.0", "3.0", "3.1", "4.0"]
    vector_string: str = Field(min_length=1)
    base_score: float = Field(ge=0.0, le=10.0)
    base_severity: Severity | None = None
    scorer: str = Field(min_length=1, description="Organization that produced this score.")
    scorer_type: Literal["primary", "secondary"] | None = None


VERSION_BOUNDS = ("start_including", "start_excluding", "end_including", "end_excluding")


def describe_version_range_shape() -> JsonDict:
    """``VersionRange.check_bounds`` as JSON Schema: an exact version and no bound, or no
    exact version and at least one bound."""
    exact_only_properties: JsonDict = {"exact": {"type": "string"}}
    one_bound_set: list[JsonValue] = []
    for bound in VERSION_BOUNDS:
        exact_only_properties[bound] = {"type": "null"}
        one_bound_set.append({"required": [bound], "properties": {bound: {"type": "string"}}})
    return {
        "oneOf": [
            {"required": ["exact"], "properties": exact_only_properties},
            {"properties": {"exact": {"type": "null"}}, "anyOf": one_bound_set},
        ]
    }


class VersionRange(ContractModel):
    """One affected version or bounded range; at least one bound or ``exact`` is set."""

    model_config = ConfigDict(json_schema_extra=describe_version_range_shape())

    exact: str | None = None
    start_including: str | None = None
    start_excluding: str | None = None
    end_including: str | None = None
    end_excluding: str | None = None

    @model_validator(mode="after")
    def check_bounds(self) -> Self:
        has_bound = any(getattr(self, bound) is not None for bound in VERSION_BOUNDS)
        if self.exact is None and not has_bound:
            raise ValueError("a version range needs an exact version or at least one bound")
        if self.exact is not None and has_bound:
            raise ValueError("an exact version cannot also carry range bounds")
        return self


class AffectedProduct(ContractModel):
    vendor: str = Field(min_length=1)
    product: str = Field(min_length=1)
    cpe: str | None = Field(default=None, pattern=r"^cpe:2\.3:")
    purl: str | None = Field(default=None, pattern=PURL_PATTERN)
    status: Literal["affected", "unaffected", "unknown"]
    version_ranges: tuple[VersionRange, ...] = ()


class Reference(ContractModel):
    url: str = Field(min_length=1, max_length=2048)
    source: str | None = None
    tags: tuple[str, ...] = ()


class KevEntry(ContractModel):
    date_added: CalendarDate
    due_date: CalendarDate | None = None
    known_ransomware_campaign_use: Literal["known", "unknown"] | None = Field(
        default=None,
        description=(
            "CISA's own Known/Unknown assessment; null when the consulted source does not carry it."
        ),
    )


class CnvdEntry(ContractModel):
    cnvd_id: str = Field(pattern=CNVD_ID_PATTERN)
    title: str = Field(min_length=1, description="CNVD's Chinese title; untrusted source text.")
    description: str = Field(
        min_length=1, description="CNVD's Chinese description; untrusted source text."
    )
    severity: Literal["high", "medium", "low"] = Field(
        description="CNVD's severity: high for 高, medium for 中, low for 低."
    )
    products: tuple[str, ...] = Field(
        default=(), description="CNVD's verbatim product text; untrusted source text."
    )
    submit_time: CalendarDate | None = Field(
        default=None, description="CNVD's submitTime calendar date, as given."
    )
    open_time: CalendarDate | None = Field(
        default=None, description="CNVD's openTime calendar date, as given; not a publication date."
    )
    handling_advice: str | None = Field(
        default=None, description="CNVD's formalWay; verbatim, untrusted source text."
    )
    evidence_id: EvidenceId


class CveRecord(ContractModel):
    """An implementation-level vulnerability record.

    ``protocol_design_claim`` and ``formal_seed_eligible`` are fixed: a CVE never
    establishes a protocol-design vulnerability and never seeds formal analysis.
    """

    record_kind: Literal["cve"] = "cve"
    cve_id: CveId
    descriptions: tuple[LocalizedText, ...] = Field(min_length=1)
    published: Timestamp | None = None
    last_modified: Timestamp | None = None
    cvss: tuple[CvssMetric, ...] = ()
    cwe_ids: tuple[CweId, ...] = ()
    affected: tuple[AffectedProduct, ...] = ()
    references: tuple[Reference, ...] = ()
    kev: KevEntry | None = Field(
        default=None, description="CISA KEV entry, when a consulted source lists one."
    )
    nvd_status: str | None = Field(
        default=None,
        description="NVD 2.0 vulnStatus verbatim, untrusted source text; "
        "null for NVD 1.1 and synthetic data.",
    )
    cnvd: tuple[CnvdEntry, ...] = Field(
        default=(), description="CNVD entries ordered by CNVD ID; Chinese text is untrusted data."
    )
    vulnerability_origin: VulnerabilityOrigin = VulnerabilityOrigin.UNKNOWN
    protocol_design_claim: Literal["not_established"] = "not_established"
    formal_seed_eligible: Literal[False] = False
    evidence_ids: tuple[EvidenceId, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def check_cnvd_order(self) -> Self:
        previous_cnvd_id = ""
        for entry in self.cnvd:
            if entry.cnvd_id <= previous_cnvd_id:
                raise ValueError("CNVD entries must be in strict CNVD ID order")
            previous_cnvd_id = entry.cnvd_id
        return self

    def list_implicated_products(self) -> tuple[AffectedProduct, ...]:
        """Products a source lists as affected or of unknown status, never ``unaffected`` ones."""
        implicated_products: list[AffectedProduct] = []
        for affected_product in self.affected:
            if affected_product.status != "unaffected":
                implicated_products.append(affected_product)
        return tuple(implicated_products)

    def find_missing_fields(self) -> tuple[str, ...]:
        """Names of the fields no source supplied; consumers must read them as unknown."""
        missing: list[str] = []
        if not self.cvss:
            missing.append("cvss")
        if not self.cwe_ids:
            missing.append("cwe_ids")
        if not self.affected:
            missing.append("affected")
        if self.published is None:
            missing.append("published")
        return tuple(missing)
