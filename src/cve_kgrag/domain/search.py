"""Search request/response contracts and the ranked-match type retrievers return."""

from collections.abc import Hashable
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    BeforeValidator,
    ConfigDict,
    Field,
    JsonValue,
    StrictBool,
    field_validator,
    model_validator,
)
from pydantic.config import JsonDict

from cve_kgrag.domain.contract_model import ContractModel
from cve_kgrag.domain.cve import CveId, CveRecord, CweId, Severity
from cve_kgrag.domain.evidence import SHA256_PATTERN, EvidenceAnchor
from cve_kgrag.domain.hashing import canonical_sha256
from cve_kgrag.domain.taxonomy import (
    BackendFailure,
    BackendFailureDetail,
    BackendStatus,
    KnowledgeScope,
    ResultStatus,
    RetrievalChannel,
    VulnerabilityOrigin,
)

# v2 is pre-release until the M7 review freezes it; every bump is a reviewed
# change to the committed snapshots under schemas/v2/.
SCHEMA_VERSION = "2.0.0-dev.26"
# The matched term a structured match names for the KEV filter.
KEV_MATCH_TERM = "listed"
MAX_QUERY_CHARS = 512
MAX_RESULTS_PER_CALL = 20
MAX_FILTER_VALUES = 20
MAX_DETAIL_CHARS = 500
# What a caller's text may not hold, because a reader cannot see it: a control character,
# or a bidirectional override or isolate, which reorders how the text around it displays.
HIDDEN_REQUEST_CHARACTERS = r"\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069"
# The same, less the tab, line feed and carriage return a query pasted from a document
# holds: normalization folds them into spaces like any other whitespace.
HIDDEN_QUERY_CHARACTERS = r"\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u202a-\u202e\u2066-\u2069"


def require_json_number(value: object) -> object:
    """Reject strings and booleans, which lax integer parsing would coerce."""
    if isinstance(value, bool | str):
        raise ValueError("expected a JSON number")
    return value


def require_served_schema_version(schema_version: str) -> str:
    if schema_version != SCHEMA_VERSION:
        raise ValueError(f"schema_version must be {SCHEMA_VERSION}, the version this code serves")
    return schema_version


# The version a response is in: the published schema pins it with ``const`` and parsing
# rejects any other, so a payload of another version is refused by both alike.
SchemaVersion = Annotated[
    str,
    AfterValidator(require_served_schema_version),
    Field(json_schema_extra={"const": SCHEMA_VERSION}),
]

# JSON Schema's "integer": any number with no fractional part, so 5.0 is accepted.
JsonInteger = Annotated[int, BeforeValidator(require_json_number)]

# Every constraint on a request value lives in its field type, using strict
# scalars and patterns that ECMA-262 and pydantic read alike, so the published
# request schema accepts exactly the requests this model accepts.
# A query may be whitespace only: it is answered ``no_match`` with ``no_searchable_terms``.
QueryText = Annotated[
    str,
    Field(
        min_length=1,
        max_length=MAX_QUERY_CHARS,
        pattern=rf"^[^{HIDDEN_QUERY_CHARACTERS}]*$",
    ),
]
FilterName = Annotated[
    str,
    Field(
        min_length=1,
        max_length=128,
        pattern=(
            rf"^[^{HIDDEN_REQUEST_CHARACTERS}]*"
            rf"[^\s{HIDDEN_REQUEST_CHARACTERS}][^{HIDDEN_REQUEST_CHARACTERS}]*$"
        ),
    ),
]
# One namespace or name segment of a package URL: it holds a character other than ".", so
# no segment is empty, "." or "..". A raw "@", "?" or "#" would start a version, qualifiers
# or subpath; inside a name the purl spec requires them percent-encoded.
PACKAGE_URL_SEGMENT = r"[A-Za-z0-9._~%-]*[A-Za-z0-9_~%-][A-Za-z0-9._~%-]*"
# A package URL without version, qualifiers or subpath: a type and its segments, from the
# versioned purl's character set. The type may be in any case: purl filters match
# case-insensitively.
UnversionedPackageUrl = Annotated[
    str,
    Field(pattern=rf"^pkg:[A-Za-z][A-Za-z0-9.+-]*(?:/{PACKAGE_URL_SEGMENT})+$", max_length=512),
]
# A package URL that names one version: a lower-case type, its segments and a version, from
# a character set without whitespace, control characters, qualifiers ("?") or a subpath ("#").
VersionedPackageUrl = Annotated[
    str,
    Field(
        pattern=rf"^pkg:[a-z][a-z0-9.+-]*(?:/{PACKAGE_URL_SEGMENT})+@[A-Za-z0-9._~%+:-]+$",
        max_length=512,
    ),
]
UNIQUE_ITEMS: dict[str, JsonValue] = {"uniqueItems": True}
# Bounds precede the validator: after it, pydantic emits them as non-standard ge/le keys.
PublishedYear = Annotated[int, Field(ge=1999, le=9999), BeforeValidator(require_json_number)]


class SearchFilters(ContractModel):
    """Structured constraints. Values within one field are ORed; fields are ANDed.

    Filters only constrain. A record that satisfies them still needs an exact-ID,
    lexical or semantic match, or a graph relation to one, to become a candidate.
    Values are kept exactly as sent. CWE IDs and severities are accepted only in
    canonical upper case; vendors, products and purls match case-insensitively.
    """

    vendors: tuple[FilterName, ...] = Field(
        default=(), max_length=MAX_FILTER_VALUES, json_schema_extra=UNIQUE_ITEMS
    )
    products: tuple[FilterName, ...] = Field(
        default=(), max_length=MAX_FILTER_VALUES, json_schema_extra=UNIQUE_ITEMS
    )
    purls: tuple[UnversionedPackageUrl, ...] = Field(
        default=(),
        max_length=MAX_FILTER_VALUES,
        json_schema_extra=UNIQUE_ITEMS,
        description="Package URLs without version, qualifiers or subpath; match any version.",
    )
    cwe_ids: tuple[CweId, ...] = Field(
        default=(), max_length=MAX_FILTER_VALUES, json_schema_extra=UNIQUE_ITEMS
    )
    severities: tuple[Severity, ...] = Field(
        default=(), max_length=MAX_FILTER_VALUES, json_schema_extra=UNIQUE_ITEMS
    )
    origins: tuple[VulnerabilityOrigin, ...] = Field(
        default=(), max_length=MAX_FILTER_VALUES, json_schema_extra=UNIQUE_ITEMS
    )
    published_years: tuple[PublishedYear, ...] = Field(
        default=(), max_length=MAX_FILTER_VALUES, json_schema_extra=UNIQUE_ITEMS
    )
    kev_only: StrictBool = False

    @field_validator(
        "vendors", "products", "purls", "cwe_ids", "severities", "origins", "published_years"
    )
    @classmethod
    def check_unique(cls, values: tuple[Hashable, ...]) -> tuple[Hashable, ...]:
        """Mirrors the schema's ``uniqueItems``: exact repeats are rejected."""
        if len(set(values)) != len(values):
            raise ValueError("filter values must be unique")
        return values

    def is_active(self) -> bool:
        return bool(
            self.vendors
            or self.products
            or self.purls
            or self.cwe_ids
            or self.severities
            or self.origins
            or self.published_years
            or self.kev_only
        )

    def list_match_terms(self) -> frozenset[str]:
        """Every value a structured match may name as a matched term: the caller's filter
        values as the structured channel compares them (names and packages case-folded),
        the published years as text, and ``listed`` for the KEV filter."""
        match_terms: set[str] = set()
        for folded_value in (*self.vendors, *self.products, *self.purls):
            match_terms.add(folded_value.casefold())
        for exact_value in (*self.cwe_ids, *self.severities, *self.origins):
            match_terms.add(str(exact_value))
        for published_year in self.published_years:
            match_terms.add(str(published_year))
        if self.kev_only:
            match_terms.add(KEV_MATCH_TERM)
        return frozenset(match_terms)


class SearchRequest(ContractModel):
    """A search. The CVE IDs the query names are looked up exactly and its other words
    searched, except stopwords, the low-signal words ``cve`` and ``cves``, and words that
    read together as a CVE ID written apart (``CVE of 2021-44228``). A query with neither
    an ID nor a search term is answered ``no_match`` with a warning, whatever its
    filters, which only narrow the records the query itself finds."""

    query: QueryText
    limit: JsonInteger = Field(default=10, ge=1, le=MAX_RESULTS_PER_CALL)
    filters: SearchFilters = Field(default_factory=SearchFilters)
    graph_expand: StrictBool = False
    semantic: StrictBool = False


GraphRelation = Literal["cwe", "vendor", "product", "cpe", "purl"]


# What a matched term may be; the search service checks each against what it sent.
MATCHED_TERMS_DESCRIPTION = (
    "Terms the server can vouch for: the caller's query terms (lexical) or filter values "
    "(structured), relation values both records carry (graph), or the requested CVE ID; "
    "none for the semantic channel."
)


class MatchedField(StrEnum):
    """A field a retrieval channel matched a record in, so no channel can name anything
    else: the lexical index's fields, the structured filter's fields, the semantic
    embedding, the graph's relations and the exact CVE ID."""

    CVE_ID = "cve_id"
    DESCRIPTION = "description"
    VENDOR = "vendor"
    PRODUCT = "product"
    CWE_IDS = "cwe_ids"
    AFFECTED_VENDOR = "affected.vendor"
    AFFECTED_PRODUCT = "affected.product"
    AFFECTED_PURL = "affected.purl"
    CVSS_BASE_SEVERITY = "cvss.base_severity"
    VULNERABILITY_ORIGIN = "vulnerability_origin"
    PUBLISHED_YEAR = "published.year"
    KEV = "kev"
    SEMANTIC_EMBEDDING = "semantic.embedding"
    RELATION_CWE = "relation.cwe"
    RELATION_VENDOR = "relation.vendor"
    RELATION_PRODUCT = "relation.product"
    RELATION_CPE = "relation.cpe"
    RELATION_PURL = "relation.purl"


class GraphPath(ContractModel):
    """One asserted relation a graph hit shares with the seed record it was reached from."""

    seed_cve_id: CveId
    relation: GraphRelation
    value: str = Field(min_length=1)


class RetrievalMatch(ContractModel):
    """One record a single channel matched, with the reasons it matched."""

    cve_id: CveId
    score: float = Field(ge=0.0, allow_inf_nan=False)
    matched_fields: tuple[MatchedField, ...]
    matched_terms: tuple[str, ...] = Field(description=MATCHED_TERMS_DESCRIPTION)
    graph_paths: tuple[GraphPath, ...] = Field(
        default=(), description="Seed-to-hit relations; set only by the graph channel."
    )


class RetrievalOutcome(ContractModel):
    """Result of one backend call; failures cannot masquerade as empty matches."""

    status: BackendStatus
    matches: tuple[RetrievalMatch, ...] = ()
    failure: BackendFailure | None = Field(
        default=None, description="Why the backend gave no answer; set exactly when it failed."
    )

    @model_validator(mode="after")
    def check_status_payload(self) -> "RetrievalOutcome":
        if self.status is BackendStatus.OK and self.failure is not None:
            raise ValueError("a successful backend outcome cannot carry a failure")
        if self.status is not BackendStatus.OK and self.matches:
            raise ValueError("an unsuccessful backend outcome cannot carry matches")
        if self.status is not BackendStatus.OK and self.failure is None:
            raise ValueError("an unsuccessful backend outcome must carry its failure")
        matched_cve_ids: set[str] = set()
        for match in self.matches:
            if match.cve_id in matched_cve_ids:
                raise ValueError(f"a backend outcome lists {match.cve_id} more than once")
            matched_cve_ids.add(match.cve_id)
        return self


def describe_channel_outcome_shape() -> JsonDict:
    """``ChannelOutcome.check_detail_when_failed`` as JSON Schema."""
    return {
        "if": {"properties": {"status": {"const": BackendStatus.OK.value}}},
        "then": {"properties": {"detail": {"type": "null"}}},
        "else": {"required": ["detail"], "properties": {"detail": {"not": {"type": "null"}}}},
    }


class ChannelOutcome(ContractModel):
    model_config = ConfigDict(json_schema_extra=describe_channel_outcome_shape())

    channel: RetrievalChannel
    status: BackendStatus
    detail: BackendFailureDetail | None = Field(
        default=None,
        description="The server's sentence for why the channel failed; null when it answered.",
    )

    @model_validator(mode="after")
    def check_detail_when_failed(self) -> Self:
        if (self.status is BackendStatus.OK) != (self.detail is None):
            raise ValueError("a channel outcome carries a detail exactly when the channel failed")
        return self


class ChannelHit(ContractModel):
    channel: RetrievalChannel
    channel_rank: int = Field(ge=1)
    raw_score: float = Field(
        ge=0.0,
        allow_inf_nan=False,
        description="The channel's own score; scales differ by channel.",
    )
    matched_fields: tuple[MatchedField, ...]
    matched_terms: tuple[str, ...] = Field(description=MATCHED_TERMS_DESCRIPTION)
    graph_paths: tuple[GraphPath, ...] = ()


class ScopeAssessment(ContractModel):
    scope: KnowledgeScope
    basis: str = Field(min_length=1, description="Why the candidate carries this scope.")


class Candidate(ContractModel):
    """A ranked record.

    Exact-ID hits rank first in request order, then records matched directly by the
    lexical or semantic channel, then records reached only through the graph. Within
    a tier, ties on ``relevance_score`` are broken by ascending CVE ID.
    """

    rank: int = Field(ge=1)
    record: CveRecord
    relevance_score: float = Field(
        ge=0.0,
        allow_inf_nan=False,
        description=(
            "Reciprocal-rank-fusion score over the exact-ID, lexical, semantic and graph hits. "
            "Measures relevance to the query only — not severity, exploitability or confidence. "
            "Structured hits record why the candidate satisfied the filters and add no score."
        ),
    )
    channel_hits: tuple[ChannelHit, ...] = Field(min_length=1)
    scope_assessment: ScopeAssessment
    missing_fields: tuple[str, ...] = Field(
        description="Record fields no source supplied; unknown, not evidence of low risk."
    )


class SemanticUnavailableDetail(StrEnum):
    """The server's sentence for a requested semantic channel that cannot search."""

    ADAPTER_UNUSABLE = "the semantic adapter is not installed or could not be loaded"
    # No collection records the corpus content digest it was built from, so none can be
    # bound to a served store; its hits would be unchecked against the store (ADR 0009 §14).
    COLLECTION_NOT_BOUND = "the semantic collection is not bound to the served corpus store"


# The failure a semantic search reports for each reason the channel cannot search.
SEMANTIC_UNAVAILABLE_FAILURES = {
    SemanticUnavailableDetail.ADAPTER_UNUSABLE: BackendFailure.ADAPTER_UNUSABLE,
    SemanticUnavailableDetail.COLLECTION_NOT_BOUND: BackendFailure.COLLECTION_NOT_BOUND,
}


class SearchWarningCode(StrEnum):
    UNKNOWN_CVE_ID = "unknown_cve_id"
    EXCLUDED_BY_FILTERS = "excluded_by_filters"
    NO_SEARCHABLE_TERMS = "no_searchable_terms"
    BACKEND_UNAVAILABLE = "backend_unavailable"
    BACKEND_INCOMPLETE = "backend_incomplete"
    BACKEND_ERROR = "backend_error"


class SearchWarning(ContractModel):
    code: SearchWarningCode
    subject: str


class SearchResponse(ContractModel):
    schema_version: SchemaVersion = SCHEMA_VERSION
    query: str
    normalized_query: str
    status: ResultStatus
    channels_executed: tuple[RetrievalChannel, ...]
    channel_outcomes: tuple[ChannelOutcome, ...]
    candidates: tuple[Candidate, ...]
    evidence: tuple[EvidenceAnchor, ...] = Field(
        description="Every anchor the candidates cite, ordered by evidence_id."
    )
    warnings: tuple[SearchWarning, ...]
    result_sha256: str = Field(
        pattern=SHA256_PATTERN,
        description=(
            "SHA-256 of the canonical JSON of this response without this field; the server "
            "recomputes it and rejects a mismatch."
        ),
    )

    def compute_result_sha256(self) -> str:
        """Hash of the response content; equal requests over equal data hash equally."""
        return canonical_sha256(self.model_dump(mode="json", exclude={"result_sha256"}))
