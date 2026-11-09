"""Closed vocabularies used by the v2 contracts.

Each value set is part of the external contract: adding a value is a schema
change, and renaming or removing one breaks consumers.
"""

from enum import StrEnum


class KnowledgeScope(StrEnum):
    """What kind of knowledge a record, evidence anchor or claim represents."""

    # Reserved for authenticated formal-analysis artifacts supplied by an
    # external system. This service never originates it (domain/validation.py).
    FORMAL_PROTOCOL_FINDING = "formal_protocol_finding"
    PROTOCOL_THREAT_CONTEXT = "protocol_threat_context"
    IMPLEMENTATION_VULNERABILITY = "implementation_vulnerability"
    UNKNOWN = "unknown"


class VulnerabilityOrigin(StrEnum):
    """Where a CVE's defect lives. A CVE never describes a protocol-design flaw here."""

    IMPLEMENTATION = "implementation"
    CONFIGURATION = "configuration"
    DEPENDENCY = "dependency"
    UNKNOWN = "unknown"


class AssertionKind(StrEnum):
    """Whether a source states a fact directly or this service derived it."""

    ASSERTED = "asserted"
    INFERRED = "inferred"


class TrustLevel(StrEnum):
    """How far a consumer may rely on an evidence anchor's source."""

    AUTHORITATIVE = "authoritative"  # the source of record for the identifier
    SECONDARY = "secondary"  # an aggregator or mirror of the source of record
    DERIVED = "derived"  # computed by this service from other evidence
    SYNTHETIC = "synthetic"  # authored test data; describes no real product


class SourceType(StrEnum):
    """Kind of source an evidence anchor points into. Values are added with their adapters."""

    SYNTHETIC_FIXTURE = "synthetic_fixture"
    NVD_API_2 = "nvd_api_2"
    NVD_JSON_11 = "nvd_json_11"
    CISA_KEV = "cisa_kev"
    CIRCL_CNVD_PARQUET = "circl_cnvd_parquet"
    VULNERABILITY_LOOKUP_CNVD_NDJSON = "vulnerability_lookup_cnvd_ndjson"
    MITRE_FIGHT_YAML = "mitre_fight_yaml"


class RetrievalChannel(StrEnum):
    """Retrieval channels whose scores and reasons stay inspectable per candidate."""

    EXACT_ID = "exact_id"
    LEXICAL = "lexical"
    STRUCTURED = "structured"
    GRAPH = "graph"
    SEMANTIC = "semantic"


class ResultStatus(StrEnum):
    """Outcome of a request. An unavailable backend is never reported as ``no_match``."""

    OK = "ok"
    NO_MATCH = "no_match"
    PARTIAL = "partial"
    INCOMPLETE_INDEX = "incomplete_index"
    SOURCE_UNAVAILABLE = "source_unavailable"
    BACKEND_ERROR = "backend_error"
    POLICY_BLOCKED = "policy_blocked"


class BackendStatus(StrEnum):
    """Typed outcome of one retrieval backend invocation."""

    OK = "ok"
    UNAVAILABLE = "unavailable"
    INCOMPLETE_INDEX = "incomplete_index"
    ERROR = "error"


class BackendFailure(StrEnum):
    """Why a retrieval channel or the FiGHT source gave no answer. An adapter names only
    the reason; the server publishes its own sentence for it (``BackendFailureDetail``),
    so no adapter text reaches a client."""

    NOT_CONFIGURED = "not_configured"
    ADAPTER_UNUSABLE = "adapter_unusable"
    UNREACHABLE = "unreachable"
    SEARCH_FAILED = "search_failed"
    INDEX_INCOMPLETE = "index_incomplete"
    FILTERS_UNSUPPORTED = "filters_unsupported"
    NO_ANSWER = "no_answer"
    COLLECTION_NOT_BOUND = "collection_not_bound"


class BackendFailureDetail(StrEnum):
    """The server's sentence for each ``BackendFailure``."""

    NOT_CONFIGURED = "The backend is not configured."
    ADAPTER_UNUSABLE = "The backend's adapter cannot be loaded."
    UNREACHABLE = "The backend could not be reached."
    SEARCH_FAILED = "The backend failed while searching."
    INDEX_INCOMPLETE = "The backend's index holds no entries for the searched records."
    FILTERS_UNSUPPORTED = "The backend cannot apply the search's filters before its limit."
    NO_ANSWER = "The backend returned nothing and does not report its own errors."
    COLLECTION_NOT_BOUND = "The backend's collection is not bound to the served dataset."


BACKEND_FAILURE_DETAILS: dict[BackendFailure, BackendFailureDetail] = {
    BackendFailure.NOT_CONFIGURED: BackendFailureDetail.NOT_CONFIGURED,
    BackendFailure.ADAPTER_UNUSABLE: BackendFailureDetail.ADAPTER_UNUSABLE,
    BackendFailure.UNREACHABLE: BackendFailureDetail.UNREACHABLE,
    BackendFailure.SEARCH_FAILED: BackendFailureDetail.SEARCH_FAILED,
    BackendFailure.INDEX_INCOMPLETE: BackendFailureDetail.INDEX_INCOMPLETE,
    BackendFailure.FILTERS_UNSUPPORTED: BackendFailureDetail.FILTERS_UNSUPPORTED,
    BackendFailure.NO_ANSWER: BackendFailureDetail.NO_ANSWER,
    BackendFailure.COLLECTION_NOT_BOUND: BackendFailureDetail.COLLECTION_NOT_BOUND,
}


def describe_backend_failure(failure: BackendFailure | None) -> BackendFailureDetail | None:
    """The server's sentence for ``failure``; ``None`` for a backend that answered."""
    if failure is None:
        return None
    return BACKEND_FAILURE_DETAILS[failure]
