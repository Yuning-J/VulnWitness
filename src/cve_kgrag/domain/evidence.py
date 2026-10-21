"""Evidence anchors and the claims that cite them."""

from typing import Annotated, Self

from pydantic import ConfigDict, Field, model_validator

from cve_kgrag.domain.contract_model import ContractModel
from cve_kgrag.domain.hashing import canonical_sha256
from cve_kgrag.domain.taxonomy import AssertionKind, KnowledgeScope, SourceType, TrustLevel
from cve_kgrag.domain.timestamps import Timestamp

EVIDENCE_ID_PATTERN = r"^ev:[0-9a-f]{24}$"
SHA256_PATTERN = r"^[0-9a-f]{64}$"
MAX_EXCERPT_CHARS = 500

# Placeholder ID an anchor carries until ``seal_evidence_anchor`` derives its own.
UNSEALED_EVIDENCE_ID = "ev:" + "0" * 24

EvidenceId = Annotated[str, Field(pattern=EVIDENCE_ID_PATTERN)]


class EvidenceAnchor(ContractModel):
    """A pointer to one source record, precise enough to re-fetch and re-hash it."""

    # The published schema states ``check_inference_method_matches_assertion_kind``.
    model_config = ConfigDict(
        json_schema_extra={
            "if": {"properties": {"assertion_kind": {"const": AssertionKind.INFERRED.value}}},
            "then": {
                "required": ["inference_method"],
                "properties": {"inference_method": {"type": "string"}},
            },
            "else": {"properties": {"inference_method": {"type": "null"}}},
        }
    )

    evidence_id: str = Field(
        pattern=EVIDENCE_ID_PATTERN,
        description=(
            "'ev:' and the first 24 hex digits of the SHA-256 of the canonical JSON of every "
            "other anchor field; it changes when any provenance field changes. The server "
            "re-derives it and rejects a mismatch. An integrity check, not proof of origin: "
            "a holder can recompute it."
        ),
    )
    source_name: str = Field(min_length=1, max_length=128)
    source_type: SourceType
    authoritative_record_id: str = Field(
        min_length=1,
        max_length=256,
        description="Identifier of the record in its source of record, e.g. a CVE ID.",
    )
    source_uri: str = Field(min_length=1, max_length=2048)
    source_version: str | None = Field(
        default=None,
        description="Release, commit, ETag or snapshot identifier, when the source exposes one.",
    )
    retrieved_at: Timestamp
    content_sha256: str = Field(
        pattern=SHA256_PATTERN,
        description="SHA-256 of the canonical JSON of the source record this anchor points at.",
    )
    locator: str = Field(
        min_length=1, max_length=512, description="Field path or JSON pointer inside the source."
    )
    excerpt: str | None = Field(
        default=None,
        max_length=MAX_EXCERPT_CHARS,
        description="Bounded excerpt, present only when the source's terms permit redistribution.",
    )
    scope: KnowledgeScope
    assertion_kind: AssertionKind
    inference_method: str | None = Field(
        default=None, description="How an inferred anchor was derived; required iff inferred."
    )
    license_or_terms_ref: str = Field(min_length=1)
    trust_level: TrustLevel

    @model_validator(mode="after")
    def check_inference_method_matches_assertion_kind(self) -> Self:
        is_inferred = self.assertion_kind is AssertionKind.INFERRED
        if is_inferred and self.inference_method is None:
            raise ValueError("an inferred anchor must name its inference_method")
        if not is_inferred and self.inference_method is not None:
            raise ValueError("an asserted anchor cannot carry an inference_method")
        return self


def derive_evidence_id(anchor: EvidenceAnchor) -> str:
    """``ev:`` and the first 24 hex digits of the SHA-256 of the canonical JSON of every
    anchor field except ``evidence_id``.

    The ID binds source name and type, authoritative record, URI, version, retrieval
    time, content hash, locator, excerpt, scope, assertion kind, inference method,
    terms and trust level: changing any of them changes the ID.
    """
    provenance = anchor.model_dump(mode="json", exclude={"evidence_id"})
    return "ev:" + canonical_sha256(provenance)[:24]


def seal_evidence_anchor(anchor: EvidenceAnchor) -> EvidenceAnchor:
    """``anchor`` carrying the evidence ID derived from its provenance fields."""
    return anchor.model_copy(update={"evidence_id": derive_evidence_id(anchor)})


class Claim(ContractModel):
    """A factual statement this service makes, scoped and backed by evidence anchors."""

    claim_id: str = Field(min_length=1, max_length=128)
    subject_id: str = Field(
        min_length=1, max_length=256, description="Identifier the claim is about, e.g. a CVE ID."
    )
    statement: str = Field(min_length=1, max_length=1000)
    scope: KnowledgeScope
    assertion_kind: AssertionKind
    evidence_ids: tuple[EvidenceId, ...] = Field(min_length=1)
