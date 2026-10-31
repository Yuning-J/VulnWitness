"""Reviewed protocol topics and the resolution of sparse query terms to them.

A topic card is curated knowledge, not model output: its aliases, exclusions and
entities decide which query terms may stand for the protocol. A card records its
own review state, so an unreviewed card can never pass as reviewed.
"""

from enum import StrEnum
from typing import Literal, Self

from pydantic import ConfigDict, Field, model_validator

from cve_kgrag.domain.contract_model import ContractModel
from cve_kgrag.domain.timestamps import CalendarDate

TOPIC_ID_PATTERN = r"^[a-z0-9]+:[a-z0-9][a-z0-9-]*$"
TOPIC_VERSION_PATTERN = r"^[0-9]+\.[0-9]+\.[0-9]+$"
SHA256_HEX_PATTERN = r"^[0-9a-f]{64}$"


class ReviewStatus(StrEnum):
    REVIEWED = "reviewed"
    PENDING_REVIEW = "pending_review"


class TopicReview(ContractModel):
    # The published schema states ``check_reviewer_matches_status``.
    model_config = ConfigDict(
        json_schema_extra={
            "if": {"properties": {"status": {"const": ReviewStatus.REVIEWED.value}}},
            "then": {
                "properties": {"reviewer": {"type": "string"}, "reviewed_on": {"type": "string"}}
            },
            "else": {"properties": {"reviewer": {"type": "null"}, "reviewed_on": {"type": "null"}}},
        }
    )

    status: ReviewStatus
    reviewer: str | None = Field(
        description="Who reviewed the card; null until a human review is recorded."
    )
    reviewed_on: CalendarDate | None
    basis: str = Field(min_length=1, description="Where each part of the card came from.")

    @model_validator(mode="after")
    def check_reviewer_matches_status(self) -> Self:
        names_reviewer = self.reviewer is not None
        names_date = self.reviewed_on is not None
        if self.status is ReviewStatus.REVIEWED and not (names_reviewer and names_date):
            raise ValueError("a reviewed card names its reviewer and review date")
        if self.status is ReviewStatus.PENDING_REVIEW and (names_reviewer or names_date):
            raise ValueError("a pending card names neither a reviewer nor a review date")
        return self


class TopicEntity(ContractModel):
    name: str = Field(min_length=1, max_length=64)
    role: str = Field(min_length=1, max_length=500)


class ContextualAlias(ContractModel):
    """A term that stands for the topic only beside one of its context terms."""

    alias: str = Field(min_length=1, max_length=128)
    requires_any: tuple[str, ...] = Field(min_length=1)


class TopicExclusion(ContractModel):
    """A term that must not resolve to the topic on its own, with the reason."""

    term: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=500)


class TopicReference(ContractModel):
    title: str = Field(min_length=1)
    uri: str = Field(min_length=1, max_length=2048)
    locator: str = Field(min_length=1, description="Clause or section inside the reference.")


class ProtocolTopic(ContractModel):
    topic_schema_version: Literal["1"] = "1"
    topic_id: str = Field(pattern=TOPIC_ID_PATTERN)
    version: str = Field(pattern=TOPIC_VERSION_PATTERN)
    canonical_name: str = Field(min_length=1, max_length=256)
    exact_aliases: tuple[str, ...] = Field(min_length=1)
    contextual_aliases: tuple[ContextualAlias, ...] = ()
    entities: tuple[TopicEntity, ...] = ()
    ecosystem_terms: tuple[str, ...] = Field(
        default=(), description="Terms of the wider technology the protocol lives in."
    )
    exclusions: tuple[TopicExclusion, ...] = ()
    query_templates: tuple[str, ...] = Field(
        min_length=1, description="Lexical queries that retrieve material about the topic."
    )
    review: TopicReview
    references: tuple[TopicReference, ...] = Field(min_length=1)


class RegisteredTopic(ContractModel):
    """A validated topic card with the hash of its canonical JSON."""

    topic: ProtocolTopic
    content_sha256: str = Field(pattern=SHA256_HEX_PATTERN)


class TopicMatchKind(StrEnum):
    CANONICAL_NAME = "canonical_name"
    EXACT_ALIAS = "exact_alias"
    CONTEXTUAL_ALIAS = "contextual_alias"


class TopicMatch(ContractModel):
    topic_id: str = Field(pattern=TOPIC_ID_PATTERN)
    topic_version: str = Field(pattern=TOPIC_VERSION_PATTERN)
    topic_sha256: str = Field(pattern=SHA256_HEX_PATTERN)
    review_status: ReviewStatus
    match_kind: TopicMatchKind
    matched_alias: str = Field(description="The card's alias or name that matched.")
    context_terms: tuple[str, ...] = Field(
        default=(), description="Context terms that licensed a contextual alias."
    )


class ExcludedTerm(ContractModel):
    topic_id: str = Field(pattern=TOPIC_ID_PATTERN)
    term: str
    reason: str


class TopicResolution(ContractModel):
    """Every topic the query names, and every excluded term it used instead."""

    normalized_query: str
    matches: tuple[TopicMatch, ...]
    excluded_terms: tuple[ExcludedTerm, ...]


def describe_topic_family_scope(match: TopicMatch) -> str | None:
    """The GTP card retrieves the whole family for every matched spelling."""
    if match.topic_id != "3gpp:gtp":
        return None
    return (
        f"matched_alias={match.matched_alias}: results cover the GTP family, including "
        "GTP-C and GTP-U, and are not limited to GTP-C or GTP-U."
    )


class RelevanceTier(StrEnum):
    """How a candidate relates to a topic. Relevance only: never severity or affectedness."""

    EXPLICIT_PROTOCOL_MENTION = "explicit_protocol_mention"
    PROTOCOL_COMPONENT_IMPLEMENTATION = "protocol_component_implementation"
    TELECOM_ECOSYSTEM_ADJACENT = "telecom_ecosystem_adjacent"
    SEMANTIC_ONLY = "semantic_only"


class RelevanceAssessment(ContractModel):
    tier: RelevanceTier
    matched_terms: tuple[str, ...] = Field(
        description=(
            "Card terms (alias, entity or ecosystem term), or a qualifying network-function "
            "abbreviation, found in the record."
        )
    )
    basis: str = Field(min_length=1)
