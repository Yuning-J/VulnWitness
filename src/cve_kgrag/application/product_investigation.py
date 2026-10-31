"""Admit product reads as unassessed, structured investigation candidates.

The search-shaped observation shares context admission and replay machinery with CVE
searches. It runs no lexical backend and assigns no relevance score. Structured hits
state the product read's field or description basis; they do not satisfy evidence needs.
"""

from cve_kgrag.application.product_query import description_names_phrase
from cve_kgrag.application.search import CVE_SCOPE_ASSESSMENT
from cve_kgrag.domain.cve import CveRecord
from cve_kgrag.domain.product_query import (
    ProductFieldBasis,
    ProductQueryResponse,
)
from cve_kgrag.domain.search import (
    Candidate,
    ChannelHit,
    ChannelOutcome,
    MatchedField,
    SearchFilters,
    SearchResponse,
    SearchWarning,
    SearchWarningCode,
)
from cve_kgrag.domain.search_filters import match_filter_reasons
from cve_kgrag.domain.taxonomy import BackendStatus, ResultStatus, RetrievalChannel
from cve_kgrag.domain.text import normalize_query, tokenize


def matches_product_name(record: CveRecord, name: str) -> bool:
    """Name support for merge priority, without asserting ownership or component relevance.

    A lexical hit naming the brand in its description keeps priority even when its
    CPE uses a different vendor spelling. Product-query ownership rules stay separate.
    """
    for entry in record.list_implicated_products():
        if name.casefold() in (entry.vendor.casefold(), entry.product.casefold()):
            return True
    return description_names_phrase(record, tokenize(name))


def adapt_product_read(
    product_read: ProductQueryResponse, filters: SearchFilters
) -> SearchResponse:
    """Keep the product service's order and validated anchors under the run's filters.

    The product service caps the read before these additional filters. The auxiliary
    path makes no claim of completeness and warns whenever that bounded read is full.
    """
    candidates: list[Candidate] = []
    evidence_ids: set[str] = set()
    for item in product_read.items:
        if match_filter_reasons(item.record, filters) is None:
            continue
        matched_fields: list[MatchedField] = []
        matched_terms: list[str] = []
        if isinstance(item.basis, ProductFieldBasis):
            if product_read.vendor is not None:
                matched_fields.append(MatchedField.AFFECTED_VENDOR)
                matched_terms.append(product_read.vendor)
            if product_read.product is not None:
                matched_fields.append(MatchedField.AFFECTED_PRODUCT)
                matched_terms.append(product_read.product)
        else:
            matched_fields.append(MatchedField.DESCRIPTION)
            matched_terms.append(item.basis.matched_phrase)
        rank = len(candidates) + 1
        candidates.append(
            Candidate(
                rank=rank,
                record=item.record,
                relevance_score=0.0,
                channel_hits=(
                    ChannelHit(
                        channel=RetrievalChannel.STRUCTURED,
                        channel_rank=rank,
                        raw_score=0.0,
                        matched_fields=tuple(matched_fields),
                        matched_terms=tuple(matched_terms),
                    ),
                ),
                scope_assessment=CVE_SCOPE_ASSESSMENT,
                missing_fields=item.record.find_missing_fields(),
            )
        )
        evidence_ids.update(item.record.evidence_ids)
    anchors = []
    for anchor in product_read.evidence:
        if anchor.evidence_id in evidence_ids:
            anchors.append(anchor)
    warnings: list[SearchWarning] = []
    if len(candidates) == product_read.limit:
        warnings.append(
            SearchWarning(
                code=SearchWarningCode.RESULT_LIMIT_REACHED, subject=str(product_read.limit)
            )
        )
    name = product_read.product or product_read.vendor
    assert name is not None
    observation = SearchResponse(
        query=name,
        normalized_query=normalize_query(name),
        status=ResultStatus.OK if candidates else ResultStatus.NO_MATCH,
        channels_executed=(RetrievalChannel.STRUCTURED,),
        channel_outcomes=(
            ChannelOutcome(channel=RetrievalChannel.STRUCTURED, status=BackendStatus.OK),
        ),
        candidates=tuple(candidates),
        evidence=tuple(anchors),
        warnings=tuple(warnings),
        result_sha256="0" * 64,
    )
    return observation.model_copy(update={"result_sha256": observation.compute_result_sha256()})
