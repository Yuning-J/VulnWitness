"""Select returned knowledge, excluding request echoes and execution diagnostics.

Search and lookup echo query text; topics and concept resolution echo it in their
resolution. Product pages echo product filters and cursors. Investigations also carry
the request, its interpretation, coverage needs and backend calls. Affectedness checks
only echo the request and report unavailability; verification reports describe supplied
evidence sets. None of those fields establish that an identifier was retrieved.
"""

import json

from pydantic import BaseModel

from vulnwitness.domain.cve_lookup import CveLookupResponse
from vulnwitness.domain.investigation import KnowledgeEvidenceSet
from vulnwitness.domain.product_query import ProductQueryResponse
from vulnwitness.domain.search import Candidate, SearchResponse
from vulnwitness.domain.tool_contracts import ConceptResolution, EvidenceLookup
from vulnwitness.domain.topic_context import TopicContextResponse


def candidate_identifier_text(candidate: Candidate) -> str:
    """Source records and catalogue associations, without query-based channel hits."""
    return candidate.model_dump_json(include={"record", "weakness_associations"})


def returned_identifier_texts(answer: BaseModel) -> list[str]:
    """Only knowledge returned by a supported session response, never echoed input."""
    texts: list[str] = []
    if isinstance(answer, SearchResponse):
        for candidate in answer.candidates:
            texts.append(candidate_identifier_text(candidate))
        if isinstance(answer, CveLookupResponse):
            for entry in answer.pending_cnvd:
                texts.append(entry.model_dump_json())
    elif isinstance(answer, ProductQueryResponse):
        for item in answer.items:
            texts.append(item.record.model_dump_json())
        for source_named in answer.source_named_candidates:
            texts.append(source_named.model_dump_json())
        for product in answer.matched_products:
            texts.append(product.model_dump_json())
    elif isinstance(answer, TopicContextResponse | KnowledgeEvidenceSet):
        for implementation in answer.implementation_candidates:
            texts.append(candidate_identifier_text(implementation.candidate))
        for excluded in answer.excluded_implementation_candidates:
            texts.append(candidate_identifier_text(excluded.candidate.candidate))
        for context in answer.protocol_context:
            texts.append(context.model_dump_json())
        if isinstance(answer, KnowledgeEvidenceSet):
            for step in answer.trajectory.steps:
                texts.append(json.dumps(step.answer_ids))
    elif isinstance(answer, ConceptResolution):
        texts.append(answer.resolution.model_dump_json(exclude={"normalized_query"}))
    elif isinstance(answer, EvidenceLookup):
        texts.append(answer.evidence.model_dump_json())
    if isinstance(
        answer, SearchResponse | ProductQueryResponse | TopicContextResponse | KnowledgeEvidenceSet
    ):
        for anchor in answer.evidence:
            texts.append(anchor.model_dump_json())
    return texts
