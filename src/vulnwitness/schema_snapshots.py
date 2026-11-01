"""Render, write and check the committed JSON Schema snapshots of the v2 contracts."""

import json
from pathlib import Path

from pydantic import BaseModel
from pydantic.json_schema import GenerateJsonSchema, JsonSchemaMode, JsonSchemaValue
from pydantic_core import CoreSchema, core_schema

from vulnwitness.domain.affectedness import AffectednessCheck, AffectednessRequest
from vulnwitness.domain.corpus_store_manifest import CorpusStoreManifest
from vulnwitness.domain.cve import CveRecord
from vulnwitness.domain.evidence import EvidenceAnchor
from vulnwitness.domain.evidence_set_verification_report import VerificationReport
from vulnwitness.domain.hashing import sha256_hex
from vulnwitness.domain.http_rejection import HttpRejection
from vulnwitness.domain.investigation import InvestigationRequest, KnowledgeEvidenceSet
from vulnwitness.domain.migration_report import MigrationReport
from vulnwitness.domain.planning import QueryPlan
from vulnwitness.domain.product_query import ProductQueryRequest, ProductQueryResponse
from vulnwitness.domain.relevance import RelevanceProposal
from vulnwitness.domain.search import SCHEMA_VERSION, SearchRequest, SearchResponse
from vulnwitness.domain.session_record import (
    SessionCall,
    SessionCheckReport,
    SessionFindings,
    SessionRecord,
)
from vulnwitness.domain.session_response import SessionResponse
from vulnwitness.domain.store_status import StoreStatus
from vulnwitness.domain.timestamps import END_OF_VALUE
from vulnwitness.domain.tool_contracts import (
    CapabilitiesRequest,
    ConceptResolution,
    ConceptResolutionRequest,
    CveLookupRequest,
    EvidenceLookup,
    EvidenceLookupRequest,
    FightSearchRequest,
    KnowledgeCapabilities,
    ToolFailure,
)
from vulnwitness.domain.topic import ProtocolTopic
from vulnwitness.domain.topic_context import TopicContextRequest, TopicContextResponse

MANIFEST_FILE = "manifest.json"
# The evidence-set schema relies on ``prefixItems``, which earlier drafts read differently.
JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
REQUEST_CONTRACTS: dict[str, type[BaseModel]] = {
    "session_findings": SessionFindings,
    "product_query_request": ProductQueryRequest,
    "search_request": SearchRequest,
    "topic_context_request": TopicContextRequest,
    "investigation_request": InvestigationRequest,
    # A model planner's reply must parse as this plan before the core gates it.
    "query_plan": QueryPlan,
    "relevance_proposal": RelevanceProposal,
    # Topic cards are input: reviewers author them against this schema.
    "protocol_topic": ProtocolTopic,
    # The MCP tools' inputs.
    "capabilities_request": CapabilitiesRequest,
    "concept_resolution_request": ConceptResolutionRequest,
    "cve_lookup_request": CveLookupRequest,
    "fight_search_request": FightSearchRequest,
    "evidence_lookup_request": EvidenceLookupRequest,
    "affectedness_request": AffectednessRequest,
}
RESPONSE_CONTRACTS: dict[str, type[BaseModel]] = {
    "session_record": SessionRecord,
    "session_call": SessionCall,
    "session_response": SessionResponse,
    "session_check_report": SessionCheckReport,
    "product_query_response": ProductQueryResponse,
    "search_response": SearchResponse,
    "topic_context_response": TopicContextResponse,
    "knowledge_evidence_set": KnowledgeEvidenceSet,
    "cve_record": CveRecord,
    "evidence_anchor": EvidenceAnchor,
    # The MCP tools' outputs.
    "knowledge_capabilities": KnowledgeCapabilities,
    "concept_resolution": ConceptResolution,
    "evidence_lookup": EvidenceLookup,
    "affectedness_check": AffectednessCheck,
    "tool_failure": ToolFailure,
    # The verdict of a whole-set verification (`vulnwitness verify`).
    "verification_report": VerificationReport,
    # What an HTTP server answers in place of a route: a refusal, the deadline, a failure.
    "http_rejection": HttpRejection,
    # The corpus store the legacy-data importer writes, and what an import reports.
    "corpus_store_manifest": CorpusStoreManifest,
    "migration_report": MigrationReport,
    "store_status": StoreStatus,
}


class PublishedJsonSchema(GenerateJsonSchema):
    """Publishes each schema under the draft it is written in, and each string pattern so
    that it ends exactly under ECMA-262 and Python ``re`` alike.

    Pydantic checks a ``Field(pattern=...)`` with the Rust regex engine, where ``$`` is the
    end of the value and lookarounds are unsupported, so the model keeps its bare ``$``
    and only the published pattern ends in ``END_OF_VALUE``.
    """

    def generate(self, schema: CoreSchema, mode: JsonSchemaMode = "validation") -> JsonSchemaValue:
        json_schema = super().generate(schema, mode=mode)
        json_schema["$schema"] = JSON_SCHEMA_DIALECT
        return json_schema

    def str_schema(self, schema: core_schema.StringSchema) -> JsonSchemaValue:
        json_schema = super().str_schema(schema)
        pattern = json_schema.get("pattern")
        if isinstance(pattern, str) and pattern.endswith("$") and not pattern.endswith("\\$"):
            json_schema["pattern"] = pattern.removesuffix("$") + END_OF_VALUE
        return json_schema


def render_schema(model: type[BaseModel], mode: JsonSchemaMode) -> str:
    schema = model.model_json_schema(mode=mode, schema_generator=PublishedJsonSchema)
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_contract_schemas() -> dict[str, str]:
    """Snapshot file name → content, including a manifest of schema version and hashes."""
    rendered: dict[str, str] = {}
    for contract_name, model in REQUEST_CONTRACTS.items():
        rendered[f"{contract_name}.schema.json"] = render_schema(model, "validation")
    for contract_name, model in RESPONSE_CONTRACTS.items():
        rendered[f"{contract_name}.schema.json"] = render_schema(model, "serialization")
    file_hashes: dict[str, str] = {}
    for file_name in sorted(rendered):
        file_hashes[file_name] = sha256_hex(rendered[file_name].encode())
    manifest = {"schema_version": SCHEMA_VERSION, "files": file_hashes}
    rendered[MANIFEST_FILE] = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    return rendered


def write_contract_schemas(schema_dir: Path) -> None:
    schema_dir.mkdir(parents=True, exist_ok=True)
    for file_name, content in render_contract_schemas().items():
        (schema_dir / file_name).write_text(content, encoding="utf-8")


def find_schema_drift(schema_dir: Path) -> list[str]:
    """Snapshot files that are missing, stale or unexpected under ``schema_dir``."""
    rendered = render_contract_schemas()
    drift: list[str] = []
    for file_name, content in sorted(rendered.items()):
        snapshot = schema_dir / file_name
        if not snapshot.is_file():
            drift.append(f"missing {file_name}")
        elif snapshot.read_text(encoding="utf-8") != content:
            drift.append(f"stale {file_name}")
    if schema_dir.is_dir():
        for snapshot in sorted(schema_dir.iterdir()):
            if snapshot.name not in rendered:
                drift.append(f"unexpected {snapshot.name}")
    return drift
