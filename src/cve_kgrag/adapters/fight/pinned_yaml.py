"""Read-only FiGHT threat context from a pinned, checksum-verified ``fight.yaml`` snapshot.

The snapshot is a local file the operator supplies, or the packaged excerpt. It is
served only when its SHA-256 matches the configured pin and is listed in the
reviewed snapshot catalog, which alone states its coverage and expected contents.
It is parsed once, with a safe loader that also rejects duplicate and merge keys;
any mismatch or shape violation raises ``FightSnapshotError`` and nothing from the
file is served. Queries never touch the network or the file system.
"""

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, cast

import yaml
from pydantic import ValidationError

from cve_kgrag.adapters.strict_yaml import load_strict_yaml
from cve_kgrag.domain.evidence import (
    MAX_EXCERPT_CHARS,
    UNSEALED_EVIDENCE_ID,
    EvidenceAnchor,
    seal_evidence_anchor,
)
from cve_kgrag.domain.hashing import canonical_sha256, sha256_hex
from cve_kgrag.domain.taxonomy import (
    AssertionKind,
    BackendFailure,
    BackendStatus,
    KnowledgeScope,
    SourceType,
    TrustLevel,
)
from cve_kgrag.domain.threat_context import (
    FIGHT_SOURCE_NAME,
    FIGHT_TECHNIQUE_ID_PATTERN,
    TACTIC_ID_PATTERN,
    FightSnapshotCatalog,
    FightSnapshotInfo,
    KnownFightSnapshot,
    ObservationStatus,
    TechniqueField,
    ThreatContextItem,
    ThreatContextOutcome,
    format_fight_locator,
)
from cve_kgrag.topics.normalization import TERM_BOUNDARY, alias_key, find_spans, split_terms

# Every status text published at FiGHT 3.1.0. A new value fails the load so its
# meaning is reviewed before it is served.
OBSERVATION_STATUS_BY_SOURCE_TEXT = {
    "Theoretical": ObservationStatus.THEORETICAL,
    "Proof Of Concept": ObservationStatus.PROOF_OF_CONCEPT,
    "POC": ObservationStatus.PROOF_OF_CONCEPT,
    "Observed": ObservationStatus.OBSERVED,
    "Observed In Enterprise": ObservationStatus.OBSERVED_OUTSIDE_5G,
    "Observed In 4G And Expected To Be Observed In 5G": ObservationStatus.OBSERVED_OUTSIDE_5G,
    "Observed In 4G; Possible In 5G": ObservationStatus.OBSERVED_OUTSIDE_5G,
    "Observed In Earlier 3GPP Generations And Expected In 5G": (
        ObservationStatus.OBSERVED_OUTSIDE_5G
    ),
}


class FightSnapshotError(ValueError):
    """The snapshot does not match its pin or the expected shape; nothing is served."""


@dataclass(frozen=True)
class IndexedTechnique:
    item: ThreatContextItem
    anchor: EvidenceAnchor
    terms_by_field: dict[TechniqueField, list[str]]


def require_text(entry: Mapping[str, Any], key: str, owner: str) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value.strip():
        raise FightSnapshotError(f"{owner}: {key} is not a non-empty string")
    return value


def require_list(entry: Mapping[str, Any], key: str, owner: str) -> list[Any]:
    value = entry.get(key)
    if not isinstance(value, list):
        raise FightSnapshotError(f"{owner}: {key} is not a list")
    return value


def require_mapping(value: object, owner: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise FightSnapshotError(f"{owner} is not a mapping")
    return cast(Mapping[str, Any], value)


def read_tactic_names(document: Mapping[str, Any]) -> dict[str, str]:
    tactic_names: dict[str, str] = {}
    for tactic_value in require_list(document, "tactics", "fight.yaml"):
        tactic = require_mapping(tactic_value, "tactic")
        tactic_id = require_text(tactic, "id", "tactic")
        if re.fullmatch(TACTIC_ID_PATTERN, tactic_id) is None or tactic_id in tactic_names:
            raise FightSnapshotError(f"tactic id {tactic_id!r} is malformed or repeated")
        tactic_names[tactic_id] = require_text(tactic, "name", tactic_id)
    return tactic_names


def read_technique_tactic_ids(
    technique: Mapping[str, Any], technique_id: str, tactic_names: Mapping[str, str]
) -> list[str]:
    technique_tactic_ids: list[str] = []
    for tactic_id in require_list(technique, "tactics", technique_id):
        if not isinstance(tactic_id, str) or tactic_id not in tactic_names:
            raise FightSnapshotError(f"{technique_id}: unknown tactic {tactic_id!r}")
        if tactic_id in technique_tactic_ids:
            raise FightSnapshotError(f"{technique_id}: tactic {tactic_id} listed twice")
        technique_tactic_ids.append(tactic_id)
    return technique_tactic_ids


def read_parent_id(technique: Mapping[str, Any], technique_id: str) -> str | None:
    """The parent of a sub-technique (``FGTnnnn`` of ``FGTnnnn.nnn``); ``None`` otherwise."""
    parent_id = technique.get("subtechnique-of")
    is_sub_technique = "." in technique_id
    if parent_id is None and not is_sub_technique:
        return None
    if not is_sub_technique or parent_id != technique_id.split(".")[0]:
        raise FightSnapshotError(f"{technique_id}: subtechnique-of {parent_id!r} disagrees")
    return cast(str, parent_id)


def read_procedure_texts(technique: Mapping[str, Any], technique_id: str) -> list[str]:
    procedure_texts: list[str] = []
    for procedure_value in require_list(technique, "procedureexamples", technique_id):
        procedure = require_mapping(procedure_value, f"{technique_id} procedure example")
        procedure_texts.append(require_text(procedure, "name", technique_id))
        procedure_texts.append(require_text(procedure, "description", technique_id))
    return procedure_texts


def hash_entry(technique: Mapping[str, Any], technique_id: str) -> str:
    """Canonical-JSON hash; YAML-only values (dates, sets, binary, cycles) are refused."""
    try:
        return canonical_sha256(technique)
    except (TypeError, ValueError, RecursionError) as error:
        raise FightSnapshotError(f"{technique_id}: holds values JSON cannot represent") from error


def check_catalogued_contents(
    known_snapshot: KnownFightSnapshot,
    tactic_ids: set[str],
    indexed_techniques: Sequence["IndexedTechnique"],
) -> None:
    """Refuse a snapshot whose contents differ from its catalog entry."""
    technique_ids: set[str] = set()
    for indexed_technique in indexed_techniques:
        technique_ids.add(indexed_technique.item.technique_id)
    if len(technique_ids) != known_snapshot.technique_count:
        raise FightSnapshotError(
            f"snapshot holds {len(technique_ids)} techniques, "
            f"{known_snapshot.technique_count} catalogued"
        )
    if len(tactic_ids) != known_snapshot.tactic_count:
        raise FightSnapshotError(
            f"snapshot holds {len(tactic_ids)} tactics, {known_snapshot.tactic_count} catalogued"
        )
    if known_snapshot.technique_ids is not None and technique_ids != set(
        known_snapshot.technique_ids
    ):
        raise FightSnapshotError("snapshot techniques differ from the catalogued technique IDs")
    if known_snapshot.tactic_ids is not None and tactic_ids != set(known_snapshot.tactic_ids):
        raise FightSnapshotError("snapshot tactics differ from the catalogued tactic IDs")


def split_field_terms(texts: Sequence[str]) -> list[str]:
    field_terms: list[str] = []
    for text in texts:
        field_terms.extend(split_terms(text))
        field_terms.append(TERM_BOUNDARY)
    return field_terms


class PinnedFightYamlSource:
    """Implements ``FightSource`` over one verified snapshot."""

    def __init__(
        self,
        snapshot_bytes: bytes,
        expected_sha256: str,
        snapshot_catalog: FightSnapshotCatalog,
        clock: Callable[[], datetime],
    ) -> None:
        """Serve ``snapshot_bytes`` only if they hash to the pin and the pin is catalogued.

        Coverage, version and expected contents all come from the catalog entry.
        """
        actual_sha256 = sha256_hex(snapshot_bytes)
        if actual_sha256 != expected_sha256:
            raise FightSnapshotError(
                f"snapshot SHA-256 {actual_sha256} does not match the pinned {expected_sha256}"
            )
        known_snapshot = snapshot_catalog.find(actual_sha256)
        if known_snapshot is None:
            raise FightSnapshotError(f"snapshot {actual_sha256} is not in the reviewed catalog")
        try:
            document = load_strict_yaml(snapshot_bytes.decode("utf-8"))
        except (UnicodeDecodeError, yaml.YAMLError) as error:
            raise FightSnapshotError(f"snapshot is not UTF-8 strict YAML: {error}") from error
        self._known_snapshot = known_snapshot
        root = require_mapping(document, "fight.yaml")
        tactic_names = read_tactic_names(root)
        self._techniques = self._index(root, tactic_names)
        check_catalogued_contents(known_snapshot, set(tactic_names), self._techniques)
        self._snapshot_info = FightSnapshotInfo(
            repository_url=known_snapshot.repository_url,
            commit=known_snapshot.commit,
            data_version=known_snapshot.data_version,
            snapshot_sha256=actual_sha256,
            coverage=known_snapshot.coverage,
            technique_count=known_snapshot.technique_count,
            tactic_count=known_snapshot.tactic_count,
            retrieved_at=known_snapshot.retrieved_at,
            ingested_at=clock(),
            terms_ref=known_snapshot.terms_ref,
        )

    def describe(self) -> FightSnapshotInfo:
        return self._snapshot_info

    def list_evidence(self) -> Sequence[EvidenceAnchor]:
        anchors: list[EvidenceAnchor] = []
        for indexed_technique in self._techniques:
            anchors.append(indexed_technique.anchor)
        return tuple(anchors)

    def list_techniques(self) -> Sequence[ThreatContextItem]:
        indexed_items: list[ThreatContextItem] = []
        for indexed_technique in self._techniques:
            indexed_items.append(indexed_technique.item)
        return tuple(indexed_items)

    def search(self, terms: Sequence[str], limit: int) -> ThreatContextOutcome:
        """Techniques naming any term, by number of distinct terms named, then by ID.

        ``matched_terms`` follow the order of ``terms``; ``matched_fields`` the order
        name, bluf, description, procedureexamples, tactics.
        """
        # Spellings with one key (5G-AKA, 5G AKA, 5gaka) count once, as the first given.
        term_keys: list[tuple[str, str]] = []
        known_keys: set[str] = set()
        for term in terms:
            term_key = alias_key(term)
            if term_key and term_key not in known_keys:
                known_keys.add(term_key)
                term_keys.append((term, term_key))
        scored_hits: list[tuple[int, IndexedTechnique, ThreatContextItem]] = []
        for indexed_technique in self._techniques:
            matched_field_names: set[TechniqueField] = set()
            matched_terms: list[str] = []
            for term, term_key in term_keys:
                for field_name, field_terms in indexed_technique.terms_by_field.items():
                    if find_spans(field_terms, term_key):
                        matched_field_names.add(field_name)
                        if term not in matched_terms:
                            matched_terms.append(term)
            matched_fields: list[TechniqueField] = []
            for field_name in indexed_technique.terms_by_field:
                if field_name in matched_field_names:
                    matched_fields.append(field_name)
            if matched_terms:
                item = indexed_technique.item.model_copy(
                    update={
                        "matched_fields": tuple(matched_fields),
                        "matched_terms": tuple(matched_terms),
                    }
                )
                scored_hits.append((len(matched_terms), indexed_technique, item))
        scored_hits.sort(key=lambda hit: (-hit[0], hit[2].technique_id))
        items: list[ThreatContextItem] = []
        anchors: list[EvidenceAnchor] = []
        for _, indexed_technique, item in scored_hits[:limit]:
            items.append(item)
            anchors.append(indexed_technique.anchor)
        return ThreatContextOutcome(
            status=BackendStatus.OK,
            items=tuple(items),
            evidence=tuple(anchors),
            snapshot=self._snapshot_info,
        )

    def _index(
        self, document: Mapping[str, Any], tactic_names: Mapping[str, str]
    ) -> list[IndexedTechnique]:
        indexed_techniques: list[IndexedTechnique] = []
        seen_ids: set[str] = set()
        for technique_value in require_list(document, "techniques", "fight.yaml"):
            technique = require_mapping(technique_value, "technique")
            indexed_technique = self._index_technique(technique, tactic_names)
            technique_id = indexed_technique.item.technique_id
            if technique_id in seen_ids:
                raise FightSnapshotError(f"technique {technique_id} appears twice")
            seen_ids.add(technique_id)
            indexed_techniques.append(indexed_technique)
        indexed_techniques.sort(key=lambda indexed: indexed.item.technique_id)
        return indexed_techniques

    def _index_technique(
        self, technique: Mapping[str, Any], tactic_names: Mapping[str, str]
    ) -> IndexedTechnique:
        technique_id = require_text(technique, "id", "technique")
        if re.fullmatch(FIGHT_TECHNIQUE_ID_PATTERN, technique_id) is None:
            raise FightSnapshotError(f"technique id {technique_id!r} is malformed")
        name = require_text(technique, "name", technique_id)
        bluf = require_text(technique, "bluf", technique_id)
        description = require_text(technique, "description", technique_id)
        source_status = require_text(technique, "status", technique_id)
        status = OBSERVATION_STATUS_BY_SOURCE_TEXT.get(source_status)
        if status is None:
            raise FightSnapshotError(f"{technique_id}: unknown status {source_status!r}")
        tactic_ids = read_technique_tactic_ids(technique, technique_id, tactic_names)
        technique_tactic_names: list[str] = []
        for tactic_id in tactic_ids:
            technique_tactic_names.append(tactic_names[tactic_id])
        anchor = self._build_anchor(technique_id, hash_entry(technique, technique_id), bluf)
        try:
            item = ThreatContextItem(
                technique_id=technique_id,
                name=name,
                status=status,
                source_status=source_status,
                tactic_ids=tuple(tactic_ids),
                tactic_names=tuple(technique_tactic_names),
                subtechnique_of=read_parent_id(technique, technique_id),
                matched_fields=(),
                matched_terms=(),
                evidence_ids=(anchor.evidence_id,),
            )
        except ValidationError as error:
            raise FightSnapshotError(f"{technique_id}: does not fit the item contract") from error
        terms_by_field = {
            TechniqueField.NAME: split_field_terms([name]),
            TechniqueField.BLUF: split_field_terms([bluf]),
            TechniqueField.DESCRIPTION: split_field_terms([description]),
            TechniqueField.PROCEDURE_EXAMPLES: split_field_terms(
                read_procedure_texts(technique, technique_id)
            ),
            TechniqueField.TACTICS: split_field_terms(technique_tactic_names),
        }
        return IndexedTechnique(item=item, anchor=anchor, terms_by_field=terms_by_field)

    def _build_anchor(self, technique_id: str, content_sha256: str, bluf: str) -> EvidenceAnchor:
        known_snapshot = self._known_snapshot
        unsealed_anchor = EvidenceAnchor(
            evidence_id=UNSEALED_EVIDENCE_ID,
            source_name=FIGHT_SOURCE_NAME,
            source_type=SourceType.MITRE_FIGHT_YAML,
            authoritative_record_id=technique_id,
            source_uri=known_snapshot.source_uri,
            source_version=known_snapshot.source_version,
            retrieved_at=known_snapshot.retrieved_at,
            content_sha256=content_sha256,
            locator=format_fight_locator(technique_id),
            excerpt=" ".join(bluf.split())[:MAX_EXCERPT_CHARS],
            scope=KnowledgeScope.PROTOCOL_THREAT_CONTEXT,
            assertion_kind=AssertionKind.ASSERTED,
            license_or_terms_ref=known_snapshot.terms_ref,
            trust_level=TrustLevel.AUTHORITATIVE,
        )
        return seal_evidence_anchor(unsealed_anchor)


class UnavailableFightSource:
    """Implements ``FightSource`` when no verified snapshot is configured."""

    def describe(self) -> FightSnapshotInfo | None:
        return None

    def list_evidence(self) -> Sequence[EvidenceAnchor]:
        return ()

    def list_techniques(self) -> Sequence[ThreatContextItem]:
        return ()

    def search(self, terms: Sequence[str], limit: int) -> ThreatContextOutcome:
        return ThreatContextOutcome(
            status=BackendStatus.UNAVAILABLE, failure=BackendFailure.NOT_CONFIGURED
        )
