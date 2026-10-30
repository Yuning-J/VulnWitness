"""Protocol threat context: FiGHT techniques as evidence-anchored knowledge items.

A technique describes how an adversary may attack a 5G system. It is threat
context, never proof that a protocol design is vulnerable and never an
implementation vulnerability, so its scope is fixed.
"""

from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, model_validator

from cve_kgrag.domain.contract_model import ContractModel
from cve_kgrag.domain.evidence import EvidenceAnchor, EvidenceId
from cve_kgrag.domain.taxonomy import BackendFailure, BackendStatus, KnowledgeScope
from cve_kgrag.domain.timestamps import Timestamp

FIGHT_TECHNIQUE_ID_PATTERN = r"^FGT[0-9]{4}(\.[0-9]{3})?$"
TACTIC_ID_PATTERN = r"^TA[0-9]{4}$"


class ObservationStatus(StrEnum):
    """FiGHT's own maturity label, normalized; ``source_status`` keeps the original text."""

    THEORETICAL = "theoretical"
    PROOF_OF_CONCEPT = "proof_of_concept"
    OBSERVED = "observed"
    # Observed in enterprise IT or earlier 3GPP generations, not (yet) in 5G.
    OBSERVED_OUTSIDE_5G = "observed_outside_5g"


def format_snapshot_version(data_version: str, commit: str, snapshot_sha256: str) -> str:
    """``<data version>@<commit>+sha256:<snapshot SHA-256>``; names one exact snapshot file."""
    return f"{data_version}@{commit}+sha256:{snapshot_sha256}"


class SnapshotCoverage(StrEnum):
    FULL = "full"
    EXCERPT = "excerpt"


class KnownFightSnapshot(ContractModel):
    """One reviewed FiGHT snapshot file, catalogued by its SHA-256.

    The catalog, not the caller, is the only source of a snapshot's coverage and
    expected contents: since the SHA-256 pins the exact bytes, a file whose hash is
    catalogued as the full upstream file is the full file. An excerpt names the
    snapshot it was cut from and lists its technique and tactic IDs.
    """

    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    repository_url: str = Field(min_length=1)
    commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    data_version: str = Field(min_length=1)
    upstream_path: str = Field(min_length=1)
    coverage: SnapshotCoverage
    derived_from_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    technique_count: int = Field(ge=1)
    tactic_count: int = Field(ge=1)
    technique_ids: tuple[str, ...] | None = None
    tactic_ids: tuple[str, ...] | None = None
    retrieved_at: Timestamp
    terms_ref: str = Field(min_length=1)

    @model_validator(mode="after")
    def check_coverage_description(self) -> Self:
        is_excerpt = self.coverage is SnapshotCoverage.EXCERPT
        if is_excerpt != (self.derived_from_sha256 is not None):
            raise ValueError("an excerpt, and only an excerpt, names the snapshot it was cut from")
        if is_excerpt and (self.technique_ids is None or self.tactic_ids is None):
            raise ValueError("an excerpt lists its technique and tactic IDs")
        if self.technique_ids is not None and len(set(self.technique_ids)) != self.technique_count:
            raise ValueError("technique_ids must hold technique_count distinct IDs")
        if self.tactic_ids is not None and len(set(self.tactic_ids)) != self.tactic_count:
            raise ValueError("tactic_ids must hold tactic_count distinct IDs")
        return self

    @property
    def source_version(self) -> str:
        return format_snapshot_version(self.data_version, self.commit, self.snapshot_sha256)

    @property
    def source_uri(self) -> str:
        return f"{self.repository_url}/blob/{self.commit}/{self.upstream_path}"


PROVENANCE_FIELDS = ("repository_url", "commit", "data_version", "upstream_path", "terms_ref")


class FightSnapshotCatalog(ContractModel):
    """Reviewed FiGHT snapshots; a source serves only a file whose hash is listed here."""

    snapshots: tuple[KnownFightSnapshot, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def check_snapshots(self) -> Self:
        full_hashes: set[str] = set()
        seen_hashes: set[str] = set()
        for snapshot in self.snapshots:
            if snapshot.snapshot_sha256 in seen_hashes:
                raise ValueError(f"snapshot {snapshot.snapshot_sha256} is listed twice")
            seen_hashes.add(snapshot.snapshot_sha256)
            if snapshot.coverage is SnapshotCoverage.FULL:
                full_hashes.add(snapshot.snapshot_sha256)
        for snapshot in self.snapshots:
            derived_from = snapshot.derived_from_sha256
            if derived_from is None:
                continue
            parent = self.find(derived_from)
            if parent is None or derived_from not in full_hashes:
                raise ValueError(
                    f"{snapshot.snapshot_sha256} is not cut from a catalogued full snapshot"
                )
            for field_name in PROVENANCE_FIELDS:
                if getattr(snapshot, field_name) != getattr(parent, field_name):
                    raise ValueError(
                        f"{snapshot.snapshot_sha256}: {field_name} differs from the snapshot "
                        "it was cut from"
                    )
        return self

    def find(self, snapshot_sha256: str) -> KnownFightSnapshot | None:
        for snapshot in self.snapshots:
            if snapshot.snapshot_sha256 == snapshot_sha256:
                return snapshot
        return None


class FightSnapshotInfo(ContractModel):
    """Identity of the FiGHT snapshot a source serves; for capability reports."""

    repository_url: str
    commit: str
    data_version: str
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    coverage: SnapshotCoverage
    technique_count: int = Field(ge=0)
    tactic_count: int = Field(ge=0)
    retrieved_at: Timestamp
    ingested_at: Timestamp = Field(description="When this process verified and parsed it.")
    terms_ref: str

    @property
    def source_version(self) -> str:
        """The version every anchor from this snapshot carries."""
        return format_snapshot_version(self.data_version, self.commit, self.snapshot_sha256)


# The source name every FiGHT anchor carries.
FIGHT_SOURCE_NAME = "mitre-fight"


def format_fight_locator(technique_id: str) -> str:
    """Where in a FiGHT snapshot a technique's anchor points: derived from its ID alone,
    so an anchor's locator carries no text of its source's choosing."""
    return f"techniques[id={technique_id}]"


class TechniqueField(StrEnum):
    """A field of a FiGHT technique a search can match, so no source names anything else."""

    NAME = "name"
    BLUF = "bluf"
    DESCRIPTION = "description"
    PROCEDURE_EXAMPLES = "procedureexamples"
    TACTICS = "tactics"


class ThreatContextItem(ContractModel):
    technique_id: str = Field(pattern=FIGHT_TECHNIQUE_ID_PATTERN)
    name: str = Field(min_length=1)
    status: ObservationStatus
    source_status: str = Field(min_length=1, description="The status text exactly as published.")
    tactic_ids: tuple[str, ...] = Field(min_length=1)
    tactic_names: tuple[str, ...] = Field(min_length=1)
    subtechnique_of: str | None = Field(default=None, pattern=FIGHT_TECHNIQUE_ID_PATTERN)
    scope: Literal[KnowledgeScope.PROTOCOL_THREAT_CONTEXT] = KnowledgeScope.PROTOCOL_THREAT_CONTEXT
    matched_fields: tuple[TechniqueField, ...]
    matched_terms: tuple[str, ...] = Field(
        description=(
            "Terms the server sent to FiGHT that the technique holds: a resolved topic's "
            "name, aliases and entities, or with no topic the question's own words."
        )
    )
    evidence_ids: tuple[EvidenceId, ...] = Field(min_length=1)


class ThreatContextOutcome(ContractModel):
    """Result of one threat-context source call; a failure cannot pass as an empty answer.

    A successful outcome names the snapshot it searched, and every anchor it returns
    carries that snapshot's version, so results and their source identity travel
    together and cannot disagree. ``matched_count`` is every technique of the snapshot
    that named a term, before the search's limit cut the items: at least the items
    listed, 0 exactly when none is, and 0 on failure (ADR 0009 §11a). ``unindexed_terms``
    are the sent terms no technique holds, the first spelling of each, in sent order, and
    none on failure. The outcome is internal and in no published schema.
    """

    status: BackendStatus
    items: tuple[ThreatContextItem, ...] = ()
    matched_count: int = Field(default=0, ge=0)
    unindexed_terms: tuple[str, ...] = ()
    evidence: tuple[EvidenceAnchor, ...] = ()
    snapshot: FightSnapshotInfo | None = None
    failure: BackendFailure | None = Field(
        default=None, description="Why the source gave no answer; set exactly when it failed."
    )

    @model_validator(mode="after")
    def check_status_payload(self) -> Self:
        is_ok = self.status is BackendStatus.OK
        if is_ok and self.failure is not None:
            raise ValueError("a successful source outcome cannot carry a failure")
        if is_ok and self.snapshot is None:
            raise ValueError("a successful source outcome must name its snapshot")
        if not is_ok and (
            self.items or self.evidence or self.unindexed_terms or self.snapshot is not None
        ):
            raise ValueError(
                "an unsuccessful source outcome cannot carry items, unindexed terms or a snapshot"
            )
        if not is_ok and self.failure is None:
            raise ValueError("an unsuccessful source outcome must carry its failure")
        if self.matched_count < len(self.items) or (self.matched_count == 0) != (not self.items):
            raise ValueError("matched_count counts at least the items listed, 0 only with none")
        if self.snapshot is not None:
            for anchor in self.evidence:
                if anchor.source_version != self.snapshot.source_version:
                    raise ValueError(
                        f"{anchor.evidence_id} comes from another snapshot than the one named"
                    )
        return self
