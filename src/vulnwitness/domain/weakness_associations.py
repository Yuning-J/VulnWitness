"""Catalogue associations and marked inference, independent of retrieval context."""

from typing import Annotated, Final, Literal, Self

from pydantic import Field, model_validator

from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.evidence import SHA256_PATTERN

MAX_WEAKNESS_PATHS = 20
DERIVED_ASSOCIATION_NOTE: Final = (
    "This association is derived from official catalogues. It is not evidence that the "
    "CVE was used with that technique. It is not an attack path."
    " No ATT&CK mapping describes only the loaded catalogue snapshot; it does not mean "
    "the weakness has no attack technique or no way to be exploited."
    " CWE inheritance is an inference along the CWE hierarchy, not a catalogue link "
    "from the original CWE to CAPEC."
)
CweId = Annotated[str, Field(pattern=r"^CWE-[0-9]+$")]
CapecId = Annotated[str, Field(pattern=r"^CAPEC-[0-9]+$")]
TechniqueId = Annotated[str, Field(pattern=r"^T[0-9]{4}(\.[0-9]{3})?$")]


class CatalogueSource(ContractModel):
    catalogue: Literal["CWE", "CAPEC", "ATT&CK Enterprise"]
    version: str = Field(min_length=1)
    sha256: str = Field(pattern=SHA256_PATTERN)


class AttackTechnique(ContractModel):
    technique_id: TechniqueId
    name: str = Field(min_length=1)
    kind: Literal["technique", "subtechnique"]
    parent_technique_id: Annotated[str, Field(pattern=r"^T[0-9]{4}$")] | None = Field(
        default=None, description="Parent is an ATT&CK technique, never a tactic."
    )
    tactics: tuple[str, ...] = Field(
        description="ATT&CK tactic names from this object's mitre-attack kill_chain_phases."
    )

    @model_validator(mode="after")
    def check_technique_kind(self) -> Self:
        parent_id, separator, _ = self.technique_id.partition(".")
        expected_kind = "subtechnique" if separator else "technique"
        expected_parent = parent_id if separator else None
        if self.kind != expected_kind or self.parent_technique_id != expected_parent:
            raise ValueError("technique kind and parent must match the ATT&CK ID")
        return self


class CapecMapping(ContractModel):
    technique: AttackTechnique
    inherited_from: CapecId | None = None
    parent_chain: tuple[CapecId, ...] = Field(
        default=(), description="ChildOf parents traversed, ending at inherited_from."
    )

    @model_validator(mode="after")
    def check_inheritance(self) -> Self:
        expected_ancestor = self.parent_chain[-1] if self.parent_chain else None
        if self.inherited_from != expected_ancestor:
            raise ValueError("inherited_from must be the last ChildOf parent")
        if len(set(self.parent_chain)) != len(self.parent_chain):
            raise ValueError("ChildOf parent chain must not contain a cycle")
        return self


class CapecAssociations(ContractModel):
    name: str
    mappings: tuple[CapecMapping, ...]
    unavailable_technique_ids: tuple[TechniqueId, ...] = ()
    unavailable_parent_ids: tuple[CapecId, ...] = ()


class MappingCounts(ContractModel):
    cwes_with_capec_links: int = Field(ge=0)
    cwes_with_inherited_capec_links: int = Field(ge=0)
    capecs_with_attack_links: int = Field(ge=0)
    direct_mappings: int = Field(ge=0)
    inherited_mappings: int = Field(ge=0)
    deprecated_capecs_skipped: int = Field(ge=0)
    deprecated_attack_objects_skipped: int = Field(ge=0)
    revoked_attack_objects_skipped: int = Field(ge=0)


class CweCapecInheritance(ContractModel):
    inherited_from_cwe: CweId
    parent_chain: tuple[CweId, ...] = Field(min_length=1)
    capec_ids: tuple[CapecId, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def check_parent_chain(self) -> Self:
        if self.inherited_from_cwe != self.parent_chain[-1]:
            raise ValueError("inherited_from_cwe must be the last CWE ChildOf parent")
        if len(set(self.parent_chain)) != len(self.parent_chain):
            raise ValueError("CWE ChildOf parent chain must not contain a cycle")
        return self


class WeaknessMappingSnapshot(ContractModel):
    format_version: Literal[2] = 2
    coverage: Literal["full", "excerpt"]
    sources: tuple[CatalogueSource, ...] = Field(min_length=3, max_length=3)
    cwe_capecs: dict[CweId, tuple[CapecId, ...]]
    cwe_inheritance: dict[CweId, tuple[CweCapecInheritance, ...]]
    capecs: dict[CapecId, CapecAssociations]
    counts: MappingCounts

    @model_validator(mode="after")
    def check_source_catalogues(self) -> Self:
        catalogue_names: set[str] = set()
        for source in self.sources:
            catalogue_names.add(source.catalogue)
        if catalogue_names != {"CWE", "CAPEC", "ATT&CK Enterprise"}:
            raise ValueError("snapshot must name each of the three input catalogues exactly once")
        for cwe_id, inheritances in self.cwe_inheritance.items():
            if cwe_id not in self.cwe_capecs or self.cwe_capecs[cwe_id]:
                raise ValueError("CWE inheritance requires a selected CWE without direct links")
            for inheritance in inheritances:
                if cwe_id in inheritance.parent_chain:
                    raise ValueError("CWE inheritance must not return to its starting CWE")
        return self


class WeaknessSnapshotCapability(ContractModel):
    coverage: Literal["full", "excerpt"]
    integrity: Literal[
        "File identity recorded; no expected SHA-256 supplied.",
        "Compared with expected SHA-256.",
    ] = Field(description="Digest recording alone does not verify that a file is unchanged.")
    snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    sources: tuple[CatalogueSource, ...]
    counts: MappingCounts


class AssociationHop(ContractModel):
    from_id: str
    to_id: str
    relation: Literal[
        "nvd_cwe",
        "cwe_child_of",
        "cwe_related_attack_pattern",
        "capec_child_of",
        "capec_attack_taxonomy_mapping",
    ]
    source: Literal["NVD record", "CWE catalogue", "CAPEC catalogue"]
    source_version: str | None = None
    source_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    evidence_ids: tuple[str, ...] = ()


class WeaknessAssociationPath(ContractModel):
    cwe_id: CweId
    capec_id: CapecId
    technique: AttackTechnique | None = None
    technique_source: CatalogueSource | None = None
    terminal_reason: Literal["no_attack_mapping"] | None = Field(
        default=None, description="No usable ATT&CK mapping in the loaded catalogue snapshot."
    )
    inherited_from: CapecId | None = None
    inherited_from_cwe: CweId | None = Field(
        default=None,
        description=(
            "Linked CWE ancestor used for hierarchy inference, not a direct catalogue link."
        ),
    )
    hops: tuple[AssociationHop, ...]
    derived: Literal[True] = True

    @model_validator(mode="after")
    def check_path_terminal(self) -> Self:
        cwe_parents: list[str] = []
        for hop in self.hops:
            if hop.relation == "cwe_child_of":
                cwe_parents.append(hop.to_id)
        expected_cwe_ancestor = cwe_parents[-1] if cwe_parents else None
        if self.inherited_from_cwe != expected_cwe_ancestor:
            raise ValueError("inherited_from_cwe must match the last CWE ChildOf hop")
        if self.terminal_reason is None:
            if self.technique is None or self.technique_source is None:
                raise ValueError("full paths require a technique and its catalogue source")
        elif (
            self.technique is not None
            or self.technique_source is not None
            or self.inherited_from is not None
            or len(self.hops) != 2 + len(cwe_parents)
            or self.hops[-1].to_id != self.capec_id
        ):
            raise ValueError("CAPEC-terminal paths must end at CAPEC without a technique")
        return self


class MissingAssociationLink(ContractModel):
    subject: str
    reason: Literal[
        "no_specific_cwe",
        "cwe_not_in_snapshot",
        "no_related_attack_pattern",
        "capec_not_in_snapshot",
        "capec_parent_unavailable",
        "attack_technique_unavailable",
    ]


class WeaknessAssociations(ContractModel):
    paths: tuple[WeaknessAssociationPath, ...] = Field(max_length=MAX_WEAKNESS_PATHS)
    omitted_count: int = Field(ge=0)
    missing_links: tuple[MissingAssociationLink, ...]
    note: Literal[
        "This association is derived from official catalogues. It is not evidence that the "
        "CVE was used with that technique. It is not an attack path."
        " No ATT&CK mapping describes only the loaded catalogue snapshot; it does not mean "
        "the weakness has no attack technique or no way to be exploited."
        " CWE inheritance is an inference along the CWE hierarchy, not a catalogue link "
        "from the original CWE to CAPEC."
    ] = DERIVED_ASSOCIATION_NOTE
    snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    ordering: Literal[
        "direct_then_capec_inherited_then_cwe_inherited_then_capec_terminal_then_id_not_importance"
    ] = "direct_then_capec_inherited_then_cwe_inherited_then_capec_terminal_then_id_not_importance"
