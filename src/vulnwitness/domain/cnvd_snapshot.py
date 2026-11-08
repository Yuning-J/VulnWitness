"""Reviewed CNVD revisions and their complete sets of pinned files (ADR 0015 §2)."""

from typing import Self

from pydantic import Field, model_validator

from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.evidence import SHA256_PATTERN


class CnvdSnapshotFile(ContractModel):
    upstream_path: str = Field(pattern=r"^data/[a-z0-9-]+\.parquet$")
    sha256: str = Field(pattern=SHA256_PATTERN)
    row_count: int = Field(ge=0)


class CnvdSnapshot(ContractModel):
    revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    language: str | None = Field(
        default=None, min_length=1, description="Language declared by this revision's dataset card."
    )
    files: tuple[CnvdSnapshotFile, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def check_distinct_files(self) -> Self:
        paths: set[str] = set()
        hashes: set[str] = set()
        for snapshot_file in self.files:
            if snapshot_file.upstream_path in paths or snapshot_file.sha256 in hashes:
                raise ValueError("a revision lists each file path and hash once")
            paths.add(snapshot_file.upstream_path)
            hashes.add(snapshot_file.sha256)
        return self


class CnvdSnapshotCatalog(ContractModel):
    snapshots: tuple[CnvdSnapshot, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def check_distinct_revisions(self) -> Self:
        revisions: set[str] = set()
        for snapshot in self.snapshots:
            if snapshot.revision in revisions:
                raise ValueError("a catalog lists each revision once")
            revisions.add(snapshot.revision)
        return self
