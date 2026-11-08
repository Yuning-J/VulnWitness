"""The KEV snapshot imported into the dataset being served."""

from typing import Self

from pydantic import ConfigDict, Field, StrictBool, model_validator

from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.timestamps import Timestamp


class KevCapability(ContractModel):
    model_config = ConfigDict(
        json_schema_extra={
            "if": {"properties": {"imported": {"const": True}}},
            "then": {
                "required": ["retrieved_at", "source_version"],
                "properties": {
                    "retrieved_at": {"type": "string"},
                    "source_version": {"type": "string"},
                },
            },
            "else": {
                "properties": {
                    "retrieved_at": {"type": "null"},
                    "source_version": {"type": "null"},
                }
            },
        }
    )

    imported: StrictBool
    retrieved_at: Timestamp | None = None
    source_version: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def check_snapshot_identity(self) -> Self:
        if self.imported != (self.retrieved_at is not None):
            raise ValueError("only an imported KEV snapshot has a retrieval time")
        if self.imported != (self.source_version is not None):
            raise ValueError("only an imported KEV snapshot has a source version")
        return self
