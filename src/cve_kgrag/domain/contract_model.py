"""Base class for every domain and contract model."""

from pydantic import BaseModel, ConfigDict


class ContractModel(BaseModel):
    """Closed, immutable model: unknown fields are rejected and instances cannot be mutated.

    Serialization schemas mark defaulted fields required, because serialized
    output always contains them.
    """

    model_config = ConfigDict(
        frozen=True, extra="forbid", json_schema_serialization_defaults_required=True
    )
