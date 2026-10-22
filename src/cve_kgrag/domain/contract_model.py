"""Base class for every domain and contract model, and how a rejected input is reported."""

from pydantic import BaseModel, ConfigDict, ValidationError


class ContractModel(BaseModel):
    """Closed, immutable model: unknown fields are rejected and instances cannot be mutated.

    Serialization schemas mark defaulted fields required, because serialized
    output always contains them.
    """

    model_config = ConfigDict(
        frozen=True, extra="forbid", json_schema_serialization_defaults_required=True
    )


def list_validation_problems(error: ValidationError) -> list[str]:
    """Each problem a contract found, as ``location: message`` (only the message for the
    document as a whole), without the rejected input."""
    problems: list[str] = []
    for problem in error.errors():
        location = ".".join(str(part) for part in problem["loc"])
        if location:
            problems.append(f"{location}: {problem['msg']}")
        else:
            problems.append(problem["msg"])
    return problems
