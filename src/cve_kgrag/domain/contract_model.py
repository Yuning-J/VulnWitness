"""Base class for every domain and contract model, and how a rejected input is reported."""

from pydantic import BaseModel, ConfigDict, ValidationError
from pydantic_core import ErrorDetails


class ContractModel(BaseModel):
    """Closed, immutable model: unknown fields are rejected and instances cannot be mutated.

    Serialization schemas mark defaulted fields required, because serialized
    output always contains them.
    """

    model_config = ConfigDict(
        frozen=True, extra="forbid", json_schema_serialization_defaults_required=True
    )


def describe_problem(problem: ErrorDetails) -> str:
    """The problem's message, in the server's own words. Pydantic's message for a tag no
    variant takes repeats the tag the input gave, so that one is rebuilt from the tags the
    contract expects."""
    if problem["type"] == "union_tag_invalid":
        context = problem.get("ctx", {})
        return (
            f"Input tag found using {context.get('discriminator')} does not match any of the "
            f"expected tags: {context.get('expected_tags')}"
        )
    return problem["msg"]


def list_validation_problems(error: ValidationError) -> list[str]:
    """Each problem a contract found, as ``location: message`` (only the message for the
    document as a whole), in the server's own words: no part of the rejected input. The
    location of an unexpected field would be the input's own key, so unexpected fields are
    reported as a count at the location that holds them, after the other problems."""
    problems: list[str] = []
    unexpected_field_counts: dict[str, int] = {}
    for problem in error.errors():
        location_parts: list[str] = []
        for part in problem["loc"]:
            location_parts.append(str(part))
        if problem["type"] == "extra_forbidden":
            parent_location = ".".join(location_parts[:-1])
            unexpected_field_counts[parent_location] = (
                unexpected_field_counts.get(parent_location, 0) + 1
            )
            continue
        location = ".".join(location_parts)
        message = describe_problem(problem)
        if location:
            problems.append(f"{location}: {message}")
        else:
            problems.append(message)
    for parent_location, unexpected_field_count in unexpected_field_counts.items():
        noun = "field" if unexpected_field_count == 1 else "fields"
        message = f"{unexpected_field_count} unexpected {noun}"
        if parent_location:
            problems.append(f"{parent_location}: {message}")
        else:
            problems.append(message)
    return problems
