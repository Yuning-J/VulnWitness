"""Read the operator's input manifest (ADR 0008 §2). A manifest that is not valid is a
usage error, reported in the server's words, never by quoting the file."""

import yaml
from pydantic import ValidationError

from vulnwitness.adapters.strict_yaml import load_declaration_yaml
from vulnwitness.domain.contract_model import list_validation_problems
from vulnwitness.domain.evidence_set_verification_report import bound_violations
from vulnwitness.domain.migration_inputs import MAX_MANIFEST_BYTES, InputsManifest


class InputsManifestError(ValueError):
    """The manifest is not a valid input manifest; the message never quotes it."""


def load_inputs_manifest(manifest_bytes: bytes) -> InputsManifest:
    """The manifest the bytes hold; raises ``InputsManifestError``."""
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise InputsManifestError(f"the manifest is larger than {MAX_MANIFEST_BYTES} bytes")
    try:
        manifest_document = load_declaration_yaml(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError):
        raise InputsManifestError(
            "the manifest is not UTF-8 YAML the declaration loader accepts"
        ) from None
    try:
        return InputsManifest.model_validate(manifest_document)
    except ValidationError as error:
        problems = "; ".join(bound_violations(list_validation_problems(error)))
        raise InputsManifestError(problems) from None
