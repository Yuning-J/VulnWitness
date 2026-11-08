"""Parse an operator's asset register through the strict declaration YAML boundary."""

import yaml
from pydantic import ValidationError

from vulnwitness.adapters.strict_yaml import load_declaration_yaml
from vulnwitness.domain.asset_register import AssetRegister
from vulnwitness.domain.contract_model import list_validation_problems


class AssetRegisterError(ValueError):
    """The register is not UTF-8 declaration YAML or violates the register contract."""


def load_asset_register(register_bytes: bytes) -> AssetRegister:
    """Validate explicit register bytes without reading a path or consulting a store."""
    try:
        register_document = load_declaration_yaml(register_bytes.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError):
        raise AssetRegisterError("the register is not UTF-8 declaration YAML") from None
    try:
        return AssetRegister.model_validate(register_document)
    except ValidationError as error:
        raise AssetRegisterError("; ".join(list_validation_problems(error))) from None
