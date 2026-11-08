"""Load packaged, strict YAML priority tables and seal their canonical content identity."""

from dataclasses import dataclass
from importlib.resources import files
from importlib.resources.abc import Traversable

import yaml
from pydantic import ValidationError

from vulnwitness.adapters.strict_yaml import load_strict_yaml
from vulnwitness.domain.contract_model import list_validation_problems
from vulnwitness.domain.priority_policy import PriorityPolicy


class PriorityPolicyError(ValueError):
    """A policy is not UTF-8 strict YAML or violates the decision-table contract."""


@dataclass(frozen=True)
class LoadedPriorityPolicy:
    policy: PriorityPolicy
    content_sha256: str


def default_priority_policy_file() -> Traversable:
    return files("vulnwitness").joinpath("knowledge", "policies", "cn-auto-demo.yaml")


def load_priority_policy(policy_file: Traversable) -> LoadedPriorityPolicy:
    """Read and validate the whole table; compute its canonical SHA-256 at this boundary."""
    try:
        policy_document = load_strict_yaml(policy_file.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError):
        raise PriorityPolicyError("the policy is not UTF-8 strict YAML") from None
    try:
        policy = PriorityPolicy.model_validate(policy_document)
    except ValidationError as error:
        raise PriorityPolicyError("; ".join(list_validation_problems(error))) from None
    return LoadedPriorityPolicy(policy=policy, content_sha256=policy.compute_content_sha256())
