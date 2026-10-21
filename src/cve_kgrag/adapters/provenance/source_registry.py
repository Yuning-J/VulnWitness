"""Load the packaged source registry (``knowledge/sources.yaml``)."""

from importlib.resources import files
from importlib.resources.abc import Traversable

from cve_kgrag.adapters.strict_yaml import load_strict_yaml
from cve_kgrag.domain.provenance import SourceRegistry


def default_source_registry_file() -> Traversable:
    return files("cve_kgrag").joinpath("knowledge", "sources.yaml")


def load_source_registry(registry_file: Traversable) -> SourceRegistry:
    return SourceRegistry.model_validate(
        load_strict_yaml(registry_file.read_text(encoding="utf-8"))
    )
