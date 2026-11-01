"""A YAML safe loader that also rejects duplicate keys and merge keys.

Plain YAML keeps the last of two equal keys and lets ``<<`` merges pull keys in
from elsewhere, so a reviewed file could change below what a reader saw. Every
YAML file this package reads goes through ``load_strict_yaml``, and every way a
document can be malformed (bad syntax, an unhashable or repeated key, a merge key,
nesting deeper than the parser can follow, a tagged or plain value the safe constructor
cannot build) raises ``yaml.YAMLError``.

An operator's declaration file (``load_declaration_yaml``) is read stricter still: it may
use no alias, and timestamps stay text, so a time is validated as written rather than
after YAML has dropped its offset or digits.
"""

from typing import Any

import yaml
from yaml.events import AliasEvent
from yaml.nodes import MappingNode, Node

MERGE_TAG = "tag:yaml.org,2002:merge"
TIMESTAMP_TAG = "tag:yaml.org,2002:timestamp"


class StrictYamlError(yaml.YAMLError):
    """The document is valid YAML but breaks the stricter rules of this loader."""


class StrictSafeLoader(yaml.SafeLoader):
    """Safe loader whose mappings refuse repeated, unhashable and merge keys."""

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        if not isinstance(node, MappingNode):
            # A ``!!set`` or ``!!omap`` tag on a sequence or scalar: the safe constructor
            # refuses it with its own ConstructorError.
            return super().construct_mapping(node, deep=deep)
        seen_keys: set[Any] = set()
        for key_node, _ in node.value:
            line = key_node.start_mark.line + 1
            if key_node.tag == MERGE_TAG:
                raise StrictYamlError(f"merge key at line {line} is not accepted")
            key = self.construct_object(key_node, deep=deep)
            try:
                is_repeated = key in seen_keys
            except TypeError as error:
                raise StrictYamlError(f"unhashable key at line {line}") from error
            if is_repeated:
                raise StrictYamlError(f"duplicate key {key!r} at line {line}")
            seen_keys.add(key)
        return super().construct_mapping(node, deep=deep)


class DeclarationLoader(StrictSafeLoader):
    """The strict loader, refusing every alias and reading timestamps as text."""

    def compose_node(self, parent: Node | None, index: int) -> Node | None:
        # Aliases are resolved while the document is composed, before any constructor
        # runs, so they are refused here.
        if self.check_event(AliasEvent):
            line = self.peek_event().start_mark.line + 1  # type: ignore[no-untyped-call]
            raise StrictYamlError(f"alias at line {line} is not accepted")
        return super().compose_node(parent, index)


def list_resolvers_without_timestamps(
    implicit_resolvers: dict[Any, list[tuple[str, Any]]],
) -> dict[Any, list[tuple[str, Any]]]:
    """``implicit_resolvers`` without the timestamp resolver, as a new mapping."""
    resolvers_without_timestamps: dict[Any, list[tuple[str, Any]]] = {}
    for first_character, resolvers in implicit_resolvers.items():
        kept_resolvers: list[tuple[str, Any]] = []
        for resolver in resolvers:
            if resolver[0] != TIMESTAMP_TAG:
                kept_resolvers.append(resolver)
        resolvers_without_timestamps[first_character] = kept_resolvers
    return resolvers_without_timestamps


DeclarationLoader.yaml_implicit_resolvers = list_resolvers_without_timestamps(
    StrictSafeLoader.yaml_implicit_resolvers
)


def load_strict_yaml(text: str) -> Any:
    return load_with(text, StrictSafeLoader)


def load_declaration_yaml(text: str) -> Any:
    """An operator's declaration file: strict, with no alias and timestamps as text."""
    return load_with(text, DeclarationLoader)


def load_with(text: str, loader: type[StrictSafeLoader]) -> Any:
    try:
        # Both loaders subclass SafeLoader, so no arbitrary objects are constructed.
        return yaml.load(text, Loader=loader)
    except RecursionError as error:
        raise StrictYamlError("nesting is deeper than the parser can follow") from error
    except (ValueError, KeyError, AttributeError) as error:
        # The safe constructor builds a tagged or plain value with no check of its own, so
        # 2024-02-30, an integer longer than Python converts, ``!!bool maybe`` and
        # ``!!timestamp now`` raise these rather than yaml.YAMLError.
        raise StrictYamlError("a value cannot be constructed") from error
