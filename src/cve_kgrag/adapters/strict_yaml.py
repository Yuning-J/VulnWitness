"""A YAML safe loader that also rejects duplicate keys and merge keys.

Plain YAML keeps the last of two equal keys and lets ``<<`` merges pull keys in
from elsewhere, so a reviewed file could change below what a reader saw. Every
YAML file this package reads goes through ``load_strict_yaml``, and every way a
document can be malformed (bad syntax, an unhashable or repeated key, a merge key,
nesting deeper than the parser can follow, a tagged or plain value the safe constructor
cannot build) raises ``yaml.YAMLError``.
"""

from typing import Any

import yaml
from yaml.nodes import MappingNode

MERGE_TAG = "tag:yaml.org,2002:merge"


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


def load_strict_yaml(text: str) -> Any:
    try:
        # StrictSafeLoader subclasses SafeLoader, so no arbitrary objects are constructed.
        return yaml.load(text, Loader=StrictSafeLoader)
    except RecursionError as error:
        raise StrictYamlError("nesting is deeper than the parser can follow") from error
    except (ValueError, KeyError, AttributeError) as error:
        # The safe constructor builds a tagged or plain value with no check of its own, so
        # 2024-02-30, an integer longer than Python converts, ``!!bool maybe`` and
        # ``!!timestamp now`` raise these rather than yaml.YAMLError.
        raise StrictYamlError("a value cannot be constructed") from error
