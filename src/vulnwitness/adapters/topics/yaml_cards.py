"""Load reviewed topic cards from YAML files shipped with the package."""

from importlib.resources import files
from importlib.resources.abc import Traversable

import yaml
from pydantic import ValidationError

from vulnwitness.adapters.strict_yaml import load_strict_yaml
from vulnwitness.domain.topic import ProtocolTopic

CARD_SUFFIX = ".yaml"


class TopicCardError(ValueError):
    """A topic card file is not UTF-8, not strict YAML, or does not fit the topic contract."""


def default_topic_dir() -> Traversable:
    return files("vulnwitness").joinpath("knowledge", "topics")


def load_topic_cards(topic_dir: Traversable) -> list[ProtocolTopic]:
    """Every ``*.yaml`` card in ``topic_dir``, in file-name order; any bad card fails all."""
    card_files: list[Traversable] = []
    for entry in topic_dir.iterdir():
        if entry.is_file() and entry.name.endswith(CARD_SUFFIX):
            card_files.append(entry)
    card_files.sort(key=lambda card_file: card_file.name)
    topics: list[ProtocolTopic] = []
    for card_file in card_files:
        try:
            card = load_strict_yaml(card_file.read_text(encoding="utf-8"))
            topics.append(ProtocolTopic.model_validate(card))
        except (UnicodeDecodeError, yaml.YAMLError, ValidationError) as error:
            raise TopicCardError(f"topic card {card_file.name} is invalid: {error}") from error
    return topics
