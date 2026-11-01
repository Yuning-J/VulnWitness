"""Read the topic documents and committed contract snapshots shipped with the package."""

import json
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

from vulnwitness.adapters.strict_yaml import load_strict_yaml
from vulnwitness.domain.topic import ProtocolTopic


@dataclass(frozen=True)
class PackagedResource:
    uri: str
    name: str
    description: str
    mime_type: str
    text: str


def load_packaged_resources() -> tuple[PackagedResource, ...]:
    documents: list[PackagedResource] = []
    topics = files("vulnwitness").joinpath("knowledge", "topics")
    for document in sorted(topics.iterdir(), key=lambda entry: entry.name):
        if not document.is_file() or not document.name.endswith(".yaml"):
            continue
        text = document.read_bytes().decode("utf-8")
        topic = ProtocolTopic.model_validate(load_strict_yaml(text))
        documents.append(
            PackagedResource(
                uri=f"vulnwitness://topics/{topic.topic_id}",
                name=topic.topic_id,
                description=f"Packaged topic card; review state: {topic.review.status.value}.",
                mime_type="text/yaml",
                text=text,
            )
        )
    schemas = files("vulnwitness").joinpath("knowledge", "schemas", "v2")
    if not schemas.is_dir():
        # Editable source trees keep the committed snapshots at the repository root.
        schemas = Path(__file__).resolve().parents[2] / "schemas" / "v2"
    manifest = json.loads(schemas.joinpath("manifest.json").read_bytes())
    for name in sorted(manifest["files"]):
        documents.append(
            PackagedResource(
                uri=f"vulnwitness://schemas/{name}",
                name=name,
                description="Committed contract JSON Schema.",
                mime_type="application/json",
                text=schemas.joinpath(name).read_bytes().decode("utf-8"),
            )
        )
    return tuple(documents)
