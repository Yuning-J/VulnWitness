"""Load the packaged catalog of reviewed FiGHT snapshots (``knowledge/fight_snapshots.yaml``)."""

from importlib.resources import files
from importlib.resources.abc import Traversable

from cve_kgrag.adapters.strict_yaml import load_strict_yaml
from cve_kgrag.domain.threat_context import FightSnapshotCatalog


def default_fight_snapshot_catalog_file() -> Traversable:
    return files("cve_kgrag").joinpath("knowledge", "fight_snapshots.yaml")


def load_fight_snapshot_catalog(catalog_file: Traversable) -> FightSnapshotCatalog:
    return FightSnapshotCatalog.model_validate(
        load_strict_yaml(catalog_file.read_text(encoding="utf-8"))
    )
