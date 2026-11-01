"""Loader for the checksum-pinned FiGHT excerpt shipped with the package.

The excerpt is real MITRE data under the terms in its ``NOTICE.md``. Every file
the manifest lists is verified; the data file's hash is then the pin the source
checks against the reviewed snapshot catalog, which states its provenance,
coverage and contents.
"""

from collections.abc import Callable
from datetime import datetime
from importlib.resources import files
from importlib.resources.abc import Traversable

from vulnwitness.adapters.fight.pinned_yaml import PinnedFightYamlSource
from vulnwitness.adapters.fixture.synthetic_fixture import (
    MANIFEST_FILE,
    FixtureFile,
    FixtureIntegrityError,
    read_verified_file,
)
from vulnwitness.domain.contract_model import ContractModel
from vulnwitness.domain.threat_context import FightSnapshotCatalog

NOTICE_FILE = "NOTICE.md"


class FightFixtureManifest(ContractModel):
    fixture: str
    description: str
    data_file: str
    files: tuple[FixtureFile, ...]


def default_fight_fixture_dir() -> Traversable:
    return files("vulnwitness").joinpath("fixtures", "fight")


def load_fight_fixture(
    fixture_dir: Traversable,
    snapshot_catalog: FightSnapshotCatalog,
    clock: Callable[[], datetime],
) -> PinnedFightYamlSource:
    """Verify the excerpt and its notice against the manifest, then load the excerpt."""
    manifest = FightFixtureManifest.model_validate_json(
        fixture_dir.joinpath(MANIFEST_FILE).read_bytes()
    )
    pinned_files: dict[str, FixtureFile] = {}
    for fixture_file in manifest.files:
        read_verified_file(fixture_dir, fixture_file)
        pinned_files[fixture_file.path] = fixture_file
    for required_file in (manifest.data_file, NOTICE_FILE):
        if required_file not in pinned_files:
            raise FixtureIntegrityError(f"manifest does not pin {required_file}")
    data_file = pinned_files[manifest.data_file]
    return PinnedFightYamlSource(
        fixture_dir.joinpath(data_file.path).read_bytes(),
        data_file.sha256,
        snapshot_catalog,
        clock,
    )
