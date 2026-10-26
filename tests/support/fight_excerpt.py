"""The packaged FiGHT excerpt's bytes and SHA-256, for tests that supply it as an operator
snapshot."""

import hashlib

from cve_kgrag.adapters.fixture.fight_fixture import default_fight_fixture_dir

EXCERPT_BYTES = default_fight_fixture_dir().joinpath("fight-excerpt.yaml").read_bytes()
EXCERPT_SHA256 = hashlib.sha256(EXCERPT_BYTES).hexdigest()
