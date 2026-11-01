"""A stdio subprocess with an injected loader controlled by a test-owned FIFO."""

import sys
from functools import partial
from pathlib import Path

from tests.support.fight_excerpt import EXCERPT_SHA256
from vulnwitness.application.serving_data_plane import ServingDataPlane
from vulnwitness.cli import (
    build_parser,
    load_data_plane_or_exit,
    load_mcp_deployment,
    run_recorded_mcp,
)
from vulnwitness.domain.served_dataset import ServedDatasetKind
from vulnwitness.interfaces.mcp.stdio_runner import serve_stdio
from vulnwitness.settings import FightSnapshotSettings, ServiceSettings


class ControlledDataPlaneLoader:
    """Hold startup until the test releases it, then build fixture tools or fail."""

    def __init__(self, release_path: Path, failure: str) -> None:
        self._release_path = release_path
        self._failure = failure

    def __call__(self, command: str, settings: ServiceSettings) -> ServingDataPlane:
        print("test: loader blocked", file=sys.stderr, flush=True)
        with self._release_path.open("rb") as release:
            release.read(1)
        if self._failure == "unexpected":
            raise RuntimeError("private loader exception")
        store_root = self._release_path.parent if self._failure == "store" else None
        fight_snapshot = None
        if self._failure == "snapshot":
            fight_snapshot = FightSnapshotSettings(
                path=self._release_path.parent / "missing.yaml", sha256=EXCERPT_SHA256
            )
        return load_data_plane_or_exit(
            command, ServiceSettings(store_root=store_root, fight_snapshot=fight_snapshot)
        )


def main() -> int:
    loader = ControlledDataPlaneLoader(Path(sys.argv[1]), sys.argv[2])
    settings = ServiceSettings()
    if len(sys.argv) > 3:
        parser = build_parser()
        arguments = parser.parse_args(["mcp", *sys.argv[3:]])
        return run_recorded_mcp(parser, arguments, settings, load_data_plane=loader)
    return serve_stdio(
        partial(load_mcp_deployment, settings, load_data_plane=loader),
        dataset_kind=ServedDatasetKind.SYNTHETIC_FIXTURE,
    )


if __name__ == "__main__":
    sys.exit(main())
