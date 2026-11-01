"""A stdio subprocess with an injected loader controlled by a test-owned FIFO."""

import sys
from pathlib import Path

from tests.support.fight_excerpt import EXCERPT_SHA256
from vulnwitness.cli import load_mcp_toolbox
from vulnwitness.domain.served_dataset import ServedDatasetKind
from vulnwitness.interfaces.knowledge_toolbox import KnowledgeToolbox
from vulnwitness.interfaces.mcp.stdio_runner import serve_stdio
from vulnwitness.settings import FightSnapshotSettings, ServiceSettings


class ControlledToolboxLoader:
    """Hold startup until the test releases it, then build fixture tools or fail."""

    def __init__(self, release_path: Path, failure: str) -> None:
        self._release_path = release_path
        self._failure = failure

    def __call__(self) -> KnowledgeToolbox:
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
        return load_mcp_toolbox(
            ServiceSettings(store_root=store_root, fight_snapshot=fight_snapshot)
        )


def main() -> int:
    return serve_stdio(
        ControlledToolboxLoader(Path(sys.argv[1]), sys.argv[2]),
        dataset_kind=ServedDatasetKind.SYNTHETIC_FIXTURE,
    )


if __name__ == "__main__":
    sys.exit(main())
