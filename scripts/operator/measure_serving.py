"""Build what a serving process builds from a store root, and print how long each part
took (ADR 0009 §12, §17). MODE is ``load`` (``load_served_corpus`` alone), ``api`` (the
API's toolbox and verification deployment over one shared data plane) or
``api-separate`` (the same two deployments, each over its own data plane, for
comparison). Run under a resource meter for peak memory.
Usage: measure_serving.py MODE STORE_ROOT"""

import sys
import time
from pathlib import Path

from vulnwitness.cli import build_evidence_set_check
from vulnwitness.composition import (
    build_knowledge_toolbox,
    build_serving_data_plane,
    load_served_corpus,
)


def main(mode: str, store_root: Path) -> None:
    started_at = time.monotonic()
    served_corpus = load_served_corpus(store_root)
    loaded_at = time.monotonic()
    print(f"records: {len(served_corpus.records)}")
    print(f"load_served_corpus: {loaded_at - started_at:.1f} s")
    if mode == "load":
        return
    if mode == "api":
        data_plane = build_serving_data_plane(served_corpus)
        build_knowledge_toolbox(data_plane)
        build_evidence_set_check(data_plane, None)
    elif mode == "api-separate":
        build_knowledge_toolbox(build_serving_data_plane(served_corpus))
        build_evidence_set_check(build_serving_data_plane(served_corpus), None)
    else:
        raise SystemExit(f"unknown mode {mode!r}")
    built_at = time.monotonic()
    print(f"{mode} deployments: {built_at - loaded_at:.1f} s")
    print(f"total: {built_at - started_at:.1f} s")


if __name__ == "__main__":
    main(sys.argv[1], Path(sys.argv[2]))
