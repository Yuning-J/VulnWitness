"""Gold files for the evaluation tests: M7b case rows the overrides adjust, encoded as YAML
over a named corpus and FiGHT snapshot, and both formats read as the command reads them."""

from typing import Any

import yaml

from cve_kgrag.domain.hashing import sha256_hex
from cve_kgrag.evaluation.gold_cases import GoldCase, read_gold_cases
from cve_kgrag.evaluation.gold_formats import read_gold_document
from cve_kgrag.evaluation.labelled_cases import GoldFile, read_gold_file
from tests.support.fight_excerpt import EXCERPT_SHA256

UNKNOWN_CORPUS_SHA256 = "0" * 64


def build_case_row(**overrides: Any) -> dict[str, Any]:
    """A sufficient implementation case whose required CVEs name the democorp gateway."""
    row: dict[str, Any] = {
        "id": "democorp-gateway",
        "split": "baseline",
        "goal": "Which known vulnerabilities affect the democorp gateway?",
        "request": {"query": "democorp gateway vulnerabilities", "scope": "implementation_only"},
        "needs": ["implementation_cves"],
        "rules": {
            "cves": {
                "relevant": {"description_any": ["democorp"]},
                "required": {"description_all": ["democorp", "gateway"]},
            }
        },
        "label": {"sufficiency": "sufficient", "reason": "Gateway CVEs exist."},
        "drafted_by": "assistant",
        "confirmed_by": "owner",
        "confirmed_on": "2026-10-28",
    }
    row.update(overrides)
    return row


def encode_gold_file(
    case_rows: list[dict[str, Any]],
    corpus_content_sha256: str = UNKNOWN_CORPUS_SHA256,
    fight_snapshot_sha256: str = EXCERPT_SHA256,
) -> bytes:
    return yaml.safe_dump(
        {
            "corpus_content_sha256": corpus_content_sha256,
            "fight_snapshot_sha256": fight_snapshot_sha256,
            "cases": case_rows,
        },
        sort_keys=False,
    ).encode()


def load_trajectory_cases(gold_bytes: bytes) -> tuple[GoldCase, ...]:
    """M7a's cases, read as ``eval planner`` reads them."""
    return read_gold_cases(read_gold_document(gold_bytes))


def load_labelled_gold_file(gold_bytes: bytes) -> GoldFile:
    """M7b's labelled cases, read as ``eval planner`` and ``eval gold-sets`` read them."""
    return read_gold_file(read_gold_document(gold_bytes), sha256_hex(gold_bytes))
