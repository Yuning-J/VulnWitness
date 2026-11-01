"""One offline release check of graph expansion over one real-store load.

Usage: .venv/bin/python scripts/operator/measure_graph_expand.py OUTPUT_DIR
       --serving-baseline-bytes BYTES
The baseline comes from the operator's external serving measurement.
Measures the synchronous search service (as the CLI does), including late completions;
compares wall time with ToolLimits, and interrupts a stuck call after 60 seconds.
Outputs contain aggregates and CVE IDs only. Never enables semantic retrieval or a model.
"""

import argparse
import json
import math
import os
import resource
import signal
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from statistics import median
from types import FrameType
from typing import Any

import yaml

from vulnwitness.application.search import SearchService
from vulnwitness.cli import build_evidence_set_check
from vulnwitness.composition import (
    build_knowledge_toolbox,
    build_serving_data_plane,
    load_fight_source,
    load_served_corpus,
)
from vulnwitness.domain.relations import Relation, record_relations
from vulnwitness.domain.search import SearchRequest
from vulnwitness.domain.taxonomy import BackendStatus, RetrievalChannel
from vulnwitness.interfaces.knowledge_tools import ToolLimits
from vulnwitness.ports.served_corpus import ServedCorpus
from vulnwitness.settings import load_settings

RSS_ALLOWANCE_BYTES = 1_073_741_824
WATCHDOG_SECONDS = 60
OUTPUT_ROOT = Path.home() / "data/vulnwitness/runs/graph-expand"
RELATION_KINDS = ("cwe", "vendor", "product", "cpe", "purl")
PASS_CRITERIA = {
    "typical": "All 10 finish within ToolLimits.time_limit_seconds with an OK graph outcome.",
    "high_degree": (
        "All 10 finish within the limit with an OK graph outcome, or an existing honest "
        "bounded graph outcome/warning. A late successful synchronous return is a failure; "
        "result_limit_reached bounds the returned list, not the traversal."
    ),
    "memory": "Process peak RSS <= the recorded serving baseline + 1 GiB.",
    "watchdog": "Operator watchdog interruption or any exception is a failure.",
}


def peak_rss_bytes() -> int:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(peak if sys.platform == "darwin" else peak * 1024)


def interrupt_search(signum: int, frame: FrameType | None) -> None:
    raise TimeoutError("operator watchdog")


def select_typical_seeds(service: SearchService) -> list[str]:
    # Only baseline cases from M7b may influence this check; relevance is unrestricted.
    gold_root = Path(__file__).resolve().parents[2] / "eval/gold"
    baseline_cases = []
    for case in yaml.safe_load((gold_root / "m7b_cases.yaml").read_text())["cases"]:
        if case["split"] == "baseline":
            baseline_cases.append(case)
    relevance_cases = yaml.safe_load((gold_root / "relevance_cases.yaml").read_text())["cases"]
    reviewed_cases = str(baseline_cases) + str(relevance_cases)
    seeds: list[str] = []
    for product in ("Open5GS", "free5GC", "Kamailio", "OpenSIPS", "OpenAirInterface"):
        if product.casefold() not in reviewed_cases.casefold():
            raise ValueError("typical product is not named by the permitted gold cases")
        search_answer = service.search(SearchRequest(query=product, semantic=False, limit=2))
        for candidate in search_answer.candidates:
            if candidate.record.cve_id not in seeds:
                seeds.append(candidate.record.cve_id)
    if len(seeds) != 10:
        raise ValueError("expected exactly ten distinct typical seeds")
    return seeds


def measure_relations(corpus: ServedCorpus) -> tuple[Counter[Relation], dict[str, Any]]:
    degrees: Counter[Relation] = Counter()
    for record in corpus.records:
        degrees.update(record_relations(record))
    distribution = {}
    for kind in RELATION_KINDS:
        kind_degrees = []
        for relation, degree in degrees.items():
            if relation[0] == kind:
                kind_degrees.append(degree)
        kind_degrees.sort()
        distribution[kind] = {
            "count": len(kind_degrees),
            "median": median(kind_degrees) if kind_degrees else None,
            "p99": kind_degrees[math.ceil(len(kind_degrees) * 0.99) - 1] if kind_degrees else None,
            "max": max(kind_degrees) if kind_degrees else None,
        }
    return degrees, distribution


def select_high_degree_seeds(
    corpus: ServedCorpus, degrees: Counter[Relation], typical_seeds: list[str]
) -> list[tuple[str, str, int]]:
    selected = []
    excluded = set(typical_seeds)
    # Four highest-degree CWEs, three vendors and three products; CVE-ID tie break.
    for kind, count in (("cwe", 4), ("vendor", 3), ("product", 3)):
        ranked_relations = []
        for relation, degree in degrees.items():
            if relation[0] == kind:
                ranked_relations.append((degree, relation))
        ranked_relations.sort(key=lambda entry: (-entry[0], entry[1]))
        for degree, relation in ranked_relations[:count]:
            for record in corpus.records:
                if record.cve_id not in excluded and relation in record_relations(record):
                    selected.append((record.cve_id, kind, degree))
                    excluded.add(record.cve_id)
                    break
    if len(selected) != 10:
        raise ValueError("expected exactly ten distinct high-degree seeds")
    return selected


def measure_seed(service: SearchService, seed_class: str, cve_id: str) -> dict[str, Any]:
    measurement: dict[str, Any] = {"seed_class": seed_class, "cve_id": cve_id}
    started_at = time.monotonic()
    signal.setitimer(signal.ITIMER_REAL, WATCHDOG_SECONDS)
    try:
        search_answer = service.search(
            SearchRequest(query=cve_id, graph_expand=True, semantic=False, limit=10)
        )
        graph_outcome = None
        for outcome in search_answer.channel_outcomes:
            if outcome.channel is RetrievalChannel.GRAPH:
                graph_outcome = outcome
        measurement["candidates"] = len(search_answer.candidates)
        measurement["graph_outcome"] = (
            graph_outcome.model_dump(mode="json") if graph_outcome is not None else None
        )
        warnings = []
        for warning in search_answer.warnings:
            warnings.append(warning.code.value)
        measurement["warnings"] = warnings
        measurement["usable_graph"] = (
            graph_outcome is not None and graph_outcome.status is BackendStatus.OK
        )
        measurement["error_type"] = None
    except Exception as error:
        # Exception text can contain record text; only the class is recorded.
        measurement.update(
            candidates=None,
            graph_outcome=None,
            warnings=[],
            usable_graph=False,
            error_type=type(error).__name__,
        )
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    measurement["wall_seconds"] = time.monotonic() - started_at
    measurement["finished_in_limit"] = (
        measurement["error_type"] is None
        and measurement["wall_seconds"] <= ToolLimits().time_limit_seconds
    )
    measurement["peak_rss_bytes"] = peak_rss_bytes()
    measurement["passed"] = measurement["finished_in_limit"] and measurement["usable_graph"]
    return measurement


def write_report(report: dict[str, Any], output_dir: Path) -> None:
    (output_dir / "measurement.json").write_text(json.dumps(report, indent=2) + "\n")
    lines = [
        f"Graph expansion release check: {'PASS' if report['passed'] else 'FAIL'}",
        f"Date: {report['measured_at']}",
        f"Corpus: `{report['corpus_content_sha256']}` ({report['records']:,} records)",
        "",
        "Fixed criteria:",
    ]
    for criterion in PASS_CRITERIA.values():
        lines.append(f"- {criterion}")
    lines.extend(
        [
            "",
            "Degrees count distinct relation values; p99 uses nearest rank.",
            "",
            "| Relation | Count | Median | p99 | Max |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    for kind, distribution in report["degree_distribution"].items():
        lines.append(
            f"| {kind} | {distribution['count']} | {distribution['median']} | "
            f"{distribution['p99']} | {distribution['max']} |"
        )
    lines.extend(
        [
            "",
            "Candidate counts are returned candidates at limit 10, not visited nodes.",
            "| Class | CVE | Wall (s) | Within 10 s | Candidates | Graph / warnings |",
            "|---|---|---:|---|---:|---|",
        ]
    )
    for measurement in report["seeds"]:
        outcome = measurement["graph_outcome"]
        outcome_text = outcome["status"] if outcome else measurement["error_type"]
        warnings = ", ".join(measurement["warnings"])
        lines.append(
            f"| {measurement['seed_class']} | {measurement['cve_id']} | "
            f"{measurement['wall_seconds']:.3f} | {measurement['finished_in_limit']} | "
            f"{measurement['candidates']} | {outcome_text}; {warnings} |"
        )
    lines.extend(
        [
            "",
            f"Peak RSS: {report['peak_rss_bytes']:,} bytes; "
            f"serving baseline: {report['serving_baseline_bytes']:,}; "
            f"allowance: {RSS_ALLOWANCE_BYTES:,}.",
            f"Memory criterion: {report['memory_passed']}.",
            f"Same-process serving peak before measurement: "
            f"{report['same_process_serving_peak_rss_bytes']:,} bytes.",
        ]
    )
    (output_dir / "summary.md").write_text("\n".join(lines) + "\n")


def main(output_dir: Path, serving_baseline_bytes: int) -> None:
    if serving_baseline_bytes <= 0:
        raise SystemExit("serving baseline must be a positive byte count")
    if not output_dir.resolve().is_relative_to(OUTPUT_ROOT.resolve()):
        raise SystemExit("output must be under ~/data/vulnwitness/runs/graph-expand")
    output_dir.mkdir(parents=True, exist_ok=True)
    if (output_dir / "measurement.json").exists():
        raise SystemExit("measurement already exists; do not repeat this release check")
    settings = load_settings(os.environ)
    if settings.store_root is None:
        raise SystemExit("a real store root is required")
    print("Loading the corpus once", flush=True)
    started_at = time.monotonic()
    corpus = load_served_corpus(settings.store_root)
    fight_source, fight_pin = load_fight_source(settings.fight_snapshot)
    data_plane = build_serving_data_plane(
        corpus, fight_source=fight_source, pinned_fight_snapshot=fight_pin
    )
    toolbox = build_knowledge_toolbox(data_plane)
    check_evidence_set = build_evidence_set_check(data_plane, None)
    report: dict[str, Any] = {
        "measured_at": datetime.now(UTC).isoformat(),
        "corpus_content_sha256": corpus.describe_served_dataset().cve_search_version.split(":")[-1],
        "records": len(corpus.records),
        "pass_criteria": PASS_CRITERIA,
        "time_limit_seconds": toolbox.limits.time_limit_seconds,
        "watchdog_seconds": WATCHDOG_SECONDS,
        "serving_baseline_bytes": serving_baseline_bytes,
        "rss_allowance_bytes": RSS_ALLOWANCE_BYTES,
        "same_process_serving_peak_rss_bytes": peak_rss_bytes(),
        "serving_build_seconds": time.monotonic() - started_at,
        "seeds": [],
    }
    print("Serving built; measuring degrees and selecting seeds", flush=True)
    degrees, report["degree_distribution"] = measure_relations(corpus)
    typical_seeds = select_typical_seeds(data_plane.search_service)
    high_degree_seeds = select_high_degree_seeds(corpus, degrees, typical_seeds)
    del degrees
    signal.signal(signal.SIGALRM, interrupt_search)
    for cve_id in typical_seeds:
        measurement = measure_seed(data_plane.search_service, "typical", cve_id)
        report["seeds"].append(measurement)
        print(f"typical {cve_id}: {measurement['wall_seconds']:.3f}s", flush=True)
    for cve_id, kind, degree in high_degree_seeds:
        measurement = measure_seed(data_plane.search_service, "high_degree", cve_id)
        measurement.update(selection_relation_kind=kind, selection_relation_degree=degree)
        report["seeds"].append(measurement)
        print(f"high_degree {cve_id}: {measurement['wall_seconds']:.3f}s", flush=True)
    report["peak_rss_bytes"] = peak_rss_bytes()
    report["memory_passed"] = report["peak_rss_bytes"] <= (
        serving_baseline_bytes + RSS_ALLOWANCE_BYTES
    )
    report["passed"] = report["memory_passed"] and all(
        measurement["passed"] for measurement in report["seeds"]
    )
    write_report(report, output_dir)
    # Retain the same objects as the API serving baseline through the measurements.
    del toolbox, check_evidence_set
    print(f"{'PASS' if report['passed'] else 'FAIL'}; report written", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--serving-baseline-bytes", type=int, required=True)
    arguments = parser.parse_args()
    main(arguments.output_dir, arguments.serving_baseline_bytes)
