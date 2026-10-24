"""The planner evaluation runner names the evaluated source and package, runs every case,
and writes each set and the report once; it writes no report when a run saw another
package."""

import os
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.application.planner_setup import ModelPlanning
from cve_kgrag.domain.investigation import KnowledgeEvidenceSet
from cve_kgrag.domain.search import SCHEMA_VERSION
from cve_kgrag.evaluation.case_runner import PACKAGE_CHANGED, EvaluationStopped, ModelRuns
from cve_kgrag.evaluation.gold_cases import load_gold_cases
from cve_kgrag.evaluation.planner_report import PlannerEvaluationReport, format_report
from cve_kgrag.evaluation.planner_runner import (
    REPORT_FILE_NAME,
    read_source_revision,
    run_planner_evaluation,
)
from cve_kgrag.evaluation.result_directory import ResultDirectory
from tests.support.evaluation import (
    EVAL_RESULTS,
    SMALL_GOLD_ROWS,
    PackageEditingModelPort,
    build_package_dir,
    encode_gold,
    list_entry_names,
)
from tests.support.planners import (
    SCRIPTED_PLANNER,
    UNAVAILABLE_REPLY,
    ScriptedModelPort,
    plan_with,
)


def read_written_set(result_directory: ResultDirectory, relative_path: str) -> KnowledgeEvidenceSet:
    return KnowledgeEvidenceSet.model_validate_json(
        (result_directory.path / relative_path).read_bytes()
    )


def test_deterministic_evaluation_writes_each_case_s_set_and_the_report_it_returns(
    tmp_path: Path, fixture_bundle: FixtureBundle
) -> None:
    cases = load_gold_cases(encode_gold(SMALL_GOLD_ROWS))
    result_directory = ResultDirectory.create(tmp_path)

    report = run_planner_evaluation(
        cases,
        gold_sha256="d" * 64,
        bundle=fixture_bundle,
        model_runs=None,
        source_revision="unavailable",
        package_dir=build_package_dir(tmp_path),
        result_directory=result_directory,
    )

    written_report = (result_directory.path / REPORT_FILE_NAME).read_bytes()
    assert written_report == format_report(report)
    assert PlannerEvaluationReport.model_validate_json(written_report) == report
    assert report.model is None
    assert (report.identity.gold_sha256, report.identity.model_runs_per_case) == ("d" * 64, 0)
    assert report.identity.model_planner_sha256 is None
    for case, deterministic_case in zip(cases, report.deterministic.cases, strict=True):
        evidence_set = read_written_set(result_directory, f"deterministic/{case.case_sha256}.json")
        assert evidence_set.request == case.request
        assert deterministic_case.case_sha256 == case.case_sha256
    assert sorted(list_entry_names(result_directory.path)) == ["deterministic", REPORT_FILE_NAME]


def test_case_with_fight_unavailable_runs_on_a_deployment_serving_no_snapshot(
    tmp_path: Path, fixture_bundle: FixtureBundle
) -> None:
    cases = load_gold_cases(encode_gold(SMALL_GOLD_ROWS))
    result_directory = ResultDirectory.create(tmp_path)

    run_planner_evaluation(
        cases,
        gold_sha256="d" * 64,
        bundle=fixture_bundle,
        model_runs=None,
        source_revision="unavailable",
        package_dir=build_package_dir(tmp_path),
        result_directory=result_directory,
    )

    fight_states: list[str] = []
    for case in cases:
        evidence_set = read_written_set(result_directory, f"deterministic/{case.case_sha256}.json")
        for capability in evidence_set.source_capabilities:
            if capability.source == "mitre_fight":
                fight_states.append(capability.state.value)
    assert fight_states == ["available", "unavailable"]


def test_model_evaluation_runs_each_case_the_given_number_of_times(
    tmp_path: Path, fixture_bundle: FixtureBundle
) -> None:
    cases = load_gold_cases(encode_gold(SMALL_GOLD_ROWS))
    result_directory = ResultDirectory.create(tmp_path)
    model_port = ScriptedModelPort([UNAVAILABLE_REPLY] * 6)

    report = run_planner_evaluation(
        cases,
        gold_sha256="d" * 64,
        bundle=fixture_bundle,
        model_runs=ModelRuns(plan_with(model_port), 3),
        source_revision="unavailable",
        package_dir=build_package_dir(tmp_path),
        result_directory=result_directory,
    )

    assert len(model_port.planning_inputs) == 6
    assert report.model is not None
    assert report.model.runs == 6
    assert report.identity.model_runs_per_case == 3
    for case in cases:
        for run_number in (1, 2, 3):
            evidence_set = read_written_set(
                result_directory, f"model/{case.case_sha256}-{run_number:02d}.json"
            )
            assert evidence_set.trajectory.planner == SCRIPTED_PLANNER


def evaluate_one_model_run(
    tmp_path: Path, fixture_bundle: FixtureBundle, model_planning: ModelPlanning
) -> PlannerEvaluationReport:
    """The report of one model run of the small gold file's first case."""
    (case,) = load_gold_cases(encode_gold(SMALL_GOLD_ROWS[:1]))
    return run_planner_evaluation(
        (case,),
        gold_sha256="d" * 64,
        bundle=fixture_bundle,
        model_runs=ModelRuns(model_planning, 1),
        source_revision="unavailable",
        package_dir=build_package_dir(tmp_path),
        result_directory=ResultDirectory.create(tmp_path),
    )


def test_report_identity_names_each_planner_by_its_own_hash(
    tmp_path: Path, fixture_bundle: FixtureBundle
) -> None:
    other_planner = SCRIPTED_PLANNER.model_copy(update={"model_name": "another-model"})

    scripted_identity = evaluate_one_model_run(
        tmp_path, fixture_bundle, plan_with(ScriptedModelPort([UNAVAILABLE_REPLY]))
    ).identity
    repeated_identity = evaluate_one_model_run(
        tmp_path, fixture_bundle, plan_with(ScriptedModelPort([UNAVAILABLE_REPLY]))
    ).identity
    other_identity = evaluate_one_model_run(
        tmp_path,
        fixture_bundle,
        ModelPlanning(other_planner, ScriptedModelPort([UNAVAILABLE_REPLY])),
    ).identity

    assert scripted_identity == repeated_identity
    assert scripted_identity.model_planner_sha256 != other_identity.model_planner_sha256
    assert (
        scripted_identity.deterministic_planner_sha256
        == other_identity.deterministic_planner_sha256
    )
    assert scripted_identity.model_planner_sha256 != scripted_identity.deterministic_planner_sha256
    assert scripted_identity.evidence_set_schema_version == SCHEMA_VERSION


@pytest.mark.parametrize(
    "source_revision",
    ["a" * 40, "b" * 64 + "+dirty", "unavailable"],
    ids=["sha1", "sha256_dirty", "unavailable"],
)
def test_every_revision_the_runner_reads_is_one_the_report_accepts(
    tmp_path: Path, fixture_bundle: FixtureBundle, source_revision: str
) -> None:
    (case,) = load_gold_cases(encode_gold(SMALL_GOLD_ROWS[:1]))

    report = run_planner_evaluation(
        (case,),
        gold_sha256="d" * 64,
        bundle=fixture_bundle,
        model_runs=None,
        source_revision=source_revision,
        package_dir=build_package_dir(tmp_path),
        result_directory=ResultDirectory.create(tmp_path),
    )

    assert report.identity.source_revision == source_revision


def test_revision_the_report_rejects_stops_the_run_before_any_case_runs(
    tmp_path: Path, fixture_bundle: FixtureBundle
) -> None:
    cases = load_gold_cases(encode_gold(SMALL_GOLD_ROWS))
    result_directory = ResultDirectory.create(tmp_path)

    with pytest.raises(ValidationError):
        run_planner_evaluation(
            cases,
            gold_sha256="d" * 64,
            bundle=fixture_bundle,
            model_runs=None,
            source_revision="not-a-revision",
            package_dir=build_package_dir(tmp_path),
            result_directory=result_directory,
        )

    assert list_entry_names(result_directory.path) == []


def test_package_changed_by_the_last_run_stops_the_evaluation_before_its_report(
    tmp_path: Path, fixture_bundle: FixtureBundle
) -> None:
    package_dir = build_package_dir(tmp_path)
    # One case: the edit lands in the last run, so only the check after it can see it.
    cases = load_gold_cases(encode_gold(SMALL_GOLD_ROWS[:1]))
    result_directory = ResultDirectory.create(tmp_path / EVAL_RESULTS)
    model_port = PackageEditingModelPort(package_dir / "knowledge" / "card.yaml")

    with pytest.raises(EvaluationStopped) as raised:
        run_planner_evaluation(
            cases,
            gold_sha256="d" * 64,
            bundle=fixture_bundle,
            model_runs=ModelRuns(plan_with(model_port), 1),
            source_revision="unavailable",
            package_dir=package_dir,
            result_directory=result_directory,
        )

    assert str(raised.value) == PACKAGE_CHANGED
    assert not (result_directory.path / REPORT_FILE_NAME).exists()


def run_git(directory: Path, *arguments: str) -> str:
    """Git's output for ``arguments`` in ``directory``, under no global or system config,
    so neither commit signing nor hooks configured on the machine change the test."""
    completed = subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            *arguments,
        ],
        cwd=directory,
        env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"},
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def build_checkout(root: Path) -> Path:
    """A git repository committing a ``src/cve_kgrag`` package; its package directory."""
    package_dir = root / "src" / "cve_kgrag"
    package_dir.mkdir(parents=True)
    (package_dir / "__init__.py").write_text("", encoding="utf-8")
    run_git(root, "init", "--quiet")
    run_git(root, "add", ".")
    run_git(root, "commit", "--quiet", "--no-verify", "-m", "package")
    return package_dir


def test_source_revision_is_the_checkout_s_commit(tmp_path: Path) -> None:
    package_dir = build_checkout(tmp_path)
    head = run_git(tmp_path, "rev-parse", "HEAD")

    source_revision = read_source_revision(package_dir)

    assert source_revision == head


def test_reading_the_source_revision_never_rewrites_the_index(tmp_path: Path) -> None:
    """Plain ``git status`` refreshes a stale index in place, which would race a commit
    running in the operator's checkout."""
    package_dir = build_checkout(tmp_path)
    tracked_file = package_dir / "__init__.py"
    # Unchanged content with a new modification time: git status always refreshes such an
    # entry's stat data, and rewrites the index unless it may take no optional lock.
    later_seconds = tracked_file.stat().st_mtime + 60
    os.utime(tracked_file, (later_seconds, later_seconds))
    index_path = tmp_path / ".git" / "index"
    index_before = (index_path.read_bytes(), index_path.stat().st_mtime_ns)

    read_source_revision(package_dir)

    assert (index_path.read_bytes(), index_path.stat().st_mtime_ns) == index_before


def test_source_revision_marks_uncommitted_changes_to_tracked_files(tmp_path: Path) -> None:
    package_dir = build_checkout(tmp_path)
    (package_dir / "__init__.py").write_text("CHANGED = True\n", encoding="utf-8")

    source_revision = read_source_revision(package_dir)

    assert source_revision.endswith("+dirty")


def test_source_revision_ignores_untracked_files(tmp_path: Path) -> None:
    package_dir = build_checkout(tmp_path)
    (tmp_path / "eval-results").mkdir()
    (tmp_path / "eval-results" / "report.json").write_text("{}", encoding="utf-8")

    source_revision = read_source_revision(package_dir)

    assert not source_revision.endswith("+dirty")


def test_source_revision_is_unavailable_outside_a_checkout(tmp_path: Path) -> None:
    package_dir = tmp_path / "site-packages" / "cve_kgrag"
    package_dir.mkdir(parents=True)

    assert read_source_revision(package_dir) == "unavailable"


def test_source_revision_is_unavailable_for_a_package_inside_another_repository(
    tmp_path: Path,
) -> None:
    """An installed package in a virtual environment kept inside some repository is not
    that repository's source."""
    build_checkout(tmp_path)
    installed_package_dir = tmp_path / ".venv" / "site-packages" / "cve_kgrag"
    installed_package_dir.mkdir(parents=True)

    assert read_source_revision(installed_package_dir) == "unavailable"
