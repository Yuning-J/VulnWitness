"""The case runner starts a run only once every call an earlier run abandoned has
returned and while the package is unchanged, and stops the evaluation otherwise."""

import threading
from pathlib import Path

import pytest

from tests.support.evaluation import (
    EVAL_RESULTS,
    PackageEditingModelPort,
    build_gold_row,
    build_package_dir,
    build_reviewed_fixture_data_planes,
    encode_gold,
    list_entry_names,
)
from tests.support.gold_files import load_trajectory_cases
from tests.support.planners import BlockingModelPort, plan_with
from vulnwitness.adapters.fixture.synthetic_fixture import FixtureBundle
from vulnwitness.application.threaded_call_runner import ThreadedCallRunner
from vulnwitness.evaluation.case_runner import (
    ABANDONED_CALLS_STILL_LIVE,
    PACKAGE_CHANGED,
    PACKAGE_UNREADABLE,
    CaseRunner,
    EvaluationStopped,
    ModelRuns,
    read_package_digest,
)
from vulnwitness.evaluation.gold_cases import GoldCase
from vulnwitness.evaluation.package_digest import fingerprint_package
from vulnwitness.evaluation.result_directory import ResultDirectory

# Long enough for a call that has returned to be counted done, short enough for a test.
SHORT_IDLE_WAIT_SECONDS = 0.2


def build_case_runner(
    tmp_path: Path, fixture_bundle: FixtureBundle, package_dir: Path
) -> tuple[CaseRunner, ResultDirectory]:
    result_directory = ResultDirectory.create(tmp_path / EVAL_RESULTS)
    case_runner = CaseRunner(
        build_reviewed_fixture_data_planes(fixture_bundle),
        ThreadedCallRunner(),
        result_directory,
        package_dir,
        fingerprint_package(package_dir),
        SHORT_IDLE_WAIT_SECONDS,
    )
    return case_runner, result_directory


def load_one_second_case(fight: str) -> GoldCase:
    """The 5G-AKA case with a one-second wall time, so a blocked planner is abandoned
    within a third of a second."""
    (case,) = load_trajectory_cases(
        encode_gold([build_gold_row("5G-AKA", fight, budget={"max_wall_time_seconds": 1})])
    )
    return case


@pytest.mark.parametrize("fight", ["packaged", "unavailable"])
def test_run_after_one_whose_planner_ignores_its_timeout_is_never_started(
    tmp_path: Path,
    fixture_bundle: FixtureBundle,
    blocked_call_release: threading.Event,
    fight: str,
) -> None:
    """The first model run abandons its planner call at the end of the planner's share;
    the second would add to it, so it never starts, whichever FiGHT source the case
    names, and the process holds no more calls than one investigation may leave (ADR
    0005 §2)."""
    case_runner, result_directory = build_case_runner(
        tmp_path, fixture_bundle, build_package_dir(tmp_path)
    )
    model_port = BlockingModelPort(blocked_call_release)

    with pytest.raises(EvaluationStopped) as raised:
        case_runner.run_case(load_one_second_case(fight), ModelRuns(plan_with(model_port), 5))

    assert str(raised.value) == ABANDONED_CALLS_STILL_LIVE
    assert model_port.started_calls == 1
    assert len(list_entry_names(result_directory.path / "model")) == 1


def test_run_after_the_package_changed_is_never_started(
    tmp_path: Path, fixture_bundle: FixtureBundle
) -> None:
    package_dir = build_package_dir(tmp_path)
    case_runner, result_directory = build_case_runner(tmp_path, fixture_bundle, package_dir)
    model_port = PackageEditingModelPort(package_dir / "knowledge" / "card.yaml")

    with pytest.raises(EvaluationStopped) as raised:
        case_runner.run_case(load_one_second_case("packaged"), ModelRuns(plan_with(model_port), 3))

    assert str(raised.value) == PACKAGE_CHANGED
    assert model_port.calls == 1
    assert len(list_entry_names(result_directory.path / "model")) == 1


def test_package_file_that_cannot_be_read_stops_the_evaluation(tmp_path: Path) -> None:
    package_dir = build_package_dir(tmp_path)
    (package_dir / "knowledge" / "card.yaml").chmod(0)

    with pytest.raises(EvaluationStopped) as raised:
        read_package_digest(package_dir)

    assert str(raised.value) == PACKAGE_UNREADABLE
