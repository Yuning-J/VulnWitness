"""``cve-kgrag eval planner`` on a gold file of labelled cases: the gold file's top-level
keys choose the evaluation, ``--sets`` binds the derived sets to it, every stated and
loaded digest is checked before any case runs, and the report adds the dataset and the
sufficiency section over the active store and the operator FiGHT snapshot."""

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from cve_kgrag.adapters.store.corpus_store import verify_corpus_store
from cve_kgrag.cli import main
from cve_kgrag.domain.hashing import sha256_hex
from cve_kgrag.domain.investigation import InvestigationRequest
from cve_kgrag.evaluation.gold_cases import compute_case_sha256
from tests.support.corpus_stores import import_store
from tests.support.evaluation import SMALL_GOLD_ROWS, write_gold_file
from tests.support.fight_excerpt import EXCERPT_BYTES, EXCERPT_SHA256
from tests.support.gold_files import UNKNOWN_CORPUS_SHA256, build_case_row, encode_gold_file

FULL_FIGHT_SHA256 = "59a9addbd75d8680091797d66d5b237d9d026512990c61a6f51692ca94d2a7a8"
PROTOCOL_CASE = build_case_row(
    id="subscriber-keys",
    split="holdout",
    request={"query": "5gaka", "scope": "protocol_context_only"},
    needs=["protocol_context"],
    rules={
        "techniques": {
            "relevant": {"technique_any": ["keys"]},
            "required": {"technique_ids": {"ids": ["FGT5044"], "reasons": {"FGT5044": "x"}}},
        }
    },
)


def run_usage_error(arguments: list[str], environment: dict[str, str]) -> int:
    with pytest.raises(SystemExit) as raised:
        main(arguments, environment)
    return int(str(raised.value.code))


@pytest.fixture
def store_root(tmp_path: Path) -> Path:
    store_root = tmp_path / "stores"
    store_root.mkdir()
    import_store(store_root, "first", cve_numbers=(1, 2))
    return store_root


@pytest.fixture(params=[False, True], ids=["computed_digest", "expected_digest"])
def settings(tmp_path: Path, store_root: Path, request: pytest.FixtureRequest) -> dict[str, str]:
    snapshot_path = tmp_path / "fight.yaml"
    snapshot_path.write_bytes(EXCERPT_BYTES)
    environment = {
        "CVE_KGRAG_STORE_ROOT": str(store_root),
        "CVE_KGRAG_FIGHT_SNAPSHOT_PATH": str(snapshot_path),
    }
    if request.param:
        environment["CVE_KGRAG_FIGHT_SNAPSHOT_SHA256"] = EXCERPT_SHA256
    assert main(["store", "activate", "first"], environment) == 0
    return environment


@pytest.fixture
def corpus_content_sha256(store_root: Path) -> str:
    return verify_corpus_store(store_root / "first").corpus_content_sha256


@pytest.fixture
def gold_path(tmp_path: Path, corpus_content_sha256: str) -> Path:
    gold_path = tmp_path / "gold.yaml"
    gold_path.write_bytes(
        encode_gold_file([build_case_row(), PROTOCOL_CASE], corpus_content_sha256)
    )
    return gold_path


@pytest.fixture
def sets_path(
    tmp_path: Path, gold_path: Path, settings: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> Path:
    assert main(["eval", "gold-sets", "--gold", str(gold_path)], settings) == 0
    sets_path = tmp_path / "sets.json"
    sets_path.write_text(capsys.readouterr().out)
    return sets_path


def evaluate(gold_path: Path, sets_path: Path | None, out_dir: Path) -> list[str]:
    arguments = ["eval", "planner", "--gold", str(gold_path), "--out", str(out_dir)]
    if sets_path is not None:
        arguments += ["--sets", str(sets_path)]
    return arguments


def test_labelled_cases_run_on_the_active_store_and_are_scored(
    tmp_path: Path,
    gold_path: Path,
    sets_path: Path,
    settings: dict[str, str],
    corpus_content_sha256: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    out_dir = tmp_path / "results"

    exit_code = main(evaluate(gold_path, sets_path, out_dir), settings)

    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert exit_code == 0
    assert "packaged synthetic fixture" not in captured.err
    assert report["identity"]["dataset"] == {
        "cve_search_version": f"corpus-store-v1@sha256:{corpus_content_sha256}",
        "fight_profile": "operator_snapshot",
        "fight_snapshot_sha256": EXCERPT_SHA256,
        "sets_sha256": sha256_hex(sets_path.read_bytes()),
    }
    sufficiency_cases = report["sufficiency"]["deterministic"]["cases"]
    assert [case["case_id"] for case in sufficiency_cases] == [
        "democorp-gateway",
        "subscriber-keys",
    ]
    assert report["sufficiency"]["model"] is None
    (result_dir,) = out_dir.iterdir()
    for sufficiency_case in sufficiency_cases:
        assert (result_dir / "deterministic" / f"{sufficiency_case['case_sha256']}.json").is_file()
    behaviour_hashes = []
    for deterministic_case in report["deterministic"]["cases"]:
        behaviour_hashes.append(deterministic_case["case_sha256"])
    expected_hash = compute_case_sha256(
        InvestigationRequest.model_validate(build_case_row()["request"]), "operator"
    )
    assert behaviour_hashes[0] == expected_hash == sufficiency_cases[0]["case_sha256"]


def test_trajectories_still_run_on_the_fixture_with_the_fixture_dataset(
    tmp_path: Path, settings: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    trajectories_path = write_gold_file(tmp_path, SMALL_GOLD_ROWS)

    exit_code = main(evaluate(trajectories_path, None, tmp_path / "results"), settings)

    report = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert report["identity"]["dataset"]["fight_profile"] == "per_case"
    assert report["identity"]["dataset"]["sets_sha256"] is None
    assert report["sufficiency"] is None


@pytest.mark.parametrize(
    ("gold_document", "with_sets", "expected_problem"),
    [
        ({"cases": []}, True, "invalid gold file"),
        ({"trajectories": [], "cases": []}, True, "invalid gold file"),
        ({"other": 1}, False, "invalid gold file"),
        ({"trajectories": []}, True, "--sets is for a gold file of labelled cases"),
        (
            {
                "cases": [],
                "corpus_content_sha256": UNKNOWN_CORPUS_SHA256,
                "fight_snapshot_sha256": EXCERPT_SHA256,
            },
            False,
            "needs --sets",
        ),
    ],
    ids=[
        "partial_labelled_signature",
        "both_signatures",
        "neither_signature",
        "sets_with_trajectories",
        "labelled_cases_without_sets",
    ],
)
def test_gold_file_and_sets_of_no_single_format_are_usage_errors(
    tmp_path: Path,
    settings: dict[str, str],
    capsys: pytest.CaptureFixture[str],
    gold_document: dict[str, Any],
    with_sets: bool,
    expected_problem: str,
) -> None:
    gold_path = tmp_path / "gold.yaml"
    gold_path.write_text(json.dumps(gold_document))
    sets_path = tmp_path / "sets.json" if with_sets else None
    out_dir = tmp_path / "results"

    exit_code = run_usage_error(evaluate(gold_path, sets_path, out_dir), settings)

    assert exit_code == 2
    assert expected_problem in capsys.readouterr().err
    assert not out_dir.exists()


@pytest.mark.parametrize(
    ("removed_variables", "expected_variable"),
    [
        (("CVE_KGRAG_STORE_ROOT",), "CVE_KGRAG_STORE_ROOT"),
        (
            ("CVE_KGRAG_FIGHT_SNAPSHOT_PATH", "CVE_KGRAG_FIGHT_SNAPSHOT_SHA256"),
            "CVE_KGRAG_FIGHT_SNAPSHOT_PATH",
        ),
    ],
    ids=["no_store_root", "no_fight_snapshot"],
)
def test_labelled_cases_without_their_sources_are_a_usage_error(
    tmp_path: Path,
    gold_path: Path,
    sets_path: Path,
    settings: dict[str, str],
    capsys: pytest.CaptureFixture[str],
    removed_variables: tuple[str, ...],
    expected_variable: str,
) -> None:
    environment = dict(settings)
    for variable in removed_variables:
        environment.pop(variable, None)

    exit_code = run_usage_error(evaluate(gold_path, sets_path, tmp_path / "results"), environment)

    assert exit_code == 2
    assert expected_variable in capsys.readouterr().err


def rewrite_gold_and_sets(gold_path: Path, sets_path: Path, **digests: str) -> None:
    """Restate the gold file's and the sets file's data digests together, keeping the sets
    file bound to the rewritten gold file, so only the check under test can fail."""
    gold_document = yaml.safe_load(gold_path.read_text())
    gold_document.update(digests)
    gold_bytes = encode_gold_file(
        gold_document["cases"],
        gold_document["corpus_content_sha256"],
        gold_document["fight_snapshot_sha256"],
    )
    gold_path.write_bytes(gold_bytes)
    sets_document = json.loads(sets_path.read_text())
    sets_document.update(digests)
    sets_document["gold_file_sha256"] = sha256_hex(gold_bytes)
    sets_path.write_text(json.dumps(sets_document, indent=2, sort_keys=True) + "\n")


def run_refused(
    tmp_path: Path,
    gold_path: Path,
    sets_path: Path,
    settings: dict[str, str],
    capsys: pytest.CaptureFixture[str],
) -> tuple[int, str]:
    """Run the evaluation expecting it to stop before any case: no result directory."""
    out_dir = tmp_path / "results"
    exit_code = main(evaluate(gold_path, sets_path, out_dir), settings)
    assert not out_dir.exists()
    captured = capsys.readouterr()
    assert captured.out == ""
    return exit_code, captured.err


def test_sets_derived_from_another_gold_file_revision_are_refused(
    tmp_path: Path,
    gold_path: Path,
    sets_path: Path,
    settings: dict[str, str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    gold_path.write_text(gold_path.read_text().replace("Gateway CVEs exist.", "Revised."))

    exit_code, message = run_refused(tmp_path, gold_path, sets_path, settings, capsys)

    assert exit_code == 1
    assert "the sets file was derived from another gold file" in message


def test_configured_snapshot_other_than_the_gold_file_s_is_refused(
    tmp_path: Path,
    gold_path: Path,
    sets_path: Path,
    settings: dict[str, str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    rewrite_gold_and_sets(gold_path, sets_path, fight_snapshot_sha256=FULL_FIGHT_SHA256)

    exit_code, message = run_refused(tmp_path, gold_path, sets_path, settings, capsys)

    assert exit_code == 1
    assert "FiGHT snapshot is not the one" in message


def test_sets_file_naming_another_corpus_than_the_gold_file_is_refused(
    tmp_path: Path,
    gold_path: Path,
    sets_path: Path,
    settings: dict[str, str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    sets_document = json.loads(sets_path.read_text())
    sets_document["corpus_content_sha256"] = UNKNOWN_CORPUS_SHA256
    sets_path.write_text(json.dumps(sets_document))

    exit_code, message = run_refused(tmp_path, gold_path, sets_path, settings, capsys)

    assert exit_code == 1
    assert "the sets file names another corpus than the gold file" in message


def test_loaded_store_other_than_the_one_both_files_name_is_refused(
    tmp_path: Path,
    gold_path: Path,
    sets_path: Path,
    settings: dict[str, str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    rewrite_gold_and_sets(gold_path, sets_path, corpus_content_sha256=UNKNOWN_CORPUS_SHA256)

    exit_code, message = run_refused(tmp_path, gold_path, sets_path, settings, capsys)

    assert exit_code == 1
    assert "the active store's corpus is not the one" in message


def test_malformed_sets_file_is_refused_without_a_traceback_or_its_keys(
    tmp_path: Path,
    gold_path: Path,
    sets_path: Path,
    settings: dict[str, str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    sets_document = json.loads(sets_path.read_text())
    sets_document["\x1b[31mforged"] = 1
    sets_path.write_text(json.dumps(sets_document))

    exit_code, message = run_refused(tmp_path, gold_path, sets_path, settings, capsys)

    assert exit_code == 1
    assert "the sets file breaks its shape" in message
    assert "forged" not in message
    assert "Traceback" not in message
