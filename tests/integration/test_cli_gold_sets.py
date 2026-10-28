"""``cve-kgrag eval gold-sets`` over a synthetic store under a root and the packaged FiGHT
excerpt as the operator snapshot: it prints each case's sets, ``--check`` compares them
with a recorded file, and settings, sources or labels it cannot use end the run with a
closed reason."""

import json
from pathlib import Path

import pytest

from cve_kgrag.adapters.store.corpus_store import verify_corpus_store
from cve_kgrag.cli import main
from tests.support.corpus_stores import import_store
from tests.support.fight_excerpt import EXCERPT_BYTES, EXCERPT_SHA256
from tests.support.gold_files import UNKNOWN_CORPUS_SHA256, build_case_row, encode_gold_file

FULL_FIGHT_SHA256 = "59a9addbd75d8680091797d66d5b237d9d026512990c61a6f51692ca94d2a7a8"
PROTOCOL_CASE = build_case_row(
    id="subscriber-keys",
    request={"query": "subscriber key threats", "scope": "protocol_context_only"},
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


@pytest.fixture
def settings(tmp_path: Path, store_root: Path) -> dict[str, str]:
    snapshot_path = tmp_path / "fight.yaml"
    snapshot_path.write_bytes(EXCERPT_BYTES)
    environment = {
        "CVE_KGRAG_STORE_ROOT": str(store_root),
        "CVE_KGRAG_FIGHT_SNAPSHOT_PATH": str(snapshot_path),
        "CVE_KGRAG_FIGHT_SNAPSHOT_SHA256": EXCERPT_SHA256,
    }
    assert main(["store", "activate", "first"], environment) == 0
    return environment


@pytest.fixture
def corpus_content_sha256(store_root: Path) -> str:
    return verify_corpus_store(store_root / "first").corpus_content_sha256


def write_gold_file(
    tmp_path: Path, corpus_content_sha256: str, fight_snapshot_sha256: str = EXCERPT_SHA256
) -> Path:
    gold_path = tmp_path / "gold.yaml"
    gold_path.write_bytes(
        encode_gold_file(
            [build_case_row(), PROTOCOL_CASE], corpus_content_sha256, fight_snapshot_sha256
        )
    )
    return gold_path


def test_gold_sets_prints_each_case_s_sets(
    tmp_path: Path,
    settings: dict[str, str],
    corpus_content_sha256: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    gold_path = write_gold_file(tmp_path, corpus_content_sha256)

    exit_code = main(["eval", "gold-sets", "--gold", str(gold_path)], settings)

    sets_document = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert sets_document["corpus_content_sha256"] == corpus_content_sha256
    assert sets_document["cases"]["democorp-gateway"]["cves"]["required"] == [
        "CVE-9999-0001",
        "CVE-9999-0002",
    ]
    assert sets_document["cases"]["subscriber-keys"]["techniques"]["required"] == ["FGT5044"]


def derive_sets_file(
    tmp_path: Path, gold_path: Path, settings: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> Path:
    assert main(["eval", "gold-sets", "--gold", str(gold_path)], settings) == 0
    sets_path = tmp_path / "sets.json"
    sets_path.write_text(capsys.readouterr().out)
    return sets_path


def test_check_of_the_printed_sets_passes(
    tmp_path: Path,
    settings: dict[str, str],
    corpus_content_sha256: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    gold_path = write_gold_file(tmp_path, corpus_content_sha256)
    sets_path = derive_sets_file(tmp_path, gold_path, settings, capsys)

    exit_code = main(
        ["eval", "gold-sets", "--gold", str(gold_path), "--check", str(sets_path)], settings
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out == ""
    assert "the recorded sets match" in captured.err


def test_check_of_edited_sets_fails_naming_the_case(
    tmp_path: Path,
    settings: dict[str, str],
    corpus_content_sha256: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    gold_path = write_gold_file(tmp_path, corpus_content_sha256)
    sets_path = derive_sets_file(tmp_path, gold_path, settings, capsys)
    sets_document = json.loads(sets_path.read_text())
    sets_document["cases"]["democorp-gateway"]["cves"]["required"].pop()
    sets_path.write_text(json.dumps(sets_document, indent=2, sort_keys=True) + "\n")

    exit_code = main(
        ["eval", "gold-sets", "--gold", str(gold_path), "--check", str(sets_path)], settings
    )

    captured_err = capsys.readouterr().err
    assert exit_code == 1
    assert "differ for democorp-gateway" in captured_err
    assert "subscriber-keys" not in captured_err


def test_check_of_a_file_that_is_not_a_sets_file_fails(
    tmp_path: Path,
    settings: dict[str, str],
    corpus_content_sha256: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    gold_path = write_gold_file(tmp_path, corpus_content_sha256)
    sets_path = tmp_path / "sets.json"
    sets_path.write_text("not json")

    exit_code = main(
        ["eval", "gold-sets", "--gold", str(gold_path), "--check", str(sets_path)], settings
    )

    assert exit_code == 1
    assert "is not the sets of this gold file" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("fight_snapshot_sha256", "corpus_matches", "expected_problem"),
    [
        (EXCERPT_SHA256, False, "the active store's corpus is not the one"),
        (FULL_FIGHT_SHA256, True, "the FiGHT snapshot is not the one"),
    ],
    ids=["other_corpus", "other_snapshot"],
)
def test_gold_file_labelled_against_other_sources_fails(
    tmp_path: Path,
    settings: dict[str, str],
    corpus_content_sha256: str,
    capsys: pytest.CaptureFixture[str],
    fight_snapshot_sha256: str,
    corpus_matches: bool,
    expected_problem: str,
) -> None:
    gold_corpus_sha256 = corpus_content_sha256 if corpus_matches else UNKNOWN_CORPUS_SHA256
    gold_path = write_gold_file(tmp_path, gold_corpus_sha256, fight_snapshot_sha256)

    exit_code = main(["eval", "gold-sets", "--gold", str(gold_path)], settings)

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert expected_problem in captured.err


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
def test_gold_sets_without_its_sources_is_a_usage_error(
    tmp_path: Path,
    settings: dict[str, str],
    capsys: pytest.CaptureFixture[str],
    removed_variables: tuple[str, ...],
    expected_variable: str,
) -> None:
    environment = dict(settings)
    for variable in removed_variables:
        del environment[variable]
    gold_path = write_gold_file(tmp_path, UNKNOWN_CORPUS_SHA256)

    exit_code = run_usage_error(["eval", "gold-sets", "--gold", str(gold_path)], environment)

    assert exit_code == 2
    assert expected_variable in capsys.readouterr().err


def test_invalid_gold_file_is_a_usage_error(
    tmp_path: Path, settings: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    gold_path = tmp_path / "gold.yaml"
    gold_path.write_text("cases: []\n")

    exit_code = run_usage_error(["eval", "gold-sets", "--gold", str(gold_path)], settings)

    assert exit_code == 2
    assert "invalid gold file" in capsys.readouterr().err


def test_root_without_an_active_store_cannot_start(
    tmp_path: Path, settings: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    empty_root = tmp_path / "empty"
    empty_root.mkdir()
    environment = {**settings, "CVE_KGRAG_STORE_ROOT": str(empty_root)}
    gold_path = write_gold_file(tmp_path, UNKNOWN_CORPUS_SHA256)

    exit_code = main(["eval", "gold-sets", "--gold", str(gold_path)], environment)

    assert exit_code == 2
    assert "store unavailable: no_active_store" in capsys.readouterr().err
