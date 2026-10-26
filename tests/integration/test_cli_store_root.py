"""Proves the CLI over a store root (ADR 0009 §8-§10): the ``store`` commands print JSON
and fail with a reason code and never a path; every serving command serves the store
``ACTIVE`` names and refuses to start, exit 2, when the root cannot be served; the
commands whose row loads no served corpus run whatever state the root is in; and
``demo`` and ``eval planner`` stay on the packaged fixture and say so."""

import json
import logging
from collections.abc import Mapping
from pathlib import Path

import pytest

from cve_kgrag.adapter_discovery import InterfaceUnavailable
from cve_kgrag.adapters.store.corpus_store import load_corpus_store
from cve_kgrag.cli import main, run_mcp_server
from cve_kgrag.domain.investigation import (
    KnowledgeEvidenceSet,
    SourceCapability,
    SourceCapabilityState,
)
from cve_kgrag.domain.search import SearchResponse, SemanticUnavailableDetail
from cve_kgrag.domain.served_dataset import ServedDatasetKind
from cve_kgrag.domain.store_status import ActiveRecordState, StoreCondition, StoreStatus
from cve_kgrag.domain.taxonomy import BackendFailureDetail
from cve_kgrag.domain.tool_contracts import KnowledgeCapabilities
from cve_kgrag.interfaces.knowledge_toolbox import KnowledgeToolbox
from cve_kgrag.settings import ServiceSettings, load_settings
from tests.support.collect import find_capability
from tests.support.corpus_stores import import_store
from tests.support.evaluation import SMALL_GOLD_ROWS, write_gold_file
from tests.support.fight_excerpt import EXCERPT_BYTES, EXCERPT_SHA256
from tests.support.legacy_inputs import (
    build_declaration,
    build_v2_entry,
    build_v2_feed,
    write_gzip_feed,
    write_inputs_manifest,
)

STORE_MARKER = "storemarker"
STORE_DESCRIPTION = f"SYNTHETIC: {STORE_MARKER} gateway mishandles input."


class RecordingMcpServerRunner:
    def __init__(self) -> None:
        self.served_toolboxes: list[KnowledgeToolbox] = []

    def __call__(self, toolbox: KnowledgeToolbox) -> None:
        self.served_toolboxes.append(toolbox)


@pytest.fixture
def store_root(tmp_path: Path) -> Path:
    store_root = tmp_path / "stores"
    store_root.mkdir()
    import_store(store_root, "first", cve_numbers=(1, 2))
    import_store(store_root, "second", cve_numbers=(3, 4), description=STORE_DESCRIPTION)
    return store_root


@pytest.fixture
def root_settings(store_root: Path) -> dict[str, str]:
    return {"CVE_KGRAG_STORE_ROOT": str(store_root)}


@pytest.fixture
def active_settings(root_settings: dict[str, str]) -> dict[str, str]:
    """The root with ``second`` active, ``first`` before it."""
    assert main(["store", "activate", "first"], root_settings) == 0
    assert main(["store", "activate", "second"], root_settings) == 0
    return root_settings


@pytest.fixture
def unservable_settings(tmp_path: Path) -> dict[str, str]:
    """A root holding a store but no ``ACTIVE``: every serving command refuses it."""
    store_root = tmp_path / "unservable"
    store_root.mkdir()
    import_store(store_root, "first")
    return {"CVE_KGRAG_STORE_ROOT": str(store_root)}


def run_usage_error(arguments: list[str], environment: Mapping[str, str]) -> int:
    with pytest.raises(SystemExit) as raised:
        main(arguments, environment)
    return int(str(raised.value.code))


# --- The store commands ---------------------------------------------------------------


def test_store_command_without_a_root_is_a_usage_error_naming_the_variable(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = run_usage_error(["store", "status"], {})

    assert exit_code == 2
    assert "CVE_KGRAG_STORE_ROOT: required by store" in capsys.readouterr().err


@pytest.mark.parametrize("name", ["ACTIVE", "active", "../first", ".hidden", "a/b", "x" * 65])
def test_store_name_that_breaks_the_rule_is_a_usage_error(
    root_settings: dict[str, str], name: str
) -> None:
    exit_code = run_usage_error(["store", "activate", name], root_settings)

    assert exit_code == 2


def test_store_activate_prints_the_status_naming_no_path(
    root_settings: dict[str, str], store_root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(["store", "activate", "first"], root_settings)

    output = capsys.readouterr().out
    store_status = StoreStatus.model_validate_json(output)
    assert exit_code == 0
    assert store_status.active_store is not None
    assert store_status.active_store.name == "first"
    assert str(store_root) not in output


def test_store_validate_prints_the_store_identity(
    root_settings: dict[str, str], store_root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(["store", "validate", "second"], root_settings)

    identity = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert identity["corpus_content_sha256"] == (
        load_corpus_store(store_root / "second").corpus_content_sha256
    )


def test_store_failure_exits_one_with_its_code_and_no_path(
    root_settings: dict[str, str], store_root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(["store", "validate", "missing"], root_settings)

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == (
        "cve-kgrag store validate failed: store_missing: no store has that name under the root\n"
    )
    assert str(store_root) not in captured.err


def test_store_rollback_returns_to_the_previous_store_once(
    active_settings: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    first_exit_code = main(["store", "rollback"], active_settings)
    store_status = StoreStatus.model_validate_json(capsys.readouterr().out)
    second_exit_code = main(["store", "rollback"], active_settings)

    assert first_exit_code == 0
    assert store_status.active_store is not None
    assert store_status.active_store.name == "first"
    assert second_exit_code == 1
    assert "no_previous_store" in capsys.readouterr().err


def test_store_status_without_active_prints_it_and_exits_one(
    root_settings: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(["store", "status"], root_settings)

    store_status = StoreStatus.model_validate_json(capsys.readouterr().out)
    assert exit_code == 1
    assert store_status.active_record is ActiveRecordState.NO_ACTIVE_STORE


def test_store_status_with_an_ok_active_store_exits_zero_whatever_the_previous(
    active_settings: dict[str, str], store_root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (store_root / "first" / "records.jsonl").write_bytes(b"\n")

    exit_code = main(["store", "status"], active_settings)

    store_status = StoreStatus.model_validate_json(capsys.readouterr().out)
    assert exit_code == 0
    assert store_status.previous_store is not None
    assert store_status.previous_store.condition is StoreCondition.STORE_INVALID


def test_store_command_on_an_unusable_root_names_the_reason_not_the_root(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing_root = tmp_path / "missing-root"

    exit_code = main(["store", "status"], {"CVE_KGRAG_STORE_ROOT": str(missing_root)})

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "store_root_unusable" in captured.err
    assert str(missing_root) not in captured.err


# --- Serving the active store ---------------------------------------------------------


def test_capabilities_name_the_active_store_s_dataset(
    active_settings: dict[str, str], store_root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(["capabilities"], active_settings)

    capabilities = KnowledgeCapabilities.model_validate_json(capsys.readouterr().out)
    cve_search = find_capability(capabilities.source_capabilities, "cve_search")
    assert exit_code == 0
    assert cve_search.version == (
        load_corpus_store(store_root / "second").describe_served_dataset().cve_search_version
    )


def test_search_serves_the_active_store_s_records(
    active_settings: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(["search", STORE_MARKER], active_settings)

    response = SearchResponse.model_validate_json(capsys.readouterr().out)
    found_ids: list[str] = []
    for candidate in response.candidates:
        found_ids.append(candidate.record.cve_id)
    assert exit_code == 0
    assert found_ids == ["CVE-9999-0003", "CVE-9999-0004"]


def test_search_of_the_fixture_does_not_find_the_store_s_records(
    capsys: pytest.CaptureFixture[str],
) -> None:
    main(["search", STORE_MARKER], {})

    response = SearchResponse.model_validate_json(capsys.readouterr().out)
    assert response.candidates == ()


def test_set_sealed_against_the_store_verifies_only_against_that_store(
    active_settings: dict[str, str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(
        ["investigate", f"{STORE_MARKER} input", "--scope", "implementation_only"], active_settings
    )
    sealed_set = KnowledgeEvidenceSet.model_validate_json(capsys.readouterr().out)
    set_path = tmp_path / "set.json"
    set_path.write_text(sealed_set.model_dump_json())

    store_exit_code = main(["verify", str(set_path)], active_settings)
    capsys.readouterr()
    fixture_exit_code = main(["verify", str(set_path)], {})

    assert store_exit_code == 0
    assert fixture_exit_code == 1


@pytest.mark.parametrize(
    "arguments",
    [
        ["search", "gateway"],
        ["lookup", "CVE-9999-0001"],
        ["topic", "5G-AKA", "--scope", "mixed"],
        ["investigate", "gateway", "--scope", "implementation_only"],
        ["capabilities"],
        ["evidence", "ev:000000000000000000000000"],
    ],
    ids=["search", "lookup", "topic", "investigate", "capabilities", "evidence"],
)
def test_serving_command_on_a_root_without_active_refuses_to_start(
    unservable_settings: dict[str, str],
    arguments: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = run_usage_error(arguments, unservable_settings)

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert captured.err == (
        f"cve-kgrag {arguments[0]} cannot start: store unavailable: no_active_store\n"
    )


def test_verify_on_a_root_without_active_refuses_to_start(
    unservable_settings: dict[str, str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    set_path = tmp_path / "set.json"
    set_path.write_text("{}")

    exit_code = run_usage_error(["verify", str(set_path)], unservable_settings)

    assert exit_code == 2
    assert "store unavailable: no_active_store" in capsys.readouterr().err


def test_mcp_serves_the_active_store(active_settings: dict[str, str], store_root: Path) -> None:
    runner = RecordingMcpServerRunner()

    exit_code = run_mcp_server(runner, ServiceSettings(store_root=store_root))

    assert exit_code == 0
    served_dataset = runner.served_toolboxes[0].describe_served_dataset()
    assert served_dataset.kind is ServedDatasetKind.CORPUS_STORE


def test_mcp_without_its_runner_exits_before_it_touches_the_root(
    unservable_settings: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    store_root = Path(unservable_settings["CVE_KGRAG_STORE_ROOT"])

    exit_code = run_mcp_server(
        InterfaceUnavailable("the 'mcp' extra is not installed"),
        ServiceSettings(store_root=store_root),
    )

    assert exit_code == 1
    assert "store unavailable" not in capsys.readouterr().err


def test_mcp_on_a_root_without_active_refuses_to_start(
    unservable_settings: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    runner = RecordingMcpServerRunner()
    store_root = Path(unservable_settings["CVE_KGRAG_STORE_ROOT"])

    with pytest.raises(SystemExit) as raised:
        run_mcp_server(runner, ServiceSettings(store_root=store_root))

    assert raised.value.code == 2
    assert runner.served_toolboxes == []
    assert capsys.readouterr().err == (
        "cve-kgrag mcp cannot start: store unavailable: no_active_store\n"
    )


# --- Commands that load no served corpus ----------------------------------------------


@pytest.mark.parametrize(
    ("arguments", "expected_exit_code"),
    [
        (["resolve", "5G-AKA"], 0),
        (["affectedness", "CVE-9999-0001", "--purl", "pkg:pypi/demo@1.0"], 1),
        (["demo"], 0),
        (["schema", "check"], 0),
    ],
    ids=["resolve", "affectedness", "demo", "schema"],
)
def test_command_whose_row_loads_no_served_corpus_runs_on_a_root_without_active(
    unservable_settings: dict[str, str], arguments: list[str], expected_exit_code: int
) -> None:
    exit_code = main(arguments, unservable_settings)

    assert exit_code == expected_exit_code


def test_eval_planner_runs_on_the_fixture_with_a_root_without_active(
    unservable_settings: dict[str, str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    gold_path = write_gold_file(tmp_path, SMALL_GOLD_ROWS)

    exit_code = main(
        ["eval", "planner", "--gold", str(gold_path), "--out", str(tmp_path / "results")],
        unservable_settings,
    )

    assert exit_code == 0
    assert capsys.readouterr().err.startswith(
        "cve-kgrag eval planner uses the packaged synthetic fixture, not the store root, and "
        "the FiGHT source each gold case names, not a configured snapshot\n"
    )


def test_eval_planner_out_inside_the_store_root_is_a_usage_error(
    root_settings: dict[str, str], store_root: Path, tmp_path: Path
) -> None:
    gold_path = write_gold_file(tmp_path, SMALL_GOLD_ROWS)

    exit_code = run_usage_error(
        ["eval", "planner", "--gold", str(gold_path), "--out", str(store_root / "results")],
        root_settings,
    )

    assert exit_code == 2
    assert not (store_root / "results").exists()


def test_migrate_runs_with_a_root_without_active(
    unservable_settings: dict[str, str], tmp_path: Path
) -> None:
    inputs_dir = tmp_path / "migrate-inputs"
    inputs_dir.mkdir()
    write_gzip_feed(inputs_dir / "nvdcve-2.0-2099.json.gz", build_v2_feed([build_v2_entry(7)]))
    manifest_path = write_inputs_manifest(
        inputs_dir, [build_declaration("nvdcve-2.0-2099.json.gz")]
    )
    store_root = Path(unservable_settings["CVE_KGRAG_STORE_ROOT"])

    exit_code = main(
        ["migrate", "legacy", "--inputs", str(manifest_path), "--target", str(store_root / "new")],
        unservable_settings,
    )

    assert exit_code == 0
    assert (store_root / "new" / "manifest.json").is_file()


def test_demo_says_once_it_uses_the_fixture_and_prints_what_it_prints_without_a_root(
    active_settings: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    main(["demo"], {})
    output_without_root = capsys.readouterr()

    exit_code = main(["demo"], active_settings)

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out == output_without_root.out
    assert captured.err == (
        "cve-kgrag demo uses the packaged synthetic fixture, not the store root\n"
    )
    assert output_without_root.err == captured.err


# --- The semantic channel in store mode -----------------------------------------------


def build_store_semantic_settings(
    active_settings: dict[str, str], persist_directory: Path
) -> dict[str, str]:
    return {
        **active_settings,
        "CVE_KGRAG_SEMANTIC_ENABLED": "true",
        "CVE_KGRAG_SEMANTIC_PERSIST_DIRECTORY": str(persist_directory),
    }


@pytest.mark.parametrize(
    "arguments",
    [
        ["search", STORE_MARKER, "--semantic"],
        ["topic", "5gaka", "--scope", "mixed", "--semantic"],
        ["investigate", f"{STORE_MARKER} input", "--scope", "implementation_only", "--semantic"],
    ],
    ids=["search", "topic", "investigate"],
)
def test_semantic_request_against_a_store_reports_the_collection_unbound_and_opens_nothing(
    active_settings: dict[str, str],
    tmp_path: Path,
    arguments: list[str],
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    persist_directory = tmp_path / "vectors"
    environment = build_store_semantic_settings(active_settings, persist_directory)

    with caplog.at_level(logging.DEBUG, logger="cve_kgrag.adapter_discovery"):
        main(arguments, environment)

    output = capsys.readouterr().out
    assert BackendFailureDetail.COLLECTION_NOT_BOUND.value in output
    assert BackendFailureDetail.ADAPTER_UNUSABLE.value not in output
    assert caplog.records == []
    assert not persist_directory.exists()


@pytest.mark.parametrize(
    ("extra_arguments", "expected_capability"),
    [
        (
            ["--semantic"],
            SourceCapability(
                source="semantic_channel",
                state=SourceCapabilityState.UNAVAILABLE,
                detail=SemanticUnavailableDetail.COLLECTION_NOT_BOUND,
            ),
        ),
        (
            [],
            SourceCapability(source="semantic_channel", state=SourceCapabilityState.NOT_CONFIGURED),
        ),
    ],
    ids=["requested", "not_requested"],
)
def test_store_capabilities_report_the_semantic_channel_by_whether_it_is_requested(
    active_settings: dict[str, str],
    tmp_path: Path,
    extra_arguments: list[str],
    expected_capability: SourceCapability,
    capsys: pytest.CaptureFixture[str],
) -> None:
    environment = build_store_semantic_settings(active_settings, tmp_path / "vectors")

    main(["capabilities", *extra_arguments], environment)

    capabilities = KnowledgeCapabilities.model_validate_json(capsys.readouterr().out)
    semantic_capability = find_capability(capabilities.source_capabilities, "semantic_channel")
    assert semantic_capability == expected_capability


# --- The operator FiGHT snapshot ------------------------------------------------------


@pytest.fixture
def missing_snapshot_settings(tmp_path: Path) -> dict[str, str]:
    return {
        "CVE_KGRAG_FIGHT_SNAPSHOT_PATH": str(tmp_path / "missing-fight.yaml"),
        "CVE_KGRAG_FIGHT_SNAPSHOT_SHA256": EXCERPT_SHA256,
    }


@pytest.mark.parametrize(
    "arguments",
    [
        ["topic", "5G-AKA", "--scope", "mixed"],
        ["investigate", "5G-AKA", "--scope", "mixed"],
        ["capabilities"],
        ["evidence", "ev:000000000000000000000000"],
    ],
    ids=["topic", "investigate", "capabilities", "evidence"],
)
def test_command_that_uses_fight_refuses_a_missing_configured_snapshot(
    missing_snapshot_settings: dict[str, str],
    arguments: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = run_usage_error(arguments, missing_snapshot_settings)

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert captured.err == (
        f"cve-kgrag {arguments[0]} cannot start: FiGHT snapshot unavailable: "
        "fight_snapshot_missing\n"
    )


def test_verify_refuses_a_missing_configured_snapshot(
    missing_snapshot_settings: dict[str, str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    set_path = tmp_path / "set.json"
    set_path.write_text("{}")

    exit_code = run_usage_error(["verify", str(set_path)], missing_snapshot_settings)

    assert exit_code == 2
    assert "FiGHT snapshot unavailable: fight_snapshot_missing" in capsys.readouterr().err


def test_mcp_refuses_a_missing_configured_snapshot_before_serving(
    missing_snapshot_settings: dict[str, str],
) -> None:
    runner = RecordingMcpServerRunner()

    with pytest.raises(SystemExit) as raised:
        run_mcp_server(runner, load_settings(missing_snapshot_settings))

    assert raised.value.code == 2
    assert runner.served_toolboxes == []


@pytest.mark.parametrize(
    ("arguments", "expected_exit_code"),
    [
        (["search", "gateway"], 0),
        (["lookup", "CVE-9999-0003"], 0),
        (["resolve", "5G-AKA"], 0),
        (["affectedness", "CVE-9999-0001", "--purl", "pkg:pypi/demo@1.0"], 1),
        (["demo"], 0),
        (["schema", "check"], 0),
    ],
    ids=["search", "lookup", "resolve", "affectedness", "demo", "schema"],
)
def test_command_whose_row_loads_no_fight_runs_with_a_missing_snapshot(
    missing_snapshot_settings: dict[str, str], arguments: list[str], expected_exit_code: int
) -> None:
    exit_code = main(arguments, missing_snapshot_settings)

    assert exit_code == expected_exit_code


def test_eval_planner_and_store_commands_run_with_a_missing_snapshot(
    missing_snapshot_settings: dict[str, str], root_settings: dict[str, str], tmp_path: Path
) -> None:
    environment = {**missing_snapshot_settings, **root_settings}
    gold_path = write_gold_file(tmp_path, SMALL_GOLD_ROWS)

    eval_exit_code = main(
        ["eval", "planner", "--gold", str(gold_path), "--out", str(tmp_path / "results")],
        environment,
    )
    store_exit_code = main(["store", "activate", "first"], environment)

    assert (eval_exit_code, store_exit_code) == (0, 0)


def test_broken_store_is_reported_before_a_broken_snapshot(
    unservable_settings: dict[str, str],
    missing_snapshot_settings: dict[str, str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = run_usage_error(
        ["capabilities"], {**unservable_settings, **missing_snapshot_settings}
    )

    assert exit_code == 2
    assert "store unavailable: no_active_store" in capsys.readouterr().err


def test_capabilities_name_the_configured_snapshot_s_pin(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snapshot_path = tmp_path / "fight.yaml"
    snapshot_path.write_bytes(EXCERPT_BYTES)
    environment = {
        "CVE_KGRAG_FIGHT_SNAPSHOT_PATH": str(snapshot_path),
        "CVE_KGRAG_FIGHT_SNAPSHOT_SHA256": EXCERPT_SHA256,
    }

    exit_code = main(["capabilities"], environment)

    capabilities = KnowledgeCapabilities.model_validate_json(capsys.readouterr().out)
    fight_capability = find_capability(capabilities.source_capabilities, "mitre_fight")
    assert exit_code == 0
    assert fight_capability.state is SourceCapabilityState.AVAILABLE
    assert fight_capability.version is not None
    assert fight_capability.version.endswith(f"+sha256:{EXCERPT_SHA256}")


def test_store_whose_manifest_nests_too_deep_fails_as_invalid_without_a_traceback(
    root_settings: dict[str, str], store_root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (store_root / "first" / "manifest.json").write_bytes(b"[" * 200_000)

    exit_code = main(["store", "validate", "first"], root_settings)

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.err == (
        "cve-kgrag store validate failed: store_invalid: the store fails verification\n"
    )


def test_eval_planner_out_inside_the_root_spelled_another_way_is_a_usage_error(
    root_settings: dict[str, str], store_root: Path, tmp_path: Path
) -> None:
    root_alias = tmp_path / "root-alias"
    root_alias.symlink_to(store_root)
    gold_path = write_gold_file(tmp_path, SMALL_GOLD_ROWS)

    exit_code = run_usage_error(
        ["eval", "planner", "--gold", str(gold_path), "--out", str(root_alias / "results")],
        root_settings,
    )

    assert exit_code == 2
    assert not (store_root / "results").exists()


def test_eval_planner_prints_the_report_it_prints_without_a_root(
    unservable_settings: dict[str, str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    gold_path = write_gold_file(tmp_path, SMALL_GOLD_ROWS)
    main(["eval", "planner", "--gold", str(gold_path), "--out", str(tmp_path / "plain")], {})
    report_without_root = capsys.readouterr().out

    main(
        ["eval", "planner", "--gold", str(gold_path), "--out", str(tmp_path / "rooted")],
        unservable_settings,
    )

    assert capsys.readouterr().out == report_without_root
