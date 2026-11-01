"""Sessions persist real interface bytes over the packaged synthetic dataset."""

import csv
import json
from functools import partial
from pathlib import Path

import pytest

from tests.support.clocks import read_fixed_clock
from tests.support.session_files import assert_check_layers_hold, write_findings
from vulnwitness.adapters.session.check import SessionChecker, collect_response_anchors
from vulnwitness.adapters.session.recorder import SessionRecorder
from vulnwitness.application.search import SearchService
from vulnwitness.cli import main
from vulnwitness.composition import build_serving_data_plane, load_packaged_fixture
from vulnwitness.domain.product_query import ProductQueryRequest, ProductQueryResponse
from vulnwitness.domain.search import SearchResponse
from vulnwitness.domain.session_record import SessionCall, SessionCheckReport, SessionRecordingError
from vulnwitness.domain.tool_contracts import ToolFailureCode
from vulnwitness.interfaces.cli_session import encode_cli_answer

UNKNOWN_ANCHOR = "ev:" + "0" * 24
PAGED_PRODUCT = ["product", "--vendor", "democorp", "--limit", "1"]


def read_tree(directory: Path) -> dict[str, bytes]:
    contents: dict[str, bytes] = {}
    for path in directory.rglob("*"):
        if path.is_file():
            contents[str(path.relative_to(directory))] = path.read_bytes()
    return contents


def observed_lookup(
    invocations: list[str],
    service: SearchService,
    cve_id: str,
) -> SearchResponse:
    invocations.append(cve_id)
    return service.lookup(cve_id)


@pytest.mark.parametrize(
    "command",
    [
        ["lookup", "CVE-9999-0001"],
        ["search", "authentication"],
        ["product", "--vendor", "democorp"],
        ["investigate", "5gaka", "--scope", "mixed"],
    ],
)
def test_recorded_text_is_refused_before_creating_a_session(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], command: list[str]
) -> None:
    # Arrange
    directory = tmp_path / "review"
    # Act
    with pytest.raises(SystemExit) as refused:
        main([*command, "--format", "text", "--session", str(directory)], environment={})
    # Assert
    streams = capsys.readouterr()
    assert refused.value.code == 2
    assert streams.out == ""
    assert "--session requires --format json" in streams.err
    assert not directory.exists()


def test_all_records_each_product_page_with_its_validated_cursor(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    directory = tmp_path / "review"
    # Act
    exit_code = main([*PAGED_PRODUCT, "--all", "--session", str(directory)], environment={})
    documents = json.loads(capsys.readouterr().out)
    write_findings(directory, [])
    # Assert
    assert exit_code == 0
    assert len(documents) == 3
    assert len(list((directory / "calls").iterdir())) == 3
    cursor = None
    for sequence, document in enumerate(documents, start=1):
        page = ProductQueryResponse.model_validate(document)
        call = SessionCall.model_validate_json(
            (directory / f"calls/{sequence:04d}.json").read_bytes()
        )
        request = ProductQueryRequest(vendor="democorp", limit=1, cursor=cursor)
        assert call.request == request.model_dump(mode="json")
        assert call.sequence == sequence and call.command == "product" and call.outcome == "ok"
        assert page.cursor == cursor
        assert (directory / call.response_file).read_bytes() == encode_cli_answer(page)[0]
        cursor = page.next_cursor
    assert cursor is None
    assert_check_layers_hold(SessionChecker(directory).check())


@pytest.mark.parametrize("export", [None, "csv", "jsonl"])
def test_mid_traversal_call_limit_leaves_only_complete_page_calls(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], export: str | None
) -> None:
    # Arrange
    directory = tmp_path / "review"
    output = tmp_path / "inventory"
    arguments = [*PAGED_PRODUCT, "--session", str(directory), "--session-call-limit", "2"]
    if export is None:
        arguments.append("--all")
    else:
        output.write_text("keep existing export")
        arguments.extend(["--output", str(output), "--export", export, "--force"])
    # Act
    exit_code = main(arguments, environment={})
    streams = capsys.readouterr()
    write_findings(directory, [])
    # Assert
    assert exit_code == 2 and streams.out == ""
    assert json.loads(streams.err)["code"] == "session_call_limit"
    assert sorted((directory / "calls").iterdir()) == [
        directory / "calls/0001.json",
        directory / "calls/0002.json",
    ]
    assert sorted((directory / "responses").iterdir()) == [
        directory / "responses/0001.json",
        directory / "responses/0002.json",
    ]
    last_page = ProductQueryResponse.model_validate_json(
        (directory / "responses/0002.json").read_bytes()
    )
    assert last_page.next_cursor is not None
    assert not list(directory.rglob("*.tmp-*"))
    assert_check_layers_hold(SessionChecker(directory).check())
    if export is not None:
        assert output.read_text() == "keep existing export"
    else:
        assert not output.exists()


@pytest.mark.parametrize("export", ["csv", "jsonl"])
@pytest.mark.parametrize("all_pages", [False, True])
def test_export_records_product_pages_without_adding_the_export_to_the_session(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], export: str, all_pages: bool
) -> None:
    # Arrange
    directory = tmp_path / "review"
    output = tmp_path / f"inventory.{export}"
    arguments = [
        *PAGED_PRODUCT,
        "--session",
        str(directory),
        "--output",
        str(output),
        "--export",
        export,
    ]
    if all_pages:
        arguments.append("--all")
    # Act
    exit_code = main(arguments, environment={})
    streams = capsys.readouterr()
    write_findings(directory, [])
    # Assert
    assert exit_code == 0 and streams.out == ""
    assert len(list((directory / "calls").iterdir())) == 3
    cve_ids: list[str] = []
    cursor = None
    for sequence in range(1, 4):
        call = SessionCall.model_validate_json(
            (directory / f"calls/{sequence:04d}.json").read_bytes()
        )
        page = ProductQueryResponse.model_validate_json(
            (directory / call.response_file).read_bytes()
        )
        request = ProductQueryRequest(vendor="democorp", limit=1, cursor=cursor)
        assert call.request == request.model_dump(mode="json")
        assert page.cursor == cursor
        assert (directory / call.response_file).read_bytes() == encode_cli_answer(page)[0]
        cve_ids.append(page.items[0].record.cve_id)
        cursor = page.next_cursor
    assert cursor is None
    rows = []
    with output.open(newline="") as export_file:
        if export == "csv":
            rows = list(csv.DictReader(export_file))
        else:
            for line in export_file:
                rows.append(json.loads(line))
    assert len(rows) == 3
    for row, cve_id in zip(rows, cve_ids, strict=True):
        assert row["cve_id"] == cve_id
    assert_check_layers_hold(SessionChecker(directory).check())
    assert sorted(directory.iterdir()) == [
        directory / ".lock",
        directory / "calls",
        directory / "findings.yaml",
        directory / "responses",
        directory / "session.json",
    ]


@pytest.mark.parametrize(
    "options",
    [
        ["--max-pages", "0"],
        ["--all", "--cursor", "invalid"],
        ["--export", "csv"],
        ["--output", "unused.csv"],
        ["--force"],
    ],
)
def test_invalid_recorded_product_options_are_refused_before_creating_a_session(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], options: list[str]
) -> None:
    # Arrange
    directory = tmp_path / "review"
    # Act
    exit_code = main([*PAGED_PRODUCT, *options, "--session", str(directory)], environment={})
    # Assert
    streams = capsys.readouterr()
    assert exit_code == 2 and streams.out == ""
    assert "vulnwitness product:" in streams.err
    assert not directory.exists()


def test_product_then_lookup_with_citations_to_both_calls_passes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Arrange
    directory = tmp_path / "review"
    # Act
    product_exit = main(
        [
            "product",
            "--vendor",
            "democorp",
            "--limit",
            "1",
            "--session",
            str(directory),
            "--session-goal",
            "Review a synthetic product",
        ],
        environment={},
    )
    product_bytes = capsys.readouterr().out.encode()
    product = json.loads(product_bytes)
    cve_id = product["items"][0]["record"]["cve_id"]
    lookup_exit = main(["lookup", cve_id, "--session", str(directory)], environment={})
    lookup_bytes = capsys.readouterr().out.encode()
    anchor = product["evidence"][0]["evidence_id"]
    write_findings(
        directory, [{"call": 1, "evidence_id": anchor}, {"call": 2, "evidence_id": anchor}]
    )
    check_exit = main(["session", "check", str(directory)], environment={})
    report = SessionCheckReport.model_validate_json(capsys.readouterr().out)
    # Assert
    assert (product_exit, lookup_exit, check_exit) == (0, 0, 0)
    assert_check_layers_hold(report)
    assert report.citations.citations_checked == 2
    assert (directory / "responses/0001.json").read_bytes() == product_bytes
    assert (directory / "responses/0002.json").read_bytes() == lookup_bytes
    assert (
        json.loads((directory / "session.json").read_bytes())["goal"]
        == "Review a synthetic product"
    )
    assert "does not establish" in report.support_limitation
    for name in ("", "calls", "responses"):
        assert (directory / name).stat().st_mode & 0o777 == 0o700
    for path in directory.rglob("*.json"):
        assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("cited_call", [1, 3])
def test_absent_anchor_or_missing_call_fails_with_citation_location(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    cited_call: int,
) -> None:
    # Arrange
    directory = tmp_path / "review"
    main(["lookup", "CVE-9999-0001", "--session", str(directory)], environment={})
    capsys.readouterr()
    write_findings(directory, [{"call": cited_call, "evidence_id": UNKNOWN_ANCHOR}])
    # Act
    exit_code = main(["session", "check", str(directory), "--format", "text"], environment={})
    # Assert
    text = capsys.readouterr().out
    assert exit_code == 1
    assert "findings.yaml.findings[0].citations[0]" in text
    assert "does not establish that a statement is supported" in text


def test_citation_of_a_failed_call_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange
    directory = tmp_path / "review"
    # Act
    failed_exit = main(["evidence", UNKNOWN_ANCHOR, "--session", str(directory)], environment={})
    failure_bytes = capsys.readouterr().out.encode()
    write_findings(directory, [{"call": 1, "evidence_id": UNKNOWN_ANCHOR}])
    report = SessionChecker(directory).check()
    # Assert
    assert failed_exit == 1
    assert json.loads(failure_bytes)["code"] == "unknown_evidence_id"
    assert (directory / "responses/0001.json").read_bytes() == failure_bytes
    assert not report.citations.resolved
    assert any("did not succeed" in violation.message for violation in report.citations.violations)


def test_anchor_in_another_call_does_not_resolve_a_citation(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Arrange
    directory = tmp_path / "review"
    main(["lookup", "CVE-9999-0001", "--session", str(directory)], environment={})
    first_lookup = json.loads(capsys.readouterr().out)
    anchor = next(iter(collect_response_anchors(first_lookup)))
    main(["lookup", "CVE-9999-0002", "--session", str(directory)], environment={})
    capsys.readouterr()
    write_findings(directory, [{"call": 2, "evidence_id": anchor}])
    # Act
    report = SessionChecker(directory).check()
    # Assert
    assert not report.citations.resolved
    assert any(
        "absent from the cited response" in issue.message for issue in report.citations.violations
    )


def test_changed_dataset_is_refused_without_recording(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Arrange
    directory = tmp_path / "review"
    main(["lookup", "CVE-9999-0001", "--session", str(directory)], environment={})
    capsys.readouterr()
    metadata_path = directory / "session.json"
    metadata = json.loads(metadata_path.read_bytes())
    metadata["dataset"]["corpus_content_sha256"] = "0" * 64
    metadata_path.write_text(json.dumps(metadata))
    before = read_tree(directory)
    # Act
    exit_code = main(["lookup", "CVE-9999-0002", "--session", str(directory)], environment={})
    streams = capsys.readouterr()
    # Assert
    assert exit_code == 2 and streams.out == ""
    assert json.loads(streams.err)["code"] == "session_dataset_mismatch"
    assert read_tree(directory) == before


def test_call_limit_refuses_the_cli_call_without_recording(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Arrange
    directory = tmp_path / "review"
    main(
        ["lookup", "CVE-9999-0001", "--session", str(directory), "--session-call-limit", "1"],
        environment={},
    )
    capsys.readouterr()
    before = read_tree(directory)
    # Act
    exit_code = main(["lookup", "CVE-9999-0002", "--session", str(directory)], environment={})
    streams = capsys.readouterr()
    # Assert
    assert exit_code == 2 and streams.out == ""
    assert json.loads(streams.err)["code"] == "session_call_limit"
    assert read_tree(directory) == before


def test_call_limit_prevents_operation_execution_with_an_injected_clock(tmp_path: Path) -> None:
    # Arrange
    plane = build_serving_data_plane(load_packaged_fixture(), clock=read_fixed_clock)
    assert plane.session_dataset is not None
    recorder = SessionRecorder(
        tmp_path / "review", plane.session_dataset, read_fixed_clock, call_limit=1
    )
    invocations: list[str] = []
    operation = partial(observed_lookup, invocations, plane.search_service, "CVE-9999-0001")
    recorder.run("cli", "lookup", {"cve_id": "CVE-9999-0001"}, operation, encode_cli_answer)
    # Act
    with pytest.raises(SessionRecordingError) as refused:
        recorder.run("cli", "lookup", {"cve_id": "CVE-9999-0001"}, operation, encode_cli_answer)
    # Assert
    assert refused.value.code is ToolFailureCode.SESSION_CALL_LIMIT
    assert invocations == ["CVE-9999-0001"]
    call = json.loads((recorder.directory / "calls/0001.json").read_bytes())
    assert call["started_at"] == call["finished_at"]


@pytest.mark.parametrize("unsafe_path", ["symlink", "in_store"])
def test_symlinked_or_in_store_directory_is_refused_before_loading(
    tmp_path: Path,
    unsafe_path: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Arrange
    store = tmp_path / "store"
    store.mkdir()
    if unsafe_path == "symlink":
        directory = tmp_path / "linked"
        directory.symlink_to(store, target_is_directory=True)
    else:
        directory = store / "review"
    # Act
    with pytest.raises(SystemExit) as refused:
        main(
            ["lookup", "CVE-9999-0001", "--session", str(directory)],
            environment={"VULNWITNESS_STORE_ROOT": str(store)},
        )
    # Assert
    assert refused.value.code == 2
    assert capsys.readouterr().out == ""
    assert list(store.iterdir()) == []


def test_recording_failure_withholds_the_cli_answer(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Arrange
    directory = tmp_path / "review"
    directory.mkdir()
    (directory / ".lock").mkdir()
    # Act
    exit_code = main(["lookup", "CVE-9999-0001", "--session", str(directory)], environment={})
    streams = capsys.readouterr()
    # Assert
    assert exit_code == 2 and streams.out == ""
    assert json.loads(streams.err)["code"] == "session_recording_failed"
    assert not (directory / "responses").exists()


@pytest.mark.parametrize(
    "damage",
    [
        "missing_response",
        "sequence_gap",
        "wrong_dataset",
        "bad_response",
        "missing_findings",
        "linked_responses",
        "wrong_schema",
        "bad_request",
    ],
)
def test_inconsistent_session_fails_with_a_location(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    damage: str,
) -> None:
    # Arrange
    directory = tmp_path / "review"
    main(["lookup", "CVE-9999-0001", "--session", str(directory)], environment={})
    capsys.readouterr()
    write_findings(directory, [])
    call_file = directory / "calls/0001.json"
    call = json.loads(call_file.read_bytes())
    if damage == "missing_response":
        (directory / "responses/0001.json").unlink()
    elif damage == "sequence_gap":
        call_file.rename(directory / "calls/0002.json")
    elif damage == "wrong_dataset":
        call["dataset"]["corpus_content_sha256"] = "0" * 64
        call_file.write_text(json.dumps(call))
    elif damage == "bad_response":
        (directory / "responses/0001.json").write_text("{}")
    elif damage == "missing_findings":
        (directory / "findings.yaml").unlink()
    elif damage == "linked_responses":
        (directory / "responses").rename(tmp_path / "outside")
        (directory / "responses").symlink_to(tmp_path / "outside", target_is_directory=True)
    elif damage == "wrong_schema":
        call["response_schema"] = "ToolFailure"
        call_file.write_text(json.dumps(call))
    elif damage == "bad_request":
        call["request"] = {"cve_id": "invalid"}
        call_file.write_text(json.dumps(call))
    # Act
    report = SessionChecker(directory).check()
    # Assert
    assert not report.record.consistent
    assert report.record.violations and all(issue.location for issue in report.record.violations)


@pytest.mark.parametrize(
    "command",
    [
        ["search", "authentication"],
        ["topic", "5gaka", "--scope", "mixed"],
        ["investigate", "5gaka", "--scope", "mixed"],
        ["capabilities"],
        ["resolve", "5gaka"],
        ["evidence", "ev:d8097ae9c31b754d26a1ef92"],
        ["affectedness", "CVE-9999-0001", "--purl", "pkg:generic/demo@1"],
    ],
)
def test_recorded_cli_commands_have_valid_response_contracts(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    command: list[str],
) -> None:
    # Arrange
    directory = tmp_path / "review"
    # Act
    main([*command, "--session", str(directory)], environment={})
    printed = capsys.readouterr().out.encode()
    write_findings(directory, [])
    report = SessionChecker(directory).check()
    # Assert
    assert (directory / "responses/0001.json").read_bytes() == printed
    assert_check_layers_hold(report)


def test_recorded_verification_has_a_valid_response_contract(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Arrange
    main(["investigate", "5gaka", "--scope", "mixed"], environment={})
    evidence_set = tmp_path / "investigation.json"
    evidence_set.write_text(capsys.readouterr().out)
    directory = tmp_path / "review"
    # Act
    main(["verify", str(evidence_set), "--session", str(directory)], environment={})
    printed = capsys.readouterr().out.encode()
    write_findings(directory, [])
    # Assert
    assert (directory / "responses/0001.json").read_bytes() == printed
    assert_check_layers_hold(SessionChecker(directory).check())


def obstruct_call_commit(directory: Path, service: SearchService) -> SearchResponse:
    (directory / "calls/0001.json").mkdir()
    return service.lookup("CVE-9999-0001")


def test_failure_after_execution_withholds_answer_and_blocks_further_appends(
    tmp_path: Path,
) -> None:
    # Arrange
    plane = build_serving_data_plane(load_packaged_fixture(), clock=read_fixed_clock)
    assert plane.session_dataset is not None
    directory = tmp_path / "review"
    recorder = SessionRecorder(directory, plane.session_dataset, read_fixed_clock)
    # Act
    with pytest.raises(SessionRecordingError) as refused:
        recorder.run(
            "cli",
            "lookup",
            {"cve_id": "CVE-9999-0001"},
            partial(obstruct_call_commit, directory, plane.search_service),
            encode_cli_answer,
        )
    invocations: list[str] = []
    with pytest.raises(SessionRecordingError):
        recorder.run(
            "cli",
            "lookup",
            {"cve_id": "CVE-9999-0001"},
            partial(observed_lookup, invocations, plane.search_service, "CVE-9999-0001"),
            encode_cli_answer,
        )
    # Assert
    assert refused.value.code is ToolFailureCode.SESSION_RECORDING_FAILED
    assert invocations == []
    assert (directory / "responses/0001.json").is_file()
    assert not list(directory.rglob("*.tmp-*"))


@pytest.mark.parametrize("limit", ["0", "101"])
def test_session_limit_outside_one_to_one_hundred_is_refused_before_writing(
    tmp_path: Path,
    limit: str,
) -> None:
    # Arrange
    directory = tmp_path / "review"
    # Act
    with pytest.raises(SystemExit) as refused:
        main(
            ["lookup", "CVE-9999-0001", "--session", str(directory), "--session-call-limit", limit],
            environment={},
        )
    # Assert
    assert refused.value.code == 2
    assert not directory.exists()
