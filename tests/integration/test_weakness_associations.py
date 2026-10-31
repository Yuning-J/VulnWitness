"""Offline build, pinned serving and candidate integrity across shared surfaces."""

import json
from pathlib import Path

import pytest

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.adapters.mitre.mapping_file import MitreSnapshotUnavailable, load_weakness_mapping
from cve_kgrag.adapters.nvd.normalizer import SourceSnapshot
from cve_kgrag.cli import main
from cve_kgrag.composition import (
    build_investigation_service,
    build_nvd_normalizer,
    build_search_service,
    build_serving_data_plane,
    load_packaged_source_registry,
)
from cve_kgrag.domain.evidence_catalog import EvidenceCatalog
from cve_kgrag.domain.hashing import sha256_hex
from cve_kgrag.domain.investigation import InvestigationRequest
from cve_kgrag.domain.investigation_validation import validate_knowledge_evidence_set
from cve_kgrag.domain.search import Candidate, SearchRequest
from cve_kgrag.domain.validation import EvidenceValidationError, validate_search_response
from cve_kgrag.domain.weakness_associations import DERIVED_ASSOCIATION_NOTE
from cve_kgrag.interfaces.investigation_summary import render_investigation_summary
from cve_kgrag.settings import MitreSnapshotSettings, SettingsError, load_settings
from tests.support.builders import build_bundle_with, build_cve_record
from tests.support.clocks import SteppingClock, read_fixed_clock
from tests.support.investigation import build_test_deployment, reseal_evidence_set
from tests.support.investigation_runs import run_five_g_aka_mixed
from tests.support.mitre_catalogues import (
    CWE_XML,
    build_snippet_mapping,
    forge_capec_hop,
    write_snippet_catalogues,
)
from tests.support.planners import DETERMINISTIC_VERIFIER


def test_packaged_memory_weakness_keeps_all_capec_terminal_paths_and_sources() -> None:
    # Arrange
    mapping = load_weakness_mapping()
    record = build_cve_record(cwe_ids=["CWE-120"])
    cwe_source = mapping.describe().sources[0]

    # Act
    associations = mapping.associate(record)

    # Assert
    assert len(associations.paths) == 13
    assert associations.omitted_count == 0
    assert associations.missing_links == ()
    assert tuple(path.capec_id for path in associations.paths) == (
        "CAPEC-10",
        "CAPEC-100",
        "CAPEC-14",
        "CAPEC-24",
        "CAPEC-42",
        "CAPEC-44",
        "CAPEC-45",
        "CAPEC-46",
        "CAPEC-47",
        "CAPEC-67",
        "CAPEC-8",
        "CAPEC-9",
        "CAPEC-92",
    )
    for path in associations.paths:
        assert path.cwe_id == "CWE-120"
        assert path.terminal_reason == "no_attack_mapping"
        assert path.technique is None
        assert path.technique_source is None
        assert path.inherited_from is None
        assert path.derived is True
        assert len(path.hops) == 2
        assert path.hops[0].from_id == record.cve_id
        assert path.hops[0].to_id == "CWE-120"
        assert path.hops[0].relation == "nvd_cwe"
        assert path.hops[0].source == "NVD record"
        assert path.hops[0].evidence_ids == record.evidence_ids
        assert path.hops[1].from_id == "CWE-120"
        assert path.hops[1].to_id == path.capec_id
        assert path.hops[1].relation == "cwe_related_attack_pattern"
        assert path.hops[1].source == "CWE catalogue"
        assert path.hops[1].source_version == cwe_source.version
        assert path.hops[1].source_sha256 == cwe_source.sha256


def test_cap_counts_full_and_capec_terminal_paths_across_cwes() -> None:
    # Arrange
    mapping = load_weakness_mapping()
    record = build_cve_record(cwe_ids=["CWE-79", "CWE-120"])

    # Act
    associations = mapping.associate(record)
    reversed_associations = mapping.associate(
        record.model_copy(update={"cwe_ids": ("CWE-120", "CWE-79")})
    )

    # Assert
    # CWE-79 has four full and five terminal paths; CWE-120 has thirteen terminal paths.
    assert len(associations.paths) == 20
    assert associations.omitted_count == 2
    assert all(path.technique is not None for path in associations.paths[:4])
    assert all(path.terminal_reason == "no_attack_mapping" for path in associations.paths[4:])
    assert reversed_associations == associations


def test_text_command_shows_a_capec_terminal_path(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Arrange
    arguments = write_snippet_catalogues(tmp_path)
    (tmp_path / "cwe").write_bytes(
        CWE_XML.replace(b'CAPEC_ID="10"', b'CAPEC_ID="12"').replace(
            b'CAPEC_ID="13"', b'CAPEC_ID="12"'
        )
    )
    snapshot_path = tmp_path / "mapping.json"
    main(["mitre", "build", *arguments, "--out", str(snapshot_path)], environment={})
    digest = json.loads(capsys.readouterr().out)["sha256"]
    environment = {
        "CVE_KGRAG_MITRE_SNAPSHOT_PATH": str(snapshot_path),
        "CVE_KGRAG_MITRE_SNAPSHOT_SHA256": digest,
    }

    # Act
    exit_code = main(
        ["investigate", "CVE-9999-0002", "--scope", "implementation_only", "--format", "text"],
        environment=environment,
    )
    summary = " ".join(capsys.readouterr().out.split())

    # Assert
    assert exit_code == 0
    assert "CWE-79 → CAPEC-12 (no ATT&CK mapping in catalogue)" in summary
    assert DERIVED_ASSOCIATION_NOTE in summary


def test_search_validator_accepts_capec_terminal_paths_and_rejects_a_forged_one(
    fixture_bundle: FixtureBundle,
) -> None:
    # Arrange
    bundle = build_bundle_with(
        fixture_bundle, "CVE-9999-5555", "Synthetic memory weakness", cwe_ids=["CWE-120"]
    )
    deployment = build_serving_data_plane(bundle, clock=read_fixed_clock)
    search_response = deployment.search_service.search(SearchRequest(query="CVE-9999-5555"))

    # Act / Assert
    validate_search_response(search_response, deployment.evidence_catalog)
    forged_candidate = forge_capec_hop(search_response.candidates[0])
    forged_candidate = Candidate.model_validate(forged_candidate.model_dump(mode="json"))
    forged_response = search_response.model_copy(update={"candidates": (forged_candidate,)})
    forged_response = forged_response.model_copy(
        update={"result_sha256": forged_response.compute_result_sha256()}
    )
    with pytest.raises(EvidenceValidationError, match="weakness associations differ"):
        validate_search_response(forged_response, deployment.evidence_catalog)


def test_operator_build_writes_a_servable_mapping_and_prints_its_digest(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Arrange
    arguments = write_snippet_catalogues(tmp_path)
    snapshot_path = tmp_path / "mapping.json"

    # Act
    exit_code = main(["mitre", "build", *arguments, "--out", str(snapshot_path)], environment={})
    report = json.loads(capsys.readouterr().out)
    mapping = load_weakness_mapping(
        MitreSnapshotSettings(path=snapshot_path, sha256=report["sha256"])
    )

    # Assert
    assert exit_code == 0
    assert report["sha256"] == sha256_hex(snapshot_path.read_bytes())
    assert report["size_bytes"] == snapshot_path.stat().st_size
    assert mapping.describe().counts.direct_mappings == 2
    assert mapping.describe().counts.inherited_mappings == 3


def test_digest_mismatch_refuses_serving_instead_of_loading_the_excerpt(tmp_path: Path) -> None:
    # Arrange
    snapshot_path = tmp_path / "mapping.json"
    snapshot_path.write_text("{}")
    settings = MitreSnapshotSettings(path=snapshot_path, sha256="0" * 64)

    # Act / Assert
    with pytest.raises(MitreSnapshotUnavailable, match="mitre_snapshot_hash_mismatch"):
        load_weakness_mapping(settings)


def test_lookup_refuses_a_configured_snapshot_digest_mismatch(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Arrange
    snapshot_path = tmp_path / "mapping.json"
    snapshot_path.write_text("{}")
    environment = {
        "CVE_KGRAG_MITRE_SNAPSHOT_PATH": str(snapshot_path),
        "CVE_KGRAG_MITRE_SNAPSHOT_SHA256": "0" * 64,
    }

    # Act / Assert
    with pytest.raises(SystemExit) as failure:
        main(["lookup", "CVE-9999-0003"], environment=environment)
    assert failure.value.code == 2
    assert "mitre_snapshot_hash_mismatch" in capsys.readouterr().err


@pytest.mark.parametrize(
    "variable", ["CVE_KGRAG_MITRE_SNAPSHOT_PATH", "CVE_KGRAG_MITRE_SNAPSHOT_SHA256"]
)
def test_snapshot_settings_require_both_variables(variable: str) -> None:
    # Arrange
    environment = {
        "CVE_KGRAG_MITRE_SNAPSHOT_PATH": "/tmp/mapping.json",
        "CVE_KGRAG_MITRE_SNAPSHOT_SHA256": "0" * 64,
    }
    del environment[variable]

    # Act / Assert
    with pytest.raises(SettingsError, match="must be set together"):
        load_settings(environment)


def test_without_settings_the_packaged_real_excerpt_is_served() -> None:
    # Arrange
    settings = load_settings({})

    # Act
    capability = load_weakness_mapping(settings.mitre_snapshot).describe()

    # Assert
    assert capability.coverage == "excerpt"
    assert capability.sources[0].version == "5.0"
    assert capability.sources[1].version == "3.9"
    assert capability.sources[2].version == "20.0"
    assert len(capability.snapshot_sha256) == 64


def test_lookup_and_capabilities_report_the_same_packaged_snapshot(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Arrange
    digest = load_weakness_mapping().describe().snapshot_sha256

    # Act
    lookup_exit = main(["lookup", "CVE-9999-0003"], environment={})
    lookup = json.loads(capsys.readouterr().out)
    capabilities_exit = main(["capabilities"], environment={})
    capabilities = json.loads(capsys.readouterr().out)

    # Assert
    assert lookup_exit == capabilities_exit == 0
    assert lookup["candidates"][0]["weakness_associations"]["snapshot_sha256"] == digest
    assert capabilities["weakness_associations"]["snapshot_sha256"] == digest
    assert capabilities["weakness_associations"]["coverage"] == "excerpt"


def test_investigation_candidates_and_text_include_associations_and_the_note_once(
    fixture_bundle: FixtureBundle,
) -> None:
    # Arrange
    evidence_set = run_five_g_aka_mixed(fixture_bundle)

    # Act
    summary = render_investigation_summary(evidence_set)
    associations = evidence_set.implementation_candidates[0].candidate.weakness_associations

    # Assert
    assert associations is not None
    assert associations.paths[0].cwe_id == "CWE-20"
    assert "CWE-20 → CAPEC-13 → T1574.006" in summary
    assert " ".join(summary.split()).count(DERIVED_ASSOCIATION_NOTE) == 1
    assert "paths omitted by the cap" in summary


def test_mapping_contents_leave_needs_stops_ranking_and_protocol_context_unchanged(
    fixture_bundle: FixtureBundle,
) -> None:
    # Arrange
    mapped_service = build_investigation_service(
        build_serving_data_plane(fixture_bundle, clock=read_fixed_clock),
        wall_clock=read_fixed_clock,
        monotonic_clock=SteppingClock().read,
    )
    sparse_service = build_investigation_service(
        build_serving_data_plane(
            fixture_bundle, weakness_mapping=build_snippet_mapping(), clock=read_fixed_clock
        ),
        wall_clock=read_fixed_clock,
        monotonic_clock=SteppingClock().read,
    )
    request = InvestigationRequest(query="5G-AKA", scope="mixed")

    # Act
    mapped_set = mapped_service.investigate(request)
    sparse_set = sparse_service.investigate(request)

    # Assert
    assert mapped_set.coverage.needs == sparse_set.coverage.needs
    assert mapped_set.stop_reason == sparse_set.stop_reason == "needs_unmet"
    assert mapped_set.protocol_context == sparse_set.protocol_context
    assert mapped_set.product_applicability == sparse_set.product_applicability
    assert mapped_set.trajectory.ranking == sparse_set.trajectory.ranking
    for mapped_candidate, sparse_candidate in zip(
        mapped_set.implementation_candidates,
        sparse_set.implementation_candidates,
        strict=True,
    ):
        assert mapped_candidate.rank == sparse_candidate.rank
        assert mapped_candidate.nvd_version_notes == sparse_candidate.nvd_version_notes
        assert mapped_candidate.candidate.record == sparse_candidate.candidate.record
        assert (
            mapped_candidate.candidate.relevance_score == sparse_candidate.candidate.relevance_score
        )


@pytest.mark.parametrize("placeholder", ["NVD-CWE-noinfo", "NVD-CWE-Other"])
def test_nvd_placeholder_reports_no_specific_cwe_without_a_path(placeholder: str) -> None:
    # Arrange
    normalizer = build_nvd_normalizer(load_packaged_source_registry())
    vulnerability = {
        "id": "CVE-9999-5555",
        "descriptions": [{"lang": "en", "value": "Synthetic record."}],
        "weaknesses": [{"description": [{"lang": "en", "value": placeholder}]}],
    }
    source = SourceSnapshot(
        source_uri="urn:test:nvd",
        retrieved_at=read_fixed_clock(),
        source_version="fixture",
    )

    # Act
    normalized = normalizer.normalize_v2(vulnerability, source)
    associations = build_snippet_mapping().associate(normalized.record)

    # Assert
    assert associations.paths == ()
    assert associations.missing_links[0].reason == "no_specific_cwe"


def test_search_validator_rejects_a_forged_catalogue_hop(
    fixture_bundle: FixtureBundle,
    packaged_evidence_catalog: EvidenceCatalog,
) -> None:
    # Arrange
    service = build_search_service(fixture_bundle)
    search_response = service.search(SearchRequest(query="CVE-9999-0003"))
    forged_candidate = forge_capec_hop(search_response.candidates[0])
    forged_response = search_response.model_copy(update={"candidates": (forged_candidate,)})
    forged_response = forged_response.model_copy(
        update={"result_sha256": forged_response.compute_result_sha256()}
    )

    # Act / Assert
    with pytest.raises(EvidenceValidationError, match="weakness associations differ"):
        validate_search_response(forged_response, packaged_evidence_catalog)


@pytest.mark.parametrize("command", ["lookup", "capabilities", "investigate"])
def test_serving_commands_use_the_operator_pinned_mapping(
    command: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Arrange
    arguments = write_snippet_catalogues(tmp_path)
    snapshot_path = tmp_path / "mapping.json"
    main(["mitre", "build", *arguments, "--out", str(snapshot_path)], environment={})
    digest = json.loads(capsys.readouterr().out)["sha256"]
    environment = {
        "CVE_KGRAG_MITRE_SNAPSHOT_PATH": str(snapshot_path),
        "CVE_KGRAG_MITRE_SNAPSHOT_SHA256": digest,
    }
    command_arguments = [command]
    if command == "lookup":
        command_arguments.append("CVE-9999-0003")
    elif command == "investigate":
        command_arguments.extend(("CVE-9999-0003", "--scope", "implementation_only"))

    # Act
    exit_code = main(command_arguments, environment=environment)
    served_answer = json.loads(capsys.readouterr().out)
    if command == "lookup":
        capability = served_answer["candidates"][0]["weakness_associations"]
    elif command == "investigate":
        capability = served_answer["implementation_candidates"][0]["candidate"][
            "weakness_associations"
        ]
    else:
        capability = served_answer["weakness_associations"]

    # Assert
    assert exit_code == 0
    assert capability["snapshot_sha256"] == digest


def test_operator_build_refuses_overwriting_an_input(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Arrange
    arguments = write_snippet_catalogues(tmp_path)
    cwe_path = tmp_path / "cwe"
    cwe_bytes = cwe_path.read_bytes()

    # Act
    exit_code = main(["mitre", "build", *arguments, "--out", str(cwe_path)], environment={})

    # Assert
    assert exit_code == 1
    assert cwe_path.read_bytes() == cwe_bytes
    assert "File exists" in capsys.readouterr().err


def test_operator_build_reports_malformed_xml_without_writing_a_snapshot(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Arrange
    arguments = write_snippet_catalogues(tmp_path)
    (tmp_path / "cwe").write_bytes(b"<invalid")
    snapshot_path = tmp_path / "mapping.json"

    # Act
    exit_code = main(["mitre", "build", *arguments, "--out", str(snapshot_path)], environment={})

    # Assert
    assert exit_code == 1
    assert not snapshot_path.exists()
    assert "mitre build failed" in capsys.readouterr().err


def test_investigation_validator_rejects_a_forged_catalogue_hop(
    fixture_bundle: FixtureBundle,
) -> None:
    # Arrange
    evidence_set = run_five_g_aka_mixed(fixture_bundle)
    deployment = build_test_deployment(fixture_bundle)
    first_candidate = evidence_set.implementation_candidates[0]
    forged_candidate = first_candidate.model_copy(
        update={"candidate": forge_capec_hop(first_candidate.candidate)}
    )
    forged_set = reseal_evidence_set(
        evidence_set,
        implementation_candidates=(forged_candidate, *evidence_set.implementation_candidates[1:]),
    )

    # Act / Assert
    with pytest.raises(EvidenceValidationError, match="weakness associations differ"):
        validate_knowledge_evidence_set(
            forged_set,
            deployment.pinned_fight_snapshot,
            deployment.evidence_catalog,
            (*deployment.source_capabilities, *DETERMINISTIC_VERIFIER),
        )
