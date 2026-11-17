"""Compose offline session prioritisation and private, atomic artifact publication."""

import argparse
import hashlib
import os
import sys
from datetime import date
from pathlib import Path

from pydantic import TypeAdapter, ValidationError
from yaml import YAMLError

from vulnwitness.adapters.epss_files import read_epss_directory
from vulnwitness.adapters.priority_policy import (
    PACKAGED_POLICY_NAMES,
    load_priority_policy,
    packaged_priority_policy_file,
)
from vulnwitness.adapters.session.check import SessionChecker
from vulnwitness.adapters.session.files import check_session_path, read_session_file
from vulnwitness.adapters.session.report_output import write_report
from vulnwitness.adapters.strict_yaml import load_declaration_yaml
from vulnwitness.application.priority_session import (
    EpssInput,
    ExploitIndexInput,
    build_session_priority,
)
from vulnwitness.distribution import read_installed_version
from vulnwitness.domain.asset_register import AssetRegister
from vulnwitness.domain.contract_model import list_validation_problems
from vulnwitness.domain.exploit_index import ExploitIndex, ExploitIndexIdentity
from vulnwitness.domain.timestamps import CalendarDate


def add_priority_parser(commands: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    parser = commands.add_parser("prioritise", help="apply a named policy to a recorded session")
    parser.add_argument("directory", type=Path)
    parser.add_argument("--assets", type=Path, required=True, metavar="FILE")
    parser.add_argument("--policy", choices=PACKAGED_POLICY_NAMES, required=True)
    parser.add_argument("--as-of", required=True, metavar="YYYY-MM-DD")
    parser.add_argument(
        "--epss-dir",
        type=Path,
        metavar="DIR",
        help="FIRST EPSS daily files you supplied (.csv or .csv.gz); files scored after "
        "--as-of are ignored",
    )
    parser.add_argument(
        "--exploit-index",
        type=Path,
        metavar="FILE",
        help="an index from 'vulnwitness exploit-index build'",
    )
    parser.add_argument("--force", action="store_true")


def parse_reference_date(value: str) -> date:
    """Accept a calendar date in the CLI's explicit YYYY-MM-DD spelling only."""
    reference_date = TypeAdapter(CalendarDate).validate_python(value)
    if reference_date.isoformat() != value:
        raise ValueError("--as-of must be YYYY-MM-DD")
    return reference_date


def read_epss_input(directory: Path, register: AssetRegister, reference_date: date) -> EpssInput:
    """The supplied files scored on or before the reference date, read for the register's
    CVEs only."""
    cve_ids = set()
    for assessment in register.assessments:
        cve_ids.add(assessment.cve_id)
    snapshots, observations = read_epss_directory(directory, cve_ids, reference_date)
    if not snapshots:
        raise ValueError("no supplied EPSS file is scored on or before --as-of")
    return EpssInput(snapshots, observations)


def read_exploit_index(path: Path) -> ExploitIndexInput:
    raw = read_session_file(path)
    try:
        index = ExploitIndex.model_validate_json(raw)
    except ValidationError as error:
        raise ValueError(f"{path} is not a VulnWitness exploit index") from error
    identity = ExploitIndexIdentity(
        sha256=hashlib.sha256(raw).hexdigest(), built_on=index.built_on, sources=index.sources
    )
    return ExploitIndexInput(index, identity)


def run_priority(arguments: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    try:
        register = AssetRegister.model_validate(
            load_declaration_yaml(read_session_file(arguments.assets).decode("utf-8"))
        )
        reference_date = parse_reference_date(arguments.as_of)
    except ValidationError as error:
        parser.error("; ".join(list_validation_problems(error)))
    except (OSError, ValueError, YAMLError, RecursionError) as error:
        parser.error(str(error))
    try:
        check_session_path(arguments.directory)
        target = arguments.directory / "priority.json"
        if target.is_symlink() or (target.exists() and not target.is_file()):
            raise ValueError("priority.json must be a regular file, not a symlink")
        if os.path.lexists(target) and not arguments.force:
            raise ValueError("priority.json already exists; use --force to overwrite")
        loaded_policy = load_priority_policy(packaged_priority_policy_file(arguments.policy))
        epss = None
        if arguments.epss_dir is not None:
            epss = read_epss_input(arguments.epss_dir, register, reference_date)
        exploit_index = None
        if arguments.exploit_index is not None:
            exploit_index = read_exploit_index(arguments.exploit_index)
        artifact = build_session_priority(
            SessionChecker(arguments.directory, include_priority=False).check_with_contents(),
            register,
            loaded_policy.policy,
            loaded_policy.content_sha256,
            reference_date,
            read_installed_version(),
            epss,
            exploit_index,
        )
        write_report(target, artifact.to_json_bytes().decode("utf-8"), arguments.force)
    except (OSError, ValueError, RecursionError) as error:
        print(f"vulnwitness prioritise: {error}", file=sys.stderr)
        return 1
    for decision in artifact.decisions:
        compliance = ", ".join(
            f"{status.regulation_id}={status.status}" for status in decision.compliance
        )
        print(
            f"{decision.asset} {decision.cve_id}: {decision.recommendation}; "
            f"compliance: {compliance or 'no applicable market regulation'}; "
            f"rule: {decision.matched_rule.id}"
        )
    return 0
