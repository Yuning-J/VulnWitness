"""``vulnwitness vex``: write an OpenVEX document from an analyst's asset register,
quoting the session's checked priority decisions when a session is given. Nothing is
loaded from a store and no service is called."""

import argparse
import json
import os
import sys
from pathlib import Path

from pydantic import TypeAdapter, ValidationError
from yaml import YAMLError

from vulnwitness.adapters.session.check import SessionChecker
from vulnwitness.adapters.session.files import read_session_file
from vulnwitness.adapters.session.report_output import write_report
from vulnwitness.adapters.strict_yaml import load_declaration_yaml
from vulnwitness.domain.asset_register import AssetRegister
from vulnwitness.domain.contract_model import list_validation_problems
from vulnwitness.domain.openvex import build_openvex
from vulnwitness.domain.timestamps import CalendarDate


def add_vex_parser(commands: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    parser = commands.add_parser(
        "vex",
        help="write an OpenVEX document from an asset register's applicability assessments",
    )
    parser.add_argument("--assets", type=Path, required=True, metavar="FILE")
    parser.add_argument("--author", required=True)
    parser.add_argument("--as-of", required=True, metavar="YYYY-MM-DD")
    parser.add_argument(
        "--session",
        type=Path,
        metavar="DIR",
        help="quote this checked session's priority.json in affected statements",
    )
    parser.add_argument("--output", type=Path, required=True, metavar="FILE")
    parser.add_argument("--force", action="store_true")


def run_vex(arguments: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    try:
        register = AssetRegister.model_validate(
            load_declaration_yaml(read_session_file(arguments.assets).decode("utf-8"))
        )
        issued_on = TypeAdapter(CalendarDate).validate_python(arguments.as_of)
        if issued_on.isoformat() != arguments.as_of:
            raise ValueError("--as-of must be YYYY-MM-DD")
    except ValidationError as error:
        parser.error("; ".join(list_validation_problems(error)))
    except (OSError, ValueError, YAMLError, RecursionError) as error:
        parser.error(str(error))
    try:
        priority = None
        if arguments.session is not None:
            contents = SessionChecker(arguments.session).check_with_contents()
            if not (
                contents.check.record.consistent
                and contents.check.citations.resolved
                and contents.check.claims.verified
            ):
                raise ValueError("the session check did not pass; run session check for details")
            if contents.priority is None:
                raise ValueError("the session has no valid priority.json")
            priority = contents.priority
        document = build_openvex(register, arguments.author, issued_on, priority)
        target: Path = arguments.output
        if os.path.lexists(target) and not arguments.force:
            raise ValueError("the output exists; use --force to overwrite")
        write_report(
            target, json.dumps(document, indent=2, ensure_ascii=False) + "\n", arguments.force
        )
    except (OSError, ValueError, RecursionError) as error:
        print(f"vulnwitness vex: {error}", file=sys.stderr)
        return 1
    statements = document["statements"]
    print(f"wrote {len(statements)} OpenVEX statements")
    return 0
