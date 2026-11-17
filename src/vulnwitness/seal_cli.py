"""``vulnwitness session seal`` and ``vulnwitness session verify-seal``."""

import argparse
import sys
from pathlib import Path

from vulnwitness.adapters.session.files import check_session_path
from vulnwitness.adapters.session.seal import (
    read_key,
    seal_session,
    verify_session_seal,
)

SEAL_COMMANDS = ("seal", "verify-seal")


def add_seal_parsers(
    session_commands: "argparse._SubParsersAction[argparse.ArgumentParser]",
) -> None:
    seal_parser = session_commands.add_parser(
        "seal",
        help="seal session.json, calls/, responses/ and priority.json when present under a key",
    )
    seal_parser.add_argument("directory", type=Path)
    seal_parser.add_argument("--key-file", type=Path, required=True, metavar="FILE")
    seal_parser.add_argument("--force", action="store_true")
    verify_parser = session_commands.add_parser(
        "verify-seal", help="check seal.json against the session's recorded files and the key"
    )
    verify_parser.add_argument("directory", type=Path)
    verify_parser.add_argument("--key-file", type=Path, required=True, metavar="FILE")


def run_seal_command(arguments: argparse.Namespace) -> int:
    """0 when sealed or the seal holds; 1 with the reason or the differing files."""
    command = arguments.session_command
    try:
        check_session_path(arguments.directory)
        key = read_key(arguments.key_file, arguments.directory)
        if command == "seal":
            seal = seal_session(arguments.directory, key, arguments.force)
            print(f"sealed {len(seal.files)} files with key {seal.key_id}")
            return 0
        verification = verify_session_seal(arguments.directory, key)
    except (OSError, ValueError) as error:
        print(f"vulnwitness session {command} failed: {error}", file=sys.stderr)
        return 1
    if verification.valid:
        print("seal holds: no sealed file changed, appeared or disappeared")
        return 0
    for label, names in (
        ("changed", verification.changed),
        ("added", verification.added),
        ("removed", verification.removed),
    ):
        for name in names:
            print(f"{label}: {name}")
    if not (verification.changed or verification.added or verification.removed):
        print("the seal's MAC does not match its file list")
    return 1
