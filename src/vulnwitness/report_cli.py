"""CLI composition for offline checking, rendering and atomic report output."""

import argparse
from pathlib import Path

from vulnwitness.adapters.session.check import SessionChecker
from vulnwitness.adapters.session.report_output import (
    read_triage_scope,
    validate_report_output,
    write_report,
)
from vulnwitness.application.session_report import build_session_report
from vulnwitness.interfaces.report_html import render_html_report
from vulnwitness.interfaces.report_markdown import render_markdown_report


def add_report_parser(commands: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    parser = commands.add_parser("report", help="render a checked session as Markdown or HTML")
    parser.add_argument("directory", type=Path)
    parser.add_argument("--format", choices=("md", "html"), default="md")
    parser.add_argument("--output", type=Path, metavar="FILE")
    parser.add_argument("--force", action="store_true")


def run_report(arguments: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    try:
        validate_report_output(arguments.directory, arguments.output, arguments.force)
        contents = SessionChecker(arguments.directory).check_with_contents()
        report = build_session_report(contents, read_triage_scope(arguments.directory))
        document = (
            render_html_report(report)
            if arguments.format == "html"
            else render_markdown_report(report)
        )
        if arguments.output is None:
            print(document, end="")
        else:
            write_report(arguments.output, document, arguments.force)
    except (OSError, ValueError, RecursionError) as error:
        parser.error(str(error))
    check = report.check
    return (
        0 if check.record.consistent and check.citations.resolved and check.claims.verified else 1
    )
