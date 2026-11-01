"""CLI composition root for the reusable triage workflow."""

import argparse
import sys
import time
from functools import partial
from pathlib import Path

from vulnwitness.adapters.session.recorder import SessionRecorder
from vulnwitness.adapters.session.triage_artifacts import SessionTriageArtifacts
from vulnwitness.application.serving_data_plane import ServingDataPlane
from vulnwitness.application.triage_workflow import TriageWorkflow
from vulnwitness.composition import build_investigation_deployment, utc_now
from vulnwitness.domain.investigation import SourceCapability
from vulnwitness.interfaces.cli_session import encode_cli_answer
from vulnwitness.interfaces.cli_triage import build_triage_plan, render_triage_summary
from vulnwitness.interfaces.knowledge_toolbox import describe_knowledge_capabilities


def preflight_triage(arguments: argparse.Namespace, store_root: Path | None) -> None:
    """Reject invalid invocations before loading any deployment data."""
    SessionTriageArtifacts(arguments.session, store_root).require_empty()
    build_triage_plan(arguments)


def run_triage(
    arguments: argparse.Namespace,
    data_plane: ServingDataPlane,
    store_root: Path | None,
    source_capabilities: tuple[SourceCapability, ...],
) -> int:
    try:
        request, limits = build_triage_plan(arguments)
        assert data_plane.session_dataset is not None
        deployment = build_investigation_deployment(data_plane)
        workflow = TriageWorkflow(
            capabilities=partial(describe_knowledge_capabilities, deployment, source_capabilities),
            query_product=deployment.product_query_service.query,
            lookup=deployment.search_service.lookup,
            recorder=SessionRecorder(
                arguments.session,
                data_plane.session_dataset,
                utc_now,
                store_root=store_root,
                call_limit=limits.call_limit,
                goal=arguments.session_goal,
                scope=arguments.session_scope,
            ),
            artifacts=SessionTriageArtifacts(arguments.session, store_root),
            clock=time.monotonic,
            limits=limits,
            encode=encode_cli_answer,
        )
        summary, check, exit_code = workflow.run(request, tuple(arguments.select))
    except (OSError, ValueError) as error:
        print(f"vulnwitness triage: {error}", file=sys.stderr)
        return 2
    print(
        summary.model_dump_json(indent=2)
        if arguments.format == "json"
        else render_triage_summary(summary, check)
    )
    return exit_code
