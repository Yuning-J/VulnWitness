"""Production REST app wiring shared by in-process route tests."""

from functools import partial
from typing import Any

from tests.support.asgi import HTTP_HOST, HTTP_PORT, HTTP_SECRET_TOKEN
from tests.support.investigation import build_test_deployment
from tests.support.planners import DETERMINISTIC_VERIFIER
from tests.support.toolbox import build_test_toolbox
from vulnwitness.adapters.fixture.synthetic_fixture import FixtureBundle
from vulnwitness.application.evidence_set_verification import check_evidence_set
from vulnwitness.interfaces.http.guard import HttpGuard
from vulnwitness.interfaces.knowledge_toolbox import KnowledgeToolbox
from vulnwitness.interfaces.rest.api_runner import build_api_app
from vulnwitness.interfaces.rest.verification_route import EvidenceSetCheck


def build_evidence_set_check(
    fixture_bundle: FixtureBundle, **deployment_wiring: Any
) -> EvidenceSetCheck:
    """``check_evidence_set`` over the test deployment with ``deployment_wiring``,
    accepting the deterministic planner, as the API's verification route runs it."""
    return partial(
        check_evidence_set,
        deployment=build_test_deployment(fixture_bundle, **deployment_wiring),
        accepted_planner_capabilities=DETERMINISTIC_VERIFIER,
    )


def build_test_api(
    fixture_bundle: FixtureBundle,
    toolbox: KnowledgeToolbox | None = None,
    check: EvidenceSetCheck | None = None,
) -> HttpGuard:
    return build_api_app(
        toolbox or build_test_toolbox(fixture_bundle),
        check or build_evidence_set_check(fixture_bundle),
        host=HTTP_HOST,
        port=HTTP_PORT,
        token=HTTP_SECRET_TOKEN,
    )
