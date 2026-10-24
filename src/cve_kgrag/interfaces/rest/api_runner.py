"""Serves the v2 REST API on a loopback address, behind the HTTP guard (ADR 0007).
Loaded only through the ``api_server`` entry point of the ``cve_kgrag.adapters`` group.

Every route but ``/health`` requires the token, and every route is one toolbox call or
one verification: ``POST /api/v2/search``, ``POST /api/v2/investigate``,
``GET /api/v2/evidence/{evidence_id}``, ``GET /api/v2/capabilities`` and
``POST /api/v2/verify``.
"""

from pydantic import SecretStr
from starlette.applications import Starlette

from cve_kgrag.application.evidence_set_verification import MAX_EVIDENCE_SET_BYTES
from cve_kgrag.interfaces.http.guard import GuardedRoute, HttpGuard
from cve_kgrag.interfaces.http.serving import find_request_deadline_seconds, serve
from cve_kgrag.interfaces.http.status_routes import (
    HEALTH_PATH,
    READY_PATH,
    ReadinessRoute,
    answer_health,
)
from cve_kgrag.interfaces.knowledge_toolbox import KnowledgeToolbox
from cve_kgrag.interfaces.knowledge_tools import KnowledgeToolName
from cve_kgrag.interfaces.rest.tool_routes import (
    ToolRoute,
    read_body_arguments,
    read_evidence_id_argument,
    read_no_arguments,
)
from cve_kgrag.interfaces.rest.verification_route import EvidenceSetCheck, VerificationRoute

API_PREFIX = "/api/v2"
GET_ONLY = frozenset({"GET"})
POST_ONLY = frozenset({"POST"})


def build_api_app(
    toolbox: KnowledgeToolbox,
    check_evidence_set: EvidenceSetCheck,
    *,
    host: str,
    port: int,
    token: SecretStr,
) -> HttpGuard:
    """The guarded REST API over ``toolbox`` and ``check_evidence_set`` for a server on
    ``host`` and ``port``; its request deadline is ``find_request_deadline_seconds``."""
    routes = {
        f"{API_PREFIX}/search": GuardedRoute(
            methods=POST_ONLY,
            app=ToolRoute(toolbox, KnowledgeToolName.SEARCH_VULNERABILITIES, read_body_arguments),
        ),
        f"{API_PREFIX}/investigate": GuardedRoute(
            methods=POST_ONLY,
            app=ToolRoute(
                toolbox, KnowledgeToolName.INVESTIGATE_TELECOM_TOPIC, read_body_arguments
            ),
        ),
        f"{API_PREFIX}/evidence/": GuardedRoute(
            methods=GET_ONLY,
            app=ToolRoute(toolbox, KnowledgeToolName.GET_EVIDENCE, read_evidence_id_argument),
            takes_path_segment=True,
        ),
        f"{API_PREFIX}/capabilities": GuardedRoute(
            methods=GET_ONLY,
            app=ToolRoute(toolbox, KnowledgeToolName.GET_KNOWLEDGE_CAPABILITIES, read_no_arguments),
        ),
        f"{API_PREFIX}/verify": GuardedRoute(
            methods=POST_ONLY,
            app=VerificationRoute(check_evidence_set),
            # A whole evidence set, up to the size `cve-kgrag verify` reads (decision 9).
            body_cap_bytes=MAX_EVIDENCE_SET_BYTES,
        ),
        HEALTH_PATH: GuardedRoute(methods=GET_ONLY, app=answer_health, is_open=True),
        READY_PATH: GuardedRoute(methods=GET_ONLY, app=ReadinessRoute(toolbox.has_free_worker)),
    }
    return HttpGuard(
        routes=routes,
        lifespan_app=Starlette(),
        host=host,
        port=port,
        token=token,
        request_deadline_seconds=find_request_deadline_seconds(toolbox.limits),
    )


def serve_api(
    toolbox: KnowledgeToolbox,
    check_evidence_set: EvidenceSetCheck,
    *,
    host: str,
    port: int,
    token: SecretStr,
) -> bool:
    """Serve the REST API until the process is interrupted; ``False`` when the server
    could not start."""
    return serve(
        build_api_app(toolbox, check_evidence_set, host=host, port=port, token=token),
        host,
        port,
    )
