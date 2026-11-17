"""An OpenVEX v0.2.0 document from an analyst's asset register (and, when given, the
recorded priority decisions), so other tools can read VulnWitness's assessments.

The analyst's applicability is the VEX status: ``affected`` stays ``affected``,
``not_affected`` stays ``not_affected`` with the analyst's justification as the impact
statement, and ``unknown`` becomes ``under_investigation``. VulnWitness never derives a
status from source data. An affected statement's action statement quotes the recorded
policy recommendation when one exists and says none was recorded otherwise. Output is
deterministic: no clock is read and statements follow register order.
"""

from datetime import date
from typing import Final, TypedDict
from urllib.parse import quote

from vulnwitness.domain.asset_register import AssetRegister
from vulnwitness.domain.hashing import canonical_sha256
from vulnwitness.domain.priority_decision import PriorityArtifact

OPENVEX_CONTEXT: Final = "https://openvex.dev/ns/v0.2.0"
VEX_STATUSES: Final = {
    "affected": "affected",
    "not_affected": "not_affected",
    "unknown": "under_investigation",
}
NO_ACTION_RECORDED: Final = (
    "No action statement recorded; the analyst assessed the asset as affected."
)

OpenVexDocument = TypedDict(
    "OpenVexDocument",
    {
        "@context": str,
        "@id": str,
        "author": str,
        "timestamp": str,
        "version": int,
        "tooling": str,
        "statements": list[dict[str, object]],
    },
)


def asset_product_id(asset_name: str) -> str:
    return "urn:vulnwitness:asset:" + quote(asset_name, safe="")


def build_openvex(
    register: AssetRegister,
    author: str,
    issued_on: date,
    priority: PriorityArtifact | None = None,
) -> OpenVexDocument:
    """The document as JSON-ready data; its ``@id`` hashes the register and priority."""
    if not author.strip():
        raise ValueError("an OpenVEX document needs an author")
    actions: dict[tuple[str, str], str] = {}
    if priority is not None:
        if priority.register_sha256 != register.compute_content_sha256():
            raise ValueError("priority.json was built from a different asset register")
        for decision in priority.decisions:
            actions[(decision.asset, decision.cve_id)] = (
                f"VulnWitness policy {priority.policy.name} recommends "
                f"{decision.recommendation}: {decision.reason}"
            )
    timestamp = f"{issued_on.isoformat()}T00:00:00Z"
    statements: list[dict[str, object]] = []
    for assessment in register.assessments:
        if assessment.assessed_at > issued_on:
            raise ValueError(
                f"assessment for {assessment.asset} / {assessment.cve_id} is dated after --as-of"
            )
        statement: dict[str, object] = {
            "vulnerability": {"name": assessment.cve_id},
            "products": [{"@id": asset_product_id(assessment.asset)}],
            "status": VEX_STATUSES[assessment.applicability],
            "timestamp": f"{assessment.assessed_at.isoformat()}T00:00:00Z",
        }
        if assessment.applicability == "not_affected":
            statement["impact_statement"] = assessment.justification
        if assessment.applicability == "affected":
            recorded = actions.get((assessment.asset, assessment.cve_id))
            if recorded is None:
                statement["action_statement"] = NO_ACTION_RECORDED
            else:
                statement["action_statement"] = recorded
        if assessment.applicability in ("unknown", "affected"):
            if assessment.justification is not None:
                statement["status_notes"] = assessment.justification
            elif assessment.applicability == "unknown":
                statement["status_notes"] = "Applicability remains unknown."
        statements.append(statement)
    identity = canonical_sha256(
        {
            "register": register.compute_content_sha256(),
            "priority": None
            if priority is None
            else canonical_sha256(priority.model_dump(mode="json")),
            "author": author,
            "issued_on": issued_on.isoformat(),
        }
    )
    return {
        "@context": OPENVEX_CONTEXT,
        "@id": f"urn:vulnwitness:vex:{identity}",
        "author": author,
        "timestamp": timestamp,
        "version": 1,
        "tooling": "VulnWitness",
        "statements": statements,
    }
