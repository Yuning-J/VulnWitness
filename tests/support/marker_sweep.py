"""A forger's marker planted in each text field of a sealed set, to find what a
verification report repeats of the set it checked."""

import json
from collections.abc import Sequence
from typing import Any

from pydantic import ValidationError

from cve_kgrag.application.evidence_set_verification import check_evidence_set
from cve_kgrag.application.investigation_deployment import InvestigationDeployment
from cve_kgrag.domain.investigation import (
    KnowledgeEvidenceSet,
    RoundRecord,
    SourceCapability,
    ToolStep,
    derive_investigation_id,
)
from cve_kgrag.domain.planning import compute_call_key, compute_model_reply_sha256

# Lower case, so it also fits the slug and free-suffix patterns (topic IDs, package URLs,
# model names) that an upper-case marker would fail to parse under.
ECHO_MARKER = "zzechomarkerzz"

TextLocation = tuple[str | int, ...]


def list_text_locations(document: Any, location: TextLocation = ()) -> list[TextLocation]:
    """The location of every string in ``document``, in document order."""
    text_locations: list[TextLocation] = []
    if isinstance(document, dict):
        for key, value in document.items():
            text_locations.extend(list_text_locations(value, (*location, key)))
    elif isinstance(document, list):
        for index, value in enumerate(document):
            text_locations.extend(list_text_locations(value, (*location, index)))
    elif isinstance(document, str):
        text_locations.append(location)
    return text_locations


def describe_field(location: TextLocation) -> str:
    """The field a location names, list positions left out: ``warnings[].subject``."""
    field_name = ""
    for part in location:
        if isinstance(part, int):
            field_name += "[]"
        elif field_name:
            field_name += "." + part
        else:
            field_name = part
    return field_name


def read_text(document: Any, location: TextLocation) -> str:
    value = document
    for part in location:
        value = value[part]
    assert isinstance(value, str)
    return value


def write_text(document: Any, location: TextLocation, text: str) -> None:
    container = document
    for part in location[:-1]:
        container = container[part]
    container[location[-1]] = text


def list_planted_texts(original_text: str) -> list[str]:
    """The marker alone, and appended to the field's text plainly and after a dash, so it
    survives a pattern that fixes only the text's start or its alphabet. Text that is itself
    a JSON document, such as a model's plan, also gets the marker appended to each string
    inside it in turn, so the document still parses and its other values still hold."""
    planted_texts = [ECHO_MARKER, original_text + ECHO_MARKER, original_text + "-" + ECHO_MARKER]
    try:
        embedded_document = json.loads(original_text)
    except json.JSONDecodeError:
        return planted_texts
    if not isinstance(embedded_document, dict | list):
        return planted_texts
    for embedded_location in list_text_locations(embedded_document):
        marked_document = json.loads(original_text)
        embedded_text = read_text(marked_document, embedded_location)
        write_text(marked_document, embedded_location, embedded_text + ECHO_MARKER)
        planted_texts.append(json.dumps(marked_document))
    return planted_texts


def list_forged_documents(document: Any, location: TextLocation) -> list[Any]:
    """``document`` with the marker planted at ``location`` in each planted form, and once
    more renaming every copy of the field's text in the trajectory, as a forger keeping a
    step's call and its round's plan in agreement would."""
    original_text = read_text(document, location)
    forged_documents: list[Any] = []
    for planted_text in list_planted_texts(original_text):
        forged_document = json.loads(json.dumps(document))
        write_text(forged_document, location, planted_text)
        forged_documents.append(forged_document)
    renamed_document = json.loads(json.dumps(document))
    trajectory = renamed_document["trajectory"]
    for trajectory_location in list_text_locations(trajectory):
        if read_text(trajectory, trajectory_location) == original_text:
            write_text(trajectory, trajectory_location, original_text + ECHO_MARKER)
    write_text(renamed_document, location, original_text + ECHO_MARKER)
    forged_documents.append(renamed_document)
    return forged_documents


def encode_forgery(forged_document: Any) -> bytes:
    """The forged set as a forger would hand it over: when it still parses, the
    investigation ID, each step's call key and each round's reply hash recomputed from the
    fields they hash and the set resealed, so the checks past those hashes see it;
    otherwise the bytes as they are."""
    try:
        forged_set = KnowledgeEvidenceSet.model_validate(forged_document)
    except ValidationError:
        return json.dumps(forged_document).encode()
    rekeyed_steps: list[ToolStep] = []
    for step in forged_set.trajectory.steps:
        rekeyed_steps.append(step.model_copy(update={"call_key": compute_call_key(step.call)}))
    rehashed_rounds: list[RoundRecord] = []
    for round_record in forged_set.trajectory.rounds:
        if round_record.model_reply is not None:
            reply_sha256 = compute_model_reply_sha256(round_record.model_reply)
            round_record = round_record.model_copy(update={"model_reply_sha256": reply_sha256})
        rehashed_rounds.append(round_record)
    rekeyed_trajectory = forged_set.trajectory.model_copy(
        update={"steps": tuple(rekeyed_steps), "rounds": tuple(rehashed_rounds)}
    )
    rekeyed_set = forged_set.model_copy(
        update={
            "investigation_id": derive_investigation_id(forged_set.request),
            "trajectory": rekeyed_trajectory,
        }
    )
    resealed_set = rekeyed_set.model_copy(
        update={"result_sha256": rekeyed_set.compute_result_sha256()}
    )
    return resealed_set.model_dump_json().encode()


def find_echoed_fields(
    evidence_set: KnowledgeEvidenceSet,
    deployment: InvestigationDeployment,
    accepted_planner_capabilities: Sequence[SourceCapability],
) -> list[str]:
    """Each text location of ``evidence_set``, as its field name, whose planted marker the
    report of ``check_evidence_set`` repeats."""
    genuine_document = json.loads(evidence_set.model_dump_json())
    echoed_fields: list[str] = []
    for location in list_text_locations(genuine_document):
        for forged_document in list_forged_documents(genuine_document, location):
            report = check_evidence_set(
                encode_forgery(forged_document), deployment, accepted_planner_capabilities
            )
            if ECHO_MARKER in report.model_dump_json():
                echoed_fields.append(describe_field(location))
                break
    return echoed_fields
