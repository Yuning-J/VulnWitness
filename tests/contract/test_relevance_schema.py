"""Published contracts admit the recorded relevance refinement loop."""

import json

from jsonschema import Draft202012Validator

from tests.support.paths import REPOSITORY_SCHEMA_DIR
from tests.support.relevance import build_relevance_bundle, run_relevance_loop
from vulnwitness.adapters.fixture.synthetic_fixture import FixtureBundle


def test_relevance_loop_evidence_set_satisfies_the_published_schema(
    fixture_bundle: FixtureBundle,
) -> None:
    # Arrange
    schema = json.loads((REPOSITORY_SCHEMA_DIR / "knowledge_evidence_set.schema.json").read_text())
    evidence_set = run_relevance_loop(build_relevance_bundle(fixture_bundle))

    # Act
    errors = list(Draft202012Validator(schema).iter_errors(evidence_set.model_dump(mode="json")))

    # Assert
    assert errors == []
