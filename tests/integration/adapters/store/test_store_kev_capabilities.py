"""Served KEV snapshot metadata comes from the verified store's manifest input."""

from pathlib import Path

import pytest

from tests.support.corpus_stores import import_store
from vulnwitness.adapters.store.corpus_store import load_corpus_store
from vulnwitness.composition import build_knowledge_toolbox, build_serving_data_plane
from vulnwitness.domain.corpus_store_manifest import StoreSource
from vulnwitness.interfaces.knowledge_tools import KnowledgeToolName, ToolAnswer


@pytest.mark.parametrize("include_kev", [True, False], ids=["imported", "not-imported"])
def test_capabilities_report_the_served_stores_kev_input(tmp_path: Path, include_kev: bool) -> None:
    root = tmp_path / "stores"
    root.mkdir()
    corpus = load_corpus_store(import_store(root, "test-store", include_kev=include_kev))
    toolbox = build_knowledge_toolbox(build_serving_data_plane(corpus))

    answer = toolbox.call(KnowledgeToolName.GET_KNOWLEDGE_CAPABILITIES, {})

    assert isinstance(answer, ToolAnswer)
    kev = answer.structured_content["kev"]
    assert kev["imported"] is include_kev
    if include_kev:
        snapshot = next(
            entry for entry in corpus.manifest.inputs if entry.source is StoreSource.CISA_KEV
        )
        expected = snapshot.model_dump(mode="json")
        assert kev["retrieved_at"] == expected["retrieved_at"]
        assert kev["source_version"] == expected["source_version"]
    else:
        assert kev == {"imported": False, "retrieved_at": None, "source_version": None}
