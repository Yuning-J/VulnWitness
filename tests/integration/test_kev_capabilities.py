"""Synthetic KEV entries do not pretend to be an imported CISA snapshot."""

import json

import pytest

from vulnwitness.cli import main
from vulnwitness.composition import load_packaged_fixture


def test_fixture_capabilities_report_no_imported_cisa_snapshot(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert any(record.kev is not None for record in load_packaged_fixture().records)

    assert main(["capabilities"], environment={}) == 0
    capabilities = json.loads(capsys.readouterr().out)

    assert capabilities["schema_version"] == "2.0.0-dev.58"
    assert capabilities["kev"] == {"imported": False, "retrieved_at": None, "source_version": None}
