"""Selection order is independent of the product service's page grouping."""

from datetime import UTC, datetime

from vulnwitness.application.triage_workflow import triage_selection_key
from vulnwitness.composition import build_product_query_service, load_packaged_fixture
from vulnwitness.domain.product_query import DescriptionMentionBasis, ProductQueryRequest


def test_field_match_precedes_a_description_hit_even_when_its_version_note_is_no_hit() -> None:
    # Arrange
    service = build_product_query_service(load_packaged_fixture())
    page = service.query(ProductQueryRequest(vendor="democorp", version="2.0"))
    by_id = {}
    for vulnerability in page.items:
        by_id[vulnerability.record.cve_id] = vulnerability
    field_no_hit = by_id["CVE-9999-0002"]
    mention_hit = by_id["CVE-9999-0001"].model_copy(
        update={"basis": DescriptionMentionBasis(matched_phrase="democorp")}
    )
    assert field_no_hit.nvd_version_note.outcome == "no_hit"
    assert mention_hit.nvd_version_note.outcome == "hit"

    # Act
    selection = sorted([mention_hit, field_no_hit], key=triage_selection_key)

    # Assert
    assert selection == [field_no_hit, mention_hit]


def test_equal_basis_and_version_sort_by_publication_then_id_with_missing_dates_last() -> None:
    # Arrange
    service = build_product_query_service(load_packaged_fixture())
    page = service.query(ProductQueryRequest(vendor="democorp"))
    earlier = page.items[-1]
    tied_record = earlier.record.model_copy(update={"cve_id": "CVE-9999-9998"})
    tied = earlier.model_copy(update={"record": tied_record})
    missing_date = earlier.model_copy(
        update={
            "record": earlier.record.model_copy(
                update={"cve_id": "CVE-9999-9999", "published": None}
            )
        }
    )
    newest = earlier.model_copy(
        update={
            "record": earlier.record.model_copy(
                update={"cve_id": "CVE-9999-9997", "published": datetime(2030, 1, 1, tzinfo=UTC)}
            )
        }
    )

    # Act
    selection = sorted([missing_date, tied, earlier, newest], key=triage_selection_key)

    # Assert
    assert selection == [newest, earlier, tied, missing_date]
