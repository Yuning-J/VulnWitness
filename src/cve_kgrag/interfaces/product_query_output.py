"""CLI-only product traversal and atomic row exports; page contracts stay intact."""

import csv
import json
import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from tempfile import mkstemp
from typing import TextIO

from cve_kgrag.application.product_query import ProductQueryService
from cve_kgrag.domain.product_query import (
    ProductQueryRequest,
    ProductQueryResponse,
    ProductVulnerability,
)
from cve_kgrag.interfaces.product_query_summary import render_product_query_summary

EXPORT_COLUMNS = (
    "cve_id",
    "basis_kind",
    "matched_products",
    "applicability",
    "published",
    "evidence_ids",
)


@dataclass(frozen=True)
class ProductOutputOptions:
    output_format: str = "json"
    all_pages: bool = False
    max_pages: int = 100
    output: Path | None = None
    export: str | None = None
    force: bool = False


def validate_product_output(request: ProductQueryRequest, options: ProductOutputOptions) -> None:
    """Reject conflicting presentation options before reading the corpus."""
    if options.max_pages < 1:
        raise ValueError("--max-pages must be at least 1")
    if (options.all_pages or options.output is not None) and request.cursor is not None:
        raise ValueError(
            "full traversal starts at the first page; omit --cursor with --all or --output"
        )
    if options.output_format == "text" and (options.all_pages or options.output is not None):
        raise ValueError("--format text cannot be combined with --all or --output")
    if (options.output is None) != (options.export is None):
        raise ValueError("--output and --export must be supplied together")
    if options.force and options.output is None:
        raise ValueError("--force requires --output")
    if options.output is not None and not options.force and os.path.lexists(options.output):
        raise ValueError("export file already exists; use --force to overwrite")


def collect_product_pages(
    service: ProductQueryService, request: ProductQueryRequest, options: ProductOutputOptions
) -> list[ProductQueryResponse]:
    """Traverse one service's fixed corpus, returning nothing if the page cap is reached."""
    pages: list[ProductQueryResponse] = []
    while True:
        page = service.query(request)
        pages.append(page)
        if not (options.all_pages or options.output is not None) or page.next_cursor is None:
            return pages
        if len(pages) >= options.max_pages:
            raise ValueError(
                f"product traversal reached --max-pages {options.max_pages} before the end; "
                "no output written. Increase --max-pages to complete the traversal"
            )
        request = request.model_copy(update={"cursor": page.next_cursor})


def build_export_row(vulnerability: ProductVulnerability) -> dict[str, object]:
    """Project one CVE's source fields; mention-only matches have no structured products."""
    matched_products: list[dict[str, str]] = []
    if vulnerability.basis.kind == "product_field":
        for product in vulnerability.basis.matched_products:
            matched_products.append(product.model_dump())
    record = vulnerability.record
    row: dict[str, object] = {
        "cve_id": record.cve_id,
        "basis_kind": vulnerability.basis.kind,
        "matched_products": matched_products,
        "applicability": vulnerability.applicability,
        "published": None if record.published is None else record.published.isoformat(),
        "evidence_ids": record.evidence_ids,
    }
    if vulnerability.nvd_version_note is not None:
        row["nvd_version_note_outcome"] = vulnerability.nvd_version_note.outcome
    return row


def write_export_rows(
    export_file: TextIO, pages: Sequence[ProductQueryResponse], export: str
) -> None:
    """CSV excludes descriptions; JSON cells keep multi-valued columns unambiguous."""
    columns = list(EXPORT_COLUMNS)
    if pages[0].version is not None:
        columns.insert(3, "nvd_version_note_outcome")
    csv_writer = csv.DictWriter(export_file, fieldnames=columns)
    if export == "csv":
        csv_writer.writeheader()
    for page in pages:
        for vulnerability in page.items:
            row = build_export_row(vulnerability)
            if export == "jsonl":
                descriptions: list[dict[str, object]] = []
                for description in vulnerability.record.descriptions:
                    descriptions.append(description.model_dump())
                row["descriptions"] = descriptions
                export_file.write(json.dumps(row, ensure_ascii=False) + "\n")
            else:
                row["matched_products"] = json.dumps(row["matched_products"], ensure_ascii=False)
                row["evidence_ids"] = json.dumps(row["evidence_ids"])
                csv_writer.writerow(row)


def write_product_export(
    pages: Sequence[ProductQueryResponse], output: Path, export: str, force: bool
) -> None:
    """Publish a complete 0600 file atomically; link provides race-safe no-clobber."""
    descriptor, temporary_name = mkstemp(dir=output.parent, prefix=".cve-kgrag-")
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, mode="w", encoding="utf-8", newline="") as export_file:
            os.fchmod(export_file.fileno(), 0o600)
            write_export_rows(export_file, pages, export)
            export_file.flush()
            os.fsync(export_file.fileno())
        if force:
            os.replace(temporary_path, output)
        else:
            try:
                os.link(temporary_path, output)
            except FileExistsError:
                raise ValueError("export file already exists; use --force to overwrite") from None
    finally:
        temporary_path.unlink(missing_ok=True)


def print_product_pages(
    pages: Sequence[ProductQueryResponse], options: ProductOutputOptions
) -> int:
    """Print one page or a JSON array of unmodified page documents, or export rows."""
    if options.output is not None:
        assert options.export is not None  # Validated before loading the corpus.
        write_product_export(pages, options.output, options.export, options.force)
    elif options.all_pages:
        documents: list[dict[str, object]] = []
        for page in pages:
            documents.append(page.model_dump(mode="json"))
        print(json.dumps(documents, indent=2, ensure_ascii=False))
    elif options.output_format == "text":
        print(render_product_query_summary(pages[0]))
    else:
        print(pages[0].model_dump_json(indent=2))
    return 0 if pages[0].items else 1
