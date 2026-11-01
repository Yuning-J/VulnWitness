"""Shared source-field formatting for deterministic CVE text views."""

from textwrap import shorten

from cve_kgrag.domain.cve import CveRecord


def summarize_description(record: CveRecord, width: int = 400) -> str:
    """Prefer English, flatten whitespace and remove terminal control characters."""
    description = next(
        (text.value for text in record.descriptions if text.lang == "en"),
        record.descriptions[0].value,
    )
    printable_characters: list[str] = []
    for character in description:
        if character.isprintable() or character.isspace():
            printable_characters.append(character)
    return shorten(" ".join("".join(printable_characters).split()), width=width, placeholder="…")


def format_published(record: CveRecord) -> str:
    return "unknown" if record.published is None else record.published.date().isoformat()
