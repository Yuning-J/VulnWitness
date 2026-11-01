"""Typed, format-independent report content built solely from checked session files."""

from dataclasses import dataclass

from pydantic import BaseModel

from vulnwitness.domain.session_record import (
    SessionCall,
    SessionCheckReport,
    SessionFindings,
    SessionRecord,
)


@dataclass(frozen=True)
class CheckedSession:
    check: SessionCheckReport
    session: SessionRecord | None
    calls: tuple[SessionCall, ...]
    responses: dict[int, BaseModel]
    findings: SessionFindings | None


@dataclass(frozen=True)
class ReportParagraph:
    text: str
    warning: bool = False


@dataclass(frozen=True)
class ReportTable:
    headings: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]


@dataclass(frozen=True)
class ReportSection:
    title: str
    paragraphs: tuple[ReportParagraph, ...] = ()
    tables: tuple[ReportTable, ...] = ()
    sections: tuple["ReportSection", ...] = ()
    verbatim: str | None = None
    bullets: tuple[str, ...] = ()


@dataclass(frozen=True)
class SessionReport:
    title: str
    synthetic: bool
    check: SessionCheckReport
    sections: tuple[ReportSection, ...]
