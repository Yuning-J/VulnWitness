"""Typed, format-independent report content built solely from checked session files."""

from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel

from vulnwitness.domain.cve import Severity
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
class ReportBadge:
    text: str
    tone: Literal["ok", "warn", "bad", "neutral"] = "neutral"
    severity: Severity | None = None


@dataclass(frozen=True)
class ReportStat:
    label: str
    value: str
    note: str


@dataclass(frozen=True)
class ReportLink:
    text: str
    target: str


@dataclass(frozen=True)
class ReportTable:
    headings: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]
    links: tuple[ReportLink, ...] = ()


@dataclass(frozen=True)
class ReportFact:
    label: str
    value: str = ""
    badge: ReportBadge | None = None
    detail: str = ""


@dataclass(frozen=True)
class ReportSection:
    title: str
    paragraphs: tuple[ReportParagraph, ...] = ()
    tables: tuple[ReportTable, ...] = ()
    sections: tuple["ReportSection", ...] = ()
    verbatim: str | None = None
    bullets: tuple[str, ...] = ()
    layout: Literal[
        "",
        "two",
        "columns",
        "panel",
        "limits",
        "card",
        "facts",
        "timeline",
        "step",
        "desc",
        "paths",
        "inline",
    ] = ""
    folded: bool = False
    anchor: str = ""
    badges: tuple[ReportBadge, ...] = ()
    chips: tuple[str, ...] = ()
    links: tuple[ReportLink, ...] = ()
    stats: tuple[ReportStat, ...] = ()
    facts: tuple[ReportFact, ...] = ()
    heading_note: str = ""


@dataclass(frozen=True)
class SessionReport:
    title: str
    synthetic: bool
    check: SessionCheckReport
    sections: tuple[ReportSection, ...]
    input_digest: str | None = None
