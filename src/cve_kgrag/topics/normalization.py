"""Alias matching on whole query terms, insensitive to case and joining punctuation.

Text is NFKC-normalized, case-folded and stripped of invisible format characters
(soft hyphens, zero-width spaces). It is then split into words: runs of letters
and digits, except that each CJK, Kana or Hangul character is a word of its own.
Two adjacent words are joinable when exactly whitespace, or exactly one dash or
underscore with no space around it, separates them, or when both are ideographs
with nothing between; anything else (other punctuation, a spaced dash, a change of
script with nothing between) becomes a ``TERM_BOUNDARY``. An alias matches a run
of adjacent joinable words whose concatenation equals the alias's own words. So ``5gaka``,
``5G-AKA``, ``5G AKA`` and ``5G-AKA协议`` match the alias ``5G-AKA``, while
``aka`` alone, ``5G, aka NR``, ``5G - aka NR`` (spaced dash), ``5G a.k.a.`` and ``5Géaka`` do
not.
"""

import re
import unicodedata
from dataclasses import dataclass

from cve_kgrag.domain.text import normalize_query

IDEOGRAPHIC_RANGES = "\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uac00-\ud7af\uf900-\ufaff"
IDEOGRAPH = re.compile(f"[{IDEOGRAPHIC_RANGES}]")
WORD = re.compile(f"[^\\W_{IDEOGRAPHIC_RANGES}]+|[{IDEOGRAPHIC_RANGES}]")
JOINING_SEPARATOR = re.compile("\\s+|[-_\\u2010-\\u2013\\u2212]")
# Alias keys hold only words, so no match can run across this marker.
TERM_BOUNDARY = "\x00"


def is_joinable(previous_word: str, separator: str, next_word: str) -> bool:
    """Adjacent ideographs join with nothing between; other words need a joining separator."""
    if not separator:
        return bool(IDEOGRAPH.fullmatch(previous_word) and IDEOGRAPH.fullmatch(next_word))
    return JOINING_SEPARATOR.fullmatch(separator) is not None


def strip_format_characters(text: str) -> str:
    """Drop invisible format characters (Unicode category Cf), e.g. soft hyphens."""
    return "".join(character for character in text if unicodedata.category(character) != "Cf")


@dataclass(frozen=True)
class TermSpan:
    """Terms ``start`` (inclusive) to ``end`` (exclusive) of a split text."""

    start: int
    end: int

    def overlaps(self, other: "TermSpan") -> bool:
        return self.start < other.end and other.start < self.end


def split_terms(text: str) -> list[str]:
    """Words of ``text``, normalized, with ``TERM_BOUNDARY`` where a hard separator stood."""
    normalized_text = normalize_query(strip_format_characters(text))
    terms: list[str] = []
    previous_end: int | None = None
    for word in WORD.finditer(normalized_text):
        if previous_end is not None and not is_joinable(
            terms[-1], normalized_text[previous_end : word.start()], word.group()
        ):
            terms.append(TERM_BOUNDARY)
        terms.append(word.group())
        previous_end = word.end()
    return terms


def has_hard_separator(text: str) -> bool:
    return TERM_BOUNDARY in split_terms(text)


def alias_key(text: str) -> str:
    """The concatenated words of ``text``; two spellings match when their keys are equal."""
    return "".join(term for term in split_terms(text) if term != TERM_BOUNDARY)


def find_spans(terms: list[str], key: str) -> list[TermSpan]:
    """Every run of adjacent terms whose concatenation equals ``key``."""
    spans: list[TermSpan] = []
    if not key:
        return spans
    for start in range(len(terms)):
        joined = ""
        for end in range(start, len(terms)):
            joined += terms[end]
            if joined == key:
                spans.append(TermSpan(start, end + 1))
                break
            if not key.startswith(joined):
                break
    return spans
