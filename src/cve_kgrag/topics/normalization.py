"""Alias matching on whole query terms, insensitive to case and joining punctuation.

Text is NFKC-normalized and case-folded, then split into words: a run of ASCII letters
and digits (``[0-9a-z]``), a run of other letters and digits (accented and other-script
letters, non-ASCII digits, modifier letters such as U+02BC, Hangul fillers), or a single
CJK, Kana or Hangul character. Two adjacent words are joinable when exactly whitespace,
or exactly one dash or underscore with no space around it, separates them, or when both
are ideographs with nothing between. Anything else becomes a ``TERM_BOUNDARY``: other
punctuation, a spaced dash, an ASCII word meeting a non-ASCII one with nothing between,
and any separator holding an invisible format character (Unicode category Cf: zero-width
space, soft hyphen), which no alias joins across. An alias matches a run of adjacent
joinable words whose concatenation equals the alias's own words.

So ``5gaka``, ``5G-AKA``, ``5G AKA``, ``5G_AKA`` and ``5G-AKA协议`` match the alias
``5G-AKA``, while ``aka`` alone, ``5G, aka NR``, ``5G - aka NR`` (spaced dash),
``5G a.k.a.``, ``5g\\u200baka`` and ``5G\\u00ad-AKA`` do not. ``5Géaka`` reads as the
words ``5g``, ``é`` and ``aka`` and so reports the excluded term ``aka``, as
``EAP-AKA\\u02bc`` reports ``EAP-AKA'``.

The ASCII words of ``split_terms(text)`` are, in order, exactly the ``[0-9a-z]`` runs of
the once-normalized text (``TOKEN.findall(normalize_query(text))`` in
``domain/text.py``). The CVE side's search terms (``list_query_terms``) normalize the
text twice, and ``normalize_query`` is not idempotent: confirmed under the current
Unicode data, ``na\\u00df\\u0301`` reads here as ``nass`` but searches ``nas``, and
``H\\u0302\\u0331`` reads here as one non-ASCII word but searches ``h``. Such a search
term is not a registry word, so an exclusion it names is not reported and the CVE side
does not strip it; ``find_fight_block``'s check of each search term read alone keeps it
from FiGHT only (ADR 0002 §8).
"""

import re
from dataclasses import dataclass

from cve_kgrag.domain.text import normalize_query

IDEOGRAPHIC_RANGES = "\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uac00-\ud7af\uf900-\ufaff"
IDEOGRAPH = re.compile(f"[{IDEOGRAPHIC_RANGES}]")
WORD = re.compile(f"[0-9a-z]+|[^\\W_0-9a-z{IDEOGRAPHIC_RANGES}]+|[{IDEOGRAPHIC_RANGES}]")
JOINING_SEPARATOR = re.compile("\\s+|[-_\\u2010-\\u2013\\u2212]")
# Alias keys hold only words, so no match can run across this marker.
TERM_BOUNDARY = "\x00"


def is_joinable(previous_word: str, separator: str, next_word: str) -> bool:
    """Adjacent ideographs join with nothing between; other words need a joining separator,
    which a format character never is."""
    if not separator:
        return bool(IDEOGRAPH.fullmatch(previous_word) and IDEOGRAPH.fullmatch(next_word))
    return JOINING_SEPARATOR.fullmatch(separator) is not None


@dataclass(frozen=True)
class TermSpan:
    """Terms ``start`` (inclusive) to ``end`` (exclusive) of a split text."""

    start: int
    end: int

    def overlaps(self, other: "TermSpan") -> bool:
        return self.start < other.end and other.start < self.end


def split_terms(text: str) -> list[str]:
    """Words of ``text``, normalized, with ``TERM_BOUNDARY`` where a hard separator stood."""
    normalized_text = normalize_query(text)
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
