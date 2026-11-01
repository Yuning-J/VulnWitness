"""Query normalization, tokenization, CVE-ID extraction and the search text of a query,
shared by every channel."""

import re
import unicodedata
from dataclasses import dataclass

# Any dash separates an ID's parts: word processors write U+2010 or U+2011 for the
# hyphen, and NFKC and NFKD fold U+2011 into U+2010 and the small and fullwidth hyphens
# into "-".
ID_DASH = "[-\u2010-\u2015\u2212\ufe58]"
# An ID written as one; a likeness (below) names an ID only when this matches all of it.
CVE_ID_SHAPE = re.compile(f"CVE{ID_DASH}([0-9]{{4}}){ID_DASH}([0-9]{{4,}})", re.IGNORECASE)
# Letters of other scripts and Latin letter forms that look like C, V and E. The ID
# skeleton keeps them as written (NFKD would fold a lunate sigma into a sigma), and a
# likeness reads them as those letters only where it expects "CVE".
C_LOOKALIKES = "\u0421\u0441\u03f9\u03f2\u13df\ua4da\u1d04"
V_LOOKALIKES = "\u0474\u0475\u03bd\u13d9\ua4e6\u1d20"
E_LOOKALIKES = "\u0415\u0435\u0395\u13ac\ua4f0\u1d07"
ID_LETTER_LOOKALIKES = frozenset(C_LOOKALIKES + V_LOOKALIKES + E_LOOKALIKES)
# What a reader takes for a CVE ID, matched on the ID skeleton (see fold_to_id_skeleton):
# "CVE", perhaps a word such as "ID" or "number", then a four-digit year and a number
# of four or more digits, or any two or more digit groups. Parts are apart by any run of
# characters other than Latin letters and digits, or by nothing: spaces, punctuation,
# dashes, symbols and another script's letters, none of which tokenize keeps as a word.
# A likeness written exactly as an ID names it; any other is a malformed token, so the
# text is never searched as words. The year-and-number reading is tried first, so an ID
# followed by another number (``CVE-2021-44228 2022``) still names it.
ID_PART_GAP = "[^0-9a-z]*"
ID_GROUP_GAP = "[^0-9a-z]+"
ID_WORD = "(?:id|identifier|no|nr|num|number)"
CVE_ID_LIKENESS = re.compile(
    f"[C{C_LOOKALIKES}][V{V_LOOKALIKES}][E{E_LOOKALIKES}]"
    f"{ID_PART_GAP}(?:{ID_WORD}{ID_PART_GAP})?"
    f"(?:[0-9]{{4}}{ID_PART_GAP}[0-9]{{4,}}|[0-9]+(?:{ID_GROUP_GAP}[0-9]+)+)",
    re.IGNORECASE,
)
TOKEN = re.compile(r"[0-9a-z]+")
# Unicode's Default_Ignorable_Code_Point property (DerivedCoreProperties.txt, Unicode 15):
# code points a renderer shows as nothing, whatever their general category.
DEFAULT_IGNORABLE_RANGES = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)

# Function words that carry no retrieval signal in vulnerability descriptions.
STOPWORDS = frozenset(
    {
        "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "in", "is",
        "it", "its", "of", "on", "or", "that", "the", "this", "to", "via", "with",
    }
)  # fmt: skip
# Query words that name the kind of record every result is, so they discriminate no
# record from another: a search drops them from its query (``extract_search_text``), and
# the index keeps them as written. Other words for "vulnerability" stay search words,
# since a caller may mean them as a search for weaknesses in general.
LOW_SIGNAL_QUERY_TERMS = frozenset({"cve", "cves"})
# A low-signal word as a reader sees it: case-folded, with nothing invisible inside,
# perhaps possessive. Matched on the visible characters of normalized text (see
# list_low_signal_spellings), where every apostrophe reads as U+0027.
LOW_SIGNAL_SPELLING = re.compile("(?<![0-9a-z])(cves?)(?:'s)?(?![0-9a-z])")
# U+0027 itself, the right single quotation mark word processors write for it, and the
# modifier letter apostrophe; NFKC folds the fullwidth apostrophe into U+0027.
APOSTROPHES = frozenset("'\u2019\u02bc")
# A word, one space and a dotted version (``kamailio 5.8.2``, ``open5gs v2.7.2``), read on
# normalized text; a version ends where no digit or letter follows it, so a sentence's
# full stop after it is not part of it. A hyphen, underscore or dot before the word makes
# it part of a longer name (``acme-f5gc``, ``linux_kernel``), which is never read as the
# whole name its last part spells.
VERSION_MENTION = re.compile(
    r"(?<![0-9a-z_.-])([0-9a-z]+) (v?[0-9]+(?:\.[0-9]+)+)(?![0-9a-z]|\.[0-9])"
)
# Words by which a question asks whether a product is affected: with one of them, a
# product followed by a version asks affectedness of that version.
AFFECTEDNESS_QUESTION_TERMS = frozenset(
    {"affect", "affected", "affecting", "affects", "vulnerable"}
)
IPV4_PART_COUNT = 4
IPV4_PART_MAX = 255


@dataclass(frozen=True)
class QueryWord:
    """A word of normalized query text, ``text[start:end]``, read as ``term``."""

    start: int
    end: int
    term: str


@dataclass(frozen=True)
class CveIdToken:
    """The token ``text[start:end]`` that holds a CVE ID. ``cve_id`` is the ID it names
    when the token is written as exactly one ID, and None when the token is malformed."""

    start: int
    end: int
    cve_id: str | None


def normalize_query(text: str) -> str:
    """NFKC-normalize, case-fold and collapse whitespace."""
    folded = unicodedata.normalize("NFKC", text).casefold()
    return " ".join(folded.split())


def tokenize(text: str) -> list[str]:
    """Split normalized text into alphanumeric tokens, dropping stopwords.

    Punctuation separates tokens, so ``5G-AKA`` yields ``5g`` and ``aka`` while
    ``5gaka`` stays one token; joining those spellings is topic resolution's job.
    """
    tokens: list[str] = []
    for token in TOKEN.findall(normalize_query(text)):
        if token not in STOPWORDS:
            tokens.append(token)
    return tokens


def is_invisible(character: str) -> bool:
    """Whether a character displays nothing: a format control (a zero-width space or
    joiner, a soft hyphen, a byte-order mark, a direction mark or override), any other
    default-ignorable code point (a variation selector, a combining grapheme joiner, a
    Hangul filler) or a control character other than whitespace."""
    category = unicodedata.category(character)
    if category == "Cf" or (category == "Cc" and not character.isspace()):
        return True
    code_point = ord(character)
    return any(first <= code_point <= last for first, last in DEFAULT_IGNORABLE_RANGES)


def continues_identifier(character: str) -> bool:
    """Whether a visible character written next to an ID would continue it as one token.

    A number of any script, a combining mark, an underscore or a Latin letter continues
    it, as does anything NFKC folds into one (``CVE-2021-44228a``, ``…²``, ``…٤``,
    ``…㊀``), and so does a code point with no character assigned to it yet or a
    private-use one. A letter of another script does not: the change of script is a word
    boundary, and Chinese, Japanese, Korean and Thai write the next word against the ID
    with no space, as in ``CVE-2021-44228漏洞``.
    """
    for candidate in character + unicodedata.normalize("NFKC", character):
        category = unicodedata.category(candidate)
        if candidate == "_" or category[0] in "NM" or category in ("Cn", "Co", "Cs"):
            return True
        # unicodedata has no script property; every Latin letter's name starts "LATIN ".
        is_letter = category[0] == "L"
        if is_letter and unicodedata.name(candidate, "").startswith("LATIN "):
            return True
    return False


def find_continuing_index(text: str, index: int, step: int) -> int | None:
    """The index of the character that continues the token adjoining ``text[index]``,
    read in direction ``step`` (1 rightwards, -1 leftwards), or None when the token ends.

    Invisible characters are read past, and the next visible character decides. Read
    leftwards, a combining mark is read past too: it belongs to the character before it,
    which decides (a Thai tone mark is not part of an ID after it).
    """
    while 0 <= index < len(text):
        character = text[index]
        is_read_past = is_invisible(character) or (
            step < 0 and unicodedata.category(character)[0] == "M"
        )
        if not is_read_past:
            return index if continues_identifier(character) else None
        index += step
    return None


def find_token_bounds(text: str, start: int, end: int) -> tuple[int, int]:
    """Widen ``text[start:end]`` to the whole token it lies in. Each step jumps to the
    deciding character, so a run of invisible characters is read once."""
    continuing_index = find_continuing_index(text, start - 1, -1)
    while continuing_index is not None:
        start = continuing_index
        continuing_index = find_continuing_index(text, start - 1, -1)
    continuing_index = find_continuing_index(text, end, 1)
    while continuing_index is not None:
        end = continuing_index + 1
        continuing_index = find_continuing_index(text, end, 1)
    return start, end


def fold_to_id_skeleton(text: str) -> tuple[str, list[int]]:
    """What a reader sees of ``text`` when looking for an ID: each character NFKD-folded
    on its own, invisible characters and combining marks left out (so a precomposed and a
    decomposed accent read alike), a decimal digit of any script read as its ASCII digit,
    and a lookalike of C, V or E kept as written. Returns the skeleton and, for each of its
    characters, the index it was folded from."""
    skeleton_characters: list[str] = []
    source_indices: list[int] = []
    for index, character in enumerate(text):
        if is_invisible(character):
            continue
        is_lookalike = character in ID_LETTER_LOOKALIKES
        folded = character if is_lookalike else unicodedata.normalize("NFKD", character)
        for folded_character in folded:
            if unicodedata.category(folded_character)[0] == "M":
                continue
            digit = unicodedata.decimal(folded_character, None)
            skeleton_characters.append(folded_character if digit is None else str(digit))
            source_indices.append(index)
    return "".join(skeleton_characters), source_indices


def is_written_as_one_id(written_id: str, matched_id: str) -> bool:
    """Whether ``written_id``, the characters a CVE-ID match ``matched_id`` was folded
    from, spell exactly that ID.

    Folded one character at a time they must give the match back: no character folds into
    more than the match covers (one symbol for "1."), and no invisible character hides inside
    (a direction override can display ``3000`` as ``0003``). Each digit must be a decimal
    digit (fullwidth included), not a superscript, circled or other number form.
    """
    folded_id = "".join(unicodedata.normalize("NFKC", character) for character in written_id)
    if folded_id != matched_id:
        return False
    for character in written_id:
        is_digit = unicodedata.normalize("NFKC", character).isdigit()
        if is_digit and unicodedata.category(character) != "Nd":
            return False
    return True


def list_cve_id_tokens(text: str) -> list[CveIdToken]:
    """Every token of ``text`` that holds a CVE ID or looks like one, in text order.

    A token runs on as long as the next character continues it, so an ID written against
    CJK text is a token of its own and names its ID, while an ID run together with
    another digit or letter (``CVE-2021-44228٤``, ``xCVE-2021-44228``) is one malformed
    token that names no ID, never a shorter one. Text a reader would take for an ID but
    that is not written as one (``CVE 2021 44228``, ``CVE.2021.44228``, ``CVE ID
    2021-44228``, ``CVE-2021-4422 8``, a Cyrillic Es for C, Arabic-Indic digits, a
    variation selector between digits) is a malformed token too: it fails closed rather
    than being searched as words. Tokens run together overlap, each starting no earlier
    than the one before it.
    """
    skeleton, source_indices = fold_to_id_skeleton(text)
    cve_id_tokens: list[CveIdToken] = []
    for likeness in CVE_ID_LIKENESS.finditer(skeleton):
        id_start = source_indices[likeness.start()]
        id_end = source_indices[likeness.end() - 1] + 1
        token_start, token_end = find_token_bounds(text, id_start, id_end)
        cve_id: str | None = None
        id_shape = CVE_ID_SHAPE.fullmatch(likeness.group(0))
        is_whole_token = (token_start, token_end) == (id_start, id_end)
        is_spelled_out = is_written_as_one_id(text[id_start:id_end], likeness.group(0))
        if id_shape is not None and is_whole_token and is_spelled_out:
            cve_id = f"CVE-{id_shape.group(1)}-{id_shape.group(2)}"
        cve_id_tokens.append(CveIdToken(start=token_start, end=token_end, cve_id=cve_id))
    return cve_id_tokens


def find_cve_ids(text: str) -> list[str]:
    """Return the CVE IDs ``text`` names, upper-cased with ASCII hyphens, in first-mention
    order; a malformed CVE-ID token names none."""
    cve_ids: list[str] = []
    for cve_id_token in list_cve_id_tokens(text):
        cve_id = cve_id_token.cve_id
        if cve_id is not None and cve_id not in cve_ids:
            cve_ids.append(cve_id)
    return cve_ids


def mentions_cve_id_token(text: str) -> bool:
    """Whether ``text`` holds a token with a CVE ID in it, well-formed or not."""
    return bool(list_cve_id_tokens(text))


def remove_spans(text: str, spans: list[tuple[int, int]]) -> str:
    """Return ``text`` without the ``(start, end)`` spans, which are in text order and may
    overlap the span before them, whitespace collapsed."""
    kept_pieces: list[str] = []
    kept_from = 0
    for start, end in spans:
        kept_pieces.append(text[kept_from:start])
        kept_from = max(kept_from, end)
    kept_pieces.append(text[kept_from:])
    return " ".join(" ".join(kept_pieces).split())


def remove_cve_id_tokens(text: str) -> str:
    """Return ``text`` without its CVE-ID tokens, malformed ones included, whitespace
    collapsed."""
    token_spans: list[tuple[int, int]] = []
    for cve_id_token in list_cve_id_tokens(text):
        token_spans.append((cve_id_token.start, cve_id_token.end))
    return remove_spans(text, token_spans)


def list_low_signal_spellings(normalized_text: str) -> list[QueryWord]:
    """The low-signal words of ``normalized_text`` however they are spelt: ``cve`` or
    ``cves`` with invisible characters inside (``c``+ZWSP+``ve``) or a possessive ``'s``
    with any of the ``APOSTROPHES`` (``cve's``), each read as the plain word. Only
    invisible characters are read past, so visible separators keep words apart (``c
    ve`` is two words)."""
    visible_characters: list[str] = []
    visible_indices: list[int] = []
    for index, character in enumerate(normalized_text):
        if not is_invisible(character):
            visible_characters.append("'" if character in APOSTROPHES else character)
            visible_indices.append(index)
    low_signal_words: list[QueryWord] = []
    for spelling in LOW_SIGNAL_SPELLING.finditer("".join(visible_characters)):
        start = visible_indices[spelling.start()]
        end = visible_indices[spelling.end() - 1] + 1
        low_signal_words.append(QueryWord(start=start, end=end, term=spelling.group(1)))
    return low_signal_words


def list_query_words(normalized_text: str) -> list[QueryWord]:
    """The words of ``normalized_text`` in text order: each low-signal spelling
    (``list_low_signal_spellings``) as one word, and every other ``TOKEN`` match, so an
    invisible character splits an ordinary word as ``tokenize`` splits it."""
    query_words = list_low_signal_spellings(normalized_text)
    for token_match in TOKEN.finditer(normalized_text):
        is_in_spelling = any(
            low_signal_word.start <= token_match.start() < low_signal_word.end
            for low_signal_word in query_words
        )
        if not is_in_spelling:
            query_words.append(
                QueryWord(
                    start=token_match.start(), end=token_match.end(), term=token_match.group(0)
                )
            )
    query_words.sort(key=read_word_start)
    return query_words


def read_word_start(query_word: QueryWord) -> int:
    return query_word.start


def find_unsearchable_word_spans(normalized_text: str) -> list[tuple[int, int]]:
    """The spans of the words of ``normalized_text`` (``list_query_words``) a search must
    not match on, in text order: the low-signal words however spelt, and every word of a
    CVE-ID likeness the words form once stopwords and punctuation are left out (``cve
    of 2021-44228`` reads as ``cve 2021 44228``, ``nvdcve in 2021 and 2022`` as ``nvdcve
    2021 2022``).

    Likenesses are read with the low-signal words in place, each as its plain word, so
    ``cve`` still marks the numbers after it as an ID's (``CVE's 2021-44228``).
    """
    terms: list[QueryWord] = []
    for query_word in list_query_words(normalized_text):
        if query_word.term not in STOPWORDS:
            terms.append(query_word)
    joined_terms = " ".join(term.term for term in terms)
    likeness_tokens = list_cve_id_tokens(joined_terms)
    unsearchable_spans: list[tuple[int, int]] = []
    term_start = 0
    for term in terms:
        term_end = term_start + len(term.term)
        is_in_likeness = any(
            likeness_token.start < term_end and term_start < likeness_token.end
            for likeness_token in likeness_tokens
        )
        if is_in_likeness or term.term in LOW_SIGNAL_QUERY_TERMS:
            unsearchable_spans.append((term.start, term.end))
        term_start = term_end + 1
    return unsearchable_spans


def extract_search_text(query: str) -> str:
    """The text of ``query`` a search matches on, whitespace collapsed: the query without
    its CVE-ID tokens (malformed ones included), normalized, then without its
    unsearchable words (``find_unsearchable_word_spans``: the low-signal words in
    ``LOW_SIGNAL_QUERY_TERMS`` and the words of an ID likeness), until it holds neither.

    IDs go first, so the ``CVE`` of an ID is never read as a word. A low-signal word is
    a whole word, however spelt (``CVE's``, ``c``+ZWSP+``ve``), never part of one:
    ``nvdcve`` and ``cvelist`` stay. Removing words can bring others together
    into a likeness (``nvdcve cves 2021 44228``), so the removal repeats until none is
    left, and the text holds no CVE-ID token. Every reader of a query's search terms
    (``list_query_terms``) takes them from this text.
    """
    search_text = normalize_query(remove_cve_id_tokens(query))
    unsearchable_spans = find_unsearchable_word_spans(search_text)
    while unsearchable_spans or mentions_cve_id_token(search_text):
        search_text = remove_cve_id_tokens(remove_spans(search_text, unsearchable_spans))
        unsearchable_spans = find_unsearchable_word_spans(search_text)
    return search_text


def list_query_terms(query: str) -> list[str]:
    """The search terms of ``query``: the tokens of ``extract_search_text``, in query
    order. Empty when the query holds nothing but CVE IDs and their likenesses, stopwords
    and low-signal words."""
    return tokenize(extract_search_text(query))


def is_ipv4_shaped(version: str) -> bool:
    """Whether a dotted number reads as an IPv4 address: four parts of at most 255."""
    parts = version.split(".")
    return len(parts) == IPV4_PART_COUNT and all(int(part) <= IPV4_PART_MAX for part in parts)


def find_version_mentions(normalized_query: str) -> list[tuple[str, str]]:
    """Each word followed by a dotted version in ``normalized_query``, as ``(word,
    version)`` in query order, without IPv4 addresses."""
    version_mentions: list[tuple[str, str]] = []
    for mention in VERSION_MENTION.finditer(normalized_query):
        word, version = mention.group(1), mention.group(2)
        if not is_ipv4_shaped(version.removeprefix("v")):
            version_mentions.append((word, version))
    return version_mentions


def asks_affectedness(normalized_query: str) -> bool:
    """Whether the query holds a word by which a question asks if a product is affected."""
    return any(token in AFFECTEDNESS_QUESTION_TERMS for token in TOKEN.findall(normalized_query))
