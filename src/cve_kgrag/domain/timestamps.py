"""Timestamp and calendar-date types whose published JSON Schema states what the server parses.

JSON Schema's ``format`` keyword is an annotation unless a validator opts in to checking
it, so a field published only as ``format: date-time`` accepts any string. Each type here
also publishes a ``pattern`` that a validator always enforces. The pattern admits only
values the server parses: a Gregorian date from year 0001 with the right number of days
in its month (29 February only in a leap year), a time from 00:00:00 to 23:59:59 with up
to six fractional digits, and a required UTC offset of at most 23:59. The server parses
some spellings the pattern refuses (a lower-case ``t``, more fractional digits), never the
reverse.
"""

from datetime import date
from typing import Annotated

from pydantic import AwareDatetime, Field

# 0001-9999; year 0000 does not exist in the proleptic Gregorian calendar Python uses.
YEAR = "(?!0000)[0-9]{4}"
MONTH_AND_DAY = (
    "(?:(?:0[13578]|1[02])-(?:0[1-9]|[12][0-9]|3[01])"
    "|(?:0[469]|11)-(?:0[1-9]|[12][0-9]|30)"
    "|02-(?:0[1-9]|1[0-9]|2[0-8]))"
)
# Divisible by 4 and not by 100, or divisible by 400.
LEAP_YEAR = "(?:[0-9]{2}(?:0[48]|[2468][048]|[13579][26])|(?:[02468][048]|[13579][26])00)"
CALENDAR_DATE = f"(?:{YEAR}-{MONTH_AND_DAY}|(?!0000){LEAP_YEAR}-02-29)"
TIME_OF_DAY = "(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\\.[0-9]{1,6})?"
UTC_OFFSET = "(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"

# Python's ``$`` also matches before a final newline, so a Python JSON Schema validator
# reads a bare ``$`` more loosely than ECMA-262 does; ``(?!\n)`` makes both end exactly.
END_OF_VALUE = "$(?!\\n)"
RFC3339_TIMESTAMP_PATTERN = f"^{CALENDAR_DATE}T{TIME_OF_DAY}{UTC_OFFSET}{END_OF_VALUE}"
CALENDAR_DATE_PATTERN = f"^{CALENDAR_DATE}{END_OF_VALUE}"

Timestamp = Annotated[
    AwareDatetime, Field(json_schema_extra={"pattern": RFC3339_TIMESTAMP_PATTERN})
]
CalendarDate = Annotated[date, Field(json_schema_extra={"pattern": CALENDAR_DATE_PATTERN})]
