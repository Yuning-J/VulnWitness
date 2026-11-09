# ADR 0018 — Raw CNVD records as an opt-in research input, with incremental sync

Status: accepted (2026-11-09). Builds on ADR 0015 (CNVD entries) and ADR 0017
(name check).

## Context

The default CNVD source is CIRCL's Hugging Face dataset, pinned at revision 986160c
(ADR 0015). It is published under CC BY 4.0 and carries six fields: ID, title, description,
grade, CVE ID and source. Its newest entry is CNVD-2026-32979.

CIRCL's Vulnerability-Lookup also publishes the raw CNVD records. As read on 2026-11-09:

**The full dump**
- `https://vulnerability.circl.lu/dumps/cnvd.ndjson`;
- 187.8 MB of NDJSON;
- last modified 2026-10-04.

**The API**
- `GET /api/vulnerability/?source=cnvd&since=DATE&date_sort=updated&sort_order=asc&per_page=100&page=N`;
- returns full records, or only `(id, source)` pairs with `light=1`;
- needs no key.
- `/api/vulnerability/last/cnvd/N` returned CNVD-2026-43388, with `openTime` 2026-10-30.
- The raw source is therefore about 10,000 IDs newer than the pinned dataset.

**The raw record carries**
- `products` (free text with a version range, e.g. `Google Pixel <2026-06-05`);
- `submitTime` and `openTime`;
- `formalWay`, CNVD's handling advice;
- `patchName` and `patchDescription`;
- `referenceLink`;
- `isEvent`.

These fields are read from CIRCL's importer and one API record; nobody has published a full
dump schema.

**What is unverified**
- **Licence.** Neither the dumps page nor the about page states a licence for the CNVD
  data. CIRCL's software licence (AGPL) says nothing about the data. CNVD's own terms remain
  unverified, as ADR 0015 already records.
- **Timestamps.** CIRCL's feeder stores `submitTime` as "published" and `openTime` as
  "updated". The API's `since` filter therefore follows CIRCL's mapping, and may not see a
  CNVD edit made after `openTime`.

The owner's direction of 2026-11-08 sets the conditions:
- the raw records are an explicitly enabled research input;
- continuous sync uses incremental API calls, never periodic full dumps;
- promotion to the default waits for the licence to be confirmed.

## Decisions

### 1. One CNVD source per store

The importer accepts either `circl-cnvd` (the Hugging Face dataset) or a new source,
`vulnerability-lookup-cnvd`. It never accepts both, because one store with two CNVD sources
would need a merge rule that nothing justifies yet.

The default refresh path is unchanged. A store built from the raw source:
- records that source in its manifest;
- serves an attribution that says the CNVD data's licence is unverified and that the store
  is for research use.

### 2. What the raw input keeps

This is store format 3, applying only to the raw source. Each CNVD entry gains optional
fields, kept verbatim and named after CNVD's own fields:

| Field | Note |
|---|---|
| `products` | a list of strings |
| `submit_time` | dates as CNVD gives them |
| `open_time` | dates as CNVD gives them |
| `handling_advice` | from `formalWay` |

`openTime` is not called "published", and it never feeds the GB 44495 basis: CNVD is not
the authoritative platform that ADR 0016 needs. Entries from the Hugging Face source leave
these fields empty.

### 3. A pinned base plus recorded increments

- **Base.** One full dump, downloaded once by an explicit operator command. It is pinned
  by SHA-256, `Last-Modified` and retrieval time, and is never fetched on a schedule.
- **Increments.** An operator command fetches the records whose `openTime` falls on or
  after the previous increment's high-water date:
  - it pages at 100 records per page, at most one request per second;
  - it overlaps the previous window by one day;
  - it writes one NDJSON file per run with a provenance row: the query, page count,
    retrieval time and SHA-256.
- **Store build.** Building a store reads the base and the increments in order. A later
  record replaces an earlier one with the same CNVD ID.
- **Stores stay immutable.** Each refresh builds a new store, so a session still names
  exactly what it read.
- **What increments cannot see.** Edits made after `openTime` are not visible through
  `since`. The runbook says so, and a new base download needs the owner's decision.

### 4. Use in the name check (ADR 0017)

The rule stays title-based in this ADR, and the raw `products` are shown beside the label.
Matching on `products` would be a later change, made only after measurement.

## Out of scope

- Promoting the raw source to the default (that waits for the licence).
- CNNVD.
- Merging the two CNVD sources.
- Scheduling: the operator runs the increment command, and nothing runs on a timer.

## Acceptance

- Synthetic tests:
  - the base and increments parse;
  - a later record replaces an earlier one;
  - a store with both CNVD sources is refused;
  - the attribution says "licence unverified";
  - format 3 round-trips;
  - Hugging Face stores are unchanged.
- A real run outside the repository: one base download and one increment since the base's
  `Last-Modified`. It reports how many CNVD IDs are newer than the pinned dataset, and how
  many new entries link to a CVE.
