# ADR 0017 — A name check on CNVD links

Status: accepted (2026-11-09). Builds on ADR 0015 (CNVD entries) and ADR 0016 (priority
decisions).

## Context

ADR 0015 attaches a CNVD entry to an NVD record by the CVE ID that CNVD cites. Nothing checks
that both describe the same product, yet a CNVD 高 grade alone can trigger rule 6 of the
`cn-auto-demo` policy (ADR 0016).

We measured 105,140 linked entries on 2026-11-09. The test compared the leading Latin-script
name in the CNVD title with the NVD record's CPE vendor/product names:

| Result | Entries | Share |
|---|---|---|
| vendor and product names overlap | 73,692 | 70.1% |
| only the product name overlaps | 15,928 | 15.1% |
| only the vendor name overlaps | 7,112 | 6.8% |
| no overlap | 3,568 | 3.4% |
| no extractable name | 3,082 | 2.9% |
| no affected products | 1,758 | 1.7% |

A hand-checked, stratified sample of 350 entries found seven clear wrong links:
- 6 of 150 in "no overlap" (Wilson 95% interval: 1.85–8.45%);
- 1 of 100 in "vendor only";
- none in the other strata.

Most mismatches are differences of scope, not wrong links:
- a marketing name vs a CPE slug;
- a platform vs its plugin;
- hardware vs its operating system;
- a library vs the product embedding it;
- an upstream project vs its distributor.

Either side can be the wrong one. CVE-2015-5989's descriptions both name Belkin, but its NVD
CPE names Zyxel. Of the titles with no extractable name, 93% start with the quantifiers 多款
or 多个.

What existing systems do:
- CIRCL Vulnerability-Lookup, our CNVD source, shows CNVD links untyped and with no warning.
- Matching tools label uncertain matches but count them at full severity until an analyst
  suppresses them with a reason. Grype, OWASP Dependency-Check and Dependency-Track all
  work this way.
- No system found weights severity by confidence.

No public, pinnable, licensed and verified table maps CNVD names, Chinese names or acquired
vendors to CPE names. The NVD CPE dictionary has no vendor-merge data, and its names need
cleaning before use.

The research reports and measurements are kept outside the repository, with the real data.

## Decisions

### 1. A served label that changes nothing

Each CNVD entry in an exact lookup carries a `name_check`, computed when the lookup is served
and never persisted. It sits beside `source_comparison` (ADR 0015 §5).

The check never removes a link and never changes a grade. Its statement says that name
overlap is evidence for review, not a judgement that the link is right or wrong, and that
either source's names may be wrong.

### 2. Values

`result` is one of:

| Value | Meaning |
|---|---|
| `vendor_product_overlap` | one NVD vendor/product pair overlaps the CNVD name in both its vendor and its product |
| `product_overlap` | some pair's product overlaps, and no single pair overlaps in both |
| `vendor_overlap` | some pair's vendor overlaps, and no pair's product does |
| `no_overlap` | a name was extracted, and nothing overlaps |
| `uncheckable` | the check cannot run |

An `uncheckable` result carries one of these reasons:
- `no_nvd_record`, for a pending entry;
- `no_affected_products`;
- `no_extractable_name`.

The label also carries:
- the rule name, `cnvd_title_vs_nvd_cpe_names`;
- the extracted CNVD name, or null;
- for an overlap result, the NVD vendor/product pair that overlaps. When several pairs
  qualify, it is the first in (vendor, product) order.

### 3. The rule

The rule is fixed and deterministic, with no translation, dictionary, model, edit distance or
version comparison.

1. **Extract the name.** Drop a leading 多款 or 多个 from the CNVD title. The name is then the
   leading run of ASCII letters, digits, spaces and the characters `. _ + - / & , ' ( ) : !`,
   trimmed. An empty run gives `uncheckable` with `no_extractable_name`.
2. **Tokenise.** Lowercase, then split on whitespace and those punctuation characters. The
   result is the title tokens.
3. **Vendor overlap.** A pair's vendor overlaps when either holds:
   - one of its slug tokens, other than the organisation suffixes `project`, `inc`, `llc`,
     `corporation`, `foundation`, `software` and `technologies`, is a title token;
   - its slug with separators removed equals two or more consecutive title tokens joined
     (GE Healthcare ↔ `gehealthcare`).
4. **Product overlap.** A pair's product overlaps when either holds:
   - its slug's first token is a title token (product-family names such as Windows ↔
     `windows_10`);
   - its slug with separators removed equals two or more consecutive title tokens joined.
5. **Pairs.** Every vendor/product pair in the record's `affected` takes part, whatever its
   status. The result is the first value in table §2 that applies.

Rejected:
- **Matching whole product phrases only.** It moved 8,579 entries from "both overlap" to
  "vendor only", and the control sample found no wrong link among them.
- **A Chinese alias table.** The top 50 names that are not quantifiers cover 5% of the
  uncheckable titles, and any candidate mapping comes from the existing links themselves.
- **The NVD CPE dictionary.** See the context.

### 4. Where it shows

- **Lookups.** The CLI, MCP and REST lookups serve the label on every linked and pending CNVD
  entry. Response validation recomputes it, as it does `source_comparison`.
- **Session reports.** These show the label and both names per CNVD entry. The key facts gain
  one line: of the linked CNVD entries in the recorded lookups, how many show no name
  overlap.
- **The local UI** shows the label beside each CNVD entry, in plain words.
- **Priority decisions (ADR 0016).**
  - The high-grade fact keeps, for each counted CNVD 高 entry whose result is `no_overlap`,
    the CNVD ID and the extracted name.
  - Rule 6's reason then adds, per such entry, that its product name does not overlap NVD's
    CPE names and that the link should be reviewed.
  - The fact's value, the rules and the outcome do not change: the grade still counts.

### 5. Later, not now

An analyst's recorded rejection of a link (a reason, who, when, and a scope fixed to one
CNVD ID and CVE ID pair) needs its own ADR. It would also have to say how a rejection
interacts with the policy and when it expires.

## Acceptance

**Unit tests** form a table with readable IDs:
- Google Chrome ↔ `google:chrome`: both overlap.
- GE Healthcare ↔ `gehealthcare:*`: vendor overlap by joined words.
- Internet Explorer ↔ `microsoft:internet_explorer`: product only.
- Google Pixel ↔ `google:android`: vendor only.
- Tableau ↔ `haier:p10_firmware`: no overlap.
- 多款 followed by a Latin name: extracted.
- A Chinese-only title: `no_extractable_name`.
- An empty `affected`: `no_affected_products`.
- A pending entry: `no_nvd_record`.
- A vendor overlapping one pair and a product overlapping another: `product_overlap`, not
  both.
- A vendor named `foo_project` and the title word "Project": no vendor overlap.

**The real store** has its distribution re-measured and recorded outside the repository. It
is expected to differ from the table above only in the directions the rules intend.

**The demonstration** is re-recorded, since older sessions fail the schema check after any
contract change:
- CVE-2026-0154 stays `attend`, labelled `vendor_overlap`.
- A fifth case, CVE-2016-8616 (curl, NVD's own v3.0 MEDIUM, not KEV-listed) on the
  telematics unit, gives `attend` through rule 6. Its CNVD-2016-00463 entry (高, titled for
  PHP) is labelled `no_overlap`, and the reason asks for the link to be reviewed.

## Consequences

- A contract version bump and regenerated schemas: the lookup, report-facing and
  `priority.json` contracts change. The store format does not change.
- The label narrows the analyst's question to specific links without hiding any grade.
  Measured noise: about 10% of linked entries show vendor-only or no overlap, and most of
  those are naming differences.
