# ADR 0025 — EPSS and NIST LEV from operator-supplied files

Status: proposed (2026-11-17). Extends ADR 0016 (priority decisions) and ADR 0021.

## Context

FIRST's EPSS estimates the probability that a CVE is exploited in the next 30 days and is
published daily ([FIRST EPSS](https://www.first.org/epss/data)). NIST CSWP 41 (2025) builds
LEV from a CVE's EPSS history: the probability that it has been exploited since EPSS first
scored it. CSWP 41 uses LEV beside KEV to find likely-exploited CVEs that KEV does not list.

FIRST states no licence or redistribution terms for EPSS (read 2026-11-16). VulnWitness
therefore commits no EPSS data. The same holds for CNVD through CIRCL (ADR 0018): files the
operator supplies are read, and only what a decision needs is recorded.

## Decisions

1. **`prioritise --epss-dir DIR`** reads FIRST's daily files (`.csv` or `.csv.gz`, with the
   `#model_version:…,score_date:…` line and the `cve,epss,percentile` header) from a
   directory the operator fills. Only rows for the register's CVEs are kept, while the files
   stream past. Files scored after `--as-of` are ignored, so no later information is used.
   The artifact records each used file's name, score date, model version, row count and
   SHA-256.
2. **LEV is computed as NIST defines it, over the supplied files only.** Each file's score
   covers the days from its date to the next file or 30 days, whichever comes first, and
   never past the reference date. The product runs over `1 − epss × days/30`. A file every
   30 days gives LEV, and a file every day gives LEV2. Days that no file covers add nothing,
   so the value is a lower bound; `covered_days` and `span_days` say how much it rests on.
   `first_scored` is the earliest supplied file that scores the CVE, which can be later
   than EPSS's own first score.
3. **One categorical fact, `exploit_probability`**, keeps policies a decision table:
   - `at_or_above_threshold` when max(EPSS, LEV) reaches the policy's
     `exploit_probability_threshold`;
   - otherwise `below_threshold`;
   - `unknown` when no file was supplied or none scores the CVE.

   KEV stays its own fact, so it is not folded into the maximum the way CSWP 41's
   composite folds it. A policy whose rules read the fact must declare a threshold. A
   policy without a threshold refuses `--epss-dir`, so the band is never set by a hidden
   default.
4. **`exploitation-demo` declares 0.1 and adds `rule-7b`**. An affected asset whose
   probability reaches the threshold gets `attend`. The rule comes after KEV and SSVC
   evidence, which give `act`. 0.1 is a demonstration value, not a FIRST, NIST or
   VulnWitness recommendation.
5. **`below_threshold` is never "not exploited".** The report states this, as it does for
   KEV `not_listed_in_snapshot`.

## Consequences

- The policy content digests change, because the threshold field is part of a validated
  policy. Existing `priority.json` files need `prioritise --force`.
- `cn-auto-demo` lists `exploit_probability` among its unknowns.
- Reading a year of daily files streams about 365 × 300k rows. The adapter caps each file
  at 64 MiB decompressed and the directory at 4,096 files.
