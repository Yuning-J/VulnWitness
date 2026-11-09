# Synthetic priority decisions

> **Synthetic demonstration data**

## Overview

✓ Record, citations and 0 claims consistent with the record

Dataset packaged demo data · session “inv\_hc2omuxejwt7enyntytg” · recorded 2026-10-15 08:30 UTC

## Key facts and limits

### What the records show

- The 1 CVE details returned 0 catalogue paths; 0 paths reaching ATT&amp;CK; 0 distinct techniques; 0 paths omitted by the cap.
- CNVD counts below cover recorded lookups from dataset synthetic\_fixture (corpus cd476ed6c0402549a39e58ba61ce0ead334c106ff343cd9f937d1b97c06ad8a1).
- CNVD grades higher under cnvd\_grade\_vs\_nvd\_own\_cvss3: 0 of 1 distinct CVEs compared.
- NVD record gaps: 0 of 1 distinct CNVD-listed CVEs have no servable record in the snapshot.
- NVD score gaps: 0 of 1 distinct CNVD-listed CVEs with a servable NVD record have no NVD-owned CVSS v3.1 or v3.0 metric for comparison.
- NVD status awaiting\_analysis: 0 of 1 distinct CNVD-listed CVEs with a servable NVD record.
- NVD status deferred: 0 of 1 distinct CNVD-listed CVEs with a servable NVD record.
- These counts describe recorded lookups only; they are not a ranking and change no triage order, selection or checker verdict. NVD status is independent of score gaps; awaiting\_analysis or deferred does not mean no score.

### What is not established

- Affectedness is unknown for every CVE: a version “hit” only matches an NVD CPE condition; configuration and environment were not evaluated.
- This association is derived from official catalogues. It is not evidence that the CVE was used with that technique. It is not an attack path. No ATT&amp;CK mapping describes only the loaded catalogue snapshot; it does not mean the weakness has no attack technique or no way to be exploited. CWE inheritance is an inference along the CWE hierarchy, not a catalogue link from the original CWE to CAPEC.
- CNVD entries from CIRCL/Vulnerability-CNVD (Hugging Face, revision 986160c), licensed CC BY 4.0 as declared by CIRCL (https://creativecommons.org/licenses/by/4.0/); normalised by VulnWitness. How this licence relates to CNVD's own terms is unverified.

## CVE details · 1 CVEs

### CVE-9999-0001

<a id="CVE-9999-0001"></a>

 Medium 5.3 · CVSS 3.1 · NVD · primary

Published unknown

Why selected: Recorded lookup; selection reason not recorded.

#### Recorded source facts

##### NVD

NVD status: Analyzed

###### NVD description · untrusted text

\[SYNTHETIC\] test record

###### Full recorded NVD description · untrusted text

<details>
<summary>Full recorded NVD description · untrusted text</summary>

    [SYNTHETIC] test record

</details>

###### Facts

| Fact | Recorded value |
| --- | --- |
| Match basis | not recorded |
| NVD version condition | not recorded |
| Affectedness | unknown · configuration and environment not evaluated |

##### CNVD · untrusted source text

###### CNVD-9999-00001

SYNTHETIC: 中文标题 &lt;img src=x onerror="alert(1)"&gt; &amp; \[链接\](bad)

CNVD severity: 中 · CNVD three-grade scheme (高 / 中 / 低) · assessed by CNVD

NVD state: analysed

NVD severity used for comparison: MEDIUM · CVSS 3.1 · assessed by nvd@nist.gov · primary · channel: NVD

Rule: cnvd\_grade\_vs\_nvd\_own\_cvss3

This is VulnWitness's mapping between two grading schemes, not a judgement that either source is right. CNVD's grading criteria are unverified. CVSS measures severity, not risk.

Evidence: ev:523d574e67f24db41268d72c · call 2

CNVD grade relative to nvd@nist.gov's CVSS 3.1 MEDIUM: same under cnvd\_grade\_vs\_nvd\_own\_cvss3

###### Full recorded CNVD description · untrusted text

<details>
<summary>Full recorded CNVD description · untrusted text</summary>

    SYNTHETIC: 中文描述 <script>alert("源")</script> & | *文本*
    第二行

</details>

###### CNVD-9999-00002

SYNTHETIC: 中文标题 &lt;img src=x onerror="alert(1)"&gt; &amp; \[链接\](bad)

CNVD severity: 低 · CNVD three-grade scheme (高 / 中 / 低) · assessed by CNVD

NVD state: analysed

NVD severity used for comparison: MEDIUM · CVSS 3.1 · assessed by nvd@nist.gov · primary · channel: NVD

Rule: cnvd\_grade\_vs\_nvd\_own\_cvss3

This is VulnWitness's mapping between two grading schemes, not a judgement that either source is right. CNVD's grading criteria are unverified. CVSS measures severity, not risk.

Evidence: ev:b7bd1c855b870dcf5bae6aa2 · call 2

CNVD grade relative to nvd@nist.gov's CVSS 3.1 MEDIUM: lower under cnvd\_grade\_vs\_nvd\_own\_cvss3

###### Full recorded CNVD description · untrusted text

<details>
<summary>Full recorded CNVD description · untrusted text</summary>

    SYNTHETIC: 中文描述 <script>alert("源")</script> & | *文本*
    第二行

</details>

#### Weakness associations

Catalogue associations, not attack paths; “no ATT&amp;CK mapping” describes this snapshot only.

Showing 0 returned paths; 0 paths reaching ATT&amp;CK; 0 distinct techniques; 0 paths omitted by the cap.

- Missing link: CVE-9999-0001: no\_specific\_cwe

##### Each original path

<details>
<summary>Each original path</summary>

</details>

#### Sources

[NVD record](https://nvd.nist.gov/vuln/detail/CVE-9999-0001)

- ev:945597b4ce639afdd263e0f1 · test-source · feed urn:vulnwitness:test · call 2
- ev:523d574e67f24db41268d72c · circl-cnvd · feed urn:synthetic:cnvd:CNVD-9999-00001 · call 2
- ev:b7bd1c855b870dcf5bae6aa2 · circl-cnvd · feed urn:synthetic:cnvd:CNVD-9999-00002 · call 2

## Execution and checks

### Call timeline

#### Call 1

mcp: get\_knowledge\_capabilities

#### Call 2

mcp: lookup\_cve

#### Stopped

End of recorded calls; stop reason not recorded.

### Check layers

Superseded findings: 0.

| Status | Layer | Count | Meaning |
| --- | --- | --- | --- |
| ✓ | Record consistency | 2 calls | Files are complete and consistent with one dataset. |
| ✓ | Citation resolution | 0 citations | Each citation points to an anchor in a successful recorded call. |
| ✓ | Structured claims | 0 claims | Claim fields equal the recorded response fields; this is not source support. |
| – | Narrative | 0 not checked | Free text is never checked. |

## Technical appendix

### Dataset identity

<details>
<summary>Dataset identity</summary>

Goal: Synthetic priority decisions

Scope: not recorded

Created at: 2026-10-15T08:30:00+00:00

Contract version: 2.0.0-dev.57

| Identity | Recorded value |
| --- | --- |
| Served dataset | synthetic\_fixture |
| Search version | synthetic-cves@1+sha256:5eda7f05bd23fec5638267fc4ba8fee188e0472bf9a01e57a0928ecf6b5a7756 |
| Store name | none (synthetic fixture) |
| Store manifest identity | 5eda7f05bd23fec5638267fc4ba8fee188e0472bf9a01e57a0928ecf6b5a7756 |
| Corpus content identity | cd476ed6c0402549a39e58ba61ce0ead334c106ff343cd9f937d1b97c06ad8a1 |
| FiGHT snapshot identity | 08cd11d579889c819c00888ecbb85d6d4b470b8fdf9fea833324441e28635726 |
| MITRE snapshot identity | a792c7b07a9c94555a0b6253a435c4c05a1043f71dacbb49a34952173f6e6a0b |

</details>

### Findings by kind and author

<details>
<summary>Findings by kind and author</summary>

None recorded.

| Kind | Author | Count |
| --- | --- | --- |

None recorded.

#### Not checked: narrative

</details>

### Per-claim check results

<details>
<summary>Per-claim check results</summary>

| Finding | Call | Status | Field | Expected | Recorded | Meaning |
| --- | --- | --- | --- | --- | --- | --- |

None recorded.

</details>

### Full check JSON

<details>
<summary>Full check JSON</summary>

    {
      "schema_version": "2.0.0-dev.57",
      "record": {
        "consistent": true,
        "calls_checked": 2,
        "violations": []
      },
      "citations": {
        "resolved": true,
        "citations_checked": 0,
        "violations": []
      },
      "claims": {
        "verified": true,
        "checks": []
      },
      "not_checked": {
        "count": 0,
        "finding_ids": []
      },
      "superseded_count": 0,
      "support_limitation": "Free narrative is not checked. This check does not establish that a statement is supported by cited evidence or prove real-world truth."
    }

</details>
