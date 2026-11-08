# Third-party data and provenance

The MIT licence of this repository covers its code only. Every data source is a
separate provenance subject; the machine-readable registry is
`src/vulnwitness/knowledge/sources.yaml`. Terms below were read from the official
pages on 2026-10-14, the trustify-mcp licence on 2026-10-17, and CIRCL's declared
CNVD licence on 2026-11-08. Where they could not be verified the entry says so, and
this repository commits no data from that source.

| Source | Terms | Redistribution | Stored here |
|---|---|---|---|
| NVD | https://nvd.nist.gov/developers/terms-of-use | allowed with conditions | operator-supplied feeds and the corpus stores imported from them only |
| CVE Program | https://www.cve.org/Legal/TermsOfUse | allowed with conditions | operator-supplied only |
| CISA KEV | https://www.cisa.gov/sites/default/files/licenses/kev/license.txt | allowed (CC0 1.0) | operator-supplied catalogs and the corpus stores imported from them only |
| CIRCL/Vulnerability-CNVD | https://creativecommons.org/licenses/by/4.0/ (as declared by CIRCL) | allowed with conditions | operator-supplied only; no CNVD data committed |
| CNVD | not verified (https://www.cnvd.org.cn) | unknown | operator-supplied only; no CNVD data committed |
| MITRE FiGHT | https://fight.mitre.org/resources/terms/ | allowed with conditions (FiGHT Terms of Use; ATT&CK terms for derived content) | six-technique excerpt (`src/vulnwitness/fixtures/fight/`); the full file only as an operator-supplied snapshot |
| MITRE ATT&CK | https://attack.mitre.org/resources/legal-and-branding/terms-of-use/ | allowed with conditions | FiGHT excerpt and the derived weakness mapping excerpt (technique names, IDs and tactics) |
| MITRE CWE | https://cwe.mitre.org/about/termsofuse.html | copies allowed with conditions | related CAPEC links in the derived weakness mapping excerpt |
| MITRE CAPEC | https://capec.mitre.org/about/termsofuse.html | copies allowed with conditions | taxonomy mappings and parent chains in the derived weakness mapping excerpt |
| 3GPP TS 33.501 | not verified | unknown | clause citations only |
| Trustify software | not verified; no adapter ships | unknown | nothing |
| Data returned by Trustify | per upstream source; not verified; no adapter ships | unknown | nothing |
| trustify-mcp tool schemas (commit ac8955f) | Apache-2.0 (LICENSE at that commit) | allowed with conditions | unmodified excerpt in `tests/contract/data/trustify_mcp_ac8955f/` |
| Synthetic CVE fixture | this repository (MIT) | allowed | `src/vulnwitness/fixtures/synthetic/` |
| Format-1 compatibility store | this repository (MIT) | allowed | `tests/contract/data/corpus_store_format1_28e5b4d/` |

## Conditions, quoted

- **NVD.** "All NIST publications are available in the public domain according to
  Title 17 of the United States Code, however services which utilize or access
  the NVD are asked to display the following notice prominently within the
  application: 'This product uses data from the NVD API but is not endorsed or
  certified by the NVD.'" and "If you modify the content accessed through the API,
  you may not attribute the source as the NVD." NVD records also carry CVE List
  text; whether NVD's public-domain status overrides the CVE terms is unverified.
- **CVE Program.** "MITRE hereby grants you a perpetual, worldwide, non-exclusive,
  no-charge, royalty-free, irrevocable copyright license to reproduce, prepare
  derivative works of, publicly display, publicly perform, sublicense, and
  distribute Common Vulnerabilities and Exposures (CVE™). Any copy you make for
  such purposes is authorized provided that you reproduce MITRE's copyright
  designation and this license in any such copy." The page does not state the
  designation's wording.
- **CISA KEV.** "The KEV database is distributed under the Creative Commons 0 1.0
  License. You may use this data in any legal manner but note that information
  provided at any 3rd party links included in the KEV database are bound by the
  policies and licenses of those 3rd party websites. Use of the information does
  not authorize you to use the CISA Logo or DHS Seal, nor should such use be
  interpreted as an endorsement by CISA or DHS."
- **CIRCL/Vulnerability-CNVD.** The [dataset card at the pinned revision](https://huggingface.co/datasets/CIRCL/Vulnerability-CNVD/blob/986160c9b1c910049f64a166ab4056de191f6de7/README.md)
  declares "license: cc-by-4.0". [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
  requires: "You must give appropriate credit, provide a link to the license, and
  indicate if changes were made." Credit CIRCL and the dataset; VulnWitness's
  attribution states that it normalises the entries. How this licence relates to
  CNVD's own terms is unverified. The repository commits no CNVD data.
- **MITRE FiGHT.** The website grants: "a non-exclusive, royalty-free license to
  use FiGHT™ for research, development, and commercial purposes. Any copy you make
  for such purposes is authorized provided that you reproduce MITRE's copyright
  designation and this license in any such copy." MITRE also publishes an
  Apache-2.0 header in the repository's `LICENSE.txt`, "ALL RIGHTS RESERVED"
  notices in the README and site footer, and a U.S. Government contract notice in
  `fight-data/README.md`.

  **Attribution policy (reviewed 2026-10-15; an engineering decision, not legal advice):**
  1. FiGHT techniques and data are governed by the FiGHT Terms of Use.
  2. ATT&CK-derived tactics and techniques must also meet the ATT&CK Terms of Use.
  3. The Apache-2.0 header licenses the repository's software and files; it does
     not replace the FiGHT-specific terms for the content.
  4. "ALL RIGHTS RESERVED" reserves copyright; it does not revoke the limited
     licence MITRE grants alongside it. "Distribution Unlimited" is a
     public-release marking, not a separate licence.
  5. The `fight-data` contract notice covers that directory's tooling; keeping it
     in the notice is the conservative choice.

  `src/vulnwitness/fixtures/fight/NOTICE.md` reproduces every one of these texts
  verbatim, which meets this attribution policy. Before a commercial public
  release, confirm the position with counsel or in writing with MITRE.
- **MITRE ATT&CK / CWE / CAPEC.** Each grants a royalty-free licence whose copies
  must reproduce MITRE's copyright designation and the licence. CWE and CAPEC word
  the grant as "use" and "copy", not "distribute".
- **trustify-mcp.** Apache-2.0 §4: "(a) You must give any other recipients of the
  Work or Derivative Works a copy of this License; and (b) You must cause any
  modified files to carry prominent notices stating that You changed the files".
  The excerpt is unmodified and its directory holds the licence text; the commit
  has no `NOTICE` file.

## Operator-supplied data

An operator imports NVD feeds, the CISA KEV catalog and both pinned CIRCL/Vulnerability-CNVD
Parquet files into a corpus store (`vulnwitness migrate legacy`) and may supply the full
FiGHT `fight.yaml` as a pinned snapshot. These stay on the operator's machine under the
sources' own terms and belong outside version control. The CNVD files must match the
revision and SHA-256 values in `src/vulnwitness/knowledge/cnvd_snapshots.yaml`; served
entries credit CIRCL, link its declared CC BY 4.0 licence and state VulnWitness's
normalisation and the unverified relation to CNVD's own terms
([ADR 0015](docs/rebuild/adr/0015-cnvd-entries.md)). A server over a corpus store gives MCP
clients the notice NVD asks services that use its data to display: "This product uses
data from the NVD API but is not endorsed or certified by the NVD." A FiGHT snapshot is
served only when the reviewed catalog lists its SHA-256, and every technique anchor it
serves cites the FiGHT terms (`license_or_terms_ref`).

The format-1 compatibility store under `tests/contract/data/` is synthetic test data
(`CVE-9999-*` records of a fictional vendor) written by this repository's importer. Its
anchors cite the canonical NVD and CISA artifact URLs and terms pages the importer cites
for real inputs; it holds no data from those sources.

## Committed third-party data

Three excerpts.

`src/vulnwitness/fixtures/fight/fight-excerpt.yaml` holds six technique entries
(FGT1499.503, FGT1562.501, FGT5019, FGT5019.005, FGT5040, FGT5044) and their five
tactics, cut byte for byte from `fight.yaml` at commit
`097cd5f73811dc34916ef84d5acc3fe7aba70450` (upstream SHA-256
`59a9addbd75d8680091797d66d5b237d9d026512990c61a6f51692ca94d2a7a8`). Its manifest
pins the excerpt's and the notice's SHA-256; the loader refuses either if changed.
The reviewed snapshot catalog (`src/vulnwitness/knowledge/fight_snapshots.yaml`)
records both the full upstream file and the excerpt, with their coverage and
contents; a FiGHT file is served only when its hash is catalogued there.

`tests/contract/data/trustify_mcp_ac8955f/tools.json` is the string
`EXPECTED_TOOLS_LIST_RESPONSE` from `tests/integration_test.rs` of guacsec/trustify-mcp
at commit `ac8955f768a5bfef6f1c9a5c1d02ec5b5cf9bf5e`, byte for byte (SHA-256
`a877d200e29b8aeea33e81c1ee1453b1575e15e33d9cc3613e4158a3332baa64`): the names,
descriptions and input schemas of its twelve tools. The commit's `LICENSE` sits beside it. Only the
contract tests read them; the wheel does not include them.

`src/vulnwitness/fixtures/mitre/weakness-mapping.json` is a derived excerpt built by
`vulnwitness mitre build` from CWE 5.0, CAPEC 3.9 and Enterprise ATT&CK 20.0 (STIX 2.1),
downloaded on 2026-10-31. It selects seven CWEs and their explicit CAPEC associations;
CAPEC `ChildOf` chains supply separately labelled inherited mappings. ATT&CK names
and tactics come from active technique objects. Its `sources` pins the SHA-256 of
each full input; `manifest.json` pins both the excerpt and its adjacent `NOTICE.md`,
which reproduces MITRE's copyright designations and licence grants. No external
mapper code is included. The derived mapping has no claim of MITRE endorsement or
of CVE exploitation with a technique. Full catalogues and derived mapping files stay
operator-supplied under the same terms.
