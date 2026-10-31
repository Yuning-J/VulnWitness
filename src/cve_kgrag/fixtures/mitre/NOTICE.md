# MITRE catalogue excerpt notice

`weakness-mapping.json` is a derived excerpt of official MITRE data downloaded on
2026-10-31. It contains only explicit CWE related attack patterns, CAPEC ATTACK
mappings and ChildOf inheritance, and ATT&CK technique names and kill-chain tactics.
It selects CWE-20, CWE-79, CWE-787, CWE-284, CWE-269, CWE-78 and CWE-120. Empty links
are retained. It is not a verbatim copy of the catalogues or evidence of CVE usage.

The `cve-kgrag mitre build` command produces the excerpt with those `--cwe-id`
arguments. Its `sources` record the versions and SHA-256 of all three full inputs:

- CWE 5.0: https://cwe.mitre.org/data/xml/cwec_v5.0.xml.zip
  (`cwec_v5.0.xml`, SHA-256 in `sources`).
- CAPEC 3.9: https://capec.mitre.org/data/xml/capec_latest.xml
  (SHA-256 in `sources`).
- Enterprise ATT&CK 20.0 STIX 2.1:
  https://github.com/mitre-attack/attack-stix-data/tree/master/enterprise-attack
  (`enterprise-attack.json`, SHA-256 in `sources`).

The manifest pins this excerpt and this notice. Full catalogues and full derived
mappings are operator-supplied, outside this repository.

## CWE

Copyright © 2006–2026, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo
are trademarks of The MITRE Corporation.

Terms: https://cwe.mitre.org/about/termsofuse.html

The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free
license to use Common Weakness Enumeration (CWE™) for research, development, and
commercial purposes. Any copy you make for such purposes is authorized provided
that you reproduce MITRE's copyright designation and this license in any such copy.

## CAPEC

Copyright © 2007–2026, The MITRE Corporation. CAPEC and the CAPEC logo are
trademarks of The MITRE Corporation.

Terms: https://capec.mitre.org/about/termsofuse.html

The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free
license to use Common Attack Pattern Enumeration and Classification (CAPEC™) for
research, development, and commercial purposes. Any copy you make for such purposes
is authorized provided that you reproduce MITRE's copyright designation and this
license in any such copy.

## ATT&CK

ATT&CK® is a registered trademark of The MITRE Corporation.

Terms: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/

The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free
license to use ATT&CK® for research, development, and commercial purposes. Any
copy you make for such purposes is authorized provided that you reproduce
MITRE's copyright designation and this license in any such copy.

© 2026 The MITRE Corporation. This work is reproduced and distributed with the
permission of The MITRE Corporation.
