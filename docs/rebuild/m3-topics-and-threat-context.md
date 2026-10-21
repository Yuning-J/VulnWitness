# M3 topics and threat context

Schema version `2.0.0-dev.5`. Adds reviewed protocol topics, a pinned FiGHT
source, CVE relevance tiers and a scoped topic-context service.

## Topics

- A topic card (`ProtocolTopic`, schema `schemas/v2/protocol_topic.schema.json`)
  holds the canonical name, exact and contextual aliases, entities with roles,
  ecosystem terms, exclusions with reasons, query templates, references and its
  review state. Cards are YAML under `cve_kgrag/knowledge/topics/`, read with a
  `SafeLoader` subclass that also rejects duplicate, unhashable and merge keys and
  turns any malformed input into a YAML error (`adapters/strict_yaml.py`), so a
  repeated key can never silently replace a reviewed field.
- The registry hashes each card's canonical JSON and rejects duplicate IDs, an
  alias claimed by two topics, a contextual alias that another topic uses as an
  exact alias, an exact or contextual alias that is also excluded, any matched term without a word or
  spanning punctuation, two spellings of one entity or ecosystem term, and a query
  template over 512 characters, without searchable terms or naming a CVE ID. A
  reviewed card must name its reviewer and date; a pending card names neither.
- Matching (`topics/normalization.py`) works on words after NFKC, case-folding and
  removal of invisible format characters (soft hyphens, zero-width spaces): runs of
  letters and digits, with each CJK, Kana or Hangul character a word of its own.
  Words join into an alias only across exactly whitespace, or exactly one dash or
  underscore with no space around it, or between two ideographs; other
  punctuation, a spaced dash and a change of script are boundaries. `5gaka`,
  `5G-AKA`, `5G AKA`, `５Ｇ－ＡＫＡ`, `5G−AKA`, `5G-AKA协议` and `5G Authentication
  and Key Agreement` resolve to `3gpp:5g-aka`; `aka`, `EAP-AKA'`, `EAP-AKA`,
  `EPS AKA`, `5G, aka NR`, `5G (aka NR)`, `5G - aka NR`, `5G a.k.a. New Radio`
  and `5Géaka` do not, and the response names any excluded term used with its
  reason.
- All spans of the canonical name and exact aliases belong to the match, so
  `5G Authentication and Key Agreement (5G-AKA)` reports no excluded `aka`. When
  several topics match, exact matches rank before contextual ones and the longer
  matched name (by its concatenated key, so `5gaka` ranks like `5G-AKA`) before
  the shorter; a contextual alias never resolves inside a longer excluded phrase.
- Known limit: `5G aka New Radio` written with plain spaces is spelled exactly like
  the normative alias `5G AKA` and resolves to it.
- The 5G-AKA card is `pending_review`: the brief specifies its aliases, six
  entities and the bare-aka exclusion; the implementer drafted the entity roles,
  the EAP-AKA' and EPS AKA exclusions, ecosystem terms and query templates from
  ETSI TS 133 501 V19.7.0 (clauses cited per role). It has no contextual alias,
  because AKA beside 5G entities also describes EAP-AKA'. Every match reports the
  card's version, hash and review status.
- The card is a cross-release, whole-protocol, high-recall topic: SUPI, SUCI and
  UDM stay entities, so it covers initial identity handling and accepts the wider
  identity and subscription threat context they match. V19.7.0 is the normative
  reference; the CCS 2018 Tamarin model (TS 33.501 V15.0.0, tamarin-prover commit
  `da8787d5`) is cited as a formal-calibration reference only. Narrower scopes
  (core authentication, identity privacy) belong to an investigation profile or a
  separate topic.

## FiGHT

- Coverage is never self-reported. A reviewed catalog of FiGHT snapshot files
  (`cve_kgrag/knowledge/fight_snapshots.yaml`), keyed by SHA-256, is the only source
  of a snapshot's version, coverage (`full` or `excerpt`) and expected contents:
  the full 3.1.0 file (`59a9add…`, 183 techniques, 15 tactics) and the packaged
  excerpt (`08cd11d5…`), which names the full file it was cut from and lists its
  technique and tactic IDs; an excerpt's repository, commit, version, path and
  terms must equal those of the file it was cut from. Because the hash pins the
  exact bytes, a file whose hash is catalogued as the full upstream file is that
  file.
- `PinnedFightYamlSource` takes the file, the configured SHA-256 pin and the
  catalog. It reads the file once: the SHA-256 must equal the pin and be
  catalogued, the YAML must be UTF-8 strict YAML, the shape must hold (tactic and
  technique IDs, each technique's non-empty, unique, known tactics, sub-technique
  parents, statuses, procedure examples, JSON-representable values), and the
  contents must match the catalog entry's counts and IDs (so an empty file can
  never match). Any failure raises `FightSnapshotError` and nothing is served.
  Queries never touch the network or the file system.
- Every successful search outcome names the snapshot it searched, and the outcome
  model refuses an anchor from any other snapshot, so results and their source
  identity cannot disagree. `describe()` reports the same snapshot: repository,
  commit, data version, SHA-256, coverage, technique and tactic counts, retrieval
  time, the ingestion time from the injected clock, and the terms reference.
- FiGHT's status is free text (eight values at 3.1.0). Each item keeps it as
  `source_status` and maps it to `theoretical`, `proof_of_concept`, `observed` or
  `observed_outside_5g` (observed in enterprise IT or earlier 3GPP generations).
  An unknown status fails the load so its meaning is reviewed first.
- Search matches the given terms against a technique's name, BLUF, description,
  procedure examples and tactic names; the score is the number of distinct terms.
  Each item cites one anchor per technique: source `mitre_fight_yaml`,
  `protocol_threat_context`, authoritative, versioned
  `<data version>@<commit>+sha256:<snapshot SHA-256>`, with the BLUF as excerpt.
  Tactic entries are reached through their techniques and are not items
  themselves.
- The package ships a verbatim six-technique excerpt of FiGHT 3.1.0
  (`cve_kgrag/fixtures/fight/`) with a notice reproducing every licence and
  notice MITRE publishes; see `THIRD_PARTY_DATA.md`. Its coverage is `excerpt`,
  so responses built on it carry a `source_snapshot_is_excerpt` warning: the
  5G-AKA terms match 5 techniques in the excerpt and 30 in the full file. In the
  excerpt only FGT1499.503 names 5G AKA (in its procedure examples); FGT1562.501
  names generic "AKA" and is never returned for 5G-AKA.

## Evidence scope

An anchor for a FiGHT technique (by `FGT` ID in any case, or by source) must be
`protocol_threat_context`; a threat-context item must cite an asserted FiGHT
anchor for its own technique, and every FiGHT anchor in a response must carry the
snapshot version its FiGHT source outcome names. Together with the M2 rule for CVE anchors, FiGHT
context and CVEs can never be relabeled into each other's scope.

## Topic context

`TopicContextService.explore(TopicContextRequest(query, scope, limit,
max_results_per_search, semantic, filters))`. The scope is required:
`protocol_context_only`, `implementation_only` or `mixed`. `filters` (a
`SearchFilters`, empty by default) constrains every template CVE search; FiGHT is
never filtered. `limit` (default 10) is the number of items each answer section
keeps; `max_results_per_search` (default and maximum 20) bounds every backend
search the exploration sends.

1. Resolve the topic. An unresolved query consults no source and returns
   `no_match` with `topic_not_resolved` and any `excluded_term` warnings.
2. Unless the scope is `implementation_only`, search FiGHT with the topic's name,
   aliases and entities, for at most `limit` and at most `max_results_per_search`
   techniques. Results count only from a source that names the verified
   snapshot it served.
3. Search CVEs once per query template (the 5G-AKA card has `5G AKA`, `5gaka`,
   `AUSF SEAF K_SEAF`, `SUCI SUPI UDM`; the compact spelling is a separate lexical
   token), each up to `max_results_per_search` and under the request's filters,
   with the semantic channel when `semantic` is set. Each CVE is assessed once, shown with the candidate from its
   best-ranked search and the union of channels that retrieved it
   (`retrieval_channels`), from the record's own text (`topics/relevance.py`):
   - `explicit_protocol_mention`: a description names the protocol;
   - `protocol_component_implementation`: two distinct topic terms, one an entity;
   - `telecom_ecosystem_adjacent`: two distinct ecosystem terms;
   - `semantic_only`: none of these, but the semantic channel matched it.

   One acronym alone never tiers a record (UDM is also the UniFi Dream Machine,
   AMF the Action Message Format, 5G a Wi-Fi band); a term inside a longer found
   term, or a second spelling of one term, does not count twice. Other candidates are dropped with an
   `unrelated_candidates_dropped` warning. Kept candidates are ordered by tier,
   then search rank, then CVE ID, and only then cut to `limit`. Tiers measure
   relevance only; every CVE stays `implementation_vulnerability`.
4. Under `protocol_context_only`, CVE candidates go to
   `excluded_implementation_candidates` with the reason; otherwise to
   `implementation_candidates`.

Each consulted source has one `SourceOutcome`; FiGHT's carries its snapshot
version and coverage, a failed one the server's sentence for its typed failure, a
failed CVE search lists its channels' failures in `channel_failures`,
and the CVE search is `ok` only when relevance kept at least one candidate. The status is decided by `decide_topic_status` over the sources that form
the answer for the scope (FiGHT; CVE search; or both): an unavailable FiGHT
source makes a protocol answer `source_unavailable`, a mixed answer `partial`, and
leaves an implementation answer unaffected. Zero CVEs is an honest `no_match` or an
empty section, never an invented record.

The validator rejects CVEs in a protocol answer, threat context in an
implementation answer, an excluded section outside `protocol_context_only`,
uncited or missing evidence, outcomes that do not name exactly the consulted
sources, a FiGHT or CVE outcome that disagrees with its section, threat context
citing anything but asserted FiGHT evidence, and any status other than the one
`decide_topic_status` gives. It is also given the FiGHT snapshot the deployment
pinned (the catalog entry the composition root selected, or none) and rejects a
served FiGHT outcome whose version or coverage differs from that pin, FiGHT
evidence whose version, source URI, retrieval time or terms differ from it, a
threat-context technique outside a pinned excerpt's catalogued IDs, a served FiGHT
outcome when nothing is pinned, and an excerpt warning that is missing, repeated
or misstates the pinned size, or that appears without the pinned excerpt being
served. A failed source outcome cannot name a snapshot or coverage at all.
`result_sha256` and evidence IDs are integrity hashes, not signatures: a response
holder can edit an anchor, recompute its ID and reseal the response, so these
checks bind a response to a deployment's pin, not to the party that produced it.
Every anchor, CVE record and FiGHT technique must also equal the one the
service's evidence catalog holds under its ID: the catalog holds the CVE records
and anchors and the FiGHT source's techniques and anchors
(`FightSource.list_techniques`, `FightSource.list_evidence`), and a served
technique is compared apart from the `matched_fields` and `matched_terms` of the
search that found it. A holder who renames a technique, changes its observation
status or rewrites a record behind its genuine anchors is therefore rejected. The
CLI exposes the service as `cve-kgrag topic <query> --scope <scope>`.

## Gold queries

`eval/gold/m3_topic_queries.yaml` holds hand-labelled resolution and context
expectations over the packaged card, FiGHT excerpt and synthetic CVEs, including
the `aka`-as-"also known as" cases; `tests/integration/test_topic_gold.py`
compares against it and never regenerates it. It supports fixture-level claims
only.

## Deliberate deferrals

- The investigation service that chooses sources and refines once
  (`m4-bounded-investigation.md`) uses the topic-context service as one of its
  tools.
- CVE→CWE→CAPEC→ATT&CK derived mappings remain deferred.
- Configuring an operator's full FiGHT snapshot (path, pin) arrives with the
  service settings in M6; the default composition uses the packaged excerpt and
  says so in every response.
