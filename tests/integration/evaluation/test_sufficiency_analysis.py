"""Scoring runs against labelled cases (``sufficiency_analysis``) on evidence sets of real
investigations over the fixture: coverage over the capped required set, irrelevant and
unjudged items, judged sufficiency, the four run judgements, and the split, category and
run aggregates with their stated denominators."""

from types import SimpleNamespace
from typing import Any

import pytest

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.domain.investigation import (
    InvestigationWarning,
    InvestigationWarningCode,
    KnowledgeEvidenceSet,
    StopReason,
)
from cve_kgrag.evaluation.gold_sets import DerivedSets
from cve_kgrag.evaluation.labelled_cases import (
    EvidenceCategory,
    LabelledCase,
    Split,
    SubjectKind,
)
from cve_kgrag.evaluation.planner_analysis import CaseRuns
from cve_kgrag.evaluation.planner_report import JudgedSufficiency
from cve_kgrag.evaluation.sufficiency_analysis import (
    JudgedCase,
    analyze_sufficiency,
    build_part,
    judge_run,
)
from tests.support.evaluation import run_deterministically
from tests.support.gold_files import build_case_row, encode_gold_file, load_labelled_gold_file

# "democorp gateway" lists CVE-9999-0001, -0002 and -0007; "5gaka" (mixed) lists
# CVE-9999-0003 and -0004 and FGT1499.503, FGT5040, FGT5019, FGT5019.005 and FGT5044.
GATEWAY_QUERY = "democorp gateway"
PROTOCOL_RULES = {
    "relevant": {"technique_any": ["x"]},
    "required": {"technique_any": ["x"]},
}


def build_case(**overrides: Any) -> LabelledCase:
    (case,) = load_labelled_gold_file(encode_gold_file([build_case_row(**overrides)])).cases
    return case


def build_sets(
    required: tuple[str, ...], allowed: tuple[str, ...] = (), irrelevant: tuple[str, ...] = ()
) -> DerivedSets:
    return DerivedSets(required=required, allowed=allowed, irrelevant=irrelevant, wide_check=None)


@pytest.fixture
def gateway_set(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    return run_deterministically(fixture_bundle, GATEWAY_QUERY, "implementation_only")


@pytest.fixture
def mixed_set(fixture_bundle: FixtureBundle) -> KnowledgeEvidenceSet:
    return run_deterministically(fixture_bundle, "5gaka", "mixed")


@pytest.mark.parametrize(
    ("required", "answer_cap", "expected_coverage", "expected_judged"),
    [
        (("CVE-9999-0001", "CVE-9999-0002"), 20, 1.0, JudgedSufficiency.SUFFICIENT),
        (
            ("CVE-9999-0001", "CVE-9999-0002", "CVE-9999-0099"),
            20,
            0.6667,
            JudgedSufficiency.PARTIAL,
        ),
        (("CVE-9999-0001", "CVE-9999-0002", "CVE-9999-0099"), 2, 1.0, JudgedSufficiency.SUFFICIENT),
        (("CVE-9999-0098", "CVE-9999-0099"), 20, 0.0, JudgedSufficiency.INSUFFICIENT),
    ],
    ids=["all_listed", "one_missing", "missing_beyond_the_cap", "none_listed"],
)
def test_coverage_counts_listed_required_items_over_the_capped_required_set(
    gateway_set: KnowledgeEvidenceSet,
    required: tuple[str, ...],
    answer_cap: int,
    expected_coverage: float,
    expected_judged: JudgedSufficiency,
) -> None:
    case = build_case(
        request={
            "query": "democorp gateway vulnerabilities",
            "scope": "implementation_only",
            "budget": {"max_results_per_call": answer_cap},
        }
    )

    judgement = judge_run(case, {SubjectKind.CVES: build_sets(required)}, gateway_set)

    category_judgement = judgement.categories[EvidenceCategory.IMPLEMENTATION_CVES]
    assert category_judgement.coverage == expected_coverage
    assert category_judgement.covered is (expected_coverage == 1.0)
    assert judgement.judged is expected_judged


@pytest.mark.parametrize(
    ("allowed", "expected_unjudged"),
    [(("CVE-9999-0002",), 0), ((), 1)],
    ids=["every_item_judged", "one_item_in_no_set"],
)
def test_irrelevant_and_unjudged_items_are_counted_apart(
    gateway_set: KnowledgeEvidenceSet, allowed: tuple[str, ...], expected_unjudged: int
) -> None:
    sets = build_sets(("CVE-9999-0001",), allowed, irrelevant=("CVE-9999-0007",))

    judgement = judge_run(build_case(), {SubjectKind.CVES: sets}, gateway_set)

    category_judgement = judgement.categories[EvidenceCategory.IMPLEMENTATION_CVES]
    assert category_judgement.irrelevant_items == 1
    assert category_judgement.unjudged_items == expected_unjudged


def test_empty_required_set_is_never_covered_and_a_sufficient_stop_is_wrong(
    gateway_set: KnowledgeEvidenceSet,
) -> None:
    case = build_case(
        rules={
            "cves": {
                "relevant": {"description_any": ["x"]},
                "wide_check": {"description_any": ["x"]},
            }
        },
        label={"sufficiency": "insufficient", "reason": "x"},
    )

    judgement = judge_run(case, {SubjectKind.CVES: build_sets(())}, gateway_set)

    assert judgement.categories[EvidenceCategory.IMPLEMENTATION_CVES].coverage is None
    assert judgement.judged is JudgedSufficiency.INSUFFICIENT
    assert gateway_set.stop_reason is StopReason.SUFFICIENT
    assert judgement.wrong_stop


@pytest.mark.parametrize(
    ("label", "expected_premature"),
    [("sufficient", True), ("insufficient", False)],
    ids=["evidence_exists", "no_evidence_exists"],
)
def test_no_evidence_stop_is_premature_only_when_the_label_says_evidence_exists(
    gateway_set: KnowledgeEvidenceSet, label: str, expected_premature: bool
) -> None:
    no_evidence_set = gateway_set.model_copy(update={"stop_reason": StopReason.NO_EVIDENCE})
    case = build_case(label={"sufficiency": label, "reason": "x"})

    judgement = judge_run(case, {SubjectKind.CVES: build_sets(("CVE-9999-0001",))}, no_evidence_set)

    assert judgement.premature_no_evidence is expected_premature


def build_affectedness_case() -> LabelledCase:
    return build_case(
        needs=["implementation_cves", "affectedness"],
        label={"sufficiency": "partial", "reason": "No affectedness source."},
    )


@pytest.mark.parametrize(
    ("warning_codes", "expected_unflagged"),
    [((), True), ((InvestigationWarningCode.APPLICABILITY_UNKNOWN,), False)],
    ids=["no_signal", "applicability_unknown"],
)
def test_affectedness_gap_is_unflagged_without_its_warning(
    gateway_set: KnowledgeEvidenceSet,
    warning_codes: tuple[InvestigationWarningCode, ...],
    expected_unflagged: bool,
) -> None:
    warnings: list[InvestigationWarning] = []
    for code in warning_codes:
        warnings.append(InvestigationWarning(code=code, subject="answer"))
    answer_set = gateway_set.model_copy(update={"warnings": tuple(warnings)})

    judgement = judge_run(
        build_affectedness_case(), {SubjectKind.CVES: build_sets(("CVE-9999-0001",))}, answer_set
    )

    assert judgement.unflagged_gap is expected_unflagged
    assert judgement.judged is JudgedSufficiency.PARTIAL


def test_protocol_gap_is_flagged_by_the_unreviewed_topic_warning(
    mixed_set: KnowledgeEvidenceSet,
) -> None:
    case = build_case(
        needs=["implementation_cves", "protocol_context"],
        request={"query": "5gaka", "scope": "mixed"},
        rules={
            "cves": {
                "relevant": {"description_any": ["x"]},
                "required": {"description_any": ["x"]},
            },
            "techniques": PROTOCOL_RULES,
        },
        label={"sufficiency": "partial", "reason": "No protocol evidence."},
    )
    case_sets = {
        SubjectKind.CVES: build_sets(("CVE-9999-0003",)),
        SubjectKind.TECHNIQUES: build_sets(()),
    }
    unsignalled_set = mixed_set.model_copy(update={"warnings": ()})

    flagged = judge_run(case, case_sets, mixed_set)
    unflagged = judge_run(case, case_sets, unsignalled_set)

    assert not flagged.unflagged_gap
    assert unflagged.unflagged_gap


def test_any_applicability_but_unknown_is_an_affectedness_violation(
    gateway_set: KnowledgeEvidenceSet,
) -> None:
    violating_set = gateway_set.model_copy(
        update={"product_applicability": (SimpleNamespace(status="affected"),)}
    )
    case_sets = {SubjectKind.CVES: build_sets(("CVE-9999-0001",))}

    assert judge_run(build_case(), case_sets, violating_set).affectedness_violation
    assert not judge_run(build_case(), case_sets, gateway_set).affectedness_violation


def build_mixed_case(**overrides: Any) -> LabelledCase:
    fields: dict[str, Any] = {
        "id": "mixed",
        "needs": ["implementation_cves", "protocol_context"],
        "request": {"query": "5gaka", "scope": "mixed"},
        "rules": {
            "cves": {
                "relevant": {"description_any": ["x"]},
                "required": {"description_any": ["x"]},
            },
            "techniques": PROTOCOL_RULES,
        },
    }
    fields.update(overrides)
    return build_case(**fields)


MIXED_SETS = {
    SubjectKind.CVES: build_sets(("CVE-9999-0003",)),
    SubjectKind.TECHNIQUES: build_sets(("FGT5044",)),
}


def test_mixed_run_counts_once_in_run_quality_and_in_each_category(
    mixed_set: KnowledgeEvidenceSet,
) -> None:
    case = build_mixed_case()
    judged_case = JudgedCase(case, (judge_run(case, MIXED_SETS, mixed_set),))

    part = build_part([judged_case])

    baseline_quality = part.evidence_quality[Split.BASELINE]
    assert part.run_quality[Split.BASELINE].runs == 1
    assert part.run_quality[Split.BASELINE].judged[JudgedSufficiency.SUFFICIENT] == 1
    assert baseline_quality.implementation_cves.category_runs == 1
    assert baseline_quality.protocol_context.category_runs == 1
    assert baseline_quality.implementation_family.category_runs == 1
    assert baseline_quality.named_cve.category_runs == 0
    assert part.evidence_quality[Split.HOLDOUT].protocol_context.category_runs == 0


def test_uncertain_case_counts_its_runs_and_affectedness_and_nothing_its_label_decides(
    gateway_set: KnowledgeEvidenceSet,
) -> None:
    case = build_case(label={"sufficiency": "uncertain", "reason": "x"})
    judgement = judge_run(case, {SubjectKind.CVES: build_sets(("CVE-9999-0099",))}, gateway_set)

    part = build_part([JudgedCase(case, (judgement,))])

    run_quality = part.run_quality[Split.BASELINE]
    assert judgement.wrong_stop
    assert run_quality.runs == 1
    assert run_quality.uncertain_runs == 1
    assert run_quality.wrong_stop.of == 0
    assert run_quality.premature_no_evidence.of == 0
    assert run_quality.affectedness_violation.of == 1
    assert part.evidence_quality[Split.BASELINE].implementation_cves.category_runs == 0
    assert part.cases[0].run_judgements.wrong_stop == 1


def test_runs_join_their_case_by_hash_and_name_its_id(
    gateway_set: KnowledgeEvidenceSet, mixed_set: KnowledgeEvidenceSet
) -> None:
    gold_file = load_labelled_gold_file(
        encode_gold_file(
            [
                build_case_row(),
                build_case_row(
                    id="mixed",
                    split="holdout",
                    needs=["implementation_cves", "protocol_context"],
                    request={"query": "5gaka", "scope": "mixed"},
                    rules={
                        "cves": {
                            "relevant": {"description_any": ["x"]},
                            "required": {"description_any": ["x"]},
                        },
                        "techniques": PROTOCOL_RULES,
                    },
                ),
            ]
        )
    )
    gateway_case, mixed_case = gold_file.cases
    gold_sets = {
        gateway_case.case_id: {SubjectKind.CVES: build_sets(("CVE-9999-0001",))},
        mixed_case.case_id: MIXED_SETS,
    }
    case_runs = [
        CaseRuns(case_sha256=mixed_case.case_sha256, deterministic_set=mixed_set, model_sets=()),
        CaseRuns(
            case_sha256=gateway_case.case_sha256, deterministic_set=gateway_set, model_sets=()
        ),
    ]

    sufficiency = analyze_sufficiency(gold_file, gold_sets, case_runs, has_model_runs=False)

    assert sufficiency.model is None
    first_entry, second_entry = sufficiency.deterministic.cases
    assert (first_entry.case_id, first_entry.case_sha256) == ("mixed", mixed_case.case_sha256)
    assert first_entry.split is Split.HOLDOUT
    assert second_entry.case_id == gateway_case.case_id
    assert sufficiency.deterministic.run_quality[Split.HOLDOUT].runs == 1
    assert sufficiency.deterministic.run_quality[Split.BASELINE].runs == 1
