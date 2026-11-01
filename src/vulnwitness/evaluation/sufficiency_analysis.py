"""Score each run against the labelled cases (``docs/rebuild/m7b-planner-evaluation.md``):
a pure function of the evidence sets, the gold labels and the recorded sets.

A run is judged only on what its answer lists: the CVE IDs of its implementation candidates
and the technique IDs of its protocol context; items the answer truncated do not count.
"""

from collections.abc import Sequence
from dataclasses import dataclass

from vulnwitness.domain.affectedness import ApplicabilityStatus
from vulnwitness.domain.investigation import (
    EvidenceNeedKind,
    KnowledgeEvidenceSet,
    NeedOutcome,
    StopReason,
)
from vulnwitness.domain.search import MAX_RESULTS_PER_CALL
from vulnwitness.evaluation.gold_sets import DerivedSets
from vulnwitness.evaluation.labelled_cases import (
    CATEGORY_SUBJECTS,
    EvidenceCategory,
    GoldFile,
    LabelledCase,
    Split,
    SubjectKind,
    Sufficiency,
)
from vulnwitness.evaluation.planner_analysis import CaseRuns, list_answer_ids, spread_rates
from vulnwitness.evaluation.planner_report import (
    RATE_DECIMALS,
    CaseCategoryFigures,
    CategoryQuality,
    JudgedSufficiency,
    RunJudgementCounts,
    RunQuality,
    SplitEvidenceQuality,
    SufficiencyCase,
    SufficiencyPart,
    SufficiencySection,
    measure_proportion,
)

# The run's need that answers for each labelled evidence category.
NEED_KIND_BY_CATEGORY = {
    EvidenceCategory.NAMED_CVE: EvidenceNeedKind.NAMED_CVE,
    EvidenceCategory.IMPLEMENTATION_CVES: EvidenceNeedKind.IMPLEMENTATION_CVES,
    EvidenceCategory.PROTOCOL_CONTEXT: EvidenceNeedKind.PROTOCOL_CONTEXT,
    EvidenceCategory.AFFECTEDNESS: EvidenceNeedKind.AFFECTEDNESS,
}
IMPLEMENTATION_FAMILY = (EvidenceCategory.NAMED_CVE, EvidenceCategory.IMPLEMENTATION_CVES)


@dataclass(frozen=True)
class CategoryJudgement:
    """One needed category of one run. ``coverage`` is ``None`` when required is empty."""

    coverage: float | None
    covered: bool
    lists_required: bool
    irrelevant_items: int
    unjudged_items: int


@dataclass(frozen=True)
class RunJudgement:
    categories: dict[EvidenceCategory, CategoryJudgement]
    judged: JudgedSufficiency
    wrong_stop: bool
    premature_no_evidence: bool
    unflagged_gap: bool
    affectedness_violation: bool
    false_gap: bool
    need_agreement: bool


@dataclass(frozen=True)
class JudgedCase:
    case: LabelledCase
    judgements: tuple[RunJudgement, ...]


def judge_category(derived_sets: DerivedSets, listed_ids: set[str]) -> CategoryJudgement:
    """Coverage@20 is over min(|required|, ``MAX_RESULTS_PER_CALL``), the server's cap on
    one answer section, never a request's lower budget: a request that asks for fewer
    results does not lower the bar a sufficient answer must clear."""
    required = set(derived_sets.required)
    judged_ids = required | set(derived_sets.allowed) | set(derived_sets.irrelevant)
    listed_required = len(listed_ids & required)
    coverage: float | None = None
    if required:
        coverage = round(listed_required / min(len(required), MAX_RESULTS_PER_CALL), RATE_DECIMALS)
    return CategoryJudgement(
        coverage=coverage,
        covered=coverage == 1,
        lists_required=listed_required > 0,
        irrelevant_items=len(listed_ids & set(derived_sets.irrelevant)),
        unjudged_items=len(listed_ids - judged_ids),
    )


def signals_gap(category: EvidenceCategory, evidence_set: KnowledgeEvidenceSet) -> bool:
    """Whether the answer names a gap in ``category``: the run records a need of that kind
    it did not find."""
    need_kind = NEED_KIND_BY_CATEGORY[category]
    return any(
        need.kind is need_kind and need.outcome is not NeedOutcome.FOUND
        for need in evidence_set.coverage.needs
    )


def has_label_needs(case: LabelledCase, evidence_set: KnowledgeEvidenceSet) -> bool:
    """Whether the run's need kinds are the labelled case's: a diagnostic of how the
    runtime reads the question, never an input to it."""
    run_need_kinds: set[EvidenceNeedKind] = set()
    for need in evidence_set.coverage.needs:
        run_need_kinds.add(need.kind)
    label_need_kinds: set[EvidenceNeedKind] = set()
    for category in case.needs:
        label_need_kinds.add(NEED_KIND_BY_CATEGORY[category])
    return run_need_kinds == label_need_kinds


def judge_run(
    case: LabelledCase,
    case_sets: dict[SubjectKind, DerivedSets],
    evidence_set: KnowledgeEvidenceSet,
) -> RunJudgement:
    """The run's figures for each needed category, its judged sufficiency and the four
    run judgements, as the M7b design defines them."""
    categories: dict[EvidenceCategory, CategoryJudgement] = {}
    gold_gaps: list[EvidenceCategory] = []
    for category in case.needs:
        subject_kind = CATEGORY_SUBJECTS[category]
        if subject_kind is None:
            gold_gaps.append(category)
            continue
        derived_sets = case_sets[subject_kind]
        if not derived_sets.required:
            gold_gaps.append(category)
        categories[category] = judge_category(
            derived_sets, list_answer_ids(evidence_set, subject_kind)
        )
    every_category_covered = not gold_gaps and all(
        judgement.covered for judgement in categories.values()
    )
    if every_category_covered:
        judged = JudgedSufficiency.SUFFICIENT
    elif any(judgement.lists_required for judgement in categories.values()):
        judged = JudgedSufficiency.PARTIAL
    else:
        judged = JudgedSufficiency.INSUFFICIENT
    is_partial_case = case.sufficiency is Sufficiency.PARTIAL
    return RunJudgement(
        categories=categories,
        judged=judged,
        wrong_stop=evidence_set.stop_reason is StopReason.SUFFICIENT
        and judged is not JudgedSufficiency.SUFFICIENT,
        premature_no_evidence=evidence_set.stop_reason is StopReason.NO_EVIDENCE
        and case.sufficiency in (Sufficiency.SUFFICIENT, Sufficiency.PARTIAL),
        unflagged_gap=is_partial_case
        and any(not signals_gap(category, evidence_set) for category in gold_gaps),
        affectedness_violation=any(
            applicability.status is not ApplicabilityStatus.UNKNOWN
            for applicability in evidence_set.product_applicability
        ),
        false_gap=judged is JudgedSufficiency.SUFFICIENT
        and evidence_set.stop_reason is not StopReason.SUFFICIENT,
        need_agreement=has_label_needs(case, evidence_set),
    )


def count_judged(judgements: Sequence[RunJudgement]) -> dict[JudgedSufficiency, int]:
    judged_counts: dict[JudgedSufficiency, int] = {}
    for judged in JudgedSufficiency:
        judged_counts[judged] = 0
    for judgement in judgements:
        judged_counts[judgement.judged] += 1
    return judged_counts


def summarize_case(judged_case: JudgedCase) -> SufficiencyCase:
    judgements = judged_case.judgements
    categories: dict[EvidenceCategory, CaseCategoryFigures] = {}
    for category in judged_case.case.needs:
        if CATEGORY_SUBJECTS[category] is None:
            continue
        category_judgements: list[CategoryJudgement] = []
        for judgement in judgements:
            category_judgements.append(judgement.categories[category])
        categories[category] = summarize_category_runs(category_judgements)
    return SufficiencyCase(
        case_sha256=judged_case.case.case_sha256,
        case_id=judged_case.case.case_id,
        split=judged_case.case.split,
        label=judged_case.case.sufficiency,
        runs=len(judgements),
        judged=count_judged(judgements),
        categories=categories,
        run_judgements=RunJudgementCounts(
            wrong_stop=sum(judgement.wrong_stop for judgement in judgements),
            premature_no_evidence=sum(judgement.premature_no_evidence for judgement in judgements),
            unflagged_gap=sum(judgement.unflagged_gap for judgement in judgements),
            affectedness_violation=sum(
                judgement.affectedness_violation for judgement in judgements
            ),
            false_gap=sum(judgement.false_gap for judgement in judgements),
            need_agreement=sum(judgement.need_agreement for judgement in judgements),
        ),
    )


def summarize_category_runs(
    category_judgements: Sequence[CategoryJudgement],
) -> CaseCategoryFigures:
    coverages: list[float | None] = []
    measured_runs = 0
    covered_runs = 0
    for category_judgement in category_judgements:
        coverages.append(category_judgement.coverage)
        if category_judgement.coverage is not None:
            measured_runs += 1
            covered_runs += category_judgement.covered
    return CaseCategoryFigures(
        coverage=spread_rates(coverages),
        covered=measure_proportion(covered_runs, measured_runs),
        irrelevant_items=sum(judgement.irrelevant_items for judgement in category_judgements),
        unjudged_items=sum(judgement.unjudged_items for judgement in category_judgements),
    )


def measure_category(category_judgements: Sequence[CategoryJudgement]) -> CategoryQuality:
    case_figures = summarize_category_runs(category_judgements)
    runs_with_irrelevant = sum(judgement.irrelevant_items > 0 for judgement in category_judgements)
    return CategoryQuality(
        category_runs=len(category_judgements),
        coverage=case_figures.coverage,
        covered=case_figures.covered,
        irrelevant_items=case_figures.irrelevant_items,
        unjudged_items=case_figures.unjudged_items,
        runs_with_irrelevant=measure_proportion(runs_with_irrelevant, len(category_judgements)),
    )


def list_category_judgements(
    judged_cases: Sequence[JudgedCase], categories: Sequence[EvidenceCategory]
) -> list[CategoryJudgement]:
    """Every judgement of ``categories`` over the runs of non-uncertain cases needing one."""
    category_judgements: list[CategoryJudgement] = []
    for judged_case in judged_cases:
        if judged_case.case.sufficiency is Sufficiency.UNCERTAIN:
            continue
        for judgement in judged_case.judgements:
            for category in categories:
                if category in judgement.categories:
                    category_judgements.append(judgement.categories[category])
    return category_judgements


def measure_evidence_quality(judged_cases: Sequence[JudgedCase]) -> SplitEvidenceQuality:
    return SplitEvidenceQuality(
        named_cve=measure_category(
            list_category_judgements(judged_cases, (EvidenceCategory.NAMED_CVE,))
        ),
        implementation_cves=measure_category(
            list_category_judgements(judged_cases, (EvidenceCategory.IMPLEMENTATION_CVES,))
        ),
        protocol_context=measure_category(
            list_category_judgements(judged_cases, (EvidenceCategory.PROTOCOL_CONTEXT,))
        ),
        implementation_family=measure_category(
            list_category_judgements(judged_cases, IMPLEMENTATION_FAMILY)
        ),
    )


def measure_run_quality(judged_cases: Sequence[JudgedCase]) -> RunQuality:
    every_run: list[RunJudgement] = []
    labelled_runs: list[RunJudgement] = []
    evidence_label_runs: list[RunJudgement] = []
    partial_label_runs: list[RunJudgement] = []
    judged_sufficient_runs: list[RunJudgement] = []
    for judged_case in judged_cases:
        label = judged_case.case.sufficiency
        every_run.extend(judged_case.judgements)
        if label is not Sufficiency.UNCERTAIN:
            labelled_runs.extend(judged_case.judgements)
        if label in (Sufficiency.SUFFICIENT, Sufficiency.PARTIAL):
            evidence_label_runs.extend(judged_case.judgements)
        if label is Sufficiency.PARTIAL:
            partial_label_runs.extend(judged_case.judgements)
        if label is not Sufficiency.UNCERTAIN:
            for judgement in judged_case.judgements:
                if judgement.judged is JudgedSufficiency.SUFFICIENT:
                    judged_sufficient_runs.append(judgement)
    return RunQuality(
        runs=len(every_run),
        uncertain_runs=len(every_run) - len(labelled_runs),
        judged=count_judged(labelled_runs),
        wrong_stop=measure_proportion(
            sum(judgement.wrong_stop for judgement in labelled_runs), len(labelled_runs)
        ),
        premature_no_evidence=measure_proportion(
            sum(judgement.premature_no_evidence for judgement in evidence_label_runs),
            len(evidence_label_runs),
        ),
        unflagged_gap=measure_proportion(
            sum(judgement.unflagged_gap for judgement in partial_label_runs),
            len(partial_label_runs),
        ),
        affectedness_violation=measure_proportion(
            sum(judgement.affectedness_violation for judgement in every_run), len(every_run)
        ),
        false_gap=measure_proportion(
            sum(judgement.false_gap for judgement in judged_sufficient_runs),
            len(judged_sufficient_runs),
        ),
        need_agreement=measure_proportion(
            sum(judgement.need_agreement for judgement in labelled_runs), len(labelled_runs)
        ),
    )


def build_part(judged_cases: Sequence[JudgedCase]) -> SufficiencyPart:
    cases: list[SufficiencyCase] = []
    for judged_case in judged_cases:
        cases.append(summarize_case(judged_case))
    evidence_quality: dict[Split, SplitEvidenceQuality] = {}
    run_quality: dict[Split, RunQuality] = {}
    for split in Split:
        split_cases: list[JudgedCase] = []
        for judged_case in judged_cases:
            if judged_case.case.split is split:
                split_cases.append(judged_case)
        evidence_quality[split] = measure_evidence_quality(split_cases)
        run_quality[split] = measure_run_quality(split_cases)
    return SufficiencyPart(
        cases=tuple(cases), evidence_quality=evidence_quality, run_quality=run_quality
    )


def analyze_sufficiency(
    gold_file: GoldFile,
    gold_sets: dict[str, dict[SubjectKind, DerivedSets]],
    case_runs: Sequence[CaseRuns],
    has_model_runs: bool,
) -> SufficiencySection:
    """The ``sufficiency`` section for ``case_runs``, one per gold case in the gold file's
    order, scored against each case's label and its recorded sets."""
    cases_by_hash: dict[str, LabelledCase] = {}
    for case in gold_file.cases:
        cases_by_hash[case.case_sha256] = case
    deterministic_cases: list[JudgedCase] = []
    model_cases: list[JudgedCase] = []
    for case_run in case_runs:
        case = cases_by_hash[case_run.case_sha256]
        case_sets = gold_sets[case.case_id]
        deterministic_cases.append(
            JudgedCase(case, (judge_run(case, case_sets, case_run.deterministic_set),))
        )
        model_judgements: list[RunJudgement] = []
        for model_set in case_run.model_sets:
            model_judgements.append(judge_run(case, case_sets, model_set))
        model_cases.append(JudgedCase(case, tuple(model_judgements)))
    return SufficiencySection(
        deterministic=build_part(deterministic_cases),
        model=build_part(model_cases) if has_model_runs else None,
    )
