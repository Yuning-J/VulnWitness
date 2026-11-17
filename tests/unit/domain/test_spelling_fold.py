"""British spellings fold to American ones for matching; folding is idempotent."""

import pytest

from vulnwitness.domain.text import SPELLING_FOLDS, fold_spelling


@pytest.mark.parametrize(
    ("word", "folded"),
    [
        ("signalling", "signaling"),
        ("authorisation", "authorization"),
        ("unsanitised", "unsanitized"),
        ("behaviour", "behavior"),
        ("licence", "license"),
        ("catalogue", "catalog"),
        ("signal", "signal"),
        ("analyses", "analyses"),
        ("señalización", "señalización"),
        ("centreon", "centeron"),
        ("workcentre", "workcenter"),
        ("wptravelly", "wptravely"),
    ],
)
def test_ascii_tokens_fold_substrings_idempotently(word: str, folded: str) -> None:
    assert fold_spelling(word) == folded
    assert fold_spelling(folded) == folded


def test_no_american_form_contains_its_british_form() -> None:
    for british, american in SPELLING_FOLDS:
        assert british not in american
