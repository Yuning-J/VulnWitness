"""Assertions about secrets that never print the secret, even when they fail."""


def assert_secret_absent(text: str, secret: str, where: str) -> None:
    """Fail, naming only ``where``, when ``secret`` occurs in ``text``; pytest's assertion
    rewriting would otherwise print both operands into the test log."""
    is_absent = secret not in text
    assert is_absent, f"the secret appears in {where}"
