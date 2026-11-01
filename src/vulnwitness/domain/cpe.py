"""CPE formatted-string component parsing."""


def split_cpe(cpe: str) -> list[str]:
    """CPE 2.3 formatted-string components after ``cpe:2.3:``, backslash escapes removed."""
    components: list[str] = []
    current: list[str] = []
    is_escaped = False
    for character in cpe.removeprefix("cpe:2.3:"):
        if is_escaped:
            current.append(character)
            is_escaped = False
        elif character == "\\":
            is_escaped = True
        elif character == ":":
            components.append("".join(current))
            current = []
        else:
            current.append(character)
    if is_escaped:
        current.append("\\")
    components.append("".join(current))
    return components
