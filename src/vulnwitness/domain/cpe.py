"""CPE formatted-string component parsing and named product identities."""

from urllib.parse import unquote


def cpe_product_identity(cpe: str) -> tuple[str, str] | None:
    """Vendor and product from a CPE 2.2 URI or 2.3 string, excluding ANY/NA values.

    URI fields are percent-decoded; formatted-string fields have backslash escapes
    removed. Unrecognized bindings and absent or logical names return None.
    """
    if cpe.startswith("cpe:2.3:"):
        components = split_cpe(cpe)
        if len(components) != 11:
            return None
        vendor, product = components[1:3]
    elif cpe.startswith("cpe:/"):
        components = cpe.removeprefix("cpe:/").split(":")
        if len(components) < 3:
            return None
        vendor, product = unquote(components[1]), unquote(components[2])
    else:
        return None
    if vendor in ("", "*", "-") or product in ("", "*", "-"):
        return None
    return vendor, product


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
