"""One-line text for the NVD configurations a record keeps; nothing is evaluated."""

from vulnwitness.domain.cve import Configuration, ConfigurationMatch, VersionRange

MAX_SHOWN_CONFIGURATIONS = 5
MAX_SHOWN_MATCHES = 4


def describe_range(condition: VersionRange | None) -> str:
    if condition is None:
        return ""
    if condition.exact is not None:
        return f" = {condition.exact}"
    bounds: list[str] = []
    for operator, bound in (
        (">=", condition.start_including),
        (">", condition.start_excluding),
        ("<=", condition.end_including),
        ("<", condition.end_excluding),
    ):
        if bound is not None:
            bounds.append(f"{operator} {bound}")
    return " " + ", ".join(bounds)


def describe_match(match: ConfigurationMatch) -> str:
    role = "vulnerable" if match.vulnerable else "running on"
    return f"{role} {match.cpe}{describe_range(match.version_range)}"


def describe_configuration(configuration: Configuration) -> str:
    """``AND`` joins nodes, ``OR`` joins the matches inside a node; ``NOT`` marks negation."""
    nodes: list[str] = []
    for node in configuration.nodes:
        matches = [describe_match(match) for match in node.matches[:MAX_SHOWN_MATCHES]]
        hidden = len(node.matches) - MAX_SHOWN_MATCHES + node.omitted_matches
        if hidden > 0:
            matches.append(f"{hidden} more")
        text = f" {node.operator} ".join(matches) or "no matches"
        if len(node.matches) > 1 or node.omitted_matches:
            text = f"({text})"
        nodes.append(f"NOT {text}" if node.negate else text)
    if configuration.omitted_nodes:
        nodes.append(f"{configuration.omitted_nodes} more nodes")
    joined = f" {configuration.operator} ".join(nodes)
    return f"NOT ({joined})" if configuration.negate else joined


def summarize_configurations(
    configurations: tuple[Configuration, ...], omitted: int
) -> tuple[str, list[str]]:
    """A heading line and up to five configuration lines."""
    total = len(configurations) + omitted
    heading = (
        f"NVD configurations beyond the product list: {total} "
        "(AND/platform conditions as NVD states them; not evaluated)"
    )
    lines = [describe_configuration(c) for c in configurations[:MAX_SHOWN_CONFIGURATIONS]]
    if total > MAX_SHOWN_CONFIGURATIONS:
        lines.append(f"{total - MAX_SHOWN_CONFIGURATIONS} more configurations")
    return heading, lines
