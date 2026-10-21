"""A genuine affectedness request: a fixture CVE against one package version."""

from cve_kgrag.domain.affectedness import AffectednessRequest


def build_affectedness_request() -> AffectednessRequest:
    return AffectednessRequest(cve_id="CVE-9999-0003", purl="pkg:generic/open5gs@2.7.0")
