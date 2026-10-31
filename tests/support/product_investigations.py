"""Synthetic product identities with lexical noise and dated product candidates."""

from cve_kgrag.adapters.fixture.synthetic_fixture import FixtureBundle
from cve_kgrag.domain.cve import VersionRange
from tests.support.builders import build_bundle_with, build_versioned_product


def build_product_investigation_bundle(bundle: FixtureBundle) -> FixtureBundle:
    specifications = (
        ("CVE-9999-7201", "kamailio", "kamailio", "[SYNTHETIC] componentalpha crash"),
        ("CVE-9999-7202", "kamailio", "kamailio", "[SYNTHETIC] unrelated subsystem"),
        ("CVE-9999-7203", "openairinterface", "demo_amf", "[SYNTHETIC] unrelated subsystem"),
        ("CVE-9999-7204", "openairinterface", "demo_smf", "[SYNTHETIC] unrelated subsystem"),
        ("CVE-9999-7205", "vendor_one", "sharedname", "[SYNTHETIC] sharedname crash"),
        ("CVE-9999-7206", "vendor_two", "sharedname", "[SYNTHETIC] sharedname crash"),
        ("CVE-9999-7207", "service", "service", "[SYNTHETIC] service crash"),
        ("CVE-9999-7208", "known", "known", "[SYNTHETIC] known crash"),
        ("CVE-9999-7209", "test_vendor", "smf", "[SYNTHETIC] smf crash"),
        ("CVE-9999-7210", "openairinterface", "openairinterface", "[SYNTHETIC] subsystem"),
        ("CVE-9999-7211", "vendor_one", "core", "[SYNTHETIC] subsystem"),
        ("CVE-9999-7212", "vendor_two", "network", "[SYNTHETIC] subsystem"),
        ("CVE-9999-7213", "vendorcollision", "demo", "[SYNTHETIC] subsystem"),
        ("CVE-9999-7214", "vendor_two", "vendorcollision", "[SYNTHETIC] subsystem"),
    )
    for cve_id, vendor, product, description in specifications:
        entry = build_versioned_product(
            vendor=vendor, product=product, version_ranges=(VersionRange(exact="5.8.2"),)
        )
        if cve_id in {"CVE-9999-7202", "CVE-9999-7203", "CVE-9999-7204", "CVE-9999-7210"}:
            description += " unrelated" * 400
        bundle = build_bundle_with(
            bundle, cve_id, description, affected=(entry,), published="2030-01-01T00:00:00Z"
        )
    for index in range(24):
        bundle = build_bundle_with(
            bundle,
            f"CVE-9999-{7300 + index}",
            "[SYNTHETIC] 5g core network vulnerabilities known affected componentalpha",
        )
    return bundle


def build_lexical_product_bundle(bundle: FixtureBundle) -> FixtureBundle:
    entry = build_versioned_product(vendor="familydemo", product="familydemo")
    alternate_entry = build_versioned_product(vendor="familydemo_project", product="demo_core")
    for index in range(20):
        lexical_entries = ()
        if index % 3 == 0:
            lexical_entries = (entry,)
        elif index % 3 == 1:
            lexical_entries = (alternate_entry,)
        bundle = build_bundle_with(
            bundle,
            f"CVE-9999-{7400 + index}",
            "[SYNTHETIC] familydemo vulnerabilities componentalpha",
            affected=lexical_entries,
            published="2029-01-01T00:00:00Z",
        )
        bundle = build_bundle_with(
            bundle,
            f"CVE-9999-{7500 + index}",
            "[SYNTHETIC] unrelated subsystem" + " unrelated" * 400,
            affected=(entry,),
            published="2030-01-01T00:00:00Z",
        )
    return bundle
