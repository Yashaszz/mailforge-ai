"""SPF / DKIM / DMARC tests, all served by stub resolvers."""

from __future__ import annotations

import pytest

from app.services.email_auth import (
    DkimResult,
    DkimSignature,
    SpfResult,
    _is_aligned,
    _org_domain,
    authenticate,
    check_dkim,
    check_dmarc,
    check_spf,
)
from app.services.eml_parser import parse_eml

from .conftest import DKIM_DOMAIN, FakeResolver, build_message

SENDER_DOMAIN = DKIM_DOMAIN.decode()


# --------------------------------------------------------------------------
# DKIM -- real signatures, verified against a stub DNS key
# --------------------------------------------------------------------------

def test_dkim_verifies_a_genuine_signature(signed_message, dkim_dnsfunc):
    parsed = parse_eml(signed_message())

    result = check_dkim(parsed, dnsfunc=dkim_dnsfunc)

    assert result.result == "pass"
    assert result.passing_domains == [SENDER_DOMAIN]
    assert result.signatures[0].selector == "mailforgetest"
    assert result.signatures[0].algorithm == "rsa-sha256"


def test_dkim_fails_when_the_body_is_tampered_with(signed_message, dkim_dnsfunc):
    raw = signed_message()
    tampered = raw.replace(b"Numbers attached", b"Wire funds urgently")
    assert tampered != raw

    result = check_dkim(parse_eml(tampered), dnsfunc=dkim_dnsfunc)

    assert result.result == "fail"
    assert result.passing_domains == []


def test_dkim_fails_when_a_signed_header_is_tampered_with(signed_message, dkim_dnsfunc):
    raw = signed_message()
    tampered = raw.replace(b"Subject: Quarterly report", b"Subject: Payment overdue")

    result = check_dkim(parse_eml(tampered), dnsfunc=dkim_dnsfunc)

    assert result.result == "fail"


def test_dkim_reports_none_without_a_signature(dkim_dnsfunc):
    result = check_dkim(parse_eml(build_message()), dnsfunc=dkim_dnsfunc)

    assert result.result == "none"
    assert result.signatures == []


def test_dkim_permerror_when_the_public_key_is_missing(signed_message):
    def empty_dns(name, timeout=5, **kwargs):  # noqa: ARG001
        return b""

    result = check_dkim(parse_eml(signed_message()), dnsfunc=empty_dns)

    assert result.result in ("permerror", "fail")
    assert result.passing_domains == []


# --------------------------------------------------------------------------
# SPF
# --------------------------------------------------------------------------

def test_spf_not_checked_without_a_client_ip():
    result = check_spf(client_ip=None, mail_from="a@b.test", helo="b.test")

    assert result.result == "not_checked"
    assert "no address to evaluate" in result.detail


def test_spf_permerror_on_a_bogus_ip():
    result = check_spf(client_ip="999.1.1.1", mail_from="a@b.test", helo="b.test")

    assert result.result == "permerror"


# --------------------------------------------------------------------------
# DMARC alignment
# --------------------------------------------------------------------------

def _passing_spf(domain: str) -> SpfResult:
    return SpfResult(result="pass", domain=domain)


def _passing_dkim(domain: str) -> DkimResult:
    return DkimResult(
        result="pass",
        signatures=[DkimSignature(index=0, domain=domain, result="pass")],
    )


def test_dmarc_passes_on_aligned_spf():
    resolver = FakeResolver({"_dmarc.example.test": ["v=DMARC1; p=reject"]})

    result = check_dmarc(
        from_domain="example.test",
        spf=_passing_spf("example.test"),
        dkim=DkimResult(result="none"),
        resolver=resolver,
    )

    assert result.result == "pass"
    assert result.spf_alignment == "pass"
    assert result.dkim_alignment == "none"
    assert result.policy == "reject"


def test_dmarc_passes_on_aligned_dkim_even_when_spf_fails():
    resolver = FakeResolver({"_dmarc.example.test": ["v=DMARC1; p=quarantine"]})

    result = check_dmarc(
        from_domain="example.test",
        spf=SpfResult(result="fail", domain="elsewhere.test"),
        dkim=_passing_dkim("example.test"),
        resolver=resolver,
    )

    assert result.result == "pass"
    assert result.dkim_alignment == "pass"
    assert result.spf_alignment == "fail"


def test_dmarc_fails_when_a_passing_spf_is_not_aligned():
    """The classic spoof: SPF passes for the attacker's own envelope domain,
    but the visible From header is a different, trusted brand."""
    resolver = FakeResolver({"_dmarc.bank.test": ["v=DMARC1; p=reject"]})

    result = check_dmarc(
        from_domain="bank.test",
        spf=_passing_spf("attacker-vps.test"),
        dkim=DkimResult(result="none"),
        resolver=resolver,
    )

    assert result.result == "fail"
    assert result.spf_alignment == "fail"
    assert result.disposition == "reject"


def test_dmarc_relaxed_alignment_accepts_a_subdomain():
    resolver = FakeResolver({"_dmarc.example.test": ["v=DMARC1; p=none"]})

    result = check_dmarc(
        from_domain="example.test",
        spf=_passing_spf("mail.example.test"),
        dkim=DkimResult(result="none"),
        resolver=resolver,
    )

    assert result.result == "pass"


def test_dmarc_strict_alignment_rejects_a_subdomain():
    resolver = FakeResolver({"_dmarc.example.test": ["v=DMARC1; p=reject; aspf=s"]})

    result = check_dmarc(
        from_domain="example.test",
        spf=_passing_spf("mail.example.test"),
        dkim=DkimResult(result="none"),
        resolver=resolver,
    )

    assert result.result == "fail"
    assert result.alignment_mode_spf == "s"


def test_dmarc_record_is_inherited_from_the_organizational_domain():
    resolver = FakeResolver({"_dmarc.example.test": ["v=DMARC1; p=none; sp=quarantine"]})

    result = check_dmarc(
        from_domain="marketing.example.test",
        spf=SpfResult(result="fail", domain="attacker.test"),
        dkim=DkimResult(result="none"),
        resolver=resolver,
    )

    assert result.record_domain == "example.test"
    # The subdomain policy applies, not the top-level one.
    assert result.disposition == "quarantine"


def test_dmarc_none_when_no_record_is_published():
    resolver = FakeResolver({})

    result = check_dmarc(
        from_domain="nothing-here.test",
        spf=SpfResult(result="none"),
        dkim=DkimResult(result="none"),
        resolver=resolver,
    )

    assert result.result == "none"
    assert result.disposition is None


def test_dmarc_ignores_unrelated_txt_records():
    resolver = FakeResolver(
        {"_dmarc.example.test": ["some-verification=abc123", "v=DMARC1; p=reject"]}
    )

    result = check_dmarc(
        from_domain="example.test",
        spf=_passing_spf("example.test"),
        dkim=DkimResult(result="none"),
        resolver=resolver,
    )

    assert result.policy == "reject"


def test_dmarc_is_inconclusive_when_spf_hit_a_dns_error():
    """A temporary DNS failure must not be reported as a DMARC failure."""
    resolver = FakeResolver({"_dmarc.example.test": ["v=DMARC1; p=reject"]})

    result = check_dmarc(
        from_domain="example.test",
        spf=SpfResult(result="temperror"),
        dkim=DkimResult(result="none"),
        resolver=resolver,
    )

    assert result.result == "temperror"
    assert result.disposition is None


@pytest.mark.parametrize(
    ("candidate", "from_domain", "mode", "expected"),
    [
        ("example.test", "example.test", "s", True),
        ("mail.example.test", "example.test", "s", False),
        ("mail.example.test", "example.test", "r", True),
        ("example.test", "other.test", "r", False),
        ("EXAMPLE.test.", "example.test", "r", True),
        ("a.example.co.in", "example.co.in", "r", True),
        ("evil.co.in", "example.co.in", "r", False),
    ],
)
def test_is_aligned(candidate: str, from_domain: str, mode: str, expected: bool):
    assert _is_aligned(candidate, from_domain, mode) is expected


def test_org_domain_handles_multi_label_public_suffixes():
    assert _org_domain("mail.example.co.in") == "example.co.in"
    assert _org_domain("news.example.com") == "example.com"


# --------------------------------------------------------------------------
# offline mode
# --------------------------------------------------------------------------

def test_offline_mode_skips_every_lookup(signed_message):
    report = authenticate(parse_eml(signed_message()), offline=True)

    assert report.dns_available is False
    assert report.spf.result == "not_checked"
    assert report.dkim.result == "not_checked"
    assert report.dmarc.result == "not_checked"
    assert report.notes
