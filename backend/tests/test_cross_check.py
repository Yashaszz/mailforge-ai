"""Cross-check tests: comparing our results with the receiving MTA's."""

from __future__ import annotations

from app.services.cross_check import cross_check
from app.services.email_auth import AuthReport, DkimResult, DmarcResult, SpfResult
from app.services.eml_parser import parse_eml

from .conftest import build_message

GMAIL_AR = (
    "Authentication-Results: mx.google.com;\n"
    "\tdkim=pass header.i=@unstop.news header.s=nc2048;\n"
    "\tspf=pass (google.com: domain of bounce@env.etransmail.com designates"
    " 202.162.224.10 as permitted sender) smtp.mailfrom=bounce@env.etransmail.com;\n"
    "\tdmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=unstop.news"
)


def _report(spf="pass", dkim="pass", dmarc="pass") -> AuthReport:
    return AuthReport(
        spf=SpfResult(result=spf, domain="unstop.news"),
        dkim=DkimResult(result=dkim),
        dmarc=DmarcResult(result=dmarc, policy="reject"),
    )


def test_full_agreement_is_reported():
    parsed = parse_eml(build_message(extra_headers=GMAIL_AR))
    result = cross_check(parsed, _report())

    assert result.available is True
    assert result.reporter == "mx.google.com"
    assert result.agreement == "full"
    assert all(m.agrees for m in result.methods)
    assert "corroborated" in result.summary


def test_disagreement_is_explained_not_hidden():
    parsed = parse_eml(build_message(extra_headers=GMAIL_AR))
    result = cross_check(parsed, _report(dkim="fail"))

    assert result.agreement == "partial"
    dkim = next(m for m in result.methods if m.method == "dkim")
    assert dkim.agrees is False
    assert dkim.ours == "fail" and dkim.theirs == "pass"
    # A rotated key is the usual cause and must be offered as an explanation.
    assert "rotated" in dkim.note


def test_key_rotation_explains_a_temperror():
    parsed = parse_eml(build_message(extra_headers=GMAIL_AR))
    result = cross_check(parsed, _report(dkim="temperror"))

    dkim = next(m for m in result.methods if m.method == "dkim")
    assert "rotated" in dkim.note


def test_absent_header_is_not_treated_as_disagreement():
    result = cross_check(parse_eml(build_message()), _report())

    assert result.available is False
    assert result.agreement == "not_available"
    assert all(m.theirs is None and m.agrees is None for m in result.methods)


def test_arc_headers_do_not_displace_the_delivering_server():
    """ARC records an intermediary's view; the delivering server's is primary."""
    parsed = parse_eml(build_message(
        extra_headers="ARC-Authentication-Results: i=1; relay.test; spf=fail\n" + GMAIL_AR
    ))
    result = cross_check(parsed, _report())

    assert result.reporter == "mx.google.com"
    assert result.agreement == "full"


def test_partially_reported_methods_are_counted_fairly():
    parsed = parse_eml(build_message(
        extra_headers="Authentication-Results: mx.test; spf=pass"
    ))
    result = cross_check(parsed, _report(dkim="fail", dmarc="fail"))

    # Only SPF was reported, so only SPF is comparable.
    assert result.agreement == "full"
    dkim = next(m for m in result.methods if m.method == "dkim")
    assert dkim.agrees is None and "Not reported" in dkim.note
