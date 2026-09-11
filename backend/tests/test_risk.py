"""Risk-scoring tests.

These run against synthetic auth reports, so they need no network and they
pin the behaviour the demo depends on.
"""

from __future__ import annotations

from app.services.email_auth import AuthReport, DkimResult, DmarcResult, SpfResult
from app.services.eml_parser import parse_eml
from app.services.risk import assess

from .conftest import build_message


def _report(*, spf="pass", dkim="pass", dmarc="pass", policy="reject",
            disposition="none", dmarc_domain="example-sender.test") -> AuthReport:
    return AuthReport(
        spf=SpfResult(result=spf, domain=dmarc_domain),
        dkim=DkimResult(result=dkim),
        dmarc=DmarcResult(
            result=dmarc, policy=policy, disposition=disposition,
            record_domain=dmarc_domain,
        ),
    )


def _clean_message(**kwargs) -> bytes:
    return build_message(
        extra_headers=(
            "Received: from mail.example-sender.test (mail.example-sender.test"
            " [45.33.32.9])\n"
            "\tby mx01.recipient.test with ESMTPS id AAA111;"
            " Tue, 9 Sep 2026 14:22:29 +0530"
        ),
        **kwargs,
    )


def test_fully_authenticated_mail_is_allowed():
    result = assess(parse_eml(_clean_message()), _report())

    assert result.level == "Allow"
    assert result.score < 20
    assert result.confidence == "high"
    assert "Deliver." in result.summary


def test_dmarc_failure_under_a_reject_policy_is_malicious():
    result = assess(
        parse_eml(_clean_message()),
        _report(spf="softfail", dkim="none", dmarc="fail", disposition="reject"),
    )

    # A DMARC failure on its own is enough to pull the message out of the
    # delivery path, but Mailforge stops at "quarantine for review" rather
    # than "block" until corroborating signals appear -- deliberately more
    # conservative than the p=reject the domain itself asks for.
    assert result.level == "High-Risk"
    assert result.reasons[0].code == "dmarc_fail"
    assert result.reasons[0].severity == "critical"


def test_reply_to_mismatch_is_flagged():
    raw = build_message(
        extra_headers=(
            "Reply-To: attacker@elsewhere.test\n"
            "Received: from mail.example-sender.test (mail [45.33.32.9])\n"
            "\tby mx01.recipient.test with ESMTP id AAA111;"
            " Tue, 9 Sep 2026 14:22:29 +0530"
        )
    )
    result = assess(parse_eml(raw), _report())

    codes = {r.code for r in result.reasons}
    assert "reply_to_mismatch" in codes


def test_brand_impersonation_in_the_display_name_is_flagged():
    raw = build_message(from_header='"PayPal Service" <billing@not-paypal.test>')
    result = assess(parse_eml(raw), _report(dmarc="none", policy=None))

    codes = {r.code for r in result.reasons}
    assert "brand_impersonation" in codes


def test_a_domain_publishing_nothing_is_penalised():
    result = assess(
        parse_eml(_clean_message()),
        _report(spf="none", dkim="none", dmarc="none", policy=None, disposition=None),
    )

    codes = {r.code for r in result.reasons}
    assert {"spf_none", "dkim_none", "dmarc_none"} <= codes
    assert result.level in ("Suspicious", "High-Risk")


def test_helo_mismatch_is_suppressed_when_dmarc_passes():
    """Providers legitimately relay one domain's mail from another's hosts."""
    raw = build_message(
        extra_headers=(
            "Received: from mail-sor-f41.google.com (mail-sor-f41.google.com"
            " [209.85.220.41])\n"
            "\tby mx01.recipient.test with ESMTPS id AAA111;"
            " Tue, 9 Sep 2026 14:22:29 +0530"
        )
    )
    codes = {r.code for r in assess(parse_eml(raw), _report()).reasons}
    assert "helo_mismatch" not in codes

    failing = _report(spf="fail", dkim="none", dmarc="fail")
    codes = {r.code for r in assess(parse_eml(raw), failing).reasons}
    assert "helo_mismatch" in codes


def test_confidence_drops_when_dns_was_unavailable():
    report = _report()
    report.dns_available = False

    assert assess(parse_eml(_clean_message()), report).confidence == "low"


def test_score_is_capped_at_100():
    raw = build_message(
        from_header='"PayPal Security" <billing@secure-verify.xyz>',
        subject="URGENT: verify your account - payment overdue",
        extra_headers="Reply-To: attacker@elsewhere.test",
        body="Immediate action required. Wire transfer payment, confidential.\n",
    )
    result = assess(
        parse_eml(raw),
        _report(spf="fail", dkim="fail", dmarc="fail", disposition="reject"),
    )

    assert result.score == 100
    assert result.level == "Malicious"
