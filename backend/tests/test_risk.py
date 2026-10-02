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


def _reply_to_message() -> bytes:
    return build_message(
        extra_headers=(
            "Reply-To: attacker@elsewhere.test\n"
            "Received: from mail.example-sender.test (mail [45.33.32.9])\n"
            "\tby mx01.recipient.test with ESMTP id AAA111;"
            " Tue, 9 Sep 2026 14:22:29 +0530"
        )
    )


def test_reply_to_mismatch_is_scored_when_the_sender_is_not_authenticated():
    result = assess(
        parse_eml(_reply_to_message()),
        _report(spf="fail", dkim="none", dmarc="fail"),
    )

    reason = next(r for r in result.reasons if r.code == "reply_to_mismatch")
    assert reason.severity == "high"
    assert reason.points > 0


def test_reply_to_mismatch_is_not_scored_when_dmarc_passes():
    """Every email service provider routes replies elsewhere. Scoring that on
    authenticated mail flags ordinary newsletters as dangerous."""
    result = assess(parse_eml(_reply_to_message()), _report())

    codes = {r.code for r in result.reasons}
    assert "reply_to_mismatch" not in codes

    reason = next(r for r in result.reasons if r.code == "reply_to_mismatch_authenticated")
    assert reason.points == 0
    assert result.level == "Allow"


def test_dkim_failure_is_damped_when_dmarc_still_passes():
    """A forwarder breaking a signature is not the same as forgery."""
    passing = assess(parse_eml(_reply_to_message()), _report(dkim="fail"))
    failing = assess(parse_eml(_reply_to_message()),
                     _report(dkim="fail", spf="fail", dmarc="fail"))

    damped = next(r for r in passing.reasons if r.code == "dkim_fail_dmarc_pass")
    full = next(r for r in failing.reasons if r.code == "dkim_fail")
    assert damped.points < full.points
    assert passing.score < failing.score


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


# --------------------------------------------------------------------------
# relay-chain consistency
# --------------------------------------------------------------------------

def _chain(*hops: str) -> bytes:
    """Build a message whose Received headers are given newest-first."""
    return build_message(extra_headers="\n".join(hops))


def test_forged_relay_timestamps_are_detected():
    """A hop cannot receive a message before the hop below it sent it."""
    raw = _chain(
        # Newest hop claims 09:00 ...
        "Received: from relay.test (relay.test [45.33.32.9])\n"
        "\tby mx01.recipient.test with ESMTP id BBB222;"
        " Tue, 9 Sep 2026 09:00:00 +0000",
        # ... but the hop beneath it only sent at 11:00.
        "Received: from origin.test (origin.test [91.198.174.192])\n"
        "\tby relay.test with ESMTP id AAA111;"
        " Tue, 9 Sep 2026 11:00:00 +0000",
    )
    result = assess(parse_eml(raw), _report(dmarc="none", policy=None))

    reason = next(r for r in result.reasons if r.code == "relay_timestamps_impossible")
    assert reason.severity == "high"
    assert "2 hours" in reason.detail


def test_a_normal_chain_is_not_flagged():
    raw = _chain(
        "Received: from relay.test (relay.test [45.33.32.9])\n"
        "\tby mx01.recipient.test with ESMTP id BBB222;"
        " Tue, 9 Sep 2026 11:00:30 +0000",
        "Received: from origin.test (origin.test [91.198.174.192])\n"
        "\tby relay.test with ESMTP id AAA111;"
        " Tue, 9 Sep 2026 11:00:00 +0000",
    )
    codes = {r.code for r in assess(parse_eml(raw), _report()).reasons}
    assert "relay_timestamps_impossible" not in codes


def test_ordinary_clock_skew_is_tolerated():
    """Server clocks disagree by minutes all the time; that is not forgery."""
    raw = _chain(
        "Received: from relay.test (relay.test [45.33.32.9])\n"
        "\tby mx01.recipient.test with ESMTP id BBB222;"
        " Tue, 9 Sep 2026 10:58:00 +0000",
        "Received: from origin.test (origin.test [91.198.174.192])\n"
        "\tby relay.test with ESMTP id AAA111;"
        " Tue, 9 Sep 2026 11:00:00 +0000",
    )
    codes = {r.code for r in assess(parse_eml(raw), _report()).reasons}
    assert "relay_timestamps_impossible" not in codes


def test_timezones_are_compared_correctly_not_wall_clock():
    """+0530 and +0000 wall times look reversed but are consistent."""
    raw = _chain(
        "Received: from relay.test (relay.test [45.33.32.9])\n"
        "\tby mx01.recipient.test with ESMTP id BBB222;"
        " Tue, 9 Sep 2026 16:31:00 +0530",       # 11:01 UTC
        "Received: from origin.test (origin.test [91.198.174.192])\n"
        "\tby relay.test with ESMTP id AAA111;"
        " Tue, 9 Sep 2026 11:00:00 +0000",       # 11:00 UTC
    )
    codes = {r.code for r in assess(parse_eml(raw), _report()).reasons}
    assert "relay_timestamps_impossible" not in codes


def test_undated_hops_do_not_trigger_a_false_positive():
    raw = _chain(
        "Received: from relay.test (relay.test [45.33.32.9]) by mx01.recipient.test",
        "Received: from origin.test (origin.test [91.198.174.192])\n"
        "\tby relay.test with ESMTP id AAA111;"
        " Tue, 9 Sep 2026 11:00:00 +0000",
    )
    codes = {r.code for r in assess(parse_eml(raw), _report()).reasons}
    assert "relay_timestamps_impossible" not in codes


def test_unknown_timezone_stamps_do_not_crash_or_false_alarm():
    """Regression: a `-0000` stamp parses naive and used to raise TypeError,
    crashing the whole analysis. Found by the SpamAssassin corpus run, where it
    hit about one legitimate message in five."""
    raw = _chain(
        "Received: from relay.test (relay.test [45.33.32.9])\n"
        "\tby mx01.recipient.test with ESMTP id BBB222;"
        " Tue, 9 Sep 2026 09:00:00 -0000",
        "Received: from origin.test (origin.test [91.198.174.192])\n"
        "\tby relay.test with ESMTP id AAA111;"
        " Tue, 9 Sep 2026 11:00:00 +0000",
    )
    result = assess(parse_eml(raw), _report(dmarc="none", policy=None))
    codes = {r.code for r in result.reasons}
    assert "relay_timestamps_impossible" not in codes


def test_aware_hops_are_still_compared_across_an_unknown_one():
    """Skipping a naive hop must not hide a forgery between the hops around it."""
    raw = _chain(
        "Received: from a.test (a.test [45.33.32.9]) by mx.test with ESMTP id C;"
        " Tue, 9 Sep 2026 09:00:00 +0000",
        "Received: from b.test (b.test [45.33.32.10]) by a.test with ESMTP id B;"
        " Tue, 9 Sep 2026 10:00:00 -0000",
        "Received: from c.test (c.test [91.198.174.192]) by b.test with ESMTP id A;"
        " Tue, 9 Sep 2026 11:00:00 +0000",
    )
    codes = {r.code for r in assess(parse_eml(raw), _report(dmarc="none", policy=None)).reasons}
    assert "relay_timestamps_impossible" in codes
