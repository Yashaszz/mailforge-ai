"""Layer 1 risk scoring: turn authentication facts into an analyst verdict.

The architecture calls for the SMTP gateway to classify every message as
Allow / Suspicious / High-Risk / Malicious. This module does that from the
signals Layer 1 already has -- authentication outcomes, identity mismatches
and relay-path anomalies.

It is deliberately **rule-based and fully explainable**: every point added to
the score comes with a human-readable reason, so an analyst can see exactly
why a message was flagged. The Phase 1 step 4 ML classifier will contribute an
additional content-based signal that gets folded in here alongside these rules,
rather than replacing them -- authentication failures are hard evidence and
should not be washed out by a probabilistic content score.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import timedelta

from .email_auth import AuthReport
from .network_intel import NetworkIntel
from .eml_parser import ParsedEmail, is_public_ip

__all__ = ["RiskAssessment", "RiskReason", "assess"]

# Score thresholds for each verdict band.
MALICIOUS_AT = 70
HIGH_RISK_AT = 45
SUSPICIOUS_AT = 20

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Brands most often impersonated in Indian phishing and BEC campaigns. Used
# only to detect a display name claiming a brand the sending domain does not
# own -- never as a blocklist.
IMPERSONATED_BRANDS = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "office365": "microsoft.com",
    "google": "google.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "sbi": "sbi.co.in",
    "hdfc": "hdfcbank.com",
    "icici": "icicibank.com",
    "axis": "axisbank.com",
    "income tax": "incometax.gov.in",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "linkedin": "linkedin.com",
    "whatsapp": "whatsapp.com",
}

# Language typical of payment-fraud and credential-harvesting lures. This is a
# deliberately small placeholder for the Layer 2 NLP classifier.
URGENCY_PATTERNS = (
    r"\burgent\b", r"\bimmediate(?:ly)?\b", r"\baction required\b",
    r"\bverify your\b", r"\bconfirm your\b", r"\bsuspend(?:ed|ion)?\b",
    r"\blimited\b", r"\bwithin 24 hours\b", r"\bwire transfer\b",
    r"\bpayment\b", r"\bconfidential\b", r"\bdo not discuss\b",
    r"\bgift card\b", r"\bbank details\b", r"\boverdue\b",
)
_URGENCY_RE = re.compile("|".join(URGENCY_PATTERNS), re.IGNORECASE)

# Cheap TLDs disproportionately used for throwaway phishing infrastructure.
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "link", "gq", "cf", "ml", "tk",
    "work", "loan", "review", "country", "kim", "men", "rest",
}


@dataclass(slots=True)
class RiskReason:
    """One scored observation, shown verbatim in the dashboard."""

    code: str
    severity: str          # critical | high | medium | low | info
    points: int
    title: str
    detail: str


@dataclass(slots=True)
class RiskAssessment:
    score: int = 0
    level: str = "Allow"           # Allow | Suspicious | High-Risk | Malicious
    confidence: str = "medium"     # low | medium | high
    summary: str = ""
    reasons: list[RiskReason] = field(default_factory=list)


def assess(
    parsed: ParsedEmail,
    report: AuthReport,
    networks: dict[str, NetworkIntel] | None = None,
) -> RiskAssessment:
    """Score a message from its Layer 1 signals."""
    reasons: list[RiskReason] = []

    _score_dmarc(report, reasons)
    _score_spf(report, reasons)
    _score_dkim(report, reasons)
    _score_identity(parsed, report, reasons)
    _score_infrastructure(parsed, report, reasons)
    _score_content(parsed, reasons)
    _score_network(parsed, networks or {}, reasons)
    _score_relay_consistency(parsed, reasons)

    reasons.sort(key=lambda r: (SEVERITY_ORDER.get(r.severity, 9), -r.points))

    score = min(100, sum(r.points for r in reasons))
    level = _level_for(score)

    return RiskAssessment(
        score=score,
        level=level,
        confidence=_confidence(report),
        summary=_summary(level, reasons),
        reasons=reasons,
    )


def _level_for(score: int) -> str:
    if score >= MALICIOUS_AT:
        return "Malicious"
    if score >= HIGH_RISK_AT:
        return "High-Risk"
    if score >= SUSPICIOUS_AT:
        return "Suspicious"
    return "Allow"


def _confidence(report: AuthReport) -> str:
    """How much the verdict can be trusted, given what could be checked."""
    if not report.dns_available:
        return "low"
    if report.dmarc.result in ("pass", "fail"):
        return "high"
    return "medium"


def _summary(level: str, reasons: list[RiskReason]) -> str:
    if not reasons:
        return "Deliver. No Layer 1 risk indicators found."

    if level == "Allow":
        # Nothing here is worth leading with, so describe the outcome instead
        # of surfacing the highest-scoring nitpick as if it were a finding.
        return (
            "Deliver. The sender is authenticated and no significant risk "
            "indicators were found."
        )

    top = reasons[0].title
    return {
        "Malicious": f"Block. {top}",
        "High-Risk": f"Quarantine for analyst review. {top}",
        "Suspicious": f"Deliver with warning. {top}",
    }[level]


# --------------------------------------------------------------------------
# authentication signals
# --------------------------------------------------------------------------

def _score_dmarc(report: AuthReport, reasons: list[RiskReason]) -> None:
    dmarc = report.dmarc

    if dmarc.result == "fail":
        # A DMARC failure means no authenticated identity matched the From
        # header the recipient actually sees. This is the single strongest
        # spoofing signal available at Layer 1.
        policy = (dmarc.disposition or dmarc.policy or "none").lower()
        points, severity = {
            "reject": (45, "critical"),
            "quarantine": (38, "critical"),
        }.get(policy, (30, "high"))
        reasons.append(RiskReason(
            code="dmarc_fail",
            severity=severity,
            points=points,
            title="DMARC failed - sender identity is not authenticated",
            detail=(
                f"Neither SPF nor DKIM produced a domain aligned with the "
                f"visible From address. The domain publishes p={dmarc.policy}, "
                f"so its own owner asks receivers to {policy} mail like this."
            ),
        ))
    elif dmarc.result == "none":
        reasons.append(RiskReason(
            code="dmarc_none",
            severity="medium",
            points=18,
            title="Sender domain publishes no DMARC policy",
            detail=(
                "The domain cannot be protected from spoofing and offers no "
                "way to verify that this message is genuine. Throwaway domains "
                "registered for a single campaign typically look exactly like this."
            ),
        ))
    elif dmarc.result == "pass":
        reasons.append(RiskReason(
            code="dmarc_pass",
            severity="info",
            points=0,
            title="DMARC passed - the From address is authenticated",
            detail=(
                f"An aligned, passing identifier was found for "
                f"{dmarc.record_domain or 'the sender domain'}."
            ),
        ))
    elif dmarc.result == "temperror":
        reasons.append(RiskReason(
            code="dmarc_temperror",
            severity="low",
            points=5,
            title="DMARC could not be evaluated",
            detail="A temporary DNS failure prevented a conclusive result.",
        ))


def _score_spf(report: AuthReport, reasons: list[RiskReason]) -> None:
    spf = report.spf
    table = {
        "fail": (25, "high", "SPF failed - the sending server is not authorised",
                 "The domain's SPF record explicitly excludes the IP that sent this message."),
        "softfail": (15, "medium", "SPF soft-failed - the sending server is not listed",
                     "The domain does not authorise this IP, but asks receivers not to reject outright."),
        "neutral": (6, "low", "SPF is neutral about the sending server",
                    "The SPF record makes no assertion about this IP."),
        "none": (10, "medium", "Sender domain publishes no SPF record",
                 "There is no way to check whether this server was allowed to send for the domain."),
    }
    if spf.result in table:
        points, severity, title, detail = table[spf.result]
        reasons.append(RiskReason("spf_" + spf.result, severity, points, title, detail))
    elif spf.result == "pass":
        reasons.append(RiskReason(
            "spf_pass", "info", 0,
            "SPF passed - the sending server is authorised",
            f"{spf.client_ip} is authorised to send for {spf.domain}.",
        ))


def _score_dkim(report: AuthReport, reasons: list[RiskReason]) -> None:
    dkim = report.dkim
    if dkim.result == "fail":
        # If DMARC passed, an aligned identifier was still proven, so a broken
        # signature is far more likely a forwarder or a relay rewriting the
        # message than forgery.
        if report.dmarc.result == "pass":
            reasons.append(RiskReason(
                "dkim_fail_dmarc_pass", "low", 6,
                "DKIM signature did not verify",
                "The sender is still authenticated: DMARC passed on the other "
                "identifier. A broken signature alongside a passing DMARC "
                "usually means a mailing list or forwarder altered the message "
                "in transit.",
            ))
        else:
            reasons.append(RiskReason(
                "dkim_fail", "high", 22,
                "DKIM signature did not verify",
                "The message was altered after signing, or the signature was "
                "forged, and no other identifier authenticates the sender.",
            ))
    elif dkim.result == "none":
        reasons.append(RiskReason(
            "dkim_none", "low", 8,
            "Message is not DKIM signed",
            "Most legitimate bulk and corporate senders sign their mail.",
        ))
    elif dkim.result == "pass":
        reasons.append(RiskReason(
            "dkim_pass", "info", 0,
            "DKIM signature verified",
            f"Cryptographically signed by {', '.join(dkim.passing_domains)}.",
        ))


# --------------------------------------------------------------------------
# identity signals
# --------------------------------------------------------------------------

def _score_identity(
    parsed: ParsedEmail, report: AuthReport, reasons: list[RiskReason]
) -> None:
    from_domain = parsed.from_domain

    # A passing DMARC means the domain owner authorised this send and the
    # visible From is authenticated. Routing details that look alarming on an
    # unauthenticated message -- a different Reply-To, a bounce domain that is
    # not the From domain -- are simply how every email service provider
    # operates, so on authenticated mail they are reported but barely scored.
    # Without that distinction the tool flags ordinary newsletters, which
    # costs far more credibility than the rare case it would catch.
    authenticated = report.dmarc.result == "pass"

    if parsed.reply_to_domain and from_domain and parsed.reply_to_domain != from_domain:
        if authenticated:
            reasons.append(RiskReason(
                "reply_to_mismatch_authenticated", "info", 0,
                "Reply-To points to a different domain than From",
                f"Replies go to {parsed.reply_to_address}. The sending domain "
                f"passed DMARC, and routing replies to a separate address is "
                f"normal for bulk and support mail, so this is not scored.",
            ))
        else:
            reasons.append(RiskReason(
                "reply_to_mismatch", "high", 20,
                "Reply-To points to a different domain than From",
                f"Replies go to {parsed.reply_to_address} rather than "
                f"{parsed.from_address}. This redirects the conversation to an "
                f"address the sender controls - the core mechanic of business "
                f"email compromise - and the sender is not authenticated.",
            ))

    # Envelope sender different from the visible From.
    if (parsed.envelope_from_domain and from_domain
            and parsed.envelope_from_domain != from_domain
            and parsed.return_path):
        if authenticated:
            reasons.append(RiskReason(
                "envelope_mismatch_authenticated", "info", 0,
                "Bounces return to a different domain than From",
                f"Mail was sent as {parsed.envelope_from}. Separate bounce "
                f"domains are standard for email service providers, and DMARC "
                f"passed, so this is not scored.",
            ))
        else:
            reasons.append(RiskReason(
                "envelope_mismatch", "medium", 10,
                "Envelope sender does not match the visible From address",
                f"Mail was sent as {parsed.envelope_from} but displays as "
                f"{parsed.from_address}, and the sender is not authenticated.",
            ))

    # Display name claiming a brand the domain does not own.
    display = (parsed.from_display_name or "").lower()
    if display and from_domain:
        for brand, brand_domain in IMPERSONATED_BRANDS.items():
            if brand in display and not from_domain.endswith(brand_domain):
                reasons.append(RiskReason(
                    "brand_impersonation", "high", 22,
                    f"Display name claims to be {brand.title()}",
                    f'The message shows "{parsed.from_display_name}" but was sent '
                    f"from {from_domain}, which is not operated by {brand.title()}. "
                    f"Most mail clients show only the display name.",
                ))
                break

    # An address embedded in the display name that differs from the real one.
    embedded = re.search(r"[\w.+-]+@[\w.-]+\.\w+", parsed.from_display_name or "")
    if embedded and embedded.group(0).lower() != (parsed.from_address or ""):
        reasons.append(RiskReason(
            "display_name_spoof", "high", 20,
            "Display name contains a different email address",
            f"The name shows {embedded.group(0)} but the message was actually "
            f"sent from {parsed.from_address}.",
        ))


# --------------------------------------------------------------------------
# infrastructure signals
# --------------------------------------------------------------------------

def _score_infrastructure(
    parsed: ParsedEmail, report: AuthReport, reasons: list[RiskReason]
) -> None:
    domain = parsed.from_domain or ""
    tld = domain.rsplit(".", 1)[-1] if "." in domain else ""

    if tld in SUSPICIOUS_TLDS:
        reasons.append(RiskReason(
            "suspicious_tld", "medium", 12,
            f"Sender uses a .{tld} domain",
            f".{tld} is disproportionately used for short-lived phishing "
            f"infrastructure because registration is cheap and unverified.",
        ))

    if parsed.client_ip and not is_public_ip(parsed.client_ip):
        reasons.append(RiskReason(
            "non_public_origin", "low", 5,
            "Originating IP is not a public address",
            f"{parsed.client_ip} is private or reserved, so the true origin "
            f"could not be established from the headers.",
        ))

    if not parsed.received_chain:
        reasons.append(RiskReason(
            "no_relay_path", "medium", 12,
            "Message carries no Received headers",
            "The relay path is missing entirely, so the message cannot be traced. "
            "Legitimate delivered mail always accumulates at least one hop.",
        ))

    # A HELO name unrelated to the sending domain is a weak signal, and only
    # meaningful when the identity is otherwise unproven. Large providers
    # legitimately relay mail for one domain from servers named under another
    # (gmail.com mail leaves google.com hosts), so a passing DMARC settles it.
    if parsed.helo and parsed.from_domain and report.dmarc.result != "pass":
        helo = parsed.helo.lower()
        if (parsed.from_domain not in helo
                and helo.split(".")[-2:] != parsed.from_domain.split(".")[-2:]):
            reasons.append(RiskReason(
                "helo_mismatch", "low", 6,
                "Sending server identifies itself under an unrelated name",
                f"The server announced itself as {parsed.helo}, which is "
                f"unrelated to {parsed.from_domain}.",
            ))


# --------------------------------------------------------------------------
# content signals (placeholder for the Layer 2 classifier)
# --------------------------------------------------------------------------

def _score_content(parsed: ParsedEmail, reasons: list[RiskReason]) -> None:
    subject = parsed.subject or ""
    matches = {m.group(0).lower() for m in _URGENCY_RE.finditer(subject)}

    body = _body_text(parsed)
    matches |= {m.group(0).lower() for m in _URGENCY_RE.finditer(body)}

    if len(matches) >= 2:
        reasons.append(RiskReason(
            "urgency_language", "medium", 12,
            "Message uses pressure and urgency language",
            "Detected: " + ", ".join(sorted(matches)[:6])
            + ". Manufactured time pressure is used to stop the recipient "
              "verifying the request through another channel.",
        ))
    elif matches:
        reasons.append(RiskReason(
            "urgency_language_weak", "low", 5,
            "Message contains pressure language",
            "Detected: " + ", ".join(sorted(matches)),
        ))


def _body_text(parsed: ParsedEmail, limit: int = 20000) -> str:
    """Best-effort plain-text extraction, used only for keyword scanning."""
    try:
        part = parsed.message.get_body(preferencelist=("plain", "html"))
        if part is None:
            return ""
        return str(part.get_content())[:limit]
    except Exception:
        try:
            return parsed.raw.decode("utf-8", "replace")[:limit]
        except Exception:
            return ""


# --------------------------------------------------------------------------
# network reputation of the sending infrastructure
# --------------------------------------------------------------------------

def _score_network(
    parsed: ParsedEmail, networks: dict[str, NetworkIntel], reasons: list[RiskReason]
) -> None:
    """Score what kind of network the mail was actually sent from.

    Using a VPN is ordinary and not suspicious in itself. A *mail server*
    behind one is not ordinary: legitimate senders publish a stable, traceable
    sending address so that receivers can authenticate them. Anonymising the
    origin defeats the entire point.
    """
    origin = networks.get(parsed.client_ip or "")
    if origin and origin.checked and origin.is_anonymising:
        kind = (origin.kind or "proxy").upper()
        points, severity = (28, "high") if kind == "TOR" else (18, "medium")
        reasons.append(RiskReason(
            code=f"origin_{kind.lower()}",
            severity=severity,
            points=points,
            title=f"Message was sent from {'a Tor exit node' if kind == 'TOR' else 'a VPN or proxy'}",
            detail=origin.detail,
        ))

    # Transit through anonymising infrastructure, excluding the origin itself
    # so a single hop is not counted twice.
    transit = [
        n for ip, n in networks.items()
        if ip != parsed.client_ip and n.checked and n.is_anonymising
    ]
    if transit:
        kinds = ", ".join(sorted({(n.kind or "proxy").upper() for n in transit}))
        reasons.append(RiskReason(
            code="relay_anonymised",
            severity="medium",
            points=min(8 * len(transit), 20),
            title=f"Relay path passes through anonymising infrastructure ({kinds})",
            detail=(
                f"{len(transit)} intermediate hop(s) are VPN, proxy or Tor nodes. "
                f"Chaining relays through anonymising networks is done to break the "
                f"trail between the sender and the recipient."
            ),
        ))


# --------------------------------------------------------------------------
# relay-chain consistency
# --------------------------------------------------------------------------

#: Server clocks genuinely disagree. Only treat a backwards jump larger than
#: this as evidence of tampering rather than ordinary skew.
#:
#: Chosen on the development split of the SpamAssassin + Nazario evaluation,
#: never on its test split. The original 10 minutes flagged 9.6% of
#: legitimate 2002 mail, overwhelmingly real clock skew (median 17 minutes);
#: 30 minutes cuts that to 1.6% while keeping almost all of the detections on
#: 2005-07 phishing (19.5% -> 17.7%). See eval/results/REPORT.md.
CLOCK_SKEW_TOLERANCE = timedelta(minutes=30)


def _score_relay_consistency(parsed: ParsedEmail, reasons: list[RiskReason]) -> None:
    """Look for a forged relay path.

    Each ``Received`` header is prepended by the server that handled the
    message, so reading top to bottom the timestamps must run backwards in
    time. An attacker fabricating hops to invent a respectable origin has to
    guess plausible times for headers they never actually generated, and
    getting that ordering right is easy to overlook.

    A hop that claims to have received the message *before* the hop beneath it
    sent it is therefore physically impossible, and is strong evidence that
    part of the chain was written by the sender rather than by a relay.
    """
    hops = parsed.received_chain
    # Only timezone-aware stamps can be ordered. A `-0000` offset (RFC 5322:
    # "local zone unknown") or a missing one parses naive, and treating it as
    # UTC could misplace it by hours and raise a false forgery alarm, so those
    # hops are left out of the comparison. Skipping a hop is safe: the
    # ordering must hold across non-adjacent hops too.
    timed = [h for h in hops if h.timestamp is not None and h.timestamp.tzinfo is not None]
    if len(timed) < 2:
        return

    violations: list[str] = []
    for newer, older in zip(timed, timed[1:]):
        # `newer` was added after `older`, so its timestamp cannot be earlier.
        drift = older.timestamp - newer.timestamp
        if drift > CLOCK_SKEW_TOLERANCE:
            violations.append(
                f"hop {newer.index} ({newer.by_host or 'unknown'}) records "
                f"{newer.timestamp:%H:%M:%S}, which is "
                f"{_humanise(drift)} before hop {older.index} "
                f"({older.by_host or 'unknown'}) at {older.timestamp:%H:%M:%S}"
            )

    if violations:
        reasons.append(RiskReason(
            code="relay_timestamps_impossible",
            severity="high",
            points=24,
            title="Relay timestamps are physically impossible",
            detail=(
                "A server recorded receiving this message before the server "
                "below it in the chain sent it: " + "; ".join(violations[:2])
                + ". Relays stamp their own time as they prepend each header, "
                "so this ordering cannot occur naturally and indicates part of "
                "the path was fabricated to disguise the true origin."
            ),
        ))


def _humanise(delta: timedelta) -> str:
    seconds = int(abs(delta.total_seconds()))
    if seconds < 90:
        return f"{seconds} seconds"
    if seconds < 5400:
        return f"{seconds // 60} minutes"
    if seconds < 172800:
        return f"{seconds // 3600} hours"
    return f"{seconds // 86400} days"
