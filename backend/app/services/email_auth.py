"""Layer 1 email authentication: SPF, DKIM and DMARC.

Why these libraries
-------------------
``checkdmarc`` answers "does this *domain* publish a sane SPF/DMARC record?",
which is domain-hygiene reporting.  Mailforge needs a different question
answered: "did *this message* pass?"  That requires evaluating the message
against the sending IP and verifying a real signature, so this module composes
the three reference implementations instead:

* **SPF**  -- ``pyspf`` (RFC 7208), evaluated against the client IP recovered
  from the ``Received`` chain.
* **DKIM** -- ``dkimpy`` (RFC 6376), real cryptographic verification against
  the public key in DNS.  No crypto is hand-rolled here.
* **DMARC** -- the policy record is fetched with ``dnspython`` and the
  identifier-alignment rules of RFC 7489 s3.1 are applied on top of the SPF
  and DKIM outcomes above.  Alignment is a domain comparison, not a protocol
  or crypto operation, so implementing it directly is safe and keeps the
  dependency footprint small.

Every check degrades gracefully: DNS failures become ``temperror`` and never
raise, because an analyst tool has to produce a verdict even on bad wifi.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from typing import Callable, Literal

import dns.exception
import dns.resolver
import spf
from publicsuffixlist import PublicSuffixList

import dkim

from .eml_parser import ParsedEmail

logger = logging.getLogger(__name__)

AuthVerdict = Literal[
    "pass",
    "fail",
    "softfail",
    "neutral",
    "none",
    "temperror",
    "permerror",
    "not_checked",
]

DEFAULT_DNS_TIMEOUT = 6.0
DEFAULT_SPF_QUERYTIME = 20.0

_psl = PublicSuffixList()

_TAG_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9_]*)\s*=\s*([^;]*)")

_resolver: dns.resolver.Resolver | None = None


# --------------------------------------------------------------------------
# DNS plumbing
# --------------------------------------------------------------------------

def configure_dns(
    servers: list[str] | None = None,
    *,
    query_timeout: float = 2.5,
    lifetime: float = DEFAULT_DNS_TIMEOUT,
) -> dns.resolver.Resolver:
    """Build the resolver every check will use, and install it globally.

    ``pyspf`` calls ``dns.resolver.query`` and ``dkimpy`` calls
    ``dns.resolver.resolve``; neither accepts a resolver argument, and both
    module-level helpers read ``dns.resolver.default_resolver``. Assigning that
    global is therefore the only way to point all three checks at the same
    servers.

    Note this is *not* ``dns.resolver.override_system_resolver()``: that patches
    ``socket.getaddrinfo`` process-wide, which would route uvicorn's own
    networking through dnspython as a side effect. We only want to redirect
    the explicit DNS queries the auth checks make.
    """
    global _resolver

    try:
        resolver = dns.resolver.Resolver(configure=True)
    except Exception as exc:
        # Serverless images do not always ship a usable /etc/resolv.conf, and
        # dnspython raises rather than falling back. We always set explicit
        # nameservers below, so an unconfigured resolver is fine.
        logger.warning("System resolver unavailable (%s); using explicit servers.", exc)
        resolver = dns.resolver.Resolver(configure=False)

    if servers:
        resolver.nameservers = list(servers)
    if not resolver.nameservers:
        resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    resolver.timeout = query_timeout
    resolver.lifetime = lifetime

    dns.resolver.default_resolver = resolver
    _resolver = resolver
    logger.info("DNS resolver configured: %s", resolver.nameservers)
    return resolver


def get_resolver() -> dns.resolver.Resolver:
    return _resolver or dns.resolver.get_default_resolver()


# --------------------------------------------------------------------------
# result containers
# --------------------------------------------------------------------------

@dataclass(slots=True)
class SpfResult:
    result: AuthVerdict = "not_checked"
    detail: str = ""
    client_ip: str | None = None
    mail_from: str | None = None
    helo: str | None = None
    domain: str | None = None          # identity SPF authenticated
    record: str | None = None


@dataclass(slots=True)
class DkimSignature:
    index: int
    domain: str | None = None          # d=
    selector: str | None = None        # s=
    algorithm: str | None = None       # a=
    result: AuthVerdict = "not_checked"
    detail: str = ""


@dataclass(slots=True)
class DkimResult:
    result: AuthVerdict = "not_checked"
    detail: str = ""
    signatures: list[DkimSignature] = field(default_factory=list)

    @property
    def passing_domains(self) -> list[str]:
        return [s.domain for s in self.signatures if s.result == "pass" and s.domain]


@dataclass(slots=True)
class DmarcResult:
    result: AuthVerdict = "not_checked"
    detail: str = ""
    record: str | None = None
    record_domain: str | None = None   # where the record was found
    policy: str | None = None          # p=
    subdomain_policy: str | None = None  # sp=
    pct: int | None = None
    spf_alignment: str = "not_checked"   # pass | fail | not_checked
    dkim_alignment: str = "not_checked"
    alignment_mode_spf: str = "r"
    alignment_mode_dkim: str = "r"
    disposition: str | None = None     # none | quarantine | reject


@dataclass(slots=True)
class AuthReport:
    spf: SpfResult = field(default_factory=SpfResult)
    dkim: DkimResult = field(default_factory=DkimResult)
    dmarc: DmarcResult = field(default_factory=DmarcResult)
    dns_available: bool = True
    notes: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# public entry point
# --------------------------------------------------------------------------

def authenticate(
    parsed: ParsedEmail,
    *,
    offline: bool = False,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    spf_querytime: float = DEFAULT_SPF_QUERYTIME,
    dkim_dnsfunc: Callable[..., bytes] | None = None,
    resolver: dns.resolver.Resolver | None = None,
) -> AuthReport:
    """Run all three Layer 1 checks over an already-parsed message.

    ``offline`` skips every DNS lookup and reports ``not_checked`` throughout,
    which keeps the demo usable without a network.  ``dkim_dnsfunc`` and
    ``resolver`` exist so tests can serve DNS answers deterministically.
    """
    report = AuthReport()

    if offline:
        note = "Offline mode: DNS lookups disabled, no authentication performed."
        report.dns_available = False
        report.notes.append(note)
        report.spf.detail = report.dkim.detail = report.dmarc.detail = note
        return report

    report.spf = check_spf(
        client_ip=parsed.client_ip,
        mail_from=parsed.envelope_from,
        helo=parsed.helo,
        timeout=timeout,
        querytime=spf_querytime,
    )
    report.dkim = check_dkim(parsed, dnsfunc=dkim_dnsfunc, timeout=timeout)
    report.dmarc = check_dmarc(
        from_domain=parsed.from_domain,
        spf=report.spf,
        dkim=report.dkim,
        timeout=timeout,
        resolver=resolver,
    )

    if "temperror" in (report.spf.result, report.dmarc.result, report.dkim.result):
        report.dns_available = False
        report.notes.append(
            "At least one check hit a DNS temporary error; results may be incomplete."
        )

    return report


# --------------------------------------------------------------------------
# SPF
# --------------------------------------------------------------------------

def check_spf(
    *,
    client_ip: str | None,
    mail_from: str | None,
    helo: str | None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    querytime: float = DEFAULT_SPF_QUERYTIME,
) -> SpfResult:
    """Evaluate RFC 7208 SPF for the reconstructed SMTP envelope."""
    result = SpfResult(client_ip=client_ip, mail_from=mail_from, helo=helo)

    if not client_ip:
        result.result = "not_checked"
        result.detail = (
            "No client IP could be recovered from the Received chain, so there "
            "is no address to evaluate SPF against."
        )
        return result

    try:
        ipaddress.ip_address(client_ip)
    except ValueError:
        result.result = "permerror"
        result.detail = f"Client IP {client_ip!r} is not a valid IP address."
        return result

    # With a null sender (bounces) SPF falls back to checking the HELO identity.
    sender = mail_from or ""
    helo_name = helo or (sender.rsplit("@", 1)[1] if "@" in sender else "unknown")
    result.helo = helo_name
    result.domain = sender.rsplit("@", 1)[1] if "@" in sender else helo_name

    if not sender and not helo:
        result.result = "none"
        result.detail = "Neither MAIL FROM nor HELO identity available."
        return result

    try:
        verdict, explanation = spf.check2(
            i=client_ip,
            s=sender,
            h=helo_name,
            timeout=int(timeout),
            querytime=int(querytime),
        )
    except spf.AmbiguityWarning as exc:
        result.result = "permerror"
        result.detail = f"Ambiguous SPF record: {exc}"
        return result
    except (dns.exception.DNSException, OSError) as exc:
        result.result = "temperror"
        result.detail = f"DNS failure during SPF evaluation: {exc}"
        return result
    except Exception as exc:  # pyspf raises assorted bare exceptions
        logger.warning("SPF evaluation failed", exc_info=True)
        result.result = "temperror"
        result.detail = f"SPF evaluation error: {type(exc).__name__}: {exc}"
        return result

    result.result = _normalise_verdict(verdict)
    result.record = _lookup_spf_record(result.domain, timeout)
    result.detail = explanation or _DEFAULT_SPF_DETAIL.get(result.result, "")
    if result.result == "none" and not result.record:
        result.detail = f"{result.domain} publishes no SPF record."
    return result


_DEFAULT_SPF_DETAIL: dict[str, str] = {
    "pass": "The sending IP is authorised by the domain's SPF record.",
    "fail": "The sending IP is explicitly not authorised by the SPF record.",
    "softfail": "The SPF record marks the sending IP as probably unauthorised.",
    "neutral": "The SPF record makes no assertion about the sending IP.",
    "none": "No applicable SPF record was found.",
    "temperror": "A temporary DNS error prevented SPF evaluation.",
    "permerror": "The SPF record is malformed or could not be evaluated.",
}


def _lookup_spf_record(domain: str | None, timeout: float) -> str | None:
    """Fetch the raw SPF TXT record, purely so the dashboard can display it."""
    if not domain:
        return None
    for txt in _txt_records(domain, timeout):
        if txt.lower().startswith("v=spf1"):
            return txt
    return None


# --------------------------------------------------------------------------
# DKIM
# --------------------------------------------------------------------------

def check_dkim(
    parsed: ParsedEmail,
    *,
    dnsfunc: Callable[..., bytes] | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
) -> DkimResult:
    """Cryptographically verify every ``DKIM-Signature`` on the message."""
    result = DkimResult()

    raw_signatures = [
        value for name, value in parsed.all_headers
        if name.lower() == "dkim-signature"
    ]

    if not raw_signatures:
        result.result = "none"
        result.detail = "Message carries no DKIM-Signature header."
        return result

    resolve = dnsfunc or _make_dkim_dnsfunc(timeout)

    try:
        verifier = dkim.DKIM(parsed.raw)
    except Exception as exc:
        result.result = "permerror"
        result.detail = f"Could not initialise DKIM verifier: {exc}"
        return result

    for index, raw_signature in enumerate(raw_signatures):
        tags = _parse_tag_value(raw_signature)
        signature = DkimSignature(
            index=index,
            domain=(tags.get("d") or "").lower() or None,
            selector=tags.get("s") or None,
            algorithm=tags.get("a") or None,
        )
        try:
            verified = verifier.verify(index, dnsfunc=resolve)
        except dkim.ValidationError as exc:
            # The signature was well-formed but did not validate -- i.e. the
            # message was altered in transit. RFC 8601 calls that `fail`, not
            # `permerror`, which is reserved for unusable signatures and keys.
            signature.result = "fail"
            signature.detail = f"Signature did not validate: {exc}"
        except dkim.DKIMException as exc:
            signature.result = "permerror"
            signature.detail = f"{type(exc).__name__}: {exc}"
        except (dns.exception.DNSException, OSError) as exc:
            signature.result = "temperror"
            signature.detail = f"DNS failure fetching the public key: {exc}"
        except Exception as exc:
            logger.warning("DKIM verification raised", exc_info=True)
            signature.result = "temperror"
            signature.detail = f"{type(exc).__name__}: {exc}"
        else:
            signature.result = "pass" if verified else "fail"
            signature.detail = (
                f"Signature by {signature.domain} verified."
                if verified
                else f"Signature by {signature.domain} did not verify "
                     "(body or headers altered, or key mismatch)."
            )
        result.signatures.append(signature)

    # A message is DKIM-authenticated if *any* signature verifies.
    verdicts = {s.result for s in result.signatures}
    if "pass" in verdicts:
        result.result = "pass"
        result.detail = (
            f"{sum(s.result == 'pass' for s in result.signatures)} of "
            f"{len(result.signatures)} signature(s) verified "
            f"({', '.join(result.passing_domains)})."
        )
    elif verdicts == {"temperror"}:
        result.result = "temperror"
        result.detail = "Could not retrieve any DKIM public key from DNS."
    elif "fail" in verdicts:
        result.result = "fail"
        result.detail = "No DKIM signature verified."
    else:
        result.result = "permerror"
        result.detail = "Every DKIM signature was malformed or unverifiable."

    return result


def _make_dkim_dnsfunc(timeout: float) -> Callable[..., bytes]:
    """Wrap dkimpy's resolver with our timeout, tolerating either call style."""
    from dkim.dnsplug import get_txt

    def resolve(name, timeout=timeout, **_kwargs):  # noqa: A002 - dkimpy's name
        return get_txt(name, timeout=timeout)

    return resolve


# --------------------------------------------------------------------------
# DMARC
# --------------------------------------------------------------------------

def check_dmarc(
    *,
    from_domain: str | None,
    spf: SpfResult,
    dkim: DkimResult,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    resolver: dns.resolver.Resolver | None = None,
) -> DmarcResult:
    """Apply RFC 7489 policy discovery and identifier alignment."""
    result = DmarcResult()

    if not from_domain:
        result.result = "none"
        result.detail = "No RFC 5322 From domain to evaluate DMARC against."
        return result

    record, record_domain, lookup_error = _find_dmarc_record(
        from_domain, timeout, resolver
    )

    if lookup_error:
        result.result = "temperror"
        result.detail = lookup_error
        return result

    if not record:
        result.result = "none"
        result.detail = (
            f"No DMARC record published for {from_domain} or its organizational "
            f"domain ({_org_domain(from_domain)})."
        )
        return result

    result.record = record
    result.record_domain = record_domain

    tags = _parse_tag_value(record)
    result.policy = (tags.get("p") or "none").lower()
    result.subdomain_policy = (tags.get("sp") or "").lower() or None
    result.alignment_mode_spf = (tags.get("aspf") or "r").lower()
    result.alignment_mode_dkim = (tags.get("adkim") or "r").lower()
    try:
        result.pct = int(tags["pct"]) if "pct" in tags else 100
    except (TypeError, ValueError):
        result.pct = 100

    # --- identifier alignment (RFC 7489 s3.1) ---------------------------
    result.spf_alignment = _spf_alignment(spf, from_domain, result.alignment_mode_spf)
    result.dkim_alignment = _dkim_alignment(
        dkim, from_domain, result.alignment_mode_dkim
    )

    if result.spf_alignment == "pass" or result.dkim_alignment == "pass":
        result.result = "pass"
        aligned = [
            name
            for name, state in (
                ("SPF", result.spf_alignment),
                ("DKIM", result.dkim_alignment),
            )
            if state == "pass"
        ]
        result.detail = f"Aligned and passing: {' and '.join(aligned)}."
        result.disposition = "none"
        return result

    # Neither identifier aligned-and-passed. A DNS temporary error on the way
    # is not a DMARC failure -- it is an inconclusive result.
    if "temperror" in (spf.result, dkim.result):
        result.result = "temperror"
        result.detail = (
            "Neither identifier could be confirmed because an underlying "
            "check hit a DNS temporary error."
        )
        return result

    result.result = "fail"
    effective_policy = _effective_policy(
        from_domain, record_domain, result.policy, result.subdomain_policy
    )
    result.disposition = effective_policy
    result.detail = (
        f"Neither SPF nor DKIM produced an identifier aligned with {from_domain} "
        f"(SPF alignment: {result.spf_alignment}, DKIM alignment: "
        f"{result.dkim_alignment}). Published policy requests: {effective_policy}."
    )
    return result


def _effective_policy(
    from_domain: str, record_domain: str | None, policy: str, subdomain_policy: str | None
) -> str:
    """``sp`` applies when the record was inherited from the parent domain."""
    if record_domain and record_domain != from_domain and subdomain_policy:
        return subdomain_policy
    return policy or "none"


def _spf_alignment(spf: SpfResult, from_domain: str, mode: str) -> str:
    """``none`` means there was no authenticated identifier to align at all,
    as distinct from ``fail``, where one existed but pointed elsewhere."""
    if spf.result == "none":
        return "none"
    if spf.result in ("temperror", "permerror", "not_checked"):
        return "not_checked"
    if spf.result != "pass" or not spf.domain:
        return "fail"
    return "pass" if _is_aligned(spf.domain, from_domain, mode) else "fail"


def _dkim_alignment(dkim: DkimResult, from_domain: str, mode: str) -> str:
    if dkim.result == "none":
        return "none"
    if dkim.result in ("temperror", "not_checked"):
        return "not_checked"
    for domain in dkim.passing_domains:
        if _is_aligned(domain, from_domain, mode):
            return "pass"
    return "fail"


def _is_aligned(candidate: str, from_domain: str, mode: str) -> bool:
    """RFC 7489 s3.1: strict alignment is an exact match, relaxed compares
    organizational domains (so ``mail.example.com`` aligns with
    ``example.com``)."""
    candidate = candidate.lower().rstrip(".")
    from_domain = from_domain.lower().rstrip(".")
    if mode == "s":
        return candidate == from_domain
    return _org_domain(candidate) == _org_domain(from_domain)


def _org_domain(domain: str | None) -> str | None:
    if not domain:
        return None
    return _psl.privatesuffix(domain.lower().rstrip(".")) or domain.lower().rstrip(".")


def _find_dmarc_record(
    from_domain: str, timeout: float, resolver: dns.resolver.Resolver | None
) -> tuple[str | None, str | None, str | None]:
    """Look up ``_dmarc.<domain>``, then the organizational domain.

    Returns ``(record, domain_it_was_found_at, error_message)``.
    """
    org_domain = _org_domain(from_domain)
    candidates = [from_domain]
    if org_domain and org_domain != from_domain:
        candidates.append(org_domain)

    last_error: str | None = None
    for candidate in candidates:
        try:
            records = _txt_records(f"_dmarc.{candidate}", timeout, resolver, raise_temp=True)
        except _TempDnsError as exc:
            last_error = f"DNS temporary failure looking up _dmarc.{candidate}: {exc}"
            continue
        for txt in records:
            if txt.lower().replace(" ", "").startswith("v=dmarc1"):
                return txt, candidate, None

    return None, None, last_error


class _TempDnsError(Exception):
    """Internal marker for a retryable DNS condition."""


def _txt_records(
    name: str,
    timeout: float,
    resolver: dns.resolver.Resolver | None = None,
    *,
    raise_temp: bool = False,
) -> list[str]:
    """Fetch TXT records, joining the character-strings of each record."""
    resolver = resolver or get_resolver()
    try:
        answer = resolver.resolve(name, "TXT", lifetime=timeout)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.exception.DNSException, OSError) as exc:
        if raise_temp:
            raise _TempDnsError(str(exc) or type(exc).__name__) from exc
        return []

    records: list[str] = []
    for rdata in answer:
        try:
            records.append(b"".join(rdata.strings).decode("utf-8", "replace"))
        except Exception:  # pragma: no cover - malformed rdata
            records.append(str(rdata).strip('"'))
    return records


# --------------------------------------------------------------------------
# shared helpers
# --------------------------------------------------------------------------

def _parse_tag_value(text: str) -> dict[str, str]:
    """Parse a ``k=v; k=v`` list (DKIM-Signature body, DMARC record, ...).

    This is plain tag parsing, not protocol logic: the crypto lives in dkimpy.
    """
    unfolded = " ".join(text.split())
    return {
        key.lower(): value.strip()
        for key, value in _TAG_RE.findall(unfolded)
    }


def _normalise_verdict(value: object) -> AuthVerdict:
    verdict = str(value).lower().strip()
    allowed = {
        "pass", "fail", "softfail", "neutral", "none", "temperror", "permerror",
    }
    if verdict in allowed:
        return verdict  # type: ignore[return-value]
    # pyspf can still emit the pre-RFC 4408 spellings.
    return {
        "unknown": "permerror",
        "error": "temperror",
        "ambiguous": "permerror",
    }.get(verdict, "permerror")  # type: ignore[return-value]
