"""Raw ``.eml`` parsing built on Python's :mod:`email` standard library.

This module is deliberately free of any network access.  It turns raw RFC 5322
bytes into the structured facts that Layer 1 needs:

* decoded, human-readable headers
* the ``Received:`` relay chain, oldest hop last (as it appears on the wire)
* the SMTP envelope identifiers that SPF evaluation requires
  (client IP, HELO name, MAIL FROM)

The ``Received:`` chain is parsed in full here rather than in the auth layer
because Phase 3 (header-trace reconstruction) needs exactly the same structure.
"""

from __future__ import annotations

import email
import email.policy
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from email.message import EmailMessage
from email.utils import getaddresses, parsedate_to_datetime

__all__ = [
    "ParsedEmail",
    "ReceivedHop",
    "parse_eml",
]

# Headers we always surface, in the order an analyst expects to read them.
INTERESTING_HEADERS = (
    "Return-Path",
    "From",
    "Reply-To",
    "To",
    "Cc",
    "Subject",
    "Date",
    "Message-ID",
    "Sender",
    "X-Originating-IP",
    "X-Mailer",
    "User-Agent",
    "List-Unsubscribe",
)

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Loose IPv6: any run of hex groups containing at least two colons.
_IPV6_RE = re.compile(r"\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b")
_HOST_CHARS = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"

_FROM_RE = re.compile(rf"\bfrom\s+(?P<host>{_HOST_CHARS})", re.IGNORECASE)
_BY_RE = re.compile(rf"\bby\s+(?P<host>{_HOST_CHARS})", re.IGNORECASE)
_WITH_RE = re.compile(r"\bwith\s+(?P<proto>[A-Za-z0-9/._-]+)", re.IGNORECASE)
_ID_RE = re.compile(r"\bid\s+(?P<id>[^\s;]+)", re.IGNORECASE)
_FOR_RE = re.compile(r"\bfor\s+<?(?P<addr>[^\s;<>]+@[^\s;<>]+)>?", re.IGNORECASE)
_BRACKETED_IP_RE = re.compile(r"[\[(]\s*(?:IPv6:)?([0-9A-Fa-f:.]+)\s*[\])]")


@dataclass(slots=True)
class ReceivedHop:
    """One parsed ``Received:`` header.

    ``index`` 0 is the header nearest the top of the message, i.e. the *last*
    relay to touch the mail (the recipient's own MTA).  The originating sender
    is therefore at the highest index.
    """

    index: int
    from_host: str | None = None
    from_ip: str | None = None
    by_host: str | None = None
    protocol: str | None = None
    queue_id: str | None = None
    recipient: str | None = None
    timestamp: datetime | None = None
    raw: str = ""

    @property
    def is_public_ip(self) -> bool:
        return is_public_ip(self.from_ip)


@dataclass(slots=True)
class ParsedEmail:
    """Everything the auth layer and the dashboard need from the raw bytes."""

    raw: bytes
    message: EmailMessage
    headers: dict[str, str] = field(default_factory=dict)
    all_headers: list[tuple[str, str]] = field(default_factory=list)
    received_chain: list[ReceivedHop] = field(default_factory=list)

    # Identities
    from_address: str | None = None
    from_display_name: str | None = None
    from_domain: str | None = None
    reply_to_address: str | None = None
    reply_to_domain: str | None = None
    return_path: str | None = None
    envelope_from: str | None = None          # MAIL FROM used for SPF
    envelope_from_domain: str | None = None

    # SMTP envelope reconstruction (there is no live connection to inspect)
    client_ip: str | None = None
    client_ip_source: str | None = None       # how we decided on that IP
    helo: str | None = None

    subject: str | None = None
    message_id: str | None = None
    date: datetime | None = None

    # The receiving MTA's own verdict, if it stamped one. Useful cross-check.
    authentication_results: list[str] = field(default_factory=list)

    attachment_count: int = 0
    attachment_names: list[str] = field(default_factory=list)

    parse_warnings: list[str] = field(default_factory=list)


def parse_eml(raw: bytes) -> ParsedEmail:
    """Parse raw ``.eml`` bytes into a :class:`ParsedEmail`.

    Uses ``policy.default`` so headers arrive RFC 2047-decoded, but every
    header read is defensive: malicious mail routinely contains headers that
    the stdlib's strict parser flags as defective, and a fraud analyser must
    survive input a normal mail client would reject.
    """
    warnings: list[str] = []

    message = email.message_from_bytes(raw, policy=email.policy.default)
    parsed = ParsedEmail(raw=raw, message=message, parse_warnings=warnings)

    for defect in getattr(message, "defects", ()) or ():
        warnings.append(f"stdlib parser defect: {type(defect).__name__}")

    parsed.all_headers = [(k, _header_str(v)) for k, v in _items(message)]
    for name in INTERESTING_HEADERS:
        value = _get_header(message, name)
        if value:
            parsed.headers[name] = value

    parsed.subject = _get_header(message, "Subject")
    parsed.message_id = _get_header(message, "Message-ID")
    parsed.date = _parse_date(_get_header(message, "Date"), warnings)

    # --- identities -------------------------------------------------------
    parsed.from_display_name, parsed.from_address = _first_address(message, "From")
    parsed.from_domain = _domain_of(parsed.from_address)

    _, parsed.reply_to_address = _first_address(message, "Reply-To")
    parsed.reply_to_domain = _domain_of(parsed.reply_to_address)

    parsed.return_path = _get_header(message, "Return-Path")
    envelope_from = _strip_angle_brackets(parsed.return_path)
    if envelope_from is None:
        # No Return-Path (common for a .eml exported before delivery). The
        # header From is the best available stand-in; flag it so the SPF
        # result is reported as an approximation rather than ground truth.
        envelope_from = parsed.from_address
        if envelope_from:
            warnings.append(
                "No Return-Path header; SPF evaluated against the From address "
                "as an approximation of MAIL FROM."
            )
    parsed.envelope_from = envelope_from
    parsed.envelope_from_domain = _domain_of(envelope_from)

    # --- relay chain ------------------------------------------------------
    parsed.received_chain = _parse_received_chain(message)
    client_ip, source, helo = _select_client(parsed.received_chain, message)
    parsed.client_ip = client_ip
    parsed.client_ip_source = source
    parsed.helo = helo or parsed.envelope_from_domain

    if client_ip is None:
        warnings.append(
            "No usable client IP found in the Received chain; SPF cannot be "
            "evaluated for this message."
        )

    parsed.authentication_results = [
        _header_str(v)
        for k, v in _items(message)
        if k.lower() in ("authentication-results", "arc-authentication-results")
    ]

    parsed.attachment_names = _attachment_names(message, warnings)
    parsed.attachment_count = len(parsed.attachment_names)

    return parsed


# --------------------------------------------------------------------------
# header helpers
# --------------------------------------------------------------------------

def _items(message: EmailMessage) -> list[tuple[str, object]]:
    """``message.items()`` that survives headers the stdlib cannot refold."""
    try:
        return list(message.items())
    except Exception:
        return list(getattr(message, "_headers", []))


def _header_str(value: object) -> str:
    """Render a header value as a plain string without ever raising."""
    try:
        return str(value)
    except Exception:  # pragma: no cover - stdlib refolding edge cases
        return repr(value)


def _get_header(message: EmailMessage, name: str) -> str | None:
    try:
        value = message.get(name)
    except Exception:
        # policy.default can raise while refolding a malformed header.
        value = None
    if value is None:
        return None
    return _header_str(value).strip() or None


def _first_address(message: EmailMessage, header: str) -> tuple[str | None, str | None]:
    """Return ``(display_name, addr_spec)`` for the first address in *header*."""
    raw = _get_header(message, header)
    if not raw:
        return None, None
    try:
        pairs = getaddresses([raw])
    except Exception:
        return None, None
    for name, addr in pairs:
        if addr and "@" in addr:
            return (name.strip() or None), addr.strip().lower()
    if pairs:
        return (pairs[0][0].strip() or None), None
    return None, None


def _strip_angle_brackets(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip()
    if value.startswith("<") and value.endswith(">"):
        value = value[1:-1].strip()
    # An empty result means the null sender used by bounces, which is a
    # legitimate MAIL FROM value -- return "" rather than None so the caller
    # does not mistake it for a missing Return-Path.
    return value.lower()


def _domain_of(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    domain = address.rsplit("@", 1)[1].strip().strip(">").lower()
    return domain or None


def _parse_date(value: str | None, warnings: list[str]) -> datetime | None:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError):
        warnings.append(f"Unparseable Date header: {value!r}")
        return None


def _attachment_names(message: EmailMessage, warnings: list[str]) -> list[str]:
    names: list[str] = []
    try:
        for part in message.walk():
            if part.get_content_disposition() == "attachment":
                names.append(part.get_filename() or "(unnamed)")
    except Exception as exc:
        warnings.append(f"Could not enumerate attachments: {exc}")
    return names


# --------------------------------------------------------------------------
# Received: chain
# --------------------------------------------------------------------------

def _parse_received_chain(message: EmailMessage) -> list[ReceivedHop]:
    raw_values = [v for k, v in _items(message) if k.lower() == "received"]
    return [_parse_received(i, _header_str(v)) for i, v in enumerate(raw_values)]


def _parse_received(index: int, raw: str) -> ReceivedHop:
    """Parse a single ``Received:`` header.

    The grammar in RFC 5321 s4.4 is widely abused, so this is a tolerant regex
    pass rather than a strict parse: every field is optional and failing to
    find one is not an error.
    """
    text = " ".join(raw.split())

    body, separator, date_part = text.rpartition(";")
    if not separator:  # no ';' at all
        body, date_part = text, ""

    hop = ReceivedHop(index=index, raw=raw.strip())

    # The `from` clause runs until the `by` clause; restricting the IP search
    # to it stops us picking up the receiving server's own address.
    by_match = _BY_RE.search(body)
    from_clause = body[: by_match.start()] if by_match else body

    match = _FROM_RE.search(from_clause)
    if match:
        hop.from_host = match.group("host")
    hop.from_ip = extract_ip(from_clause)

    if by_match:
        hop.by_host = by_match.group("host")
    match = _WITH_RE.search(body)
    if match:
        hop.protocol = match.group("proto")
    match = _ID_RE.search(body)
    if match:
        hop.queue_id = match.group("id")
    match = _FOR_RE.search(body)
    if match:
        hop.recipient = match.group("addr")

    if date_part.strip():
        try:
            hop.timestamp = parsedate_to_datetime(date_part.strip())
        except (TypeError, ValueError):
            hop.timestamp = None

    return hop


def extract_ip(text: str) -> str | None:
    """Pull the most plausible peer IP out of a ``from`` clause.

    Prefers a public address; bracketed forms (``[1.2.3.4]``) are the
    conventional way an MTA records the peer, so they are tried first.
    """
    candidates: list[str] = list(_BRACKETED_IP_RE.findall(text))
    candidates.extend(_IPV4_RE.findall(text))
    candidates.extend(_IPV6_RE.findall(text))

    normalised: list[str] = []
    for candidate in candidates:
        cleaned = candidate.strip().strip("[]()").removeprefix("IPv6:")
        try:
            addr = ipaddress.ip_address(cleaned)
        except ValueError:
            continue
        normalised.append(str(addr))

    for addr in normalised:
        if is_public_ip(addr):
            return addr
    return normalised[0] if normalised else None


def is_public_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return addr.is_global and not addr.is_multicast


def _select_client(
    hops: list[ReceivedHop], message: EmailMessage
) -> tuple[str | None, str | None, str | None]:
    """Decide which IP actually connected to the recipient's boundary MTA.

    SPF is evaluated by the receiving edge server against the IP that connected
    to it.  Reading a ``.eml`` after the fact there is no connection to inspect,
    so we walk the ``Received`` chain from the top (most recent hop) downwards
    and take the first *public* address: hops above it are internal relays
    inside the recipient's own infrastructure, and hops below it are hearsay
    asserted by the sender, which must not be trusted.

    Returns ``(ip, description_of_how_we_chose_it, helo_name)``.
    """
    for hop in hops:
        if hop.is_public_ip:
            return (
                hop.from_ip,
                f"First public IP in the Received chain (hop {hop.index}, "
                f"received by {hop.by_host or 'unknown'})",
                hop.from_host,
            )

    # Nothing public in the chain. Some providers strip Received headers and
    # leave only X-Originating-IP; fall back to it, but say so loudly.
    originating = _get_header(message, "X-Originating-IP")
    if originating:
        candidate = extract_ip(originating)
        if is_public_ip(candidate):
            return (
                candidate,
                "No public IP in the Received chain; fell back to the "
                "X-Originating-IP header (sender-asserted, lower trust)",
                hops[-1].from_host if hops else None,
            )

    # Last resort: a private/loopback address (typical of lab captures).
    for hop in hops:
        if hop.from_ip:
            return (
                hop.from_ip,
                f"Only non-public addresses present; using hop {hop.index} "
                f"({hop.from_ip}). SPF results will not be meaningful.",
                hop.from_host,
            )

    return None, "No IP address could be recovered from the headers", None
