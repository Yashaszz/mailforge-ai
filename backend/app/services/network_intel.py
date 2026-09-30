"""Network reputation for relay addresses: VPN, proxy and Tor detection.

Answers a question the headers alone cannot: *what kind of network* did this
message come from? A residential ISP, a datacentre, a commercial VPN, or a
Tor exit node are very different things behind an identical-looking IP.

This runs server-side because the upstream service sends no CORS headers, so
the browser cannot call it directly. It is deliberately fail-safe: any error,
timeout or quota exhaustion yields "unknown" rather than raising, because a
reputation lookup must never cost an analyst their verdict.

Uses only the standard library so the serverless bundle gains no dependency.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

logger = logging.getLogger(__name__)

__all__ = ["NetworkIntel", "lookup", "lookup_many"]

ENDPOINT = "https://proxycheck.io/v2/"
DEFAULT_TIMEOUT = 4.0

#: Most hops we will ever look up for one message. Bounds both latency and
#: the free-tier query budget on a service we do not authenticate to.
MAX_LOOKUPS = 6

#: Process-wide cache. Serverless containers are reused between requests, so
#: repeat demos of the same message cost no further upstream queries.
_CACHE: dict[str, "NetworkIntel"] = {}

#: Upstream `type` values that mean the address anonymises its user.
ANONYMISING = {"vpn", "tor", "proxy", "socks", "socks4", "socks5", "web", "compromised"}


@dataclass(slots=True)
class NetworkIntel:
    ip: str
    is_anonymising: bool = False
    kind: str | None = None        # VPN | TOR | Proxy | Business | Residential ...
    risk: int | None = None        # 0-100 as reported upstream
    provider: str | None = None
    checked: bool = False          # False when the lookup could not be made
    detail: str = ""

    @property
    def label(self) -> str:
        if not self.checked:
            return "not assessed"
        return (self.kind or "unknown").upper() if self.is_anonymising else "clean"


def lookup(ip: str | None, *, timeout: float = DEFAULT_TIMEOUT) -> NetworkIntel:
    """Classify one address. Never raises."""
    if not ip:
        return NetworkIntel(ip="", detail="No address to check.")
    if ip in _CACHE:
        return _CACHE[ip]

    result = NetworkIntel(ip=ip)
    query = urllib.parse.urlencode({"vpn": "1", "risk": "1", "asn": "1"})
    url = f"{ENDPOINT}{urllib.parse.quote(ip)}?{query}"

    try:
        request = urllib.request.Request(url, headers={"User-Agent": "Mailforge/0.1"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        result.detail = f"Reputation lookup unavailable: {type(exc).__name__}"
        logger.info("network intel lookup failed for %s: %s", ip, exc)
        _CACHE[ip] = result
        return result

    if payload.get("status") not in ("ok", "warning"):
        # Most often the daily free-tier quota; treat as simply unknown.
        result.detail = f"Reputation service returned status {payload.get('status')!r}."
        _CACHE[ip] = result
        return result

    record = payload.get(ip)
    if not isinstance(record, dict):
        result.detail = "Reputation service returned no record for this address."
        _CACHE[ip] = result
        return result

    result.checked = True
    result.kind = record.get("type")
    result.provider = record.get("provider") or record.get("organisation")
    result.is_anonymising = (
        str(record.get("proxy", "no")).lower() == "yes"
        or str(result.kind or "").lower() in ANONYMISING
    )
    try:
        result.risk = int(record.get("risk"))
    except (TypeError, ValueError):
        result.risk = None

    result.detail = _describe(result)
    _CACHE[ip] = result
    return result


def lookup_many(ips: list[str], *, timeout: float = DEFAULT_TIMEOUT) -> dict[str, NetworkIntel]:
    """Classify several addresses, newest-relevant first, within the cap."""
    out: dict[str, NetworkIntel] = {}
    for ip in list(dict.fromkeys(filter(None, ips)))[:MAX_LOOKUPS]:
        out[ip] = lookup(ip, timeout=timeout)
    return out


def _describe(intel: NetworkIntel) -> str:
    kind = (intel.kind or "").lower()
    where = f" ({intel.provider})" if intel.provider else ""

    if kind == "tor":
        return (
            f"This address is a Tor exit node{where}. Mail leaving the Tor network "
            f"has had its true origin deliberately stripped — the sender cannot be "
            f"traced any further back than this hop."
        )
    if kind == "vpn":
        return (
            f"This address belongs to a commercial VPN or anonymising service{where}. "
            f"The sender's real network is hidden behind it."
        )
    if intel.is_anonymising:
        return f"This address is a known proxy ({intel.kind}){where}."
    if kind in ("business", "hosting"):
        return (
            f"Datacentre or business address{where} — normal for a mail server, and "
            f"not an anonymising service."
        )
    return f"No proxy, VPN or Tor association found for this address{where}."
