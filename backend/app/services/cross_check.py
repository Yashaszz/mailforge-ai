"""Corroborate our own results against the receiving MTA's.

Every message delivered to Gmail, Outlook or any competent provider carries an
``Authentication-Results`` header recording what *that* provider concluded
about SPF, DKIM and DMARC at the moment of delivery.

That is an independent second opinion, computed by a different implementation
on the same message, and comparing against it answers the first question any
reviewer asks: how do you know your verdict is right?

It is corroboration, not ground truth. Disagreement has legitimate causes --
most often that the receiving MTA checked at delivery time while we check now,
against DNS records and signing keys that may have rotated since. Those cases
are reported as explainable rather than as errors.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .email_auth import AuthReport
from .eml_parser import ParsedEmail

__all__ = ["CrossCheck", "MethodComparison", "cross_check"]

# `method=result` pairs, e.g. `dkim=pass`, `spf=softfail`, `dmarc=fail`.
_METHOD_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)

#: Spellings different MTAs use for the same outcome.
_NORMALISE = {
    "hardfail": "fail",
    "bestguesspass": "pass",
    "unknown": "permerror",
    "error": "temperror",
}


@dataclass(slots=True)
class MethodComparison:
    method: str                      # spf | dkim | dmarc
    ours: str
    theirs: str | None
    agrees: bool | None = None       # None when the MTA did not report it
    note: str = ""


@dataclass(slots=True)
class CrossCheck:
    available: bool = False
    reporter: str | None = None      # the MTA that stamped the header
    agreement: str = "not_available"  # full | partial | none | not_available
    summary: str = ""
    methods: list[MethodComparison] = field(default_factory=list)


def cross_check(parsed: ParsedEmail, report: AuthReport) -> CrossCheck:
    """Compare our SPF/DKIM/DMARC results with the receiving MTA's."""
    header = _primary_header(parsed.authentication_results)
    ours = {
        "spf": report.spf.result,
        "dkim": report.dkim.result,
        "dmarc": report.dmarc.result,
    }

    if not header:
        return CrossCheck(
            summary="The receiving mail server did not record its own "
                    "authentication results, so there is nothing to compare against.",
            methods=[MethodComparison(m, r, None) for m, r in ours.items()],
        )

    theirs = _parse_methods(header)
    result = CrossCheck(available=True, reporter=_reporter(header))

    compared = 0
    agreed = 0
    for method, our_value in ours.items():
        their_value = theirs.get(method)
        comparison = MethodComparison(method=method, ours=our_value, theirs=their_value)

        if their_value is None:
            comparison.note = "Not reported by the receiving server."
        elif their_value == our_value:
            compared += 1
            agreed += 1
            comparison.agrees = True
            comparison.note = "Independently confirmed."
        else:
            compared += 1
            comparison.agrees = False
            comparison.note = _explain(method, our_value, their_value)

        result.methods.append(comparison)

    if compared == 0:
        result.agreement = "not_available"
        result.summary = ("The receiving server stamped a header but recorded no "
                          "SPF, DKIM or DMARC result to compare.")
    elif agreed == compared:
        result.agreement = "full"
        result.summary = (
            f"All {compared} check(s) match what {result.reporter or 'the receiving server'} "
            f"concluded at delivery — independently corroborated."
        )
    elif agreed:
        result.agreement = "partial"
        result.summary = (
            f"{agreed} of {compared} checks match {result.reporter or 'the receiving server'}. "
            f"Differences are explained per check below."
        )
    else:
        result.agreement = "none"
        result.summary = (
            f"None of the {compared} checks match {result.reporter or 'the receiving server'}. "
            f"Most often this means the message is old enough that DNS records or "
            f"signing keys have changed since delivery."
        )

    return result


def _primary_header(headers: list[str]) -> str | None:
    """Prefer a plain Authentication-Results over ARC copies.

    The parser keeps header values without their names, so ARC entries are
    told apart by their content: RFC 8617 requires an ARC-Authentication-
    Results value to begin with an instance tag, ``i=N;``. Those record an
    intermediary's view, whereas the plain header is what the server that
    actually delivered to this mailbox concluded.

    Values arrive nearest-hop first, so the first non-ARC entry is the one
    added by the delivering server.
    """
    for value in headers:
        if not _ARC_INSTANCE_RE.match(value):
            return value
    return headers[0] if headers else None


_ARC_INSTANCE_RE = re.compile(r"\s*(arc-authentication-results\s*:\s*)?i\s*=\s*\d+\s*;", re.IGNORECASE)


def _reporter(header: str) -> str | None:
    first = header.split(";", 1)[0].strip()
    # Some servers prefix the header name when the value is re-serialised.
    first = re.sub(r"^(arc-)?authentication-results\s*:\s*", "", first, flags=re.IGNORECASE)
    first = first.split()[0] if first.split() else ""
    return first.rstrip(".") or None


def _parse_methods(header: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for method, value in _METHOD_RE.findall(header):
        method = method.lower()
        value = value.lower()
        # Keep the first mention: later ones are usually per-signature detail.
        found.setdefault(method, _NORMALISE.get(value, value))
    return found


def _explain(method: str, ours: str, theirs: str) -> str:
    label = method.upper()

    if theirs == "pass" and ours in ("temperror", "permerror"):
        return (f"{label} passed at delivery but cannot be re-verified now — "
                f"the DNS record or signing key has most likely been rotated since.")
    if theirs == "pass" and ours == "fail" and method == "dkim":
        return ("The signature verified at delivery but not now. Either the key "
                "has been rotated, or the message was altered after it arrived.")
    if theirs == "none" and ours != "none":
        return (f"The receiving server recorded no {label} result; we found one, "
                f"which can happen when it skipped the check.")
    if ours == "none" and theirs != "none":
        return (f"We found no {label} record to evaluate, while the receiving "
                f"server did — the domain's DNS has most likely changed since delivery.")
    return (f"We concluded {ours}; the receiving server recorded {theirs} at "
            f"delivery time.")
