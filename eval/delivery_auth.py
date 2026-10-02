"""How often did phishing pass SPF, DKIM and DMARC at the moment of delivery?

Re-verifying an old message against today's DNS measures the domain as it is
now, not as it was. Recent Nazario archives avoid that problem: each message
carries the receiving server's own Authentication-Results header, stamped at
delivery. This script reads those delivery-time verdicts.

This describes the phishing corpus, not Mailforge's accuracy. The verdicts
are the receiving provider's, and the corpus is one person's hand-labelled
inbox, so rates are indicative rather than population estimates.

Usage:
    MAILFORGE_CORPORA=C:/mailforge-corpora python eval/delivery_auth.py
"""

from __future__ import annotations

import collections
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "eval"))

from app.services.cross_check import _parse_methods, _primary_header, _reporter  # noqa: E402
from app.services.eml_parser import parse_eml  # noqa: E402
from run_corpus import CORPORA, RESULTS, load_nazario, wilson  # noqa: E402

#: Years whose archives carry delivery-time verdicts on nearly every message.
YEARS = ("2022", "2023", "2024", "2025")
METHODS = ("spf", "dkim", "dmarc")


def main() -> int:
    by_year: dict[str, dict[str, collections.Counter]] = collections.defaultdict(
        lambda: {m: collections.Counter() for m in METHODS})
    counted = collections.Counter()
    missing = collections.Counter()
    reporters = collections.Counter()

    for sample in load_nazario(CORPORA / "nazario"):
        if sample.era not in YEARS:
            continue
        header = _primary_header(parse_eml(sample.raw).authentication_results)
        if not header:
            missing[sample.era] += 1
            continue
        counted[sample.era] += 1
        reporters[_reporter(header)] += 1
        verdicts = _parse_methods(header)
        for method in METHODS:
            by_year[sample.era][method][verdicts.get(method, "absent")] += 1

    total = sum(counted.values())
    overall = {m: collections.Counter() for m in METHODS}
    for era in by_year:
        for m in METHODS:
            overall[m].update(by_year[era][m])

    def rate(k: int, n: int) -> str:
        lo, hi = wilson(k, n)
        return f"{100 * k / n:.1f}% [{100 * lo:.1f}–{100 * hi:.1f}]"

    lines = [
        "# Delivery-time authentication of modern phishing",
        "",
        f"Generated {datetime.now(timezone.utc).isoformat(timespec='seconds')} by "
        "`eval/delivery_auth.py`. Do not edit by hand.",
        "",
        f"Nazario phishing {YEARS[0]}–{YEARS[-1]}: **{total}** messages carry a delivery-time "
        f"Authentication-Results header ({sum(missing.values())} do not and are excluded).",
        f"Stamped by the recipient's provider (`{reporters.most_common(1)[0][0].split('.', 1)[-1]}`).",
        "",
        "## Pass rate at delivery",
        "",
        "| Check | Passed [95% CI] | Other outcomes |",
        "| --- | --- | --- |",
    ]
    for m in METHODS:
        c = overall[m]
        other = ", ".join(f"{v} {n}" for v, n in c.most_common() if v != "pass")
        lines.append(f"| {m.upper()} | {rate(c['pass'], total)} | {other} |")

    lines += [
        "",
        "## DMARC pass rate by year",
        "",
        "| Year | Messages | DMARC passed [95% CI] |",
        "| --- | --- | --- |",
        *[f"| {era} | {counted[era]} | {rate(by_year[era]['dmarc']['pass'], counted[era])} |"
          for era in YEARS if counted[era]],
        "",
        "## Reading",
        "",
        "A DMARC pass means the visible From domain was authenticated: the sender controlled it. "
        "Phishing that passes was sent from lookalike or newly registered domains with valid "
        "authentication, from compromised accounts, or through legitimate services. Authentication "
        "establishes who sent a message, not whether they are trustworthy.",
        "",
        "Source: J. Nazario, Phishing Corpus, https://monkey.org/~jose/phishing/ (CC-BY-4.0). "
        "One hand-classified inbox; indicative, not a population estimate.",
        "",
    ]

    RESULTS.mkdir(parents=True, exist_ok=True)
    out = RESULTS / f"delivery_auth_{datetime.now():%Y%m%d}.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
