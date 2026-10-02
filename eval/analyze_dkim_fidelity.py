"""Analyse the DKIM retrieval-fidelity measurements exported by the extension.

Each row compares one real message retrieved two ways -- Gmail's "Download
Original" (verbatim) and the "Show original" rendered view -- with both copies
verified back to back against the same DNS. The question is how often the
retrieval path alone changes the DKIM verdict, and why.

Several exports can be combined (one per contributor). Records carry no
identifying data; each export's message hashes are salted per install, so they
cannot be linked across contributors.

Usage:
    python eval/analyze_dkim_fidelity.py path/to/export1.csv [export2.csv ...]
"""

from __future__ import annotations

import csv
import math
import sys
from collections import Counter
from pathlib import Path


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (math.nan, math.nan)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def rate(k: int, n: int) -> str:
    if n == 0:
        return "   n/a"
    lo, hi = wilson(k, n)
    return f"{100 * k / n:5.1f}%  [{100 * lo:4.1f}-{100 * hi:4.1f}]  ({k}/{n})"


def truthy(v: str) -> bool:
    return str(v).strip().lower() in ("true", "1", "yes")


def load(paths: list[Path]) -> list[dict]:
    rows = []
    for path in paths:
        with path.open(newline="", encoding="utf-8") as handle:
            for i, row in enumerate(csv.DictReader(handle)):
                row["_file"] = path.name
                rows.append(row)
    return rows


def bucket(value: int, edges: list[int], unit: str = "") -> str:
    for edge in edges:
        if value <= edge:
            return f"<= {edge}{unit}"
    return f"> {edges[-1]}{unit}"


def breakdown(rows: list[dict], key, label: str) -> None:
    print(f"\n  DKIM flip rate by {label}")
    groups: dict[str, list[dict]] = {}
    for row in rows:
        groups.setdefault(key(row), []).append(row)
    for name, members in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        flips = sum(truthy(r["dkim_flipped"]) for r in members)
        print(f"    {name:28s} {rate(flips, len(members))}")


def main(argv: list[str]) -> int:
    paths = [Path(a) for a in argv]
    if not paths:
        print(__doc__)
        return 1
    rows = load(paths)
    if not rows:
        print("No records.")
        return 1

    # A verification that errored is not evidence either way.
    errors = [r for r in rows if "error" in (r["dkim_verbatim"], r["dkim_rendered"])]
    valid = [r for r in rows if r not in errors]
    signed = [r for r in valid if int(r["dkim_signatures"] or 0) > 0]

    print(f"Records: {len(rows)} from {len(paths)} export(s); "
          f"{len(errors)} excluded for verification errors; {len(valid)} analysed")
    print(f"DKIM-signed messages: {len(signed)}")

    differ = sum(not truthy(r["identical"]) for r in valid)
    flips = sum(truthy(r["dkim_flipped"]) for r in signed)
    print("\nHEADLINE")
    print(f"  Rendered copy differs from verbatim bytes   {rate(differ, len(valid))}")
    print(f"  DKIM verdict flipped (signed messages)      {rate(flips, len(signed))}")

    passing = [r for r in signed if r["dkim_verbatim"] == "pass"]
    lost = sum(r["dkim_rendered"] != "pass" for r in passing)
    print(f"  Valid signatures reported as not passing    {rate(lost, len(passing))}")

    print("\nFLIP DIRECTION (verbatim -> rendered)")
    for (a, b), n in Counter((r["dkim_verbatim"], r["dkim_rendered"])
                             for r in signed if truthy(r["dkim_flipped"])).most_common():
        print(f"  {a:>10} -> {b:<10} {n}")

    print("\nOTHER CHECKS (should be robust: SPF and DMARC read headers, not body bytes)")
    for check in ("spf", "dmarc"):
        changed = sum(r[f"{check}_verbatim"] != r[f"{check}_rendered"] for r in valid)
        print(f"  {check.upper():5s} changed  {rate(changed, len(valid))}")

    print("\nWHY THE COPIES DIFFER")
    for kind, n in Counter(r["diff_kind"] for r in valid).most_common():
        print(f"  {kind:14s} {n:>5}  ({100 * n / len(valid):4.1f}%)")

    if signed:
        breakdown(signed, lambda r: r["diff_kind"], "difference kind")
        breakdown(signed, lambda r: r["diff_region"], "where the first difference falls")
        breakdown(signed, lambda r: r["encodings"], "transfer encodings present")
        breakdown(signed, lambda r: bucket(int(r["max_line_length"]), [78, 998, 4000], " chars"),
                  "longest line")
        breakdown(signed, lambda r: bucket(int(r["bytes_verbatim"]) // 1024, [10, 50, 200], " KB"),
                  "message size")
        breakdown(signed, lambda r: "non-ASCII" if truthy(r["non_ascii"]) else "ASCII only",
                  "character content")

    print("\nNote: intervals are 95% Wilson score intervals. Messages are a convenience")
    print("sample of the contributors' own mailboxes, not a random sample of all mail.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
