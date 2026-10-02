"""Evaluate the Mailforge risk engine on public email corpora.

Runs every message through the production pipeline (parse -> authenticate ->
assess) in-process and reports detection performance against the corpus
labels.

Methodological choices, stated up front because they decide what the numbers
mean:

1. **Live DNS is off.** The corpora date from 2002-2025. Re-checking an old
   message's SPF, DKIM or DMARC against today's DNS measures how its domain is
   configured *now*, not whether the message was authentic *then* -- and DMARC
   did not exist before 2012. So authentication results are `not_checked`
   throughout, and this evaluation measures the time-independent signals only:
   identity, infrastructure, relay-chain integrity and content.
2. **Network reputation is off.** VPN/Tor classification describes an IP's use
   today, not at sending time, and is rate-limited.
3. **The rules are untuned.** Every weight and threshold was set before these
   corpora were seen. Nothing here was fitted to them. Any future tuning must
   use the held-out split this script freezes, never the full set.
4. **Exact duplicates are removed** (SHA-256 of the raw bytes), since the
   Nazario archives overlap.

Usage:
    MAILFORGE_CORPORA=C:/mailforge-corpora python eval/run_corpus.py
"""

from __future__ import annotations

import csv
import hashlib
import json
import mailbox
import math
import os
import random
import sys
import tarfile
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from app.services.email_auth import authenticate  # noqa: E402
from app.services.eml_parser import parse_eml  # noqa: E402
from app.services.risk import assess  # noqa: E402

CORPORA = Path(os.environ.get("MAILFORGE_CORPORA", ROOT / "data" / "corpora"))
RESULTS = ROOT / "eval" / "results"

#: Verdict bands, as the product defines them.
THRESHOLDS = {"Suspicious+": 20, "High-Risk+": 45, "Malicious": 70}

SPLIT_SEED = 20261002
HOLDOUT_FRACTION = 0.7        # 70% frozen as test; 30% available for tuning


#: Rule families, for the ablation. Each scored reason code maps to one.
FAMILIES = {
    "content": ("urgency_language", "urgency_language_weak"),
    "identity": ("reply_to_mismatch", "envelope_mismatch", "brand_impersonation",
                 "display_name_spoof"),
    "infrastructure": ("helo_mismatch", "suspicious_tld", "non_public_origin", "no_relay_path"),
    "chain_integrity": ("relay_timestamps_impossible",),
}


def family_of(code: str) -> str:
    for family, codes in FAMILIES.items():
        if code in codes:
            return family
    return "other"


@dataclass(slots=True)
class Sample:
    uid: str
    corpus: str
    source: str
    group: str                # ham | spam | phish
    era: str
    raw: bytes


@dataclass(slots=True)
class Outcome:
    uid: str
    corpus: str
    source: str
    group: str
    era: str
    split: str
    score: int | None = None
    level: str | None = None
    codes: list[str] = field(default_factory=list)
    hops: int = 0
    error: str | None = None
    family_points: dict = field(default_factory=dict)


# ──────────────────────────────────────────────────────────────────────────
# loading
# ──────────────────────────────────────────────────────────────────────────

def load_spamassassin(folder: Path):
    for archive in sorted(folder.glob("*.tar.bz2")):
        group = "spam" if "spam" in archive.name else "ham"
        with tarfile.open(archive, "r:bz2") as tar:
            for member in tar:
                # Each archive carries a `cmds` file of shell commands, not mail.
                if not member.isfile() or member.name.endswith("/cmds"):
                    continue
                data = tar.extractfile(member).read()
                yield Sample(
                    uid=f"sa:{archive.stem}:{Path(member.name).name}",
                    corpus="spamassassin", source=archive.name.replace(".tar.bz2", ""),
                    group=group, era="2002-2005", raw=data,
                )


def nazario_era(name: str) -> str:
    if name.startswith("phishing-"):
        return name.split("-", 1)[1]
    # phishing0-3, 20051114 and private-phishing4 are the 2005-2007 archives.
    return "2005-2007"


def load_nazario(folder: Path):
    for path in sorted(folder.iterdir()):
        if path.name in ("README.txt", "LICENSE.txt", "MANIFEST.json") or not path.is_file():
            continue
        box = mailbox.mbox(str(path), create=False)
        try:
            for index, key in enumerate(box.iterkeys()):
                yield Sample(
                    uid=f"nz:{path.name}:{index}", corpus="nazario", source=path.name,
                    group="phish", era=nazario_era(path.name), raw=box.get_bytes(key),
                )
        finally:
            box.close()


# ──────────────────────────────────────────────────────────────────────────
# running
# ──────────────────────────────────────────────────────────────────────────

def split_for(uid: str) -> str:
    """Deterministic, stable assignment independent of iteration order."""
    digest = hashlib.sha256(f"{SPLIT_SEED}:{uid}".encode()).digest()
    return "test" if digest[0] / 255 < HOLDOUT_FRACTION else "dev"


def evaluate(sample: Sample) -> Outcome:
    out = Outcome(sample.uid, sample.corpus, sample.source, sample.group,
                  sample.era, split_for(sample.uid))
    try:
        parsed = parse_eml(sample.raw)
        report = authenticate(parsed, offline=True)
        result = assess(parsed, report, networks={})
    except Exception as exc:                      # report, never abort the run
        out.error = f"{type(exc).__name__}: {exc}"[:200]
        return out
    out.score = result.score
    out.level = result.level
    out.codes = [r.code for r in result.reasons if r.points > 0]
    for reason in result.reasons:
        if reason.points > 0:
            fam = family_of(reason.code)
            out.family_points[fam] = out.family_points.get(fam, 0) + reason.points
    out.hops = len(parsed.received_chain)
    return out


# ──────────────────────────────────────────────────────────────────────────
# metrics
# ──────────────────────────────────────────────────────────────────────────

def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a proportion."""
    if n == 0:
        return (math.nan, math.nan)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def auc(pos: list[int], neg: list[int]) -> float:
    """ROC AUC as the Mann-Whitney U statistic, ties counted as half."""
    if not pos or not neg:
        return math.nan
    ranked = sorted([(s, 1) for s in pos] + [(s, 0) for s in neg])
    rank_sum, i = 0.0, 0
    while i < len(ranked):
        j = i
        while j < len(ranked) and ranked[j][0] == ranked[i][0]:
            j += 1
        avg_rank = (i + 1 + j) / 2
        rank_sum += avg_rank * sum(1 for _, label in ranked[i:j] if label == 1)
        i = j
    u = rank_sum - len(pos) * (len(pos) + 1) / 2
    return u / (len(pos) * len(neg))


def confusion(pos: list[int], neg: list[int], threshold: int) -> dict:
    tp = sum(s >= threshold for s in pos)
    fn = len(pos) - tp
    fp = sum(s >= threshold for s in neg)
    tn = len(neg) - fp
    precision = tp / (tp + fp) if tp + fp else math.nan
    recall = tp / len(pos) if pos else math.nan
    fpr = fp / len(neg) if neg else math.nan
    f1 = (2 * precision * recall / (precision + recall)
          if precision + recall and not math.isnan(precision) else math.nan)
    return {
        "threshold": threshold, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision, "recall": recall, "recall_ci": wilson(tp, len(pos)),
        "fpr": fpr, "fpr_ci": wilson(fp, len(neg)), "f1": f1,
    }


def task(outcomes: list[Outcome], positive: set[str], split: str | None) -> dict:
    rows = [o for o in outcomes if o.score is not None and (split is None or o.split == split)]
    pos = [o.score for o in rows if o.group in positive]
    neg = [o.score for o in rows if o.group == "ham"]
    return {
        "n_positive": len(pos), "n_negative": len(neg), "auc": auc(pos, neg),
        "thresholds": {name: confusion(pos, neg, t) for name, t in THRESHOLDS.items()},
    }


def ablation(outcomes: list[Outcome]) -> dict:
    """AUC of each rule family on its own, phishing vs ham, test split only.

    Above 0.5 the family ranks phishing above legitimate mail; below 0.5 it
    ranks legitimate mail higher -- i.e. it carries signal pointing the wrong
    way on this corpus.
    """
    rows = [o for o in outcomes if o.score is not None and o.split == "test"]
    pos = [o for o in rows if o.group == "phish"]
    neg = [o for o in rows if o.group == "ham"]
    result = {}
    for family in list(FAMILIES) + ["all"]:
        pick = (lambda o: o.score) if family == "all" else (lambda o, f=family: o.family_points.get(f, 0))
        result[family] = auc([pick(o) for o in pos], [pick(o) for o in neg])
    return result


def rule_rates(outcomes: list[Outcome]) -> list[dict]:
    """How often each rule fires on legitimate vs phishing mail."""
    ok = [o for o in outcomes if o.score is not None]
    by_group = {g: [o for o in ok if o.group == g] for g in ("ham", "spam", "phish")}
    codes = sorted({c for o in ok for c in o.codes})
    table = []
    for code in codes:
        rate = {g: (sum(code in o.codes for o in rows) / len(rows) if rows else math.nan)
                for g, rows in by_group.items()}
        table.append({"code": code, **rate,
                      "lift_phish_vs_ham": (rate["phish"] / rate["ham"]
                                            if rate["ham"] else math.inf)})
    return sorted(table, key=lambda r: -r["phish"])


# ──────────────────────────────────────────────────────────────────────────
# main
# ──────────────────────────────────────────────────────────────────────────

def main() -> int:
    if not CORPORA.exists():
        print(f"No corpora at {CORPORA}. Run eval/fetch_corpora.py first.", file=sys.stderr)
        return 1

    started = time.perf_counter()
    seen: set[str] = set()
    duplicates = Counter()
    outcomes: list[Outcome] = []

    loaders = [
        load_spamassassin(CORPORA / "spamassassin"),
        load_nazario(CORPORA / "nazario"),
    ]
    for loader in loaders:
        for sample in loader:
            digest = hashlib.sha256(sample.raw).hexdigest()
            if digest in seen:
                duplicates[sample.corpus] += 1
                continue
            seen.add(digest)
            outcomes.append(evaluate(sample))
            if len(outcomes) % 2000 == 0:
                print(f"  {len(outcomes):>6} messages  ({time.perf_counter() - started:5.0f}s)")

    elapsed = time.perf_counter() - started
    errors = [o for o in outcomes if o.error]
    ok = [o for o in outcomes if o.score is not None]

    composition = Counter((o.corpus, o.group) for o in outcomes)
    summary = {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "method": {
            "live_dns": False, "network_reputation": False, "rules_tuned_on_corpus": False,
            "dedup": "sha256 of raw bytes", "split_seed": SPLIT_SEED,
            "holdout_fraction": HOLDOUT_FRACTION,
        },
        "counts": {
            "messages": len(outcomes), "analysed": len(ok), "errors": len(errors),
            "duplicates_removed": dict(duplicates),
            "composition": {f"{c}/{g}": n for (c, g), n in sorted(composition.items())},
            "seconds": round(elapsed, 1),
            "ms_per_message": round(1000 * elapsed / max(1, len(outcomes)), 2),
        },
        "tasks": {
            "phish_vs_ham": {"all": task(outcomes, {"phish"}, None),
                             "test": task(outcomes, {"phish"}, "test")},
            "spam_vs_ham": {"all": task(outcomes, {"spam"}, None)},
            "malicious_vs_ham": {"all": task(outcomes, {"phish", "spam"}, None)},
        },
        "phish_detection_by_era": {},
        "rules": rule_rates(outcomes),
        "ablation_auc_test": ablation(outcomes),
        "false_positive_drivers": {},
        "error_samples": [o.error for o in errors[:10]],
    }

    for era in sorted({o.era for o in ok if o.group == "phish"}):
        scores = [o.score for o in ok if o.group == "phish" and o.era == era]
        hits = sum(s >= THRESHOLDS["High-Risk+"] for s in scores)
        summary["phish_detection_by_era"][era] = {
            "n": len(scores), "recall_high_risk": hits / len(scores) if scores else math.nan,
            "recall_ci": wilson(hits, len(scores)),
            "mean_score": sum(scores) / len(scores) if scores else math.nan,
        }

    fp = [o for o in ok if o.group == "ham" and o.score >= THRESHOLDS["High-Risk+"]]
    driver = Counter(c for o in fp for c in o.codes)
    summary["false_positive_drivers"] = {
        "n_false_positives_high_risk": len(fp),
        "rule_present_in_fraction_of_them": {c: n / len(fp) for c, n in driver.most_common(10)} if fp else {},
    }

    RESULTS.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d")
    with (RESULTS / f"corpus_{stamp}.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["uid", "corpus", "source", "group", "era", "split",
                         "score", "level", "hops", "rules", "error"])
        for o in outcomes:
            writer.writerow([o.uid, o.corpus, o.source, o.group, o.era, o.split,
                             o.score, o.level, o.hops, ";".join(o.codes), o.error or ""])
    (RESULTS / f"corpus_{stamp}_summary.json").write_text(
        json.dumps(summary, indent=2, default=lambda v: None if isinstance(v, float) and math.isnan(v) else v),
        encoding="utf-8")

    (RESULTS / f"corpus_{stamp}_report.md").write_text(render_report(summary), encoding="utf-8")
    print_summary(summary)
    print(f"\nWrote {RESULTS / f'corpus_{stamp}.csv'}, the summary JSON and the markdown report.")
    return 0


def render_report(s: dict) -> str:
    """Every number in the write-up comes from here, never from hand-copying."""
    c = s["counts"]
    t = s["tasks"]["phish_vs_ham"]["test"]
    a = s["tasks"]["phish_vs_ham"]["all"]

    def band_row(band: str, m: dict) -> str:
        lo, hi = m["recall_ci"]
        flo, fhi = m["fpr_ci"]
        return (f"| {band} | {pct(m['precision'])} | {pct(m['recall'])} [{pct(lo)}–{pct(hi)}] | "
                f"{pct(m['fpr'])} [{pct(flo)}–{pct(fhi)}] | {pct(m['f1'])} |")

    def lift(value) -> str:
        return "∞" if value is None or value == math.inf else f"{value:.2f}"

    lines = [
        "# Corpus evaluation — Layer 1 time-independent signals",
        "",
        f"Generated {s['generated']} by `eval/run_corpus.py`. Do not edit by hand.",
        "",
        "## Method",
        "",
        "- Live DNS **off**: the corpora date from 2002–2025, so re-verifying SPF/DKIM/DMARC today "
        "would measure each domain's current DNS, not the message's authenticity when sent.",
        "- Network reputation **off**: it describes an IP's use today, not at sending time.",
        "- Measured: identity, infrastructure, relay-chain integrity and content signals only.",
        "- Rules were written before these corpora were seen. One hyperparameter — the relay "
        "clock-skew tolerance — was then chosen on the **development** split. Results are on the "
        "**held-out test** split unless stated.",
        f"- Exact duplicates removed by SHA-256: {c['duplicates_removed']}.",
        f"- Split seed {s['method']['split_seed']}, {int(100 * s['method']['holdout_fraction'])}% held out.",
        "",
        "## Data",
        "",
        "| Corpus / class | Messages |",
        "| --- | --- |",
        *[f"| {k} | {v} |" for k, v in c["composition"].items()],
        f"| **Total unique** | **{c['messages']}** ({c['errors']} errors) |",
        "",
        "## Phishing vs legitimate — held-out test split",
        "",
        f"AUC **{t['auc']:.3f}** ({t['n_positive']} phishing, {t['n_negative']} legitimate). "
        f"Full-corpus AUC {a['auc']:.3f}.",
        "",
        "| Band | Precision | Recall [95% CI] | False-positive rate [95% CI] | F1 |",
        "| --- | --- | --- | --- | --- |",
        *[band_row(b, m) for b, m in t["thresholds"].items()],
        "",
        "## Ablation — AUC of each rule family alone (test split)",
        "",
        "Above 0.5 a family ranks phishing above legitimate mail; below 0.5 it points the wrong way.",
        "",
        "| Family | AUC |",
        "| --- | --- |",
        *[f"| {f} | {v:.3f} |" for f, v in s["ablation_auc_test"].items()],
        "",
        "## Rule firing rates (full corpus)",
        "",
        "| Rule | Legitimate | Phishing | Spam | Lift (phish / legit) |",
        "| --- | --- | --- | --- | --- |",
        *[f"| `{r['code']}` | {pct(r['ham'])} | {pct(r['phish'])} | {pct(r['spam'])} | "
          f"{lift(r['lift_phish_vs_ham'])} |" for r in s["rules"]],
        "",
        "## Phishing recall at High-Risk+ by year",
        "",
        "| Year | n | Recall [95% CI] | Mean score |",
        "| --- | --- | --- | --- |",
        *[f"| {e} | {v['n']} | {pct(v['recall_high_risk'])} "
          f"[{pct(v['recall_ci'][0])}–{pct(v['recall_ci'][1])}] | {v['mean_score']:.1f} |"
          for e, v in s["phish_detection_by_era"].items()],
        "",
        "## Sources and licences",
        "",
        "- SpamAssassin public corpus, https://spamassassin.apache.org/old/publiccorpus/ — message "
        "copyright remains with the senders; used offline only and not redistributed.",
        "- J. Nazario, Phishing Corpus, https://monkey.org/~jose/phishing/ — CC-BY-4.0.",
        "",
    ]
    return "\n".join(lines)


def pct(x: float) -> str:
    return "  n/a " if x is None or (isinstance(x, float) and math.isnan(x)) else f"{100 * x:5.1f}%"


def print_summary(s: dict) -> None:
    c = s["counts"]
    print(f"\n{c['messages']} unique messages ({c['analysed']} analysed, {c['errors']} errors), "
          f"{c['ms_per_message']} ms/message")
    print(f"duplicates removed: {c['duplicates_removed']}")
    for k, v in c["composition"].items():
        print(f"  {k:28s} {v:>6}")

    for name, key in (("PHISHING vs HAM", "phish_vs_ham"), ("SPAM vs HAM", "spam_vs_ham"),
                      ("ALL MALICIOUS vs HAM", "malicious_vs_ham")):
        t = s["tasks"][key]["all"]
        print(f"\n{name}   positives={t['n_positive']}  negatives={t['n_negative']}  "
              f"AUC={t['auc']:.3f}")
        print(f"  {'band':12s} {'precision':>9} {'recall':>8} {'FPR':>8} {'F1':>7}   TP/FP/TN/FN")
        for band, m in t["thresholds"].items():
            print(f"  {band:12s} {pct(m['precision']):>9} {pct(m['recall']):>8} "
                  f"{pct(m['fpr']):>8} {pct(m['f1']):>7}   "
                  f"{m['tp']}/{m['fp']}/{m['tn']}/{m['fn']}")

    t = s["tasks"]["phish_vs_ham"]["test"]
    print(f"\nHELD-OUT TEST SPLIT, PHISHING vs HAM   AUC={t['auc']:.3f}  "
          f"(positives={t['n_positive']}, negatives={t['n_negative']})")
    for band, m in t["thresholds"].items():
        lo, hi = m["fpr_ci"]
        print(f"  {band:12s} precision {pct(m['precision'])}  recall {pct(m['recall'])}  "
              f"FPR {pct(m['fpr'])} [{pct(lo)}-{pct(hi)}]")

    print("\nABLATION: AUC of each rule family alone (test split, phishing vs ham)")
    for family, value in s["ablation_auc_test"].items():
        print(f"  {family:16s} {value:.3f}")

    print("\nPHISHING RECALL AT High-Risk+ BY ERA")
    for era, e in s["phish_detection_by_era"].items():
        lo, hi = e["recall_ci"]
        print(f"  {era:10s} n={e['n']:>5}  recall {pct(e['recall_high_risk'])} "
              f"[{pct(lo)}-{pct(hi)}]  mean score {e['mean_score']:.1f}")


if __name__ == "__main__":
    raise SystemExit(main())
