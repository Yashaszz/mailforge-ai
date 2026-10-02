"""Download the public evaluation corpora into data/corpora/ (gitignored).

The corpora are NOT committed: SpamAssassin's messages remain the copyright of
their senders, and redistributing them is not ours to do. This script records
exactly what was fetched, from where, with SHA-256 digests, so a result can be
reproduced against the same bytes.

Sources
-------
SpamAssassin public corpus -- https://spamassassin.apache.org/old/publiccorpus/
    "suitable for use in testing spam filtering systems"; copyright stays with
    the original senders; not to be used to test a live mail system. We only
    parse offline.
Nazario phishing corpus -- https://monkey.org/~jose/phishing/
    CC-BY-4.0. Attribution required: cite J. Nazario, Phishing Corpus.

Usage:  python eval/fetch_corpora.py
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Live phishing should not sit in a cloud-synced folder, so the location is
# configurable; it defaults to the repo's gitignored data/ directory.
DEST = Path(os.environ.get("MAILFORGE_CORPORA", ROOT / "data" / "corpora"))

SPAMASSASSIN = "https://spamassassin.apache.org/old/publiccorpus/"
NAZARIO = "https://monkey.org/~jose/phishing/"

# The conventional SpamAssassin selection: the 2003 ham sets and the 2003 and
# 2005 spam sets. The 2002 archives are earlier subsets of these.
FILES: list[tuple[str, str, str]] = [
    ("spamassassin", SPAMASSASSIN, "20030228_easy_ham.tar.bz2"),
    ("spamassassin", SPAMASSASSIN, "20030228_easy_ham_2.tar.bz2"),
    ("spamassassin", SPAMASSASSIN, "20030228_hard_ham.tar.bz2"),
    ("spamassassin", SPAMASSASSIN, "20030228_spam.tar.bz2"),
    ("spamassassin", SPAMASSASSIN, "20050311_spam_2.tar.bz2"),
] + [
    ("nazario", NAZARIO, name) for name in (
        "phishing0.mbox", "phishing1.mbox", "phishing2.mbox", "phishing3.mbox",
        "20051114.mbox", "private-phishing4.mbox",
        *(f"phishing-{year}" for year in range(2015, 2026)),
        "README.txt", "LICENSE.txt",
    )
]


def fetch(url: str, path: Path) -> None:
    """Download atomically.

    Bytes land in a .part file that is renamed only once complete, and checked
    against Content-Length when the server sends one. An interrupted download
    must never be mistaken for a finished file on the next run -- a silently
    truncated corpus would corrupt every number computed from it.
    """
    partial = path.with_name(path.name + ".part")
    request = urllib.request.Request(url, headers={"User-Agent": "Mailforge-eval/0.1"})
    with urllib.request.urlopen(request, timeout=120) as response, partial.open("wb") as out:
        expected = response.headers.get("Content-Length")
        while chunk := response.read(1 << 16):
            out.write(chunk)
    if expected is not None and partial.stat().st_size != int(expected):
        got = partial.stat().st_size
        partial.unlink(missing_ok=True)
        raise OSError(f"truncated download: {got} of {expected} bytes")
    partial.replace(path)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    manifest = []
    for corpus, base, name in FILES:
        folder = DEST / corpus
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / name
        if path.exists() and path.stat().st_size > 0:
            status = "cached"
        else:
            try:
                fetch(base + name, path)
                status = "downloaded"
            except Exception as exc:          # one bad file must not stop the rest
                print(f"  FAILED  {corpus}/{name}: {exc}", file=sys.stderr)
                path.unlink(missing_ok=True)
                continue
        try:
            digest = sha256(path)
        except OSError as exc:
            # Endpoint security software routinely blocks phishing archives.
            # Record the exclusion rather than dropping it silently: a file
            # missing from the evaluation is a selection bias to be reported.
            status, digest = "blocked", None
            print(f"  BLOCKED  {corpus}/{name}: unreadable ({exc.strerror}) - "
                  f"likely local antivirus", file=sys.stderr)
        manifest.append({
            "corpus": corpus, "file": name, "url": base + name, "status": status,
            "bytes": path.stat().st_size if path.exists() else 0, "sha256": digest,
        })
        if status != "blocked":
            print(f"  {status:10s} {corpus}/{name}  {path.stat().st_size / 1e6:6.1f} MB")

    (DEST / "MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    total = sum(m["bytes"] for m in manifest)
    print(f"\n{len(manifest)} files, {total / 1e6:.1f} MB -> {DEST}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
