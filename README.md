<div align="center">

# 🛡️ Mailforge AI

**Email fraud detection + forensic tracing**

Smart India Hackathon 2026 · Problem Statement 26106
Team **SNPSU Zyronix** · SNPSU0282

*Traditional filters tell you an email is phishing.
Mailforge also tells you **where it came from**.*

</div>

---

## The problem

A spam filter gives you a boolean. When a ₹40-lakh wire transfer has already
gone out, "it was phishing" is not an answer — an investigator needs to know
which IP opened the connection, which relays carried the message, whether the
sending domain actually authorised it, and whether this message belongs to a
wider campaign.

Mailforge is a three-layer platform that does both: it **detects**, and it
**traces**.

| Layer | Role | Cost |
|---|---|---|
| **1 · SMTP Gateway** | IP reputation, SPF/DKIM/DMARC, risk classification | cheap — runs on every message |
| **2 · AI Content Analysis** | NLP classifier, URL &amp; attachment analysis, threat-intel lookup | moderate |
| **3 · Deep Forensics** | Relay-path reconstruction, geolocation, campaign correlation | expensive — high-risk mail only |

The design is **progressive**: Layer 1 filters bulk traffic cheaply, and the
expensive forensics only run on what survives.

---

## What works today

**Layer 1 is complete and operational**, with a full analyst dashboard.

- Raw `.eml` parsing and SMTP-envelope reconstruction from headers
- **SPF** evaluated against the true originating IP (RFC 7208, `pyspf`)
- **DKIM** cryptographic signature verification (RFC 6376, `dkimpy`)
- **DMARC** policy discovery + identifier alignment (RFC 7489)
- **Risk scoring** into Allow / Suspicious / High-Risk / Malicious, with every
  point attributable to a named, human-readable reason
- **Relay-path reconstruction** — the full `Received:` chain, origin hop marked
- Web dashboard with one-click demo scenarios, drag-and-drop upload, and paste

```
                    ┌──────────────────────────────────────┐
  .eml ───────────▶ │  parse headers + Received chain      │
                    │  reconstruct SMTP envelope           │
                    └──────────────┬───────────────────────┘
                                   ▼
                    ┌──────────────────────────────────────┐
                    │  SPF      pyspf      ← client IP     │
                    │  DKIM     dkimpy     ← live DNS key  │
                    │  DMARC    alignment  ← RFC 7489      │
                    └──────────────┬───────────────────────┘
                                   ▼
                    ┌──────────────────────────────────────┐
                    │  risk engine → score + reasons       │
                    └──────────────┬───────────────────────┘
                                   ▼
                         Allow / Suspicious /
                         High-Risk / Malicious
```

---

## Run it

Requires **Python 3.11+** (developed on 3.13). No Node, no build step, no
database — the backend serves the dashboard itself.

```bash
git clone https://github.com/Yashaszz/mailforge-ai.git
```

```bash
cd mailforge-ai/backend
```

Create the virtual environment. On **Windows** use the `py` launcher — a bare
`python` often resolves to the Microsoft Store stub and fails:

```bash
py -3 -m venv .venv
```

On **macOS / Linux**:

```bash
python3 -m venv .venv
```

Activate it — **Windows**:

```bash
.venv\Scripts\activate
```

**macOS / Linux**:

```bash
source .venv/bin/activate
```

Then, from `backend/`:

```bash
pip install -r requirements.txt
```

```bash
uvicorn app.main:app --reload
```

Open **<http://127.0.0.1:8000>** — that is the whole application.

| URL | What it is |
|---|---|
| `http://127.0.0.1:8000` | Analyst dashboard |
| `http://127.0.0.1:8000/docs` | Interactive OpenAPI reference |
| `http://127.0.0.1:8000/health` | Liveness + mode |

> **Demoing on unreliable wifi?** Start with `MAILFORGE_OFFLINE=true` and the
> parser, relay-path reconstruction and dashboard all still work; only the DNS
> checks report `not_checked`.

---

## The demo: three clicks, three verdicts

The dashboard ships with three bundled scenarios. Click each in order — they
tell a complete story.

| # | Scenario | Verdict | What it demonstrates |
|---|---|---|---|
| 1 | **Legitimate mail** | 🟢 `Allow` | SPF passes, DMARC aligns, and the internal `127.0.0.1` hop is correctly skipped when picking the client IP. |
| 2 | **Spoofed PayPal phishing** | 🔴 `Malicious` | `From: service@paypal.com` sent from an unrelated VPS. SPF alone misses it; DMARC alignment catches it. |
| 3 | **CEO fraud (BEC)** | 🔴 `Malicious` | No failed check at all — the lookalike domain publishes *nothing*. Scoring the absence is what catches it. |
| 4 | **Anonymised sender (VPN)** | 🔴 `Malicious` | Sent straight from a commercial VPN exit, so the real network is unrecoverable. |
| 5 | **Multi-hop relay laundering** | 🔴 `Malicious` | Routed Lagos → Sofia → **Tor exit** → VPN before delivery, plotted on the world map. |
| 6 | **Forged relay headers** | 🔴 `Malicious` | Fake internal hops prepended to fake a trusted origin — the timestamps make the forgery provable. |

**Scenario 2 is the one to dwell on.** SPF alone does not catch a brand spoof —
an attacker passes SPF for their own domain all day long. What catches it is
**DMARC alignment**: the authenticated domain versus the `From:` header the
victim actually sees. The dashboard shows that comparison explicitly.

**Scenario 3 makes the opposite point.** There is no failed check to point at,
because the throwaway domain publishes no SPF and no DMARC. A pass/fail-only
view sees nothing wrong. Mailforge scores the *absence* of authentication,
plus the redirected `Reply-To` that makes BEC work, and still flags it.

---

## API

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/analyze` | Analyse an uploaded `.eml` (multipart field `file`) |
| `GET` | `/samples` | List bundled demo messages |
| `POST` | `/samples/{name}/analyze` | Analyse a bundled sample |
| `GET` | `/health` | Liveness + offline mode |

```bash
curl -X POST http://127.0.0.1:8000/analyze -F "file=@samples/02_spoofed_paypal_phish.eml"
```

Abridged response:

```jsonc
{
  "assessment": {
    "score": 100,
    "level": "Malicious",
    "confidence": "high",
    "summary": "Block. DMARC failed - sender identity is not authenticated",
    "reasons": [
      { "severity": "critical", "points": 45, "code": "dmarc_fail",
        "title": "DMARC failed - sender identity is not authenticated",
        "detail": "Neither SPF nor DKIM produced a domain aligned with the visible From address..." },
      { "severity": "high", "points": 20, "code": "reply_to_mismatch", "...": "..." }
    ]
  },
  "message":  { "from_address": "service@paypal.com", "reply_to_address": "security-verification@paypa1-account-alerts.example" },
  "origin":   { "client_ip": "45.137.22.190", "client_ip_source": "First public IP in the Received chain (hop 1, ...)" },
  "authentication": {
    "spf":   { "result": "softfail" },
    "dkim":  { "result": "none" },
    "dmarc": { "result": "fail", "policy": "reject", "spf_alignment": "fail", "disposition": "reject" }
  },
  "received_chain": [ /* every hop, parsed */ ],
  "warnings": [ /* anything that made the analysis approximate */ ]
}
```

Authentication results follow RFC 8601: `pass`, `fail`, `softfail`, `neutral`,
`none`, `temperror`, `permerror`, plus `not_checked`.

---

## Design decisions worth defending

### Why not `checkdmarc`?

`checkdmarc` answers *"does this domain publish a valid SPF/DMARC record?"* —
domain hygiene. It never sees a message. Mailforge has to answer *"did **this
message**, from **this IP**, carrying **this signature**, pass?"* Those are
different questions, so we compose the three reference implementations:

| Check | Library | What it does |
|---|---|---|
| SPF | `pyspf` | RFC 7208 evaluation against the recovered client IP |
| DKIM | `dkimpy` | RFC 6376 signature verification against the DNS public key |
| DMARC | `dnspython` + `publicsuffixlist` | Policy discovery, then RFC 7489 §3.1 alignment |

**No crypto or wire-protocol logic is hand-rolled.** The only thing implemented
directly is DMARC alignment, which is a domain comparison under the public
suffix list — so `mail.example.co.in` correctly aligns with `example.co.in`.

### Reconstructing an envelope that no longer exists

SPF is normally evaluated live by the receiving MTA against the IP that opened
the TCP connection. Analysing a `.eml` after the fact, there is no connection:

- **Client IP** — walk the `Received:` chain from the top, take the first
  *public* address. Hops above it are relays inside the recipient's own
  infrastructure; hops below it are asserted by the sender and cannot be
  trusted. Falls back to `X-Originating-IP`, flagged as lower trust.
- **MAIL FROM** — the `Return-Path` header, falling back to `From` with a
  recorded warning.
- **HELO** — the hostname in the selected hop's `from` clause.

Every one of these choices is reported back in `origin.client_ip_source` and
`warnings`. An SPF verdict is only as trustworthy as the IP it was evaluated
against, and an analyst has to be able to see *why* the tool concluded what it
did.

### Why the risk engine is rules, not ML (for now)

Authentication failures are **hard evidence**. A probabilistic content score
should not be able to wash out a cryptographic DMARC failure. So the rule
engine owns the authentication signals and stays fully explainable — every
point in the score has a named reason attached. The Layer 2 classifier will
contribute an *additional* content signal alongside these rules rather than
replacing them.

---

## Tests

```bash
cd backend
python -m pytest
```

**81 backend tests plus 21 extension tests, no network required.**

- DKIM is tested by signing a message with a keypair generated for this repo
  and verifying it through a stub resolver — real signature verification,
  including tamper cases (a modified body and a modified `Subject` both
  correctly `fail`).
- DMARC alignment, policy inheritance (`sp=`), and strict vs. relaxed modes run
  against a fake resolver.
- Risk scoring is pinned so the demo verdicts cannot silently regress.
- API tests cover the response contract, oversized uploads, empty files,
  non-email input, and malformed messages.
- Relay-timestamp forgery detection is tested against clock skew and
  cross-timezone chains so it cannot fire on ordinary mail.
- Extension tests (`cd extension && npm test`) pin message retrieval
  byte-for-byte, since a single altered byte turns a valid DKIM
  signature into a reported forgery.

---

## Layout

```
mailforge/
├── backend/
│   ├── app/
│   │   ├── main.py                FastAPI app + static dashboard
│   │   ├── config.py              env-overridable settings
│   │   ├── schemas.py             Pydantic response contract
│   │   └── services/
│   │       ├── eml_parser.py      header parsing, relay chain, envelope recovery
│   │       ├── email_auth.py      SPF / DKIM / DMARC
│   │       └── risk.py            scoring → verdict + reasons
│   ├── tests/                     68 tests, no network
│   └── requirements.txt
├── frontend/                      dashboard (vanilla JS, no build step)
├── samples/                       three demo .eml files
└── README.md
```

---

## Configuration

Copy `backend/.env.example` to `backend/.env`. Everything is optional.

| Variable | Default | Notes |
|---|---|---|
| `MAILFORGE_OFFLINE` | `false` | Skip all DNS; checks report `not_checked` |
| `MAILFORGE_DNS_SERVERS` | `1.1.1.1,8.8.8.8,9.9.9.9` | `system` to use the machine's resolver |
| `MAILFORGE_SPF_QUERYTIME` | `20.0` | Budget for a full SPF evaluation |
| `MAILFORGE_MAX_UPLOAD_BYTES` | `26214400` | 25 MB |

Public resolvers are the default deliberately: on the development network the
router's DNS took ~3 s per query and intermittently timed out, which turned
genuine SPF failures into `temperror`. Switching cut a full analysis from
~23 s to ~0.7 s.

---

## Roadmap

**Phase 2 — enrichment**
MaxMind GeoLite2 geolocation · WHOIS / DNS domain intelligence ·
VirusTotal + AbuseIPDB reputation for extracted URLs and IPs

**Phase 2 — content**
TF-IDF + Logistic Regression classifier trained on the Nazario phishing corpus,
SpamAssassin, and Enron. Folds in as an additional signal beside the rules.

**Phase 3 — forensics**
Visual relay-path rendering · NetworkX campaign correlation across messages
sharing domains or IPs · analyst True/False-Positive feedback capture

---

## Known limitations

- The client IP is **inferred**, not observed. Against mail whose `Received`
  chain has been stripped or forged above the trust boundary, the SPF result is
  only as good as that inference — which is why it is reported explicitly.
- DKIM verification needs the selector's key to still be published. Keys rotate,
  so archived mail can legitimately return `permerror`.
- `pct=` is parsed and reported but not applied as sampling.
- No live SMTP gateway — the pipeline is driven by `.eml` files, by design.
- The urgency-language rule is a deliberately small placeholder for the Layer 2
  NLP classifier, not a serious content model.

---

<div align="center">
<sub>Built for Smart India Hackathon 2026 · Problem Statement 26106 · Team SNPSU Zyronix</sub>
</div>
