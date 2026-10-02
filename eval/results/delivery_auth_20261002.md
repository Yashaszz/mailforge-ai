# Delivery-time authentication of modern phishing

Generated 2026-10-02T08:35:19+00:00 by `eval/delivery_auth.py`. Do not edit by hand.

Nazario phishing 2022–2025: **1547** messages carry a delivery-time Authentication-Results header (3 do not and are excluded).
Stamped by the recipient's provider (`b.hostedemail.com`).

## Pass rate at delivery

| Check | Passed [95% CI] | Other outcomes |
| --- | --- | --- |
| SPF | 73.0% [70.7–75.1] | softfail 174, none 152, fail 67, neutral 12, temperror 11, permerror 2 |
| DKIM | 67.2% [64.8–69.5] | none 467, fail 24, absent 11, temperror 6 |
| DMARC | 48.7% [46.2–51.2] | none 718, fail 42, temperror 15, absent 11, permerror 8 |

## DMARC pass rate by year

| Year | Messages | DMARC passed [95% CI] |
| --- | --- | --- |
| 2022 | 245 | 23.3% [18.4–28.9] |
| 2023 | 419 | 39.4% [34.8–44.1] |
| 2024 | 402 | 59.0% [54.1–63.7] |
| 2025 | 481 | 61.1% [56.7–65.4] |

## Reading

A DMARC pass means the visible From domain was authenticated: the sender controlled it. Phishing that passes was sent from lookalike or newly registered domains with valid authentication, from compromised accounts, or through legitimate services. Authentication establishes who sent a message, not whether they are trustworthy.

Source: J. Nazario, Phishing Corpus, https://monkey.org/~jose/phishing/ (CC-BY-4.0). One hand-classified inbox; indicative, not a population estimate.
