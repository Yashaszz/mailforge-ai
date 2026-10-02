# Corpus evaluation — Layer 1 time-independent signals

Generated 2026-10-02T08:33:14+00:00 by `eval/run_corpus.py`. Do not edit by hand.

## Method

- Live DNS **off**: the corpora date from 2002–2025, so re-verifying SPF/DKIM/DMARC today would measure each domain's current DNS, not the message's authenticity when sent.
- Network reputation **off**: it describes an IP's use today, not at sending time.
- Measured: identity, infrastructure, relay-chain integrity and content signals only.
- Rules were written before these corpora were seen. One hyperparameter — the relay clock-skew tolerance — was then chosen on the **development** split. Results are on the **held-out test** split unless stated.
- Exact duplicates removed by SHA-256: {'nazario': 7}.
- Split seed 20261002, 70% held out.

## Data

| Corpus / class | Messages |
| --- | --- |
| nazario/phish | 12003 |
| spamassassin/ham | 4150 |
| spamassassin/spam | 1896 |
| **Total unique** | **18049** (0 errors) |

## Phishing vs legitimate — held-out test split

AUC **0.463** (8351 phishing, 2933 legitimate). Full-corpus AUC 0.462.

| Band | Precision | Recall [95% CI] | False-positive rate [95% CI] | F1 |
| --- | --- | --- | --- | --- |
| Suspicious+ |  81.6% |  37.2% [ 36.2%– 38.3%] |  23.9% [ 22.4%– 25.5%] |  51.1% |
| High-Risk+ |  89.9% |   3.1% [  2.8%–  3.5%] |   1.0% [  0.7%–  1.4%] |   6.0% |
| Malicious | 100.0% |   0.1% [  0.0%–  0.2%] |   0.0% [  0.0%–  0.1%] |   0.2% |

## Ablation — AUC of each rule family alone (test split)

Above 0.5 a family ranks phishing above legitimate mail; below 0.5 it points the wrong way.

| Family | AUC |
| --- | --- |
| content | 0.734 |
| identity | 0.321 |
| infrastructure | 0.390 |
| chain_integrity | 0.558 |
| all | 0.463 |

## Rule firing rates (full corpus)

| Rule | Legitimate | Phishing | Spam | Lift (phish / legit) |
| --- | --- | --- | --- | --- |
| `helo_mismatch` |  90.6% |  87.2% |  93.7% | 0.96 |
| `urgency_language_weak` |   5.1% |  29.5% |  18.8% | 5.76 |
| `urgency_language` |   0.6% |  22.3% |   8.2% | 37.01 |
| `envelope_mismatch` |  70.7% |  22.0% |  19.9% | 0.31 |
| `relay_timestamps_impossible` |   1.8% |  13.1% |   7.0% | 7.47 |
| `reply_to_mismatch` |  19.1% |   7.5% |  13.1% | 0.39 |
| `brand_impersonation` |   0.0% |   6.0% |   0.0% | 124.30 |
| `display_name_spoof` |   0.1% |   1.5% |   0.5% | 15.56 |
| `non_public_origin` |  15.4% |   0.4% |   0.0% | 0.03 |
| `suspicious_tld` |   0.0% |   0.2% |   0.0% | ∞ |
| `no_relay_path` |   3.3% |   0.1% |   0.0% | 0.03 |

## Phishing recall at High-Risk+ by year

| Year | n | Recall [95% CI] | Mean score |
| --- | --- | --- | --- |
| 2005-2007 | 8538 |   3.8% [  3.4%–  4.2%] | 20.1 |
| 2015 | 307 |   3.9% [  2.2%–  6.7%] | 18.0 |
| 2016 | 494 |   1.8% [  1.0%–  3.4%] | 12.4 |
| 2017 | 325 |   2.2% [  1.0%–  4.4%] | 13.7 |
| 2018 | 288 |   1.7% [  0.7%–  4.0%] | 12.6 |
| 2019 | 243 |   1.6% [  0.6%–  4.2%] | 11.0 |
| 2020 | 158 |   1.3% [  0.3%–  4.5%] | 14.4 |
| 2021 | 101 |   0.0% [  0.0%–  3.7%] | 11.6 |
| 2022 | 246 |   0.8% [  0.2%–  2.9%] | 13.8 |
| 2023 | 419 |   0.5% [  0.1%–  1.7%] | 10.4 |
| 2024 | 403 |   0.2% [  0.0%–  1.4%] | 11.5 |
| 2025 | 481 |   0.0% [  0.0%–  0.8%] | 11.3 |

## Sources and licences

- SpamAssassin public corpus, https://spamassassin.apache.org/old/publiccorpus/ — message copyright remains with the senders; used offline only and not redistributed.
- J. Nazario, Phishing Corpus, https://monkey.org/~jose/phishing/ — CC-BY-4.0.
