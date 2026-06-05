# DLP / PII Scanner & Redactor

A **data security** tool that finds sensitive data (PII) in text and files,
classifies it by sensitivity, and produces a **redacted** copy. Credit cards are
**Luhn-validated** so arbitrary 16-digit numbers aren't mistaken for cards. Pure
standard library.

| Area | What's shown |
|------|--------------|
| **Data security / DLP** | sensitive-data discovery + classification + masking |
| **Detection accuracy** | Luhn checksum for cards, range checks for IPs (fewer false positives) |
| **Privacy by design** | redaction keeps only a card's last 4 digits; values never echoed |

## Detects

| Type | Severity | Notes |
|------|----------|-------|
| SSN | high | `NNN-NN-NNNN` |
| Credit card | high | 13–19 digits, **Luhn-validated** |
| AWS access key | high | `AKIA…` |
| Email | medium | |
| Phone (US) | medium | |
| IP address | low | octet-range checked |

## Run

```bash
docker build -t dlp-scanner .

# scan: report PII counts per file (exit non-zero if any found)
docker run --rm -v "$PWD:/data" dlp-scanner scan /data

# redact: print a masked copy of a file
docker run --rm -v "$PWD:/data" dlp-scanner redact /data/customers.csv
```

Locally: `python -m dlp.cli scan <path>` / `python -m dlp.cli redact <file>`.

Example redaction:

```
in:   SSN 123-45-6789, card 4111 1111 1111 1111, email alice@example.com
out:  SSN [REDACTED:ssn], card [CARD ****1111], email [REDACTED:email]
```

## Tests

```bash
python -m pytest          # Luhn, per-type detection, redaction, no-false-positives
```

## Layout

```
dlp/detectors.py  regex + Luhn PII detectors (typed Findings with spans)
dlp/redact.py     overlap-merged redaction (cards keep last 4)
dlp/cli.py        scan / redact commands, CI-gating exit code
tests/            detection + redaction tests
```
