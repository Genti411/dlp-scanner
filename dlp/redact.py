"""Redact detected sensitive values from text.

Overlapping detections (e.g. a phone-shaped substring inside a card) are merged,
keeping the finding that starts first / spans widest, so each region is redacted
once. Credit cards keep the last 4 digits (a common, audit-friendly masking)."""
from __future__ import annotations

from .detectors import Finding, find_all


def _mask(f: Finding) -> str:
    if f.type == "credit_card":
        last4 = "".join(c for c in f.value if c.isdigit())[-4:]
        return f"[CARD ****{last4}]"
    return f"[REDACTED:{f.type}]"


def _dedupe(findings: list[Finding]) -> list[Finding]:
    # Prefer earlier start; on tie, the wider span.
    ordered = sorted(findings, key=lambda f: (f.start, -(f.end - f.start)))
    merged: list[Finding] = []
    for f in ordered:
        if merged and f.start < merged[-1].end:
            continue  # overlaps a kept finding
        merged.append(f)
    return merged


def redact(text: str) -> tuple[str, list[Finding]]:
    findings = find_all(text)
    out: list[str] = []
    cursor = 0
    for f in _dedupe(findings):
        out.append(text[cursor:f.start])
        out.append(_mask(f))
        cursor = f.end
    out.append(text[cursor:])
    return "".join(out), findings
