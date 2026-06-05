"""PII / sensitive-data detectors.

Each detector yields Findings (type, severity, value, span). Credit cards are
validated with the Luhn checksum to cut false positives — a key DLP technique, so
arbitrary 16-digit numbers aren't flagged as cards.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class Finding:
    type: str
    severity: str
    value: str
    start: int
    end: int


def luhn_valid(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CARD = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_PHONE = re.compile(r"\b(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]?\d{3}[ .-]?\d{4}\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_AWS = re.compile(r"\bAKIA[0-9A-Z]{16}\b")


def find_all(text: str) -> list[Finding]:
    out: list[Finding] = []

    for m in _SSN.finditer(text):
        out.append(Finding("ssn", "high", m.group(), m.start(), m.end()))

    for m in _CARD.finditer(text):
        if luhn_valid(m.group()):
            out.append(Finding("credit_card", "high", m.group(), m.start(), m.end()))

    for m in _AWS.finditer(text):
        out.append(Finding("aws_key", "high", m.group(), m.start(), m.end()))

    for m in _EMAIL.finditer(text):
        out.append(Finding("email", "medium", m.group(), m.start(), m.end()))

    for m in _PHONE.finditer(text):
        out.append(Finding("phone", "medium", m.group(), m.start(), m.end()))

    for m in _IPV4.finditer(text):
        parts = m.group().split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            out.append(Finding("ip_address", "low", m.group(), m.start(), m.end()))

    return out
