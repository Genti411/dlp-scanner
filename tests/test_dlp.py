import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dlp.detectors import find_all, luhn_valid
from dlp.redact import redact


def types(text):
    return {f.type for f in find_all(text)}


def test_luhn_validation():
    assert luhn_valid("4111111111111111")       # valid test Visa
    assert not luhn_valid("4111111111111112")    # one digit off -> invalid


def test_detects_each_pii_type():
    t = ("SSN 123-45-6789, card 4111 1111 1111 1111, "
         "email alice@example.com, phone (415) 555-0132, host 10.0.0.5")
    assert {"ssn", "credit_card", "email", "phone", "ip_address"} <= types(t)


def test_invalid_card_not_flagged_as_card():
    assert "credit_card" not in types("acct 4111 1111 1111 1112")


def test_aws_key_detected():
    assert "aws_key" in types("AWS_KEY=AKIA" + "ABCDEFGHIJKLMNOP")


def test_redaction_masks_and_keeps_card_last4():
    text = "SSN 123-45-6789 and card 4111 1111 1111 1111 for alice@example.com"
    red, findings = redact(text)
    assert "123-45-6789" not in red and "[REDACTED:ssn]" in red
    assert "4111 1111 1111 1111" not in red and "****1111" in red
    assert "alice@example.com" not in red
    assert {f.type for f in findings} >= {"ssn", "credit_card", "email"}


def test_no_false_positives_on_clean_text():
    assert find_all("Hello world, this is a perfectly clean document.") == []
