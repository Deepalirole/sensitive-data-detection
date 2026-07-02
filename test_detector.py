"""Basic tests for detection, validation and classification."""

from detector import detect, summarize_counts, redact
from classifier import classify


def test_detects_common_pii():
    text = (
        "Email: a@b.com Phone: 9876543210 PAN: ABCDE1234F "
        "Aadhaar: 2345 6789 0123 Card: 4111 1111 1111 1111"
    )
    counts = summarize_counts(detect(text))
    assert counts.get("Email Address") == 1
    assert counts.get("Phone Number") == 1
    assert counts.get("PAN Number") == 1
    assert counts.get("Aadhaar Number") == 1
    assert counts.get("Credit Card Number") == 1


def test_rejects_invalid_credit_card():
    # Fails Luhn check -> not a card.
    counts = summarize_counts(detect("Card: 1234 5678 9012 3456"))
    assert counts.get("Credit Card Number") is None


def test_detects_secrets():
    counts = summarize_counts(detect("API_KEY = sk-ABCDEF1234567890abcdef\npassword = hunter2"))
    assert counts.get("API Key / Secret") == 1
    assert counts.get("Password") >= 1


def test_high_risk_classification():
    text = (
        "Aadhaar: 2345 6789 0123 Card: 4111 1111 1111 1111 "
        "sk-ABCDEF1234567890abcdef password = SuperSecret1"
    )
    level, score, _ = classify(detect(text))
    assert level == "High Risk"
    assert score > 0


def test_empty_is_low_risk():
    level, score, _ = classify(detect("Just a normal sentence with no secrets."))
    assert level == "Low Risk"
    assert score == 0


def test_redaction_removes_values():
    text = "Email: secret@corp.com"
    red = redact(text, detect(text))
    assert "secret@corp.com" not in red
    assert "REDACTED" in red
