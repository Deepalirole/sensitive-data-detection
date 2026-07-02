"""
Sensitive data detection engine.

Uses a curated set of regular expressions plus light validation
(Luhn check for cards, checksum-style filters) to detect and locate
sensitive / confidential information inside free text.

Each detector returns matches with their value, character span and a
category. The `SENSITIVITY` map assigns a per-category risk weight that
the classifier consumes to decide the document-level risk level.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable


# --------------------------------------------------------------------------- #
# Risk weighting per category. Higher weight = more damaging if leaked.
# --------------------------------------------------------------------------- #
SENSITIVITY: dict[str, int] = {
    "Aadhaar Number": 5,
    "PAN Number": 4,
    "Credit Card Number": 5,
    "Bank Account Number": 4,
    "IFSC Code": 2,
    "API Key / Secret": 5,
    "Password": 5,
    "Email Address": 2,
    "Phone Number": 2,
    "Employee ID": 2,
    "Confidential Business Info": 3,
}


@dataclass
class Match:
    category: str
    value: str
    start: int
    end: int
    weight: int

    def masked(self) -> str:
        """Return a redacted version of the value keeping only edges."""
        v = self.value
        if len(v) <= 4:
            return "*" * len(v)
        return v[:2] + "*" * (len(v) - 4) + v[-2:]


# --------------------------------------------------------------------------- #
# Validators
# --------------------------------------------------------------------------- #
def _luhn_ok(number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# --------------------------------------------------------------------------- #
# Pattern definitions.  (category, compiled regex, optional validator)
# --------------------------------------------------------------------------- #
@dataclass
class Pattern:
    category: str
    regex: re.Pattern
    validator: Callable[[str], bool] | None = None


# Order matters: more specific / higher-value patterns run first so they
# claim their spans before generic numeric patterns (phone, bank account).
_PATTERNS: list[Pattern] = [
    # Credit card: 13-16 digits with optional spaces/dashes, Luhn validated.
    Pattern(
        "Credit Card Number",
        re.compile(r"\b(?:\d[ -]?){13,16}\b"),
        validator=_luhn_ok,
    ),
    # Aadhaar: 12 digits, usually grouped in 3x4. First digit 2-9.
    Pattern(
        "Aadhaar Number",
        re.compile(r"\b[2-9][0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b"),
    ),
    # PAN: 5 letters, 4 digits, 1 letter.
    Pattern(
        "PAN Number",
        re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
    ),
    # IFSC: 4 letters, 0, 6 alnum.
    Pattern(
        "IFSC Code",
        re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
    ),
    # Email
    Pattern(
        "Email Address",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    # Phone: Indian / international, 10 digits optionally with +country code.
    # Runs before the generic bank-account pattern so 10-digit mobiles are
    # not misclassified as account numbers.
    Pattern(
        "Phone Number",
        re.compile(r"(?<!\d)(?:\+?\d{1,3}[\s-]?)?[6-9]\d{9}(?!\d)"),
    ),
    # Bank account: 9-18 digit standalone number (checked last among numerics).
    Pattern(
        "Bank Account Number",
        re.compile(r"\b\d{9,18}\b"),
    ),
    # API keys / secrets: common prefixes + long tokens.
    Pattern(
        "API Key / Secret",
        re.compile(
            r"\b(?:sk-[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{20,}"
            r"|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b"
        ),
    ),
    # Passwords / secrets assigned in key=value form.
    Pattern(
        "Password",
        re.compile(
            r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|token)\b\s*[:=]\s*"
            r"['\"]?([^\s'\"]{4,})['\"]?"
        ),
    ),
    # Employee IDs: EMP123, EMP-2024-0012 etc.
    Pattern(
        "Employee ID",
        re.compile(r"\b(?:EMP|EMPID|EID)[-_]?\d{3,8}\b", re.IGNORECASE),
    ),
]

# Keywords that flag confidential business information.
_CONFIDENTIAL_KEYWORDS = re.compile(
    r"(?i)\b(confidential|proprietary|internal use only|trade secret|"
    r"do not distribute|classified|restricted|nda|non-disclosure)\b"
)


def detect(text: str) -> list[Match]:
    """Scan text and return all non-overlapping sensitive matches."""
    matches: list[Match] = []
    claimed: list[tuple[int, int]] = []

    def overlaps(s: int, e: int) -> bool:
        return any(s < ce and e > cs for cs, ce in claimed)

    for pat in _PATTERNS:
        for m in pat.regex.finditer(text):
            # For grouped patterns (e.g. password), prefer the captured group.
            if pat.regex.groups:
                value = m.group(1)
                start, end = m.span(1)
            else:
                value, start, end = m.group(0), m.start(), m.end()

            if pat.validator and not pat.validator(value):
                continue
            if overlaps(start, end):
                continue

            claimed.append((start, end))
            matches.append(
                Match(
                    category=pat.category,
                    value=value.strip(),
                    start=start,
                    end=end,
                    weight=SENSITIVITY.get(pat.category, 1),
                )
            )

    for m in _CONFIDENTIAL_KEYWORDS.finditer(text):
        if not overlaps(m.start(), m.end()):
            claimed.append((m.start(), m.end()))
            matches.append(
                Match(
                    "Confidential Business Info",
                    m.group(0),
                    m.start(),
                    m.end(),
                    SENSITIVITY["Confidential Business Info"],
                )
            )

    matches.sort(key=lambda x: x.start)
    return matches


def summarize_counts(matches: list[Match]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for m in matches:
        counts[m.category] = counts.get(m.category, 0) + 1
    return counts


def redact(text: str, matches: list[Match]) -> str:
    """Return the text with every detected value replaced by a mask."""
    result = text
    for m in sorted(matches, key=lambda x: x.start, reverse=True):
        result = result[: m.start] + f"[REDACTED:{m.category}]" + result[m.end :]
    return result
