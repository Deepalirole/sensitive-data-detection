"""
Risk classification and compliance summary generation.

The classifier turns a list of detected matches into a document-level
risk level (Low / Medium / High) using a weighted score. The summary
generator produces compliance observations, security risks and
remediation steps. If an OpenAI API key is available it enriches the
summary with an LLM narrative; otherwise a deterministic rule-based
summary is used so the app always works offline.
"""

from __future__ import annotations

import os

from detector import Match, summarize_counts

# Categories mapped to the compliance regimes they implicate.
_COMPLIANCE_MAP = {
    "Aadhaar Number": "India DPDP Act 2023, Aadhaar Act",
    "PAN Number": "India DPDP Act 2023, Income Tax rules",
    "Credit Card Number": "PCI-DSS",
    "Bank Account Number": "RBI data norms, PCI-DSS",
    "IFSC Code": "RBI data norms",
    "API Key / Secret": "Internal security policy, OWASP",
    "Password": "Internal security policy, OWASP",
    "Email Address": "GDPR, DPDP Act (PII)",
    "Phone Number": "GDPR, DPDP Act (PII)",
    "Employee ID": "Internal HR data policy",
    "Confidential Business Info": "NDA / contractual confidentiality",
}


def classify(matches: list[Match]) -> tuple[str, int, dict[str, int]]:
    """
    Return (risk_level, score, counts).

    Score is the sum of per-match weights. Thresholds:
        0            -> Low
        1-9          -> Low
        10-24        -> Medium
        25+          -> High
    Presence of any weight-5 category (Aadhaar, cards, secrets) with
    multiple hits escalates to High regardless of total.
    """
    counts = summarize_counts(matches)
    score = sum(m.weight for m in matches)

    high_value_hits = sum(1 for m in matches if m.weight >= 5)

    if score == 0:
        level = "Low Risk"
    elif high_value_hits >= 3 or score >= 25:
        level = "High Risk"
    elif score >= 10 or high_value_hits >= 1:
        level = "Medium Risk"
    else:
        level = "Low Risk"

    return level, score, counts


def _rule_based_summary(matches: list[Match], level: str, counts: dict[str, int]) -> str:
    if not matches:
        return (
            "### Compliance Observations\n"
            "- No sensitive or confidential data was detected in this document.\n\n"
            "### Security Risks\n"
            "- None identified by automated scanning.\n\n"
            "### Suggested Remediation\n"
            "- No action required. Continue routine handling per data policy."
        )

    regimes = sorted({_COMPLIANCE_MAP.get(c, "General privacy policy") for c in counts})
    obs = [f"- **{cat}**: {n} instance(s) detected." for cat, n in sorted(counts.items())]

    risks = []
    if any(m.weight >= 5 for m in matches):
        risks.append("- Highly sensitive data (identifiers, cards or secrets) "
                     "present — exposure could cause identity theft or financial fraud.")
    if "API Key / Secret" in counts or "Password" in counts:
        risks.append("- Hard-coded credentials detected — risk of unauthorized "
                     "system access if the document leaks.")
    if "Email Address" in counts or "Phone Number" in counts:
        risks.append("- Personal contact data present — subject to privacy "
                     "regulations and phishing/targeting risk.")
    if not risks:
        risks.append("- Moderate exposure from the detected data categories.")

    remediation = [
        "- Mask or redact sensitive fields before sharing this document.",
        "- Restrict access on a need-to-know basis and encrypt at rest/in transit.",
        "- Rotate any exposed credentials/API keys immediately.",
        "- Log and audit access to this document.",
    ]

    return (
        f"**Overall Risk Level: {level}**\n\n"
        f"**Applicable regimes:** {', '.join(regimes)}\n\n"
        "### Compliance Observations\n" + "\n".join(obs) + "\n\n"
        "### Security Risks\n" + "\n".join(risks) + "\n\n"
        "### Suggested Remediation\n" + "\n".join(remediation)
    )


def _llm_summary(text: str, matches: list[Match], level: str, counts: dict[str, int]) -> str | None:
    """Try an OpenAI-generated narrative; return None if unavailable."""
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None
    try:
        from openai import OpenAI

        client = OpenAI(api_key=api_key)
        findings = "\n".join(f"- {c}: {n}" for c, n in counts.items())
        prompt = (
            "You are a data protection & compliance analyst. Based on the "
            f"detected sensitive data below (risk level: {level}), write a concise "
            "report with three sections: Compliance Observations, Security Risks, "
            "and Suggested Remediation. Reference GDPR, PCI-DSS and India's DPDP "
            f"Act where relevant.\n\nDetected data:\n{findings}"
        )
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
        )
        return resp.choices[0].message.content
    except Exception:
        return None


def generate_summary(text: str, matches: list[Match], level: str, counts: dict[str, int]) -> str:
    """Return a compliance summary, preferring LLM output, falling back to rules."""
    return _llm_summary(text, matches, level, counts) or _rule_based_summary(
        matches, level, counts
    )
