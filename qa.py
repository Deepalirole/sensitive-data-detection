"""
Question answering over the uploaded document.

Two layers:
  1. A deterministic intent handler that answers the common analytical
     questions from the detection results (counts, categories, risks) —
     works fully offline and is fast/accurate.
  2. An optional retrieval-augmented LLM answer for open-ended questions,
     used only when an OpenAI key is configured.
"""

from __future__ import annotations

import os
import re

from detector import Match, summarize_counts
from classifier import classify, generate_summary


def _rule_based_answer(question: str, text: str, matches: list[Match]) -> str | None:
    q = question.lower()
    counts = summarize_counts(matches)

    # "How many <thing>" style questions.
    if "how many" in q or "number of" in q or "count" in q:
        for cat in counts:
            key = cat.lower().split()[0]  # email, phone, aadhaar...
            if key in q or cat.lower() in q:
                return f"There are **{counts[cat]}** {cat}(s) in the document."
        if "email" in q:
            return "There are **0** Email Address(es) in the document."
        total = len(matches)
        return f"A total of **{total}** sensitive item(s) were detected."

    # "What sensitive data exists"
    if "what sensitive" in q or "what data" in q or ("sensitive" in q and "exist" in q):
        if not counts:
            return "No sensitive data was detected in the document."
        lines = "\n".join(f"- {c}: {n}" for c, n in sorted(counts.items()))
        return "The following sensitive data was detected:\n" + lines

    # "Summarize"
    if "summar" in q:
        level, _, counts = classify(matches)
        return generate_summary(text, matches, level, counts)

    # "compliance risks"
    if "compliance" in q or "risk" in q:
        level, _, counts = classify(matches)
        return generate_summary(text, matches, level, counts)

    # "list emails / show phone numbers" (masked)
    if any(w in q for w in ("list", "show", "which")):
        for cat in counts:
            key = cat.lower().split()[0]
            if key in q or cat.lower() in q:
                vals = [m.masked() for m in matches if m.category == cat]
                return f"Detected {cat}(s) (masked):\n" + "\n".join(f"- {v}" for v in vals)

    return None


def _llm_answer(question: str, text: str, matches: list[Match]) -> str | None:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None
    try:
        from openai import OpenAI

        client = OpenAI(api_key=api_key)
        # Keep context bounded.
        context = text[:6000]
        counts = summarize_counts(matches)
        findings = ", ".join(f"{c}={n}" for c, n in counts.items()) or "none"
        prompt = (
            "You answer questions about an uploaded document for a data "
            "compliance assistant. Detected sensitive data summary: "
            f"{findings}.\n\nDocument excerpt:\n{context}\n\n"
            f"Question: {question}\nAnswer concisely."
        )
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
        )
        return resp.choices[0].message.content
    except Exception:
        return None


def answer(question: str, text: str, matches: list[Match]) -> str:
    """Answer a user question, preferring exact rule-based intents."""
    rb = _rule_based_answer(question, text, matches)
    if rb is not None:
        return rb
    llm = _llm_answer(question, text, matches)
    if llm is not None:
        return llm
    # Last-resort keyword search over the document.
    words = [w for w in re.findall(r"\w+", question.lower()) if len(w) > 3]
    hits = [
        line for line in text.splitlines()
        if any(w in line.lower() for w in words)
    ][:5]
    if hits:
        return "I found these relevant lines in the document:\n" + "\n".join(
            f"- {h.strip()}" for h in hits
        )
    return ("I couldn't answer that from the document automatically. "
            "Try asking about counts, sensitive data, or compliance risks, "
            "or configure an OpenAI API key for open-ended Q&A.")
