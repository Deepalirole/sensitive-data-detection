"""
Provider-agnostic LLM helper.

Order of preference:
  1. Google Gemini   — if GEMINI_API_KEY (or GOOGLE_API_KEY) is set
  2. OpenAI          — if OPENAI_API_KEY is set
  3. None            — callers fall back to the offline rule-based engine

A single `complete(prompt)` function returns the model's text, or None if
no provider is configured or the call fails.
"""

from __future__ import annotations

import os


def _gemini(prompt: str) -> str | None:
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    if not api_key:
        return None
    try:
        import google.generativeai as genai

        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(os.getenv("GEMINI_MODEL", "gemini-1.5-flash"))
        resp = model.generate_content(prompt)
        return resp.text
    except Exception:
        return None


def _openai(prompt: str) -> str | None:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None
    try:
        from openai import OpenAI

        client = OpenAI(api_key=api_key)
        resp = client.chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
        )
        return resp.choices[0].message.content
    except Exception:
        return None


def complete(prompt: str) -> str | None:
    """Return an LLM completion using whichever provider is configured."""
    return _gemini(prompt) or _openai(prompt)
