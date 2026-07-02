"""
Command-line interface for the Compliance Assistant.

Usage:
    python cli.py <path-to-file> [--redact] [--ask "your question"]

Scans a PDF/TXT/CSV, prints detected sensitive data, risk level and a
compliance summary. Works offline; uses OpenAI if OPENAI_API_KEY is set.
"""

from __future__ import annotations

import argparse
import sys

from dotenv import load_dotenv

import file_loader
from detector import detect, redact
from classifier import classify, generate_summary
from qa import answer


def main() -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Sensitive Data Compliance Assistant")
    parser.add_argument("file", help="Path to a PDF, TXT or CSV file")
    parser.add_argument("--redact", action="store_true", help="Print a redacted copy")
    parser.add_argument("--ask", help="Ask a question about the document")
    args = parser.parse_args()

    with open(args.file, "rb") as fh:
        data = fh.read()

    text = file_loader.load(args.file, data)
    matches = detect(text)
    level, score, counts = classify(matches)

    print(f"\n=== RISK LEVEL: {level} (score {score}) ===\n")
    print("Detected sensitive data:")
    if not matches:
        print("  (none)")
    for m in matches:
        print(f"  [{m.category}] {m.masked()}  @{m.start}-{m.end}")

    print("\n--- Compliance Summary ---")
    print(generate_summary(text, matches, level, counts))

    if args.ask:
        print(f"\n--- Q: {args.ask} ---")
        print(answer(args.ask, text, matches))

    if args.redact:
        print("\n--- Redacted Document ---")
        print(redact(text, matches))

    return 0


if __name__ == "__main__":
    sys.exit(main())
