"""File loading utilities: extract plain text from PDF, TXT and CSV."""

from __future__ import annotations

import io

import pandas as pd


def load_txt(data: bytes) -> str:
    for enc in ("utf-8", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="ignore")


def load_csv(data: bytes) -> str:
    try:
        df = pd.read_csv(io.BytesIO(data), dtype=str, keep_default_na=False)
    except Exception:
        return load_txt(data)
    # Flatten to text so the detector can scan every cell + header.
    lines = [", ".join(df.columns)]
    for _, row in df.iterrows():
        lines.append(", ".join(str(v) for v in row.values))
    return "\n".join(lines)


def load_pdf(data: bytes) -> str:
    import pdfplumber

    text_parts: list[str] = []
    with pdfplumber.open(io.BytesIO(data)) as pdf:
        for page in pdf.pages:
            text_parts.append(page.extract_text() or "")
    return "\n".join(text_parts)


def load(filename: str, data: bytes) -> str:
    """Dispatch on file extension and return extracted text."""
    name = filename.lower()
    if name.endswith(".pdf"):
        return load_pdf(data)
    if name.endswith(".csv"):
        return load_csv(data)
    if name.endswith(".txt"):
        return load_txt(data)
    raise ValueError(f"Unsupported file type: {filename}")
