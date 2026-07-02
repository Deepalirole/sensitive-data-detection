# 🛡️ Sensitive Data Detection & Compliance Assistant

An AI-powered application that ingests documents (**PDF / TXT / CSV**), detects
sensitive & confidential information, classifies the document's **risk level**,
generates a **compliance summary**, and answers **natural-language questions**
about the document — with data **redaction** and **audit logging** built in.

Runs **fully offline** using a deterministic rule-based engine, and optionally
enriches summaries and open-ended Q&A with an **LLM (OpenAI)** when an API key
is configured.

---

## ✨ Features

| Requirement | Status |
|---|---|
| Upload PDF / TXT / CSV | ✅ |
| Detect Aadhaar, PAN, Email, Phone, Credit Card, Bank details, API keys/passwords, Employee IDs, Confidential business info | ✅ |
| Risk classification (Low / Medium / High) | ✅ |
| AI summary: compliance observations, security risks, remediation | ✅ |
| Question answering | ✅ |
| Streamlit UI + CLI | ✅ |
| **Bonus:** data masking/redaction, audit logging, Dockerization, LLM/RAG-style Q&A, multi-format | ✅ |

---

## 🚀 Setup

```bash
# 1. Clone
git clone <your-repo-url>
cd compliance-assistant

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) enable LLM features
cp .env.example .env
# then set OPENAI_API_KEY=sk-...   (skip to run fully offline)

# 4a. Run the web app
streamlit run app.py
# open http://localhost:8501

# 4b. …or use the CLI
python cli.py sample_data/sample_document.txt --ask "How many email addresses are present?"

# 5. Run tests
pytest -q
```

### Docker

```bash
docker build -t compliance-assistant .
docker run -p 8501:8501 --env-file .env compliance-assistant
```

---

## 🏗️ Architecture Overview

```
                ┌──────────────┐
   PDF/TXT/CSV ─▶ file_loader  │  extract plain text
                └──────┬───────┘
                       ▼
                ┌──────────────┐
                │  detector.py │  validated regex + Luhn checks
                └──────┬───────┘  → list[Match] (category, span, weight)
                       ▼
              ┌────────────────┐
              │ classifier.py  │  weighted score → Low/Medium/High
              │                │  + compliance summary (rules or LLM)
              └──────┬─────────┘
                     ▼
        ┌────────────────────────┐        ┌────────────┐
        │  app.py (Streamlit)    │◀──────▶ │   qa.py    │  intent + RAG-lite Q&A
        │  cli.py  (terminal)    │         └────────────┘
        └────────────────────────┘
```

**Modules**
- `file_loader.py` — extracts text from PDF (`pdfplumber`), TXT, and CSV (`pandas`, every cell + header flattened).
- `detector.py` — 11 sensitive-data categories via curated regexes; **Luhn validation** for credit cards, format checks for Aadhaar/PAN/IFSC; overlap resolution so numeric patterns don't double-count; per-category **risk weights**; masking + redaction helpers.
- `classifier.py` — weighted scoring → Low/Medium/High, mapping of each category to the compliance regime it implicates (GDPR, PCI-DSS, India DPDP Act, RBI), and summary generation.
- `qa.py` — deterministic intent handler for the required questions (counts, "what sensitive data", "summarize", "compliance risks"), with an LLM/keyword-search fallback.
- `app.py` — Streamlit UI: risk banner, metrics, detected-data table + chart, summary, Q&A, redacted view, audit log.
- `cli.py` — headless equivalent for terminal use / automation.

---

## 🤖 AI/ML Approach

The system is a **hybrid**: rules-first, LLM-optional.

1. **Detection — pattern recognition + validation.** Regular expressions locate
   candidate entities; validators reduce false positives (e.g. the **Luhn
   algorithm** verifies credit cards, Aadhaar requires a valid leading digit and
   12-digit grouping, PAN/IFSC enforce structural formats). Detection order is
   prioritised (specific → generic) so a 10-digit mobile isn't mislabelled as a
   bank account.

2. **Classification — weighted risk scoring.** Each category carries a
   sensitivity weight (identifiers/cards/secrets = 5, PII = 2, etc.). The
   document score plus high-value-hit heuristics map to Low / Medium / High.

3. **Summarisation & Q&A — LLM-augmented.** When `OPENAI_API_KEY` is present,
   `gpt-4o-mini` produces the compliance narrative and answers open-ended
   questions grounded in a bounded document excerpt (a lightweight
   retrieval-augmented pattern). Without a key, deterministic templates and an
   intent classifier guarantee the app still satisfies every requirement
   offline — important for a *privacy* tool where sending data to a third party
   may itself be a compliance concern.

**Why this design:** for PII detection, precision and explainability matter more
than a black box. Regex + validators give auditable, reproducible results with
zero data egress; the LLM layer adds natural-language polish where it's safe to.

---

## 🧗 Challenges Faced

- **Overlapping numeric patterns** — Aadhaar (12 digits), credit cards (13–16),
  phones (10) and bank accounts (9–18) collide. Solved with priority ordering
  plus a span-claiming/overlap-resolution step in `detect()`.
- **False positives** — random 16-digit numbers aren't cards. Added Luhn
  validation and leading-digit constraints.
- **Offline-first vs AI requirement** — resolved with the hybrid engine so the
  tool degrades gracefully with no API key while still using an LLM when allowed.
- **CSV/PDF heterogeneity** — normalised everything to plain text before
  detection so a single engine handles all formats.

---

## 🔮 Future Improvements

- **NER via spaCy / Presidio** to catch names, addresses and context-dependent
  PII that regex misses.
- **True RAG** with chunking + FAISS/Chroma embeddings for large, multi-document
  corpora and citation-backed answers.
- **OCR** (Tesseract) for scanned PDFs and images.
- **Multi-document dashboard** with trend analytics and exportable audit reports.
- **Role-based access & persistent, tamper-evident audit log** (currently
  session-scoped).
- **Configurable policy packs** (per-regulation category weights & thresholds).

---

## 🗂️ Repository Layout

```
compliance-assistant/
├── app.py              # Streamlit web app
├── cli.py              # Command-line interface
├── file_loader.py      # PDF/TXT/CSV → text
├── detector.py         # Sensitive-data detection + masking
├── classifier.py       # Risk classification + compliance summary
├── qa.py               # Question answering
├── test_detector.py    # Unit tests (pytest)
├── requirements.txt
├── Dockerfile
├── .env.example
├── .streamlit/config.toml
└── sample_data/sample_document.txt
```

---

## 📹 Demo & Deployment

- **Demo video:** _add link here_
- **Live deployment:** deploy `app.py` to [Streamlit Community Cloud](https://streamlit.io/cloud)
  (free) — point it at this repo and `app.py`; add `OPENAI_API_KEY` in *Secrets*
  if you want LLM features. _Add link here._
