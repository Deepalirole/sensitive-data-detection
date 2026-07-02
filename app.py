"""
Sensitive Data Detection & Compliance Assistant — Streamlit UI.

Upload a PDF / TXT / CSV, detect sensitive data, classify risk, generate
a compliance summary, ask questions, and optionally download a redacted
copy. Runs fully offline with rule-based AI; enriches output with an LLM
if OPENAI_API_KEY is set.
"""

from __future__ import annotations

import datetime as dt

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

import file_loader
from detector import detect, redact
from classifier import classify, generate_summary
from qa import answer

load_dotenv()

st.set_page_config(page_title="Compliance Assistant", page_icon="🛡️", layout="wide")

RISK_COLORS = {"Low Risk": "#2e7d32", "Medium Risk": "#ed6c02", "High Risk": "#c62828"}


def _audit(event: str) -> None:
    st.session_state.setdefault("audit_log", [])
    st.session_state.audit_log.append(
        {"time": dt.datetime.now().strftime("%H:%M:%S"), "event": event}
    )


st.title("🛡️ Sensitive Data Detection & Compliance Assistant")
st.caption(
    "Upload a document to detect sensitive data, assess risk, and get a "
    "compliance summary. Ask questions about it below."
)

with st.sidebar:
    st.header("How it works")
    st.markdown(
        "1. **Upload** a PDF, TXT or CSV\n"
        "2. **Detect** sensitive data via validated regex patterns\n"
        "3. **Classify** overall risk (Low / Medium / High)\n"
        "4. **Summarize** compliance observations & remediation\n"
        "5. **Ask** questions about the document"
    )
    st.divider()
    st.markdown(
        "AI narrative uses **OpenAI** if `OPENAI_API_KEY` is set, "
        "otherwise a deterministic rule-based engine (fully offline)."
    )

uploaded = st.file_uploader("Upload document", type=["pdf", "txt", "csv"])

if uploaded is not None:
    data = uploaded.getvalue()
    try:
        text = file_loader.load(uploaded.name, data)
    except Exception as e:  # noqa: BLE001
        st.error(f"Could not read file: {e}")
        st.stop()

    _audit(f"Uploaded '{uploaded.name}' ({len(data)} bytes)")

    matches = detect(text)
    level, score, counts = classify(matches)
    _audit(f"Scan complete: {len(matches)} items, risk={level}")

    # Persist for the Q&A section.
    st.session_state.text = text
    st.session_state.matches = matches

    # ---- Risk banner + metrics ------------------------------------------- #
    color = RISK_COLORS[level]
    st.markdown(
        f"<div style='padding:14px;border-radius:8px;background:{color};"
        f"color:white;font-size:20px;font-weight:600'>Risk Level: {level} "
        f"(score {score})</div>",
        unsafe_allow_html=True,
    )

    c1, c2, c3 = st.columns(3)
    c1.metric("Sensitive items", len(matches))
    c2.metric("Distinct categories", len(counts))
    c3.metric("Characters scanned", len(text))

    tabs = st.tabs(
        ["🔍 Detected Data", "📋 Compliance Summary", "💬 Ask Questions",
         "🕶️ Redacted View", "🗂️ Audit Log"]
    )

    # ---- Detected data --------------------------------------------------- #
    with tabs[0]:
        if not matches:
            st.success("No sensitive data detected.")
        else:
            df = pd.DataFrame(
                [
                    {
                        "Category": m.category,
                        "Value (masked)": m.masked(),
                        "Position": f"{m.start}-{m.end}",
                        "Weight": m.weight,
                    }
                    for m in matches
                ]
            )
            st.dataframe(df, use_container_width=True, hide_index=True)
            st.subheader("Counts by category")
            st.bar_chart(pd.Series(counts).sort_values(ascending=False))

    # ---- Summary --------------------------------------------------------- #
    with tabs[1]:
        with st.spinner("Generating compliance summary..."):
            summary = generate_summary(text, matches, level, counts)
        st.markdown(summary)
        st.download_button("Download summary (.md)", summary,
                           file_name="compliance_summary.md")

    # ---- Q&A ------------------------------------------------------------- #
    with tabs[2]:
        st.markdown("Try: *What sensitive data exists?* · "
                    "*How many email addresses are present?* · "
                    "*Summarize this document.* · *What compliance risks exist?*")
        question = st.text_input("Your question")
        if question:
            _audit(f"Q&A: {question}")
            st.markdown(answer(question, text, matches))

    # ---- Redacted view --------------------------------------------------- #
    with tabs[3]:
        redacted = redact(text, matches)
        st.text_area("Redacted document", redacted, height=400)
        st.download_button("Download redacted (.txt)", redacted,
                           file_name="redacted.txt")

    # ---- Audit log ------------------------------------------------------- #
    with tabs[4]:
        st.dataframe(pd.DataFrame(st.session_state.audit_log),
                     use_container_width=True, hide_index=True)
else:
    st.info("Upload a document to begin. A sample file is provided in "
            "`sample_data/` in the repository.")
