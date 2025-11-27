# ui/app.py
import sys
import os
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(ROOT_DIR)
import streamlit as st
import requests
from responders.db_logger import DBLogger
from memory.knowledge_store import KnowledgeStore
from config.settings import settings
from ui.components import metric_card, event_table, risk_trend_chart


API_URL = f"http://{settings.HOST}:{settings.PORT}"

db = DBLogger(settings.DATABASE_URL)
memory = KnowledgeStore(settings.MEMORY_PATH)

st.set_page_config(
    page_title="Cybersec Assistant Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# ---------------------- SIDEBAR ----------------------
st.sidebar.title("🛡️ Cybersec Assistant")
page = st.sidebar.radio("Navigation", ["Home", "Analyze", "Memory"])

# ---------------------- HOME -------------------------
if page == "Home":
    st.title("🧠 Cybersecurity Assistant Dashboard")
    st.write("Live threat analysis, memory insights, and event monitoring.")

    # Summary Cards
    summary = memory.summary()
    metric_card("Total Events", summary["total_events"], "All incidents logged")
    metric_card("Average Risk Score", round(summary["avg_risk_score"], 2), "System-wide threat level", "#FF5733")

    if summary["top_malicious_urls"]:
        st.subheader("Top Malicious URLs")
        st.json(summary["top_malicious_urls"])

# ---------------------- ANALYZE -----------------------
elif page == "Analyze":
    st.title("🔍 Analyze Input")

    analyze_type = st.selectbox("Select Input Type", ["URL", "Password", "Text"])

    if analyze_type == "URL":
        url = st.text_input("Enter URL:")
        if st.button("Analyze URL"):
            res = requests.post(f"{API_URL}/analyze/url", json={"url": url})
            st.json(res.json())

    if analyze_type == "Password":
        pwd = st.text_input("Enter Password:", type="password")
        if st.button("Analyze Password"):
            res = requests.post(f"{API_URL}/analyze/password", json={"password": pwd})
            st.json(res.json())

    if analyze_type == "Text":
        txt = st.text_area("Enter Text to Analyze:")
        if st.button("Analyze Text"):
            res = requests.post(f"{API_URL}/analyze/text", json={"text": txt})
            st.json(res.json())


# ---------------------- MEMORY -----------------------
elif page == "Memory":
    st.title("🧠 System Memory")

    st.subheader("Short-Term Memory (Last 10 Events)")
    st.json(memory.last_events(10))

    st.subheader("Long-Term Memory Summary")
    st.json(memory.summary())

    st.subheader("Find Similar Events (Text Only)")
    query = st.text_input("Enter text to find similar past events:")
    if st.button("Search Similar"):
        res = memory.find_similar_events(query)
        st.json(res)
