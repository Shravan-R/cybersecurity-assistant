    # ui/components.py
import streamlit as st
import pandas as pd
import plotly.express as px

# ---------- CARD ----------
def metric_card(title: str, value: str, desc: str = "", color: str = "#4CAF50"):
    st.markdown(
        f"""
        <div style="
            padding: 20px;
            border-radius: 12px;
            background-color: {color};
            color: white;
            margin-bottom: 12px;
        ">
            <h4 style="margin-bottom: 5px;">{title}</h4>
            <h2 style="margin-top: 0px; margin-bottom: 5px;">{value}</h2>
            <p style="margin:0px; opacity:0.8;">{desc}</p>
        </div>
        """,
        unsafe_allow_html=True
    )

# ---------- TABLE ----------
def event_table(events: list):
    if not events:
        st.info("No events logged yet.")
        return
    df = pd.DataFrame(events)
    st.dataframe(df, use_container_width=True)

# ---------- CHART ----------
def risk_trend_chart(events: list):
    if not events:
        return st.info("Not enough data for chart.")
    df = pd.DataFrame(events)
    df["ts"] = pd.to_datetime(df["ts"])
    fig = px.line(df, x="ts", y="score", title="Risk Score Trend")
    st.plotly_chart(fig, use_container_width=True)
