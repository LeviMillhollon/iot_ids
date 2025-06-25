# dashboard.py

import streamlit as st
import pandas as pd
import json
import os
from datetime import datetime


st.set_page_config(page_title="IoT IDS Dashboard", layout="wide")
st.title("📡 IoT IDS Alert Dashboard")

st.subheader("Devices Found on Network")

def load_devices(filepath="devices.json"):
    if not os.path.exists(filepath):
        st.warning("⚠️ devices.json not found. Run the fingerprint engine first.")
        return None
    with open(filepath, "r") as f:
        try:
            devices = json.load(f)
            return pd.DataFrame(devices)
        except json.JSONDecodeError:
            st.error("❌ Error decoding devices.json")
            return None

device_df = load_devices()

if device_df is not None and not device_df.empty:
    st.dataframe(device_df, use_container_width=True)
    st.sidebar.download_button("Download Devices as CSV", device_df.to_csv(index=False), "devices.csv", "text/csv")
else:
    st.info("No devices to display.")

   

def load_alerts(filepath="alerts.jsonl"):
    if not os.path.exists(filepath):
        st.warning("⚠️ alerts.jsonl file not found. Run the IDS to generate alerts.")
        return None
    alerts = []
    with open(filepath, "r") as f:
        for line in f:
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if not alerts:
        st.info("No alerts found.")
        return None
    df = pd.DataFrame(alerts)
    df["timestamp"] = pd.to_datetime(df["timestamp"], format='ISO8601')
    return df

df = load_alerts()



if df is not None:
    st.sidebar.header("🔍 Filter Alerts")
    ip_filter = st.sidebar.multiselect("Filter by Source IP", sorted(df["src_ip"].unique()))
    rule_filter = st.sidebar.multiselect("Filter by Rule", sorted(df["rule"].unique()))

    if ip_filter:
        df = df[df["src_ip"].isin(ip_filter)]
    if rule_filter:
        df = df[df["rule"].isin(rule_filter)]

    st.subheader("📊 Summary Table")
    summary = (
        df.groupby(["src_ip", "rule"])
        .agg(count=("rule", "count"), last_seen=("timestamp", "max"))
        .reset_index()
        .sort_values(by="last_seen", ascending=False)
    )
    st.dataframe(summary, use_container_width=True)




    # Severity-to-color mapping
    SEVERITY_COLOR = {
        "high": "red",
        "medium": "orange",
        "low": "lightgreen",
        "unknown": "gray"
    }

    def color_row(row):
        severity = str(row.get("severity", "unknown")).lower()
        color = SEVERITY_COLOR.get(severity, "gray")
        return [f"background-color: {color}"] * len(row)

    if st.checkbox("Show Raw Alerts"):
        st.subheader("📄 Raw Alerts")
        styled_df = df.sort_values(by="timestamp", ascending=False).style.apply(color_row, axis=1)
        st.dataframe(styled_df, use_container_width=True)

    st.sidebar.markdown("---")
    st.sidebar.subheader("📁 Export Data")

    csv = summary.to_csv(index=False).encode("utf-8")
    st.sidebar.download_button("Download Summary as CSV", csv, "alert_summary.csv", "text/csv")

    json_export = df.to_json(orient="records", date_format="iso")
    st.sidebar.download_button("Download Raw Alerts as JSON", json_export, "raw_alerts.json", "application/json")


