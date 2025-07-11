

# ──────────────────────────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────────────────────────
from __future__ import annotations
from pathlib import Path
from collections import deque
from datetime import datetime
import json, os, pandas as pd, streamlit as st

# ──────────────────────────────────────────────────────────────
# Config (override via env vars if you want)
# ──────────────────────────────────────────────────────────────
HOME_FILE    = Path(os.getenv("IDS_HOME_FILE",  "devices_home.json"))
AP_FILE      = Path(os.getenv("IDS_AP_FILE",    "devices_ap.json"))
ALERT_FILE   = Path(os.getenv("IDS_ALERT_FILE", "alerts.jsonl"))
SURICATA_DIR = Path("/var/log/suricata")
EVE_FILE     = SURICATA_DIR / "eve.json"

# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────
SEV_NUM = {1: "background-color:red",
           2: "background-color:orange",
           3: "background-color:lightgreen",
           4: "background-color:lightgray"}
SEV_STR = {"high":   SEV_NUM[1],
           "medium": SEV_NUM[2],
           "low":    SEV_NUM[3],
           "info":   SEV_NUM[4]}

def _hilite(row):
    sev = row.get("severity")
    try:
        sev = int(sev)
        colour = SEV_NUM.get(sev, "")
    except (ValueError, TypeError):
        colour = SEV_STR.get(str(sev).lower(), "")
    return [colour] * len(row)

@st.cache_data(ttl=5)
def _load_json(path: Path) -> list[dict]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    try:
        with open(path) as fh:
            if path.suffix == ".jsonl":
                return [json.loads(line) for line in fh if line.strip()]
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return []

@st.cache_data(ttl=5)
def _tail_jsonl(path: Path, n: int) -> pd.DataFrame:
    dq = deque(maxlen=n)
    if path.exists():
        with open(path) as fh:
            for line in fh:
                try:
                    dq.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    df = pd.DataFrame(dq)
    if not df.empty and "timestamp" in df:
        df["timestamp"] = pd.to_datetime(df["timestamp"],
                                         utc=True, errors="coerce")
    return df

def _truncate(path: Path) -> bool:
    try:
        path.write_text("")
        return True
    except Exception:
        return False

def _truncate_dir(d: Path) -> list[str]:
    cleared: list[str] = []
    if d.is_dir():
        for f in d.iterdir():
            if f.suffix in (".json", ".log") and _truncate(f):
                cleared.append(f.name)
    return cleared

def _dedupe(df: pd.DataFrame) -> pd.DataFrame:
    """Drop duplicate column names caused by case-mismatch merges."""
    return df.loc[:, ~df.columns.duplicated()] if not df.empty else df

# ──────────────────────────────────────────────────────────────
# Streamlit main
# ──────────────────────────────────────────────────────────────
def main() -> None:
    st.set_page_config(page_title="📡 IoT-IDS Dashboard", layout="wide")
    st.title("📡 IoT-IDS Alert Dashboard")

    # ───── Sidebar housekeeping ───────────────────────────────
    st.sidebar.header("⚙️ Controls")
    for label, fp in (("Home Devices", HOME_FILE),
                      ("AP Devices",   AP_FILE),
                      ("Alerts",       ALERT_FILE)):
        if st.sidebar.button(f"Clear {label}"):
            st.sidebar.success("Cleared." if _truncate(fp) else "Not found.")
    if st.sidebar.button("Clear Suricata Logs"):
        done = _truncate_dir(SURICATA_DIR)
        st.sidebar.success("Truncated: " + ", ".join(done) if done else "None.")
    if st.sidebar.button("Clear All"):
        for p in (HOME_FILE, AP_FILE, ALERT_FILE):
            _truncate(p)
        _truncate_dir(SURICATA_DIR)
        st.sidebar.success("Everything cleared.")
    show_incidents = st.sidebar.checkbox("Show Flow Incidents", value=True)
    if st.sidebar.button("🔄 Refresh Data"):
        st.experimental_rerun()

    # ───── Load datasets (with de-dupe) ───────────────────────
    df_home   = _dedupe(pd.DataFrame(_load_json(HOME_FILE)))
    df_ap     = _dedupe(pd.DataFrame(_load_json(AP_FILE)))
    df_alerts = _dedupe(pd.DataFrame(_load_json(ALERT_FILE)))
    df_eve    = _tail_jsonl(EVE_FILE, 500)

    # Normalise ‘dest_ip’→‘dst_ip’ so filters work
    for df in (df_alerts, df_eve):
        if "dest_ip" in df.columns:
            df["dst_ip"] = df["dest_ip"]
        elif "dst_ip" not in df.columns:
            df["dst_ip"] = None

    # ───── Home vs. AP tables (kept 100 % separate) ───────────
    for title, df, fname in (
        ("🏠 Home Network Devices", df_home, "home_devices.csv"),
        ("🚩 AP-Connected Devices", df_ap, "ap_devices.csv"),
    ):
        st.subheader(title)
        if df.empty:
            st.info("None found.")
        else:
            st.dataframe(df, use_container_width=True)
            st.sidebar.download_button(f"Download {title.split()[0]} CSV",
                                       df.to_csv(index=False),
                                       file_name=fname,
                                       mime="text/csv")

    # ───── Alerts summary & details ───────────────────────────
    st.markdown("---")
    st.subheader("🔔 Alerts Summary & Details")
    if df_alerts.empty:
        st.info("No alerts generated yet.")
    else:
        st.sidebar.subheader("🔍 Filter Alerts")
        ip_sel   = st.sidebar.multiselect(
            "Source IP",
            sorted(df_alerts.get("src_ip", pd.Series(dtype=str))
                              .dropna().unique()))
        rule_sel = st.sidebar.multiselect(
            "Rule",
            sorted(df_alerts.get("rule", pd.Series(dtype=str))
                              .dropna().unique()))

        data = df_alerts.copy()
        if ip_sel:
            data = data[data["src_ip"].isin(ip_sel)]
        if rule_sel:
            data = data[data["rule"].isin(rule_sel)]

        for c in ("app_proto", "dest_country"):
            if c not in data.columns:
                data[c] = None

        g_cols = [c for c in
                  ("src_ip", "dst_ip", "rule", "severity",
                   "app_proto", "dest_country") if c in data]
        summary = (data.groupby(g_cols, dropna=False)
                         .agg(count      =("rule", "count"),
                              first_seen =("timestamp", "min"),
                              last_seen  =("timestamp", "max"))
                         .reset_index()
                         .sort_values("last_seen", ascending=False))

        st.dataframe(summary.style.apply(_hilite, axis=1),
                     use_container_width=True)
        st.sidebar.download_button("Download Alert Summary CSV",
                                   summary.to_csv(index=False),
                                   "alert_summary.csv", "text/csv")

        if st.checkbox("Show Raw Alerts"):
            st.dataframe(data.sort_values("timestamp", ascending=False)
                             .style.apply(_hilite, axis=1),
                         use_container_width=True)
            st.sidebar.download_button("Raw Alerts JSON",
                                       data.to_json(orient="records",
                                                    date_format="iso"),
                                       "raw_alerts.json",
                                       "application/json")

        # ─── Flow incidents (optional) ────────────────────────
        if show_incidents:
            st.markdown("---")
            st.subheader("🗂️ Flow Incidents")
            if data.empty:
                st.info("No flow incidents.")
            else:
                ports = [c for c in ("src_port", "dst_port") if c in data]
                group_cols = ["src_ip", "dst_ip"] + ports
                inc_group = (data.groupby(group_cols, dropna=False)
                                   .agg(count     =("rule", "count"),
                                        first_seen=("timestamp", "min"),
                                        last_seen =("timestamp", "max"),
                                        rules      =("rule",
                                                     lambda s: ", "
                                                     .join(sorted(set(s)))))
                                   .reset_index()
                                   .sort_values("last_seen",
                                                ascending=False))
                st.dataframe(inc_group.style.apply(_hilite, axis=1),
                             use_container_width=True)

    # ───── Suricata alert log tail ────────────────────────────
    st.markdown("---")
    st.subheader("📊 Suricata Recent Alerts (500-line tail)")
    if "alert" not in df_eve.columns or \
       df_eve[df_eve["event_type"] == "alert"].empty:
        st.info("No recent Suricata alerts.")
    else:
        eve_alerts = df_eve[df_eve["event_type"] == "alert"].copy()
        eve_alerts["signature"] = eve_alerts["alert"].apply(
            lambda a: a.get("signature") if isinstance(a, dict) else None)

        def _join(a, key):
            if isinstance(a, dict) and isinstance(a.get("metadata"), dict):
                return ", ".join(a["metadata"].get(key, []))
            return None

        eve_alerts["cve"]   = eve_alerts["alert"].apply(lambda a: _join(a, "cve"))
        eve_alerts["mitre"] = eve_alerts["alert"].apply(lambda a: _join(a, "mitre"))
        if "dest_geoip" in eve_alerts.columns:
            eve_alerts["dest_country"] = eve_alerts["dest_geoip"].apply(
                lambda g: g.get("country_iso") if isinstance(g, dict) else None)

        show_cols = [c for c in
                     ("timestamp", "signature", "src_ip", "dst_ip",
                      "cve", "mitre", "severity", "dest_country")
                     if c in eve_alerts.columns]

        st.dataframe(eve_alerts[show_cols]
                     .rename(columns={"dest_country": "dst_cc"})
                     .style.apply(_hilite, axis=1),
                     use_container_width=True)

# ──────────────────────────────────────────────────────────────
# Entry-point
# ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()