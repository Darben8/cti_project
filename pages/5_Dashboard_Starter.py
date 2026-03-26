"""Dynamic dashboard starter for Milestone 1."""

import os
from datetime import datetime

import pandas as pd
import plotly.express as px
import requests
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

st.title("📊 Dynamic CTI Dashboard Starter")
st.caption("Interactive filtering, live-source enrichment, chart/table updates, and KPI metrics.")


@st.cache_data(ttl=3600)
def load_local_events() -> pd.DataFrame:
    df = pd.read_csv("data/threat_events.csv")
    df["date"] = pd.to_datetime(df["date"]) 
    return df


@st.cache_data(ttl=3600)
def fetch_phishtank_count() -> int:
    url = "https://data.phishtank.com/data/online-valid.json"
    try:
        r = requests.get(url, timeout=12)
        r.raise_for_status()
        payload = r.json()
        return len(payload) if isinstance(payload, list) else 0
    except Exception:
        return -1


@st.cache_data(ttl=3600)
def fetch_ransomware_live_count() -> int:
    url = "https://api.ransomware.live/v2/recentvictims"
    try:
        r = requests.get(url, timeout=12)
        r.raise_for_status()
        payload = r.json()
        return len(payload) if isinstance(payload, list) else 0
    except Exception:
        return -1


@st.cache_data(ttl=3600)
def fetch_shodan_bank_exposure() -> int:
    key = os.getenv("SHODAN_API_KEY", "").strip()
    if not key:
        return -2

    query = 'org:"Bank" port:443 country:"US"'
    url = f"https://api.shodan.io/shodan/host/count?key={key}&query={query}"
    try:
        r = requests.get(url, timeout=12)
        r.raise_for_status()
        payload = r.json()
        return int(payload.get("total", 0))
    except Exception:
        return -1


df = load_local_events()

threat_options = sorted(df["threat_type"].unique().tolist())
asset_options = sorted(df["target_asset"].unique().tolist())

col_f1, col_f2 = st.columns(2)
with col_f1:
    selected_threats = st.multiselect("Filter by threat category", threat_options, default=threat_options)
with col_f2:
    selected_assets = st.multiselect("Filter by asset", asset_options, default=asset_options)

filtered = df[df["threat_type"].isin(selected_threats) & df["target_asset"].isin(selected_assets)].copy()

k1, k2, k3, k4 = st.columns(4)
with k1:
    st.metric("Filtered Events", int(filtered["incident_count"].sum()))
with k2:
    st.metric("Average Severity", f"{filtered['severity'].mean():.1f}" if not filtered.empty else "0.0")
with k3:
    pcount = fetch_phishtank_count()
    st.metric("PhishTank Active Entries", "Unavailable" if pcount < 0 else f"{pcount:,}")
with k4:
    rcount = fetch_ransomware_live_count()
    st.metric("Ransomware.live Recent Victims", "Unavailable" if rcount < 0 else f"{rcount:,}")

st.markdown("#### Threat Volume Over Time")
if filtered.empty:
    st.warning("No records match current filters.")
else:
    series = filtered.groupby(["date", "threat_type"], as_index=False)["incident_count"].sum()
    fig = px.line(
        series,
        x="date",
        y="incident_count",
        color="threat_type",
        markers=True,
        labels={"incident_count": "Incident Count", "date": "Date"},
    )
    fig.update_layout(plot_bgcolor="#F4F8FC", paper_bgcolor="#F4F8FC")
    st.plotly_chart(fig, use_container_width=True)

st.markdown("#### Filtered Threat/Event Table")
display_cols = [
    "date",
    "threat_type",
    "target_asset",
    "region",
    "mitre_technique",
    "incident_count",
    "severity",
    "source",
]
st.dataframe(filtered[display_cols].sort_values("date", ascending=False), use_container_width=True, hide_index=True)

st.markdown("#### Exposure Snapshot (Shodan)")
shodan_total = fetch_shodan_bank_exposure()
if shodan_total == -2:
    st.info("Set SHODAN_API_KEY in .env to enable Shodan exposure metric.")
elif shodan_total == -1:
    st.warning("Shodan query unavailable right now (API/network/error).")
else:
    st.success(f"Shodan matched hosts for US banking exposure query: {shodan_total:,}")

st.caption(f"Last dashboard refresh: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
