"""Unified dashboard combining local CTI datasets and live source summaries."""

import os
from datetime import datetime

import pandas as pd
import requests
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

st.title("CTI Dashboard")
st.caption("Merged dashboard and explorer for local datasets and live CTI sources.")


def empty_records_df() -> pd.DataFrame:
    return pd.DataFrame(
        columns=["indicator", "type", "category", "source", "date", "tags", "record_kind"]
    )


def first_available_series(df: pd.DataFrame, columns: list[str], default_value="") -> pd.Series:
    for column in columns:
        if column in df.columns:
            return df[column].fillna(default_value)
    return pd.Series([default_value] * len(df), index=df.index)


def normalize_ioc_df(df: pd.DataFrame, source_name: str) -> pd.DataFrame:
    if df.empty:
        return empty_records_df()

    working = df.copy()
    lower_map = {col.lower().strip(): col for col in working.columns}

    indicator_col = lower_map.get("indicator") or lower_map.get("ioc")
    type_col = lower_map.get("type") or lower_map.get("ioc_type") or lower_map.get("ioc type")
    category_col = lower_map.get("ioc type") or lower_map.get("threat_type") or lower_map.get("category")
    date_col = lower_map.get("first seen") or lower_map.get("first_seen") or lower_map.get("date")
    tags_col = lower_map.get("tags") or lower_map.get("malware") or lower_map.get("malware_printable")

    normalized = pd.DataFrame()
    normalized["indicator"] = working[indicator_col] if indicator_col else ""
    normalized["type"] = working[type_col] if type_col else "unknown"
    normalized["category"] = working[category_col] if category_col else normalized["type"]
    normalized["source"] = source_name
    normalized["date"] = pd.to_datetime(
        working[date_col] if date_col else pd.NaT,
        errors="coerce",
        dayfirst=True,
        utc=True,
    )
    normalized["tags"] = working[tags_col] if tags_col else ""
    normalized["record_kind"] = "ioc"
    return normalized[["indicator", "type", "category", "source", "date", "tags", "record_kind"]]


@st.cache_data(ttl=3600)
def load_phishtank_local() -> pd.DataFrame:
    try:
        df = pd.read_csv("data/phishtank.csv")
        return normalize_ioc_df(df, "PhishTank CSV")
    except Exception:
        return empty_records_df()


@st.cache_data(ttl=3600)
def load_combined_iocs() -> pd.DataFrame:
    try:
        df = pd.read_csv("data/combined_iocs.csv")
        source_series = df["source"] if "source" in df.columns else "Combined IOCs"
        normalized = normalize_ioc_df(df, "Combined IOCs")
        if "source" in df.columns:
            normalized["source"] = source_series.fillna("Combined IOCs")
        return normalized
    except Exception:
        return empty_records_df()


@st.cache_data(ttl=3600)
def fetch_threatfox_live() -> pd.DataFrame:
    url = "https://threatfox-api.abuse.ch/api/v1/"
    headers = {
        "User-Agent": "CTI-Streamlit-App/1.0 (Academic Project)",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    threatfox_key = os.getenv("THREATFOX_API_KEY", "").strip()
    if threatfox_key:
        headers["Auth-Key"] = threatfox_key

    try:
        response = requests.post(
            url,
            json={"query": "get_iocs", "limit": 100},
            headers=headers,
            timeout=12,
        )
        response.raise_for_status()
        payload = response.json()
        if payload.get("query_status") != "ok":
            return empty_records_df()

        df = pd.DataFrame(payload.get("data", []))
        return normalize_ioc_df(df, "ThreatFox API")
    except Exception:
        return empty_records_df()


@st.cache_data(ttl=3600)
def fetch_ransomware_live() -> pd.DataFrame:
    try:
        response = requests.get("https://api.ransomware.live/v2/recentvictims", timeout=12)
        response.raise_for_status()
        payload = response.json()
        df = pd.DataFrame(payload if isinstance(payload, list) else [])
        if df.empty:
            return empty_records_df()

        normalized = pd.DataFrame()
        normalized["indicator"] = first_available_series(
            df,
            ["victim", "name", "domain"],
            default_value="ransomware victim",
        )
        normalized["type"] = "victim"
        normalized["category"] = "ransomware"
        normalized["source"] = "ransomware.live"
        normalized["date"] = pd.to_datetime(
            first_available_series(df, ["discovered", "published", "date"], default_value=pd.NaT),
            errors="coerce",
            utc=True,
        )
        normalized["tags"] = first_available_series(df, ["group_name", "group", "country"], default_value="")
        normalized["record_kind"] = "victim"
        return normalized[["indicator", "type", "category", "source", "date", "tags", "record_kind"]]
    except Exception:
        return empty_records_df()


@st.cache_data(ttl=3600)
def fetch_shodan_summary() -> pd.DataFrame:
    key = os.getenv("SHODAN_API_KEY", "").strip()
    if not key:
        return pd.DataFrame([{"source": "Shodan", "metric": "US banking exposure matches", "value": "Missing API key"}])

    query = 'org:"Bank" port:443 country:"US"'
    try:
        response = requests.get(
            "https://api.shodan.io/shodan/host/count",
            params={"key": key, "query": query},
            timeout=12,
        )
        response.raise_for_status()
        payload = response.json()
        total = int(payload.get("total", 0))
        return pd.DataFrame([{"source": "Shodan", "metric": "US banking exposure matches", "value": f"{total:,}"}])
    except Exception:
        return pd.DataFrame([{"source": "Shodan", "metric": "US banking exposure matches", "value": "Unavailable"}])


with st.spinner("Loading local and live intelligence sources..."):
    records_df = pd.concat(
        [
            load_phishtank_local(),
            load_combined_iocs(),
            fetch_threatfox_live(),
            fetch_ransomware_live(),
        ],
        ignore_index=True,
    )
    shodan_df = fetch_shodan_summary()

if records_df.empty:
    st.warning("No dashboard records could be loaded.")
    st.stop()

source_options = sorted(records_df["source"].dropna().unique().tolist())
selected_sources = st.multiselect(
    "Filter by data source",
    options=source_options,
    default=source_options,
)

filtered_df = records_df[records_df["source"].isin(selected_sources)].copy()

st.subheader("Summary Statistics")
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Filtered Records", len(filtered_df))

with col2:
    st.metric("Unique Indicators", filtered_df["indicator"].nunique())

with col3:
    top_category = (
        filtered_df["category"].fillna("Unknown").value_counts().idxmax()
        if not filtered_df.empty
        else "N/A"
    )
    st.metric("Top Category", top_category)

with col4:
    valid_dates = filtered_df["date"].dropna()
    if valid_dates.empty:
        st.metric("Date Coverage", "N/A")
    else:
        coverage = f"{valid_dates.min().date()} to {valid_dates.max().date()}"
        st.metric("Date Coverage", coverage)

st.subheader("Top Categories")
top_categories = filtered_df["category"].fillna("Unknown").value_counts().head(10)
st.bar_chart(top_categories)

st.subheader("Sample Records")
sample_cols = ["source", "indicator", "type", "category", "date", "tags"]
st.dataframe(
    filtered_df[sample_cols].sort_values("date", ascending=False, na_position="last").head(25),
    use_container_width=True,
    hide_index=True,
)

st.subheader("Shodan Summary")
st.dataframe(shodan_df, use_container_width=True, hide_index=True)

st.caption(f"Last dashboard refresh: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
