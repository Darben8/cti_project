import streamlit as st
import pandas as pd
import requests
from datetime import datetime

st.title("📊 Dynamic Data Explorer (Live API)")

# -------------------------------
# API FUNCTIONS
# -------------------------------

@st.cache_data(ttl=3600)
def fetch_openphish():
    url = "https://openphish.com/feed.txt"
    try:
        res = requests.get(url, timeout=10)
        lines = res.text.strip().split("\n")
        df = pd.DataFrame(lines, columns=["indicator"])
        df["date"] = pd.Timestamp.now(tz="UTC")
        df["type"] = "phishing"
        df["source"] = "OpenPhish"
        return df[["indicator", "date", "type", "source"]]
    except Exception as e:
        st.error(f"OpenPhish API error: {e}")
        return pd.DataFrame()


@st.cache_data(ttl=3600)
def fetch_threatfox():
    url = "https://threatfox-api.abuse.ch/api/v1/"
    headers = {
        "User-Agent": "CTI-Streamlit-App/1.0 (Academic Project)",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Auth-Key": "fed4e03e0b56b36bfc0468217bc4acaeb1153d887d818d2b"
    }
    payload = {
        "query": "get_iocs",
        "limit": 100
    }
    try:
        res = requests.post(url, json=payload, headers=headers, timeout=10)
        data = res.json()

        if data.get("query_status") != "ok":
            st.error(f"ThreatFox error: {data}")
            return pd.DataFrame()

        df = pd.DataFrame(data["data"])
        df["indicator"] = df["ioc"]
        df["type"] = df["threat_type"]
        df["date"] = pd.to_datetime(df["first_seen"], errors="coerce")
        df["source"] = "ThreatFox"
        return df[["indicator", "date", "type", "source"]]

    except Exception as e:
        st.error(f"ThreatFox API error: {e}")
        return pd.DataFrame()


# -------------------------------
# LOAD DATA
# -------------------------------

with st.spinner("Fetching live threat intelligence data..."):
    openphish_df = fetch_openphish()
    threatfox_df = fetch_threatfox()

st.subheader("DEBUG: Raw Data Counts")
st.write("OpenPhish rows:", len(openphish_df))
st.write("ThreatFox rows:", len(threatfox_df))

df = pd.concat([openphish_df, threatfox_df], ignore_index=True)

if df.empty:
    st.warning("No data could be loaded from APIs.")
    st.stop()

# Convert date safely
df["date"] = pd.to_datetime(df["date"], errors="coerce", utc=True)


# -------------------------------
# FILTERS
# -------------------------------

st.sidebar.header("Filter Options")

sources = st.sidebar.multiselect(
    "Select Data Source",
    options=df["source"].unique(),
    default=df["source"].unique()
)

types = st.sidebar.multiselect(
    "Select Indicator Type",
    options=df["type"].dropna().unique(),
    default=df["type"].dropna().unique()
)

filtered_df = df[
    (df["source"].isin(sources)) &
    (df["type"].isin(types))
]


# -------------------------------
# SAMPLE DATA
# -------------------------------

st.subheader("Sample Records")
st.dataframe(filtered_df.head(50), use_container_width=True)

# -------------------------------
# SUMMARY STATS
# -------------------------------

st.subheader("Summary Statistics")

col1, col2, col3 = st.columns(3)

with col1:
    st.metric("Total Records", len(filtered_df))

with col2:
    unique_indicators = filtered_df["indicator"].nunique()
    st.metric("Unique Indicators", unique_indicators)

with col3:
    min_date = filtered_df["date"].min()
    max_date = filtered_df["date"].max()
    if pd.notnull(min_date) and pd.notnull(max_date):
        st.metric("Date Range", f"{min_date.date()} → {max_date.date()}")
    else:
        st.metric("Date Range", "N/A")

# -------------------------------
# TOP CATEGORIES
# -------------------------------

st.subheader("Top Indicator Types")
top_types = filtered_df["type"].value_counts().head(10)
st.bar_chart(top_types)

# -------------------------------
# RECENT ACTIVITY
# -------------------------------

st.subheader("Recent Activity (Last 7 Days)")

cutoff = pd.Timestamp.now(tz="UTC") - pd.Timedelta(days=7)
recent_df = filtered_df[filtered_df["date"] >= cutoff]
st.metric("Records (Last 7 Days)", len(recent_df))