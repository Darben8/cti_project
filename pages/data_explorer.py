import streamlit as st
import pandas as pd
import requests
from datetime import datetime

st.title("📊 Dynamic Data Explorer (Live API)")

# -------------------------------
# API FUNCTIONS
# -------------------------------

@st.cache_data(ttl=3600)
def fetch_phishtank():
    url = "https://data.phishtank.com/data/online-valid.json"

    try:
        res = requests.get(url, timeout=10)
        data = res.json()

        df = pd.DataFrame(data)

        # Normalize columns
        df = df.rename(columns={
            "phish_id": "id",
            "url": "indicator",
            "submission_time": "date"
        })

        df["source"] = "PhishTank"
        df["type"] = "phishing"

        return df[["id", "indicator", "date", "type", "source"]]

    except Exception as e:
        st.error(f"PhishTank API error: {e}")
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

    auth_key = "anonymous"

    payload = {
        "query": "get_iocs",
        "limit": 100,
    }

    try:
        res = requests.post(url, json=payload, headers=headers, timeout=10)

        data = res.json()

        if data.get("query_status") != "ok":
            st.error("ThreatFox API returned non-ok response")
            return pd.DataFrame()

        df = pd.DataFrame(data["data"])

        df["indicator"] = df.get("ioc")
        df["type"] = df.get("ioc_type")
        df["date"] = df.get("first_seen")
        df["source"] = "ThreatFox"

        return df

    except Exception as e:
        st.error(f"ThreatFox API error: {e}")
        return pd.DataFrame()


# -------------------------------
# LOAD DATA
# -------------------------------

with st.spinner("Fetching live threat intelligence data..."):
    phish_df = fetch_phishtank()
    threatfox_df = fetch_threatfox()

df = pd.concat([phish_df, threatfox_df], ignore_index=True)

if df.empty:
    st.warning("No data could be loaded from APIs.")
    st.stop()

# Convert date safely
df["date"] = pd.to_datetime(df["date"], errors="coerce")


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
# OPTIONAL: RECENT ACTIVITY
# -------------------------------

st.subheader("Recent Activity (Last 7 Days)")

if "date" in filtered_df.columns:
    cutoff = pd.Timestamp.now(tz="UTC") - pd.Timedelta(days=7)

    recent_df = filtered_df[
        filtered_df["date"] >= cutoff
    ]

    st.metric("Records (Last 7 Days)", len(recent_df))
else:
    st.metric("Records (Last 7 Days)", "N/A")

st.metric("Records (Last 7 Days)", len(recent_df))