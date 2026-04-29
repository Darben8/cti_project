"""Unified CTI dashboard for local datasets and live source summaries."""

import os
from datetime import datetime

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st
from dotenv import load_dotenv
import plotly.express as px

load_dotenv()

st.title("CTI Dashboard")
st.caption("Merged dashboard for PhishTank, combined IOC data, ransomware.live, Shodan, and critical assets.")

SOURCE_COLORS = {
    "PhishTank CSV": "#00A6A6",
    "combined_iocs.csv": "#F18F01",
    "ThreatFox API": "#6A4C93",
    "ransomware.live": "#C73E1D",
}

TYPE_COLORS = [
    "#00A6A6",
    "#F18F01",
    "#C73E1D",
    "#6A4C93",
    "#2E86AB",
    "#7FB069",
    "#D1495B",
]

CATEGORY_COLORS = [
    "#00A6A6",
    "#F18F01",
    "#C73E1D",
    "#6A4C93",
    "#2E86AB",
    "#7FB069",
    "#D1495B",
    "#577590",
]

ASSET_HEATMAP_SCALE = [
    [0.0, "#fef6e4"],
    [0.2, "#ffd166"],
    [0.4, "#f4a261"],
    [0.6, "#e76f51"],
    [0.8, "#8d99ae"],
    [1.0, "#264653"],
]


def empty_records_df() -> pd.DataFrame:
    return pd.DataFrame(
        columns=["indicator", "type", "category", "source", "date", "tags", "record_kind", "asset"]
    )


def first_available_series(df: pd.DataFrame, columns: list[str], default_value="") -> pd.Series:
    for column in columns:
        if column in df.columns:
            return df[column].fillna(default_value)
    return pd.Series([default_value] * len(df), index=df.index)


def classify_asset(indicator: str, category: str, tags: str, source: str) -> str:
    text = " ".join([str(indicator), str(category), str(tags), str(source)]).lower()

    if any(token in text for token in ["phishing", "login", "credential", "url"]):
        return "Online and mobile banking platforms"
    if any(token in text for token in ["domain", "ipv4", "host", "port", "exposure"]):
        return "Internet-facing infrastructure"
    if any(token in text for token in ["dridex", "qakbot", "gozi", "icedid", "malware", "sha256", "md5"]):
        return "Customer data repositories"
    if any(token in text for token in ["ransomware", "victim"]):
        return "Core banking systems"
    return "Security operations stack (SIEM/EDR/SOAR)"


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
    normalized["asset"] = normalized.apply(
        lambda row: classify_asset(row["indicator"], row["category"], row["tags"], row["source"]),
        axis=1,
    )
    return normalized[["indicator", "type", "category", "source", "date", "tags", "record_kind", "asset"]]


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
        normalized = normalize_ioc_df(df, "combined_iocs.csv")
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
        normalized["asset"] = "Core banking systems"
        return normalized[["indicator", "type", "category", "source", "date", "tags", "record_kind", "asset"]]
    except Exception:
        return empty_records_df()


@st.cache_data(ttl=3600)
def fetch_shodan_summary() -> tuple[pd.DataFrame, int | None]:
    key = os.getenv("SHODAN_API_KEY", "").strip()
    if not key:
        df = pd.DataFrame([{"source": "Shodan", "metric": "US banking exposure matches", "value": "Missing API key"}])
        return df, None

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
        df = pd.DataFrame([{"source": "Shodan", "metric": "US banking exposure matches", "value": f"{total:,}"}])
        return df, total
    except Exception:
        df = pd.DataFrame([{"source": "Shodan", "metric": "US banking exposure matches", "value": "Unavailable"}])
        return df, None


@st.cache_data(ttl=3600)
def load_critical_assets() -> pd.DataFrame:
    df = pd.read_csv("data/critical_assets.csv")
    df["criticality_1_low_5_high"] = pd.to_numeric(df["criticality_1_low_5_high"], errors="coerce").fillna(0)
    return df


def build_asset_alignment(assets_df: pd.DataFrame) -> pd.DataFrame:
    aligned = assets_df.copy()
    aligned["alignment_group"] = aligned["asset"]
    return aligned


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
    shodan_df, shodan_total = fetch_shodan_summary()
    critical_assets_df = build_asset_alignment(load_critical_assets())

if records_df.empty:
    st.warning("No dashboard records could be loaded.")
    st.stop()

with st.expander("Milestone 3 Deliverables"):
    st.subheader("Preliminary Visualization: Infrastructure Exposure")
#################################################################################
    # 1. Ensure date is datetime (Fixes the .dt error from earlier)
    df_shodan = pd.read_csv('data/threat_events.csv')
    df_shodan['date'] = pd.to_datetime(df_shodan['date'])

    with st.expander("View Threats by Density & Severity"):

        # 2. Create the Scatter Plot
        # x: Time of incident
        # y: Type of threat or asset
        # size: Number of incidents (to make it a 'bubble' chart)
        # color: Severity level
        fig = px.scatter(
            df_shodan, 
            x="date", 
            y="threat_type",
            size="incident_count", 
            color="severity",
            hover_name="target_asset",
            title="Threat Density & Severity Over Time",
            labels={"date": "Discovery Date", "threat_type": "Type of Threat"},
            template="plotly_white" # This helps remove background colors
        )

        # 3. Remove background color specifically from this chart object
        fig.update_layout({
            'plot_bgcolor': 'rgba(0, 0, 0, 0)',
            'paper_bgcolor': 'rgba(0, 0, 0, 0)',
        })

        st.plotly_chart (fig, use_container_width=True)

###############################################################################
    df_shodan=pd.read_csv('data/threat_events.csv')

    # Create the Chart: Port Distribution
    fig = px.pie(df_shodan, 
                names='threat_type', 
                title='Distribution of Threat Types')
    with st.expander("View Threats per Exposed Ports (Shodan)", expanded=False):
        st.plotly_chart(fig, use_container_width=True)


##############################################################################
    # Load data
    df_shodan = pd.read_csv('data/threat_events.csv')

    # Convert date column
    df_shodan['date'] = pd.to_datetime(df_shodan['date'])

    with st.expander("View Threats per Critical Asset", expanded=False):

        # ---- Date Filter ----
        date_range = st.date_input(
            "Select Date Range",
            [
                df_shodan['date'].min().date(),
                df_shodan['date'].max().date()
            ]
        )

        # ---- Categorical Filters ----
        col1, col2, col3 = st.columns(3)

        with col1:
            threat_types = st.multiselect(
                "Threat Type",
                sorted(df_shodan['threat_type'].unique()),
                default=sorted(df_shodan['threat_type'].unique())
            )

        with col2:
            regions = st.multiselect(
                "Region",
                sorted(df_shodan['region'].unique()),
                default=sorted(df_shodan['region'].unique())
            )

        with col3:
            severities = st.multiselect(
                "Severity",
                sorted(df_shodan['severity'].unique()),
                default=sorted(df_shodan['severity'].unique())
            )

        assets = st.multiselect(
            "Target Asset",
            sorted(df_shodan['target_asset'].unique()),
            default=sorted(df_shodan['target_asset'].unique())
        )

        sources = st.multiselect(
            "Source",
            sorted(df_shodan['source'].unique()),
            default=sorted(df_shodan['source'].unique())
        )

        # ---- Top N Slider ----
        top_n = st.slider(
            "Show Top N Assets",
            min_value=1,
            max_value=len(df_shodan['target_asset'].unique()),
            value=5
        )

        # ---- Apply Filters ----
        filtered_df = df_shodan[
            (df_shodan['date'].dt.date >= date_range[0]) &
            (df_shodan['date'].dt.date <= date_range[1]) &
            (df_shodan['threat_type'].isin(threat_types)) &
            (df_shodan['region'].isin(regions)) &
            (df_shodan['severity'].isin(severities)) &
            (df_shodan['target_asset'].isin(assets)) &
            (df_shodan['source'].isin(sources))
        ]

        # ---- Aggregate and Select Top N Assets ----
        top_assets_df = (
            filtered_df
            .groupby('target_asset', as_index=False)['incident_count']
            .sum()
            .sort_values(by='incident_count', ascending=False)
            .head(top_n)
        )

        # ---- Pie Chart ----
        fig = px.pie(
            top_assets_df,
            names='target_asset',
            values='incident_count',
            title=f'Top {top_n} Threatened Critical Assets'
        )

        fig.update_layout(height=600)

        st.plotly_chart(fig, use_container_width=True)

st.divider()

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
    top_category = filtered_df["category"].fillna("Unknown").value_counts().idxmax() if not filtered_df.empty else "N/A"
    st.metric("Top Category", top_category)

with col4:
    valid_dates = filtered_df["date"].dropna()
    coverage = "N/A" if valid_dates.empty else f"{valid_dates.min().date()} to {valid_dates.max().date()}"
    st.metric("Date Coverage", coverage)

# st.subheader("Timeline by Source")
# timeline_df = (
#     filtered_df.dropna(subset=["date"])
#     .assign(date_day=lambda frame: frame["date"].dt.date)
#     .groupby(["date_day", "source"], as_index=False)
#     .size()
#     .rename(columns={"size": "record_count"})
# )
# if timeline_df.empty:
#     st.info("No dated records available for the current filters.")
# else:
#     fig_timeline = px.line(
#         timeline_df,
#         x="date_day",
#         y="record_count",
#         color="source",
#         markers=True,
#         color_discrete_map=SOURCE_COLORS,
#         labels={"date_day": "Date", "record_count": "Record Count", "source": "Source"},
#     )
#     fig_timeline.update_layout(plot_bgcolor="#fffaf2", paper_bgcolor="#fffaf2")
#     st.plotly_chart(fig_timeline, use_container_width=True)

left_col, right_col = st.columns(2)

with left_col:
    st.subheader("Indicator Type Distribution")
    type_counts = (
        filtered_df["type"]
        .fillna("Unknown")
        .value_counts()
        .rename_axis("type")
        .reset_index(name="count")
    )
    if type_counts.empty:
        st.info("No indicator types are available for the current filters.")
    else:
        fig_types = px.pie(
            type_counts,
            names="type",
            values="count",
            color_discrete_sequence=TYPE_COLORS,
            hole=0.45,
        )
        fig_types.update_layout(paper_bgcolor="#f6fbff")
        st.plotly_chart(fig_types, use_container_width=True)

with right_col:
    st.subheader("Ransomware Activity Over Time")
    ransomware_df = filtered_df[filtered_df["source"] == "ransomware.live"].dropna(subset=["date"]).copy()
    # Convert the date column to datetime objects
    ransomware_df['date'] = pd.to_datetime(ransomware_df['date'])   
    if ransomware_df.empty:
        st.info("No ransomware.live records available for the current filters.")
    else:
        ransomware_series = (
            ransomware_df.assign(date_day=lambda frame: frame["date"].dt.date)
            .groupby("date_day", as_index=False)
            .size()
            .rename(columns={"size": "victim_count"})
        )
        fig_ransomware = px.bar(
            ransomware_series,
            x="date_day",
            y="victim_count",
            color="victim_count",
            color_continuous_scale=["#ffd166", "#f18f01", "#c73e1d"],
            labels={"date_day": "Date", "victim_count": "Victim Count"},
        )
        fig_ransomware.update_layout(plot_bgcolor="#fff7f5", paper_bgcolor="#fff7f5", coloraxis_showscale=False)
        st.plotly_chart(fig_ransomware, use_container_width=True)

asset_threat_counts = (
    filtered_df.groupby("asset", as_index=False)
    .size()
    .rename(columns={"size": "threat_count"})
)
asset_threat_counts = asset_threat_counts.rename(columns={"asset": "mapped_asset"})

asset_bar_df = critical_assets_df.merge(
    asset_threat_counts,
    left_on="alignment_group",
    right_on="mapped_asset",
    how="left",
).fillna({"threat_count": 0})

st.subheader("Threat Counts Aligned to Critical Assets")
fig_assets = px.bar(
    asset_bar_df.sort_values(["threat_count", "criticality_1_low_5_high"], ascending=[False, False]),
    x="threat_count",
    y="asset",
    orientation="h",
    color="criticality_1_low_5_high",
    color_continuous_scale=["#43aa8b", "#90be6d", "#f9c74f", "#f3722c", "#f94144"],
    labels={"threat_count": "Mapped Threat Count", "asset": "Critical Asset", "criticality_1_low_5_high": "Criticality"},
)
fig_assets.update_layout(plot_bgcolor="#f8fff7", paper_bgcolor="#f8fff7", coloraxis_showscale=False)
st.plotly_chart(fig_assets, use_container_width=True)

heatmap_df = (
    filtered_df.groupby(["source", "asset"], as_index=False)
    .size()
    .rename(columns={"size": "record_count"})
)

st.subheader("Source-to-Asset Heatmap")
if heatmap_df.empty:
    st.info("No source-to-asset combinations are available for the current filters.")
else:
    heatmap_pivot = heatmap_df.pivot(index="source", columns="asset", values="record_count").fillna(0)
    fig_heatmap = go.Figure(
        data=go.Heatmap(
            z=heatmap_pivot.values,
            x=list(heatmap_pivot.columns),
            y=list(heatmap_pivot.index),
            colorscale=ASSET_HEATMAP_SCALE,
            hoverongaps=False,
        )
    )
    fig_heatmap.update_layout(plot_bgcolor="#fbf8ff", paper_bgcolor="#fbf8ff")
    st.plotly_chart(fig_heatmap, use_container_width=True)

st.subheader("Top Exposed Categories from Shodan + Critical Asset Alignment")
if shodan_total is None:
    st.info("Shodan exposure data is unavailable right now.")
else:
    shodan_alignment = critical_assets_df.copy()
    shodan_alignment["internet_exposure_weight"] = shodan_alignment["asset"].str.contains(
        "online|mobile|payment|swift|tokenized|identity",
        case=False,
        regex=True,
    ).astype(int) + (shodan_alignment["criticality_1_low_5_high"] / 5.0)
    shodan_alignment["aligned_exposure_score"] = (
        shodan_alignment["internet_exposure_weight"] / shodan_alignment["internet_exposure_weight"].sum()
    ) * shodan_total
    fig_shodan = px.bar(
        shodan_alignment.sort_values("aligned_exposure_score", ascending=False),
        x="asset",
        y="aligned_exposure_score",
        color="criticality_1_low_5_high",
        color_continuous_scale=["#577590", "#43aa8b", "#f9c74f", "#f3722c"],
        labels={"asset": "Critical Asset", "aligned_exposure_score": "Inferred Exposure Alignment", "criticality_1_low_5_high": "Criticality"},
    )
    fig_shodan.update_layout(plot_bgcolor="#f4fbff", paper_bgcolor="#f4fbff", coloraxis_showscale=False)
    st.plotly_chart(fig_shodan, use_container_width=True)
    st.caption("Shodan alignment is an inferred view based on exposure count plus critical asset internet-facing relevance.")

st.subheader("Top Categories")
top_categories = (
    filtered_df["category"]
    .fillna("Unknown")
    .value_counts()
    .head(10)
    .rename_axis("category")
    .reset_index(name="count")
)
if top_categories.empty:
    st.info("No categories are available for the current filters.")
else:
    fig_categories = px.bar(
        top_categories,
        x="category",
        y="count",
        color="category",
        color_discrete_sequence=CATEGORY_COLORS,
        labels={"category": "Threat Category", "count": "Record Count"},
    )
    fig_categories.update_layout(plot_bgcolor="#fffaf2", paper_bgcolor="#fffaf2", showlegend=False)
    st.plotly_chart(fig_categories, use_container_width=True)

# st.subheader("Sample Records")
# sample_cols = ["source", "asset", "indicator", "type", "category", "date", "tags"]
# st.dataframe(
#     filtered_df[sample_cols].sort_values("date", ascending=False, na_position="last").head(25),
#     use_container_width=True,
#     hide_index=True,
# )

st.subheader("Shodan Summary")
st.dataframe(shodan_df, use_container_width=True, hide_index=True)

st.caption(f"Last dashboard refresh: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
