"""Role-based analytics page for executive and analyst audiences."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pandas as pd
import hashlib
from pandas.errors import EmptyDataError
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CORRELATION_DIR = PROJECT_ROOT / "data" / "ransomware_event_correlation"
THREATFOX_PATH = PROJECT_ROOT / "data" / "filtered_iocs_threatfox.csv"
TEXT_MINING_DIR = PROJECT_ROOT / "data" / "phishing_url_text_mining"
THREATFOX_KMEANS_DIR = PROJECT_ROOT / "data" / "kmeans_validation"
CRITICAL_ASSETS_PATH = PROJECT_ROOT / "data" / "critical_assets.csv"
PHISHING_RAW_PATH = PROJECT_ROOT / "data" / "verified_online_banking_finance.csv"
FINANCE_VICTIMS_PATH = PROJECT_ROOT / "data" / "finance_victims.csv"

PAGE_COLORS = {
    "group": "#C73E1D",
    "victim": "#2E86AB",
    "country": "#7FB069",
    "ioc": "#F18F01",
    "ioc_type": "#6A4C93",
    "ttp": "#00A6A6",
    "malware": "#D1495B",
}


# ── Dark theme + component CSS ────────────────────────────────────────────────
DARK_THEME_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600;700&display=swap');

html, body, [data-testid="stAppViewContainer"] {
    background-color: #080f1a;
    color: #c9d1d9;
    font-family: 'IBM Plex Sans', sans-serif;
}

[data-testid="stSidebar"] {
    background-color: #0d1526 !important;
    border-right: 1px solid #1e3a5f;
}
[data-testid="stSidebar"] * {
    color: #8ba3c0 !important;
    font-family: 'IBM Plex Sans', sans-serif !important;
}
[data-testid="stSidebar"] [aria-selected="true"] {
    background-color: #0f2644 !important;
    color: #38bdf8 !important;
    border-left: 3px solid #38bdf8;
}

.block-container { padding-top: 2rem; }

/* ── Executive finding cards ── */
.exec-card {
    border: 1px solid #1e3a5f;
    border-radius: 14px;
    padding: 1rem 1.1rem;
    margin-bottom: 0.9rem;
    background: linear-gradient(180deg, #0d1e35 0%, #0a1828 100%);
}
.exec-card h4 {
    margin: 0 0 0.4rem 0;
    color: #e6edf3;
}
.exec-card p {
    margin: 0.15rem 0 0.35rem 0;
    color: #8ba3c0;
}
.exec-label {
    color: #38bdf8;
    font-weight: 700;
}

/* ── COA cards — same visual treatment as exec-card ── */
.coa-card {
    border: 1px solid #1e3a5f;
    border-radius: 14px;
    padding: 1rem 1.1rem;
    margin-bottom: 0.9rem;
    background: linear-gradient(180deg, #0d1e35 0%, #0a1828 100%);
}
.coa-card h4 {
    margin: 0 0 0.5rem 0;
    color: #e6edf3;
    font-size: 0.97rem;
}
.coa-meta {
    display: flex;
    gap: 1.4rem;
    flex-wrap: wrap;
    margin-bottom: 0.4rem;
}
.coa-meta-item {
    font-size: 0.82rem;
    color: #8ba3c0;
}
.coa-meta-item strong {
    color: #38bdf8;
    font-weight: 600;
}
.coa-why {
    font-size: 0.85rem;
    color: #8ba3c0;
    margin: 0;
    line-height: 1.55;
}

/* ── Approach justification cards ── */
.cti-banner {
    background: linear-gradient(135deg, #0f2644 0%, #080f1a 60%, #091a10 100%);
    color: #e6edf3;
    border: 1px solid #1e3a5f;
    border-radius: 14px;
    padding: 1.2rem 1.3rem;
    margin-bottom: 1rem;
}
.cti-banner h3 { margin: 0 0 0.35rem 0; color: #e6edf3; }
.cti-banner p  { margin: 0; color: #8ba3c0; }

.cti-badge {
    display: inline-block;
    padding: 0.35rem 0.7rem;
    margin: 0 0.4rem 0.45rem 0;
    border-radius: 999px;
    font-size: 0.84rem;
    font-weight: 600;
    border: 1px solid transparent;
}
.badge-blue  { background: rgba(56,189,248,0.12); color: #38bdf8; border-color: rgba(56,189,248,0.3); }
.badge-teal  { background: rgba(45,196,190,0.10); color: #2dc4be; border-color: rgba(45,196,190,0.3); }
.badge-slate { background: rgba(139,163,192,0.10); color: #8ba3c0; border-color: rgba(139,163,192,0.25); }

.method-card {
    border-radius: 14px;
    padding: 1rem 1rem 0.9rem 1rem;
    margin-bottom: 1rem;
    border: 1px solid #1e3a5f;
    background: #0d1526;
}
.method-card h4 { margin: 0 0 0.2rem 0; color: #e6edf3; }
.method-card p  { margin: 0 0 0.75rem 0; color: #8ba3c0; }
.method-blue  { border-top: 5px solid #38bdf8; }
.method-teal  { border-top: 5px solid #2dc4be; }
.method-navy  { border-top: 5px solid #6366f1; }

.info-block {
    border-radius: 8px;
    padding: 0.6rem 0.8rem;
    margin-bottom: 0.5rem;
    border-left: 4px solid;
    font-size: 0.83rem;
    color: #8ba3c0;
}
.analysis-block   { border-color: #38bdf8; background: rgba(56,189,248,0.06); }
.output-block     { border-color: #2dc4be; background: rgba(45,196,190,0.06); }
.validation-block { border-color: #4ade80; background: rgba(74,222,128,0.06); }
.limit-block      { border-color: #f59e0b; background: rgba(245,158,11,0.06); }
.risk-block       { border-color: #f87171; background: rgba(248,113,113,0.06); }

.bottom-panel {
    border-radius: 12px;
    padding: 1rem 1rem 0.8rem 1rem;
    border: 1px solid #1e3a5f;
    background: #0d1526;
    height: 100%;
}
.bottom-panel h4 { margin: 0 0 0.5rem 0; color: #e6edf3; }
.bottom-panel ul { margin: 0; padding-left: 1.1rem; }
.bottom-panel li { margin-bottom: 0.45rem; color: #8ba3c0; }

/* ── Analyst divider label ── */
.analyst-section-label {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.68rem;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: #38bdf8;
    margin: 1.6rem 0 0.5rem;
    padding-left: 2px;
}

#MainMenu, footer, header { visibility: hidden; }
</style>
"""


st.markdown(DARK_THEME_CSS, unsafe_allow_html=True)
st.title("CTI Analytics")
st.caption(
    "Role-based CTI analytics for U.S. banking, translating the same threat findings "
    "into leadership-ready decisions and analyst-ready technical evidence."
)


# ── Data loaders ──────────────────────────────────────────────────────────────

@st.cache_data
def load_csv(name: str) -> pd.DataFrame:
    path = CORRELATION_DIR / name
    if not path.exists():
        return pd.DataFrame()
    try:
        return pd.read_csv(path)
    except EmptyDataError:
        return pd.DataFrame()


@st.cache_data
def load_table(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame()
    try:
        return pd.read_csv(path)
    except EmptyDataError:
        return pd.DataFrame()


@st.cache_data
def load_critical_assets() -> pd.DataFrame:
    if not CRITICAL_ASSETS_PATH.exists():
        return pd.DataFrame()
    df = pd.read_csv(CRITICAL_ASSETS_PATH)
    if "criticality_1_low_5_high" in df.columns:
        df["criticality_1_low_5_high"] = pd.to_numeric(
            df["criticality_1_low_5_high"], errors="coerce"
        ).fillna(0)
    return df


def build_asset_alignment(assets_df: pd.DataFrame) -> pd.DataFrame:
    aligned = assets_df.copy()
    if "alignment_group" not in aligned.columns and "asset" in aligned.columns:
        aligned["alignment_group"] = aligned["asset"]
    return aligned


@st.cache_data
def load_phishing_raw() -> pd.DataFrame:
    if not PHISHING_RAW_PATH.exists():
        return pd.DataFrame()
    df = pd.read_csv(PHISHING_RAW_PATH)
    if "submission_time" in df.columns:
        df["submission_time"] = pd.to_datetime(df["submission_time"], errors="coerce", utc=True)
    return df


def empty_records_df() -> pd.DataFrame:
    return pd.DataFrame(
        columns=["indicator", "type", "category", "source", "date", "tags", "record_kind", "asset"]
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def classify_asset(indicator: str, category: str, tags: str, source: str) -> str:
    text = " ".join([str(indicator), str(category), str(tags), str(source)]).lower()
    if any(token in text for token in ["phishing", "login", "credential", "url"]):
        return "Online and mobile banking platforms"
    if any(token in text for token in ["domain", "ipv4", "host", "port", "exposure", "ip:port"]):
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

    indicator_col = lower_map.get("indicator") or lower_map.get("ioc") or lower_map.get("ioc_value")
    type_col      = lower_map.get("type") or lower_map.get("ioc_type") or lower_map.get("ioc type")
    category_col  = lower_map.get("ioc type") or lower_map.get("threat_type") or lower_map.get("category")
    date_col      = (lower_map.get("first seen") or lower_map.get("first_seen")
                    or lower_map.get("date") or lower_map.get("first_seen_utc"))
    tags_col      = lower_map.get("tags") or lower_map.get("malware") or lower_map.get("malware_printable")

    normalized = pd.DataFrame()
    normalized["indicator"] = working[indicator_col] if indicator_col else ""
    normalized["type"]      = working[type_col]      if type_col      else "unknown"
    normalized["category"]  = working[category_col]  if category_col  else normalized["type"]
    normalized["source"]    = source_name
    normalized["date"]      = pd.to_datetime(
        working[date_col] if date_col else pd.NaT,
        errors="coerce", dayfirst=True, utc=True,
    )
    normalized["tags"]        = working[tags_col] if tags_col else ""
    normalized["record_kind"] = "ioc"
    normalized["asset"]       = normalized.apply(
        lambda row: classify_asset(row["indicator"], row["category"], row["tags"], row["source"]),
        axis=1,
    )
    return normalized[["indicator", "type", "category", "source", "date", "tags", "record_kind", "asset"]]


@st.cache_data
def build_executive_records() -> pd.DataFrame:
    records: list[pd.DataFrame] = []

    phishing_df = load_phishing_raw()
    if not phishing_df.empty:
        phishing_records = pd.DataFrame()
        phishing_records["indicator"]   = phishing_df["url"]
        phishing_records["type"]        = "url"
        phishing_records["category"]    = "phishing"
        phishing_records["source"]      = "Verified Banking Phishing"
        phishing_records["date"]        = pd.to_datetime(phishing_df["submission_time"], errors="coerce", utc=True)
        phishing_records["tags"]        = phishing_df["target"].fillna("") + " " + phishing_df["banking_match_term"].fillna("")
        phishing_records["record_kind"] = "ioc"
        phishing_records["asset"]       = phishing_records.apply(
            lambda row: classify_asset(row["indicator"], row["category"], row["tags"], row["source"]),
            axis=1,
        )
        records.append(
            phishing_records[["indicator", "type", "category", "source", "date", "tags", "record_kind", "asset"]]
        )

    threatfox_df = load_table(THREATFOX_PATH)
    if not threatfox_df.empty:
        records.append(normalize_ioc_df(threatfox_df, "ThreatFox"))

    if FINANCE_VICTIMS_PATH.exists():
        victims_df = pd.read_csv(FINANCE_VICTIMS_PATH)
        if not victims_df.empty:
            victims_records = pd.DataFrame()
            victims_records["indicator"]   = victims_df["victim_name"].fillna(victims_df.get("website", "ransomware victim"))
            victims_records["type"]        = "victim"
            victims_records["category"]    = "ransomware"
            victims_records["source"]      = "Finance Victims"
            victims_records["date"]        = pd.to_datetime(victims_df["discovered"], errors="coerce", utc=True)
            victims_records["tags"]        = victims_df["group"].fillna("") + " " + victims_df["country"].fillna("")
            victims_records["record_kind"] = "victim"
            victims_records["asset"]       = "Core banking systems"
            records.append(
                victims_records[["indicator", "type", "category", "source", "date", "tags", "record_kind", "asset"]]
            )

    if not records:
        return empty_records_df()
    return pd.concat(records, ignore_index=True)


def has_columns(df: pd.DataFrame, required: list[str]) -> bool:
    return not df.empty and all(column in df.columns for column in required)


def selected_relations(view: str) -> set[str]:
    if view == "Group -> IOC type -> TTP":
        return {"group_to_ioc", "ioc_to_type", "group_to_ttp"}
    if view == "Group -> Country -> IOC":
        return {"group_to_country", "group_to_ioc"}
    return {"group_to_victim"}


# ── Network figure ────────────────────────────────────────────────────────────

def build_network_figure(
    nodes_df: pd.DataFrame,
    edges_df: pd.DataFrame,
    groups: set[str],
    view: str,
    max_iocs: int = 120,
) -> go.Figure:
    required_node_cols = ["node_id", "node_type", "degree", "label", "component_id"]
    required_edge_cols = ["source", "target", "relation"]
    if not has_columns(nodes_df, required_node_cols) or not has_columns(edges_df, required_edge_cols):
        return go.Figure()

    relation_filter = selected_relations(view)
    group_node_ids  = {f"group:{group}" for group in groups}
    selected_edges  = edges_df[edges_df["relation"].isin(relation_filter)].copy()
    selected_edges  = selected_edges[
        selected_edges["source"].isin(group_node_ids) | selected_edges["target"].isin(group_node_ids)
    ]

    if "group_to_ioc" in relation_filter:
        ioc_edges    = selected_edges[selected_edges["relation"] == "group_to_ioc"].head(max_iocs)
        allowed_iocs = set(ioc_edges["target"])
        selected_edges = selected_edges[
            (selected_edges["relation"] != "group_to_ioc")
            | selected_edges["target"].isin(allowed_iocs)
            | selected_edges["source"].isin(allowed_iocs)
        ]

    selected_nodes = set(selected_edges["source"]) | set(selected_edges["target"])
    network_nodes  = nodes_df[nodes_df["node_id"].isin(selected_nodes)].copy()

    if network_nodes.empty or selected_edges.empty:
        return go.Figure()

    type_order = ["group", "country", "ioc_type", "ttp", "ioc", "victim", "malware"]
    x_positions = {node_type: idx for idx, node_type in enumerate(type_order)}
    network_nodes["x"]    = network_nodes["node_type"].map(x_positions).fillna(len(type_order))
    network_nodes["rank"] = network_nodes.groupby("node_type").cumcount()
    type_counts = network_nodes["node_type"].value_counts().to_dict()
    network_nodes["y"] = network_nodes.apply(
        lambda row: row["rank"] - ((type_counts.get(row["node_type"], 1) - 1) / 2),
        axis=1,
    )

    position = network_nodes.set_index("node_id")[["x", "y"]].to_dict("index")
    edge_x: list[float | None] = []
    edge_y: list[float | None] = []

    for _, row in selected_edges.iterrows():
        if row["source"] not in position or row["target"] not in position:
            continue
        edge_x.extend([position[row["source"]]["x"], position[row["target"]]["x"], None])
        edge_y.extend([position[row["source"]]["y"], position[row["target"]]["y"], None])

    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=edge_x, y=edge_y,
            mode="lines",
            line=dict(width=0.6, color="rgba(90,90,90,0.35)"),
            hoverinfo="none",
            name="relationships",
        )
    )

    for node_type, color in PAGE_COLORS.items():
        subset = network_nodes[network_nodes["node_type"] == node_type]
        if subset.empty:
            continue
        fig.add_trace(
            go.Scatter(
                x=subset["x"], y=subset["y"],
                mode="markers+text",
                marker=dict(
                    size=subset["degree"].clip(lower=4, upper=28),
                    color=color,
                    line=dict(width=0.7, color="white"),
                ),
                text=subset["label"].where(subset["degree"] >= 3, ""),
                textposition="middle right",
                hovertemplate=(
                    "<b>%{customdata[0]}</b><br>"
                    "Type: %{customdata[1]}<br>"
                    "Degree: %{customdata[2]}<br>"
                    "Component: %{customdata[3]}<extra></extra>"
                ),
                customdata=subset[["label", "node_type", "degree", "component_id"]],
                name=node_type,
            )
        )

    # fig.update_layout(
    #     title=f"Relationship Network: {view}",
    #     xaxis=dict(visible=False),
    #     yaxis=dict(visible=False),
    #     height=650,
    #     margin=dict(l=10, r=10, t=60, b=10),
    #     legend_title_text="Node Type",
    #     paper_bgcolor="rgba(0,0,0,0)",
    #     plot_bgcolor="rgba(0,0,0,0)",
    #     font_color="#c9d1d9",
    # )
    # return fig


# ── Metric helpers ────────────────────────────────────────────────────────────

def metric_lookup(metrics_df: pd.DataFrame, metric_name: str, default: float = 0.0) -> float:
    if not has_columns(metrics_df, ["metric", "value"]):
        return default
    match = metrics_df.loc[metrics_df["metric"] == metric_name, "value"]
    if match.empty:
        return default
    return float(match.iloc[0])


def risk_label(score: float) -> str:
    if score >= 5:
        return "Critical"
    if score >= 4:
        return "High"
    if score >= 3:
        return "Moderate"
    return "Monitored"


# ── Analyst panels ────────────────────────────────────────────────────────────

def render_text_mining_panel(
    features_df: pd.DataFrame,
    metrics_df: pd.DataFrame,
    tfidf_df: pd.DataFrame,
    ngrams_df: pd.DataFrame,
) -> None:
    st.markdown("### Text Mining Explorer")

    if features_df.empty:
        st.info("No phishing URL text-mining outputs were found.")
        return

    control_cols = st.columns([1.2, 1.2, 1, 1])
    target_options  = ["All"] + sorted(features_df["target"].dropna().astype(str).unique().tolist())
    selected_target = control_cols[0].selectbox("Target", target_options, key="tm_target_analytics")
    tld_options     = sorted(features_df["tld"].dropna().astype(str).unique().tolist())
    selected_tlds   = control_cols[1].multiselect(
        "TLDs", tld_options,
        default=tld_options[: min(6, len(tld_options))] if tld_options else [],
        key="tm_tlds_analytics",
    )
    banking_only   = control_cols[2].checkbox("Banking keywords only",  value=False, key="tm_kw_only_analytics")
    suspicious_only = control_cols[3].checkbox("Suspicious TLDs only", value=False, key="tm_suspicious_only_analytics")

    query = st.text_input(
        "Search URL or matched term",
        placeholder="Filter by URL, domain, target, or matched term",
        key="tm_search_analytics",
    ).strip()

    panel_df = features_df.copy()
    if selected_target != "All":
        panel_df = panel_df[panel_df["target"] == selected_target]
    if selected_tlds:
        panel_df = panel_df[panel_df["tld"].isin(selected_tlds)]
    if banking_only:
        panel_df = panel_df[panel_df["contains_banking_keyword"] == 1]
    if suspicious_only:
        panel_df = panel_df[panel_df["is_suspicious_tld"] == 1]
    if query:
        mask = (
            panel_df["url"].astype(str).str.contains(query, case=False, na=False)
            | panel_df["domain"].astype(str).str.contains(query, case=False, na=False)
            | panel_df["target"].astype(str).str.contains(query, case=False, na=False)
            | panel_df["banking_match_term"].astype(str).str.contains(query, case=False, na=False)
        )
        panel_df = panel_df[mask]

    metrics_cols  = st.columns(4)
    https_pct     = panel_df["uses_https"].mean() * 100 if not panel_df.empty else 0.0
    suspicious_pct = panel_df["is_suspicious_tld"].mean() * 100 if not panel_df.empty else 0.0
    metrics_cols[0].metric("URLs In View",       f"{len(panel_df):,}")
    metrics_cols[1].metric("Average URL Length", f"{panel_df['url_length'].mean() if not panel_df.empty else 0:.1f}")
    metrics_cols[2].metric("HTTPS Share",        f"{https_pct:.1f}%")
    metrics_cols[3].metric("Suspicious TLD Share", f"{suspicious_pct:.1f}%")

    if panel_df.empty:
        st.info("No phishing URL records match the current filters.")
        return

    keyword_cols   = [column for column in panel_df.columns if column.startswith("kw_")]
    keyword_counts = (
        panel_df[keyword_cols].sum().sort_values(ascending=False).head(10)
        .rename_axis("keyword").reset_index(name="count")
    )
    keyword_counts["keyword"] = keyword_counts["keyword"].str.replace("kw_", "", regex=False)
    tld_counts = panel_df["tld"].value_counts().head(10).rename_axis("tld").reset_index(name="count")

    left, right = st.columns([1.2, 1])
    with left:
        fig_keywords = px.bar(
            keyword_counts, x="keyword", y="count", color="count",
            color_continuous_scale="Tealgrn",
            title="Top Banking and Brand Keywords",
            labels={"keyword": "Keyword", "count": "URLs"},
        )
        fig_keywords.update_layout(coloraxis_showscale=False, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9")
        st.plotly_chart(fig_keywords, use_container_width=True)
    with right:
        fig_tlds = px.bar(
            tld_counts, x="tld", y="count", color="count",
            color_continuous_scale="Sunset",
            title="Top TLDs In View",
            labels={"tld": "TLD", "count": "URLs"},
        )
        fig_tlds.update_layout(coloraxis_showscale=False, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9")
        st.plotly_chart(fig_tlds, use_container_width=True)

    insight_left, insight_right = st.columns([1.1, 1])
    with insight_left:
        top_terms = tfidf_df.head(15) if not tfidf_df.empty else pd.DataFrame(columns=["term", "mean_tfidf"])
        if not top_terms.empty:
            fig_tfidf = px.bar(
                top_terms.sort_values("mean_tfidf"), x="mean_tfidf", y="term", orientation="h",
                title="Top TF-IDF Terms",
                labels={"mean_tfidf": "Mean TF-IDF", "term": "Term"},
            )
            fig_tfidf.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9")
            st.plotly_chart(fig_tfidf, use_container_width=True)
        else:
            st.info("No TF-IDF keywords were found.")
    with insight_right:
        top_ngrams_view = ngrams_df.head(15) if not ngrams_df.empty else pd.DataFrame(columns=["ngram", "count"])
        if not top_ngrams_view.empty:
            fig_ngrams = px.bar(
                top_ngrams_view.sort_values("count"), x="count", y="ngram", orientation="h",
                title="Most Repeated N-Grams",
                labels={"count": "Count", "ngram": "N-Gram"},
            )
            fig_ngrams.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9")
            st.plotly_chart(fig_ngrams, use_container_width=True)
        else:
            st.info("No n-gram output was found.")

    st.dataframe(
        panel_df[[
            "url", "target", "banking_match_source", "banking_match_term",
            "tld", "url_length", "uses_https", "suspicious_keyword_count",
            "finance_keyword_count", "brand_keyword_count",
        ]].head(75),
        use_container_width=True, hide_index=True,
    )

    if has_columns(metrics_df, ["metric", "value", "interpretation"]):
        st.markdown("### Text-Mining Evaluation Metrics")
        st.dataframe(metrics_df, use_container_width=True, hide_index=True)


def render_phishing_kmeans_panel(features_df: pd.DataFrame, metrics_df: pd.DataFrame) -> None:
    st.markdown("### Phishing URL Pattern Clustering")
    st.caption(
        "Source: `utilities/phishing_url_text_mining.py` using `phishing_url_features.csv` "
        "and `evaluation_metrics.csv`."
    )

    required_columns = [
        "url_pattern_cluster", "target", "uses_https",
        "url_length", "finance_keyword_count", "brand_keyword_count",
    ]
    if not has_columns(features_df, required_columns):
        st.info("No phishing URL K-Means clustering output was found in the text-mining files.")
        return

    control_cols    = st.columns([1.2, 1.2, 1, 1])
    cluster_options = sorted(features_df["url_pattern_cluster"].dropna().astype(int).unique().tolist())
    selected_clusters = control_cols[0].multiselect(
        "Clusters", cluster_options, default=cluster_options, key="km_clusters_analytics",
    )
    target_options  = ["All"] + sorted(features_df["target"].dropna().astype(str).unique().tolist())
    selected_target = control_cols[1].selectbox("Target", target_options, key="km_target_analytics")
    https_only      = control_cols[2].checkbox("HTTPS only", value=False, key="km_https_analytics")
    min_finance_terms = control_cols[3].slider("Min finance keywords", 0, 10, 0, key="km_finance_min_analytics")

    panel_df = features_df.copy()
    if selected_clusters:
        panel_df = panel_df[panel_df["url_pattern_cluster"].isin(selected_clusters)]
    if selected_target != "All":
        panel_df = panel_df[panel_df["target"] == selected_target]
    if https_only:
        panel_df = panel_df[panel_df["uses_https"] == 1]
    panel_df = panel_df[panel_df["finance_keyword_count"] >= min_finance_terms]

    silhouette    = metric_lookup(metrics_df, "silhouette_score")
    davies_bouldin = metric_lookup(metrics_df, "davies_bouldin_score")
    calinski      = metric_lookup(metrics_df, "calinski_harabasz_score")

    metrics_cols = st.columns(4)
    metrics_cols[0].metric("URLs In View",    f"{len(panel_df):,}")
    metrics_cols[1].metric("Clusters In View", f"{panel_df['url_pattern_cluster'].nunique() if not panel_df.empty else 0:,}")
    metrics_cols[2].metric("Silhouette Score", f"{silhouette:.3f}")
    metrics_cols[3].metric("Davies-Bouldin",   f"{davies_bouldin:.3f}")
    st.caption(f"Calinski-Harabasz score: {calinski:.3f}")

    if panel_df.empty:
        st.info("No clustered URL records match the current filters.")
        return

    cluster_summary = (
        panel_df.groupby("url_pattern_cluster")
        .agg(
            url_count=("url", "count"),
            avg_url_length=("url_length", "mean"),
            avg_finance_keywords=("finance_keyword_count", "mean"),
            avg_brand_keywords=("brand_keyword_count", "mean"),
            dominant_target=("target", lambda s: s.mode().iloc[0] if not s.mode().empty else "Unknown"),
        )
        .reset_index()
    )

    left, right = st.columns([1.2, 1])
    with left:
        fig_clusters = px.bar(
            cluster_summary, x="url_pattern_cluster", y="url_count", color="dominant_target",
            title="Records Per Cluster",
            labels={"url_pattern_cluster": "Cluster", "url_count": "URLs", "dominant_target": "Dominant Target"},
        )
        fig_clusters.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9")
        st.plotly_chart(fig_clusters, use_container_width=True)
    with right:
        fig_cluster_keywords = px.scatter(
            cluster_summary, x="avg_finance_keywords", y="avg_brand_keywords",
            size="url_count", color="url_pattern_cluster", hover_name="dominant_target",
            title="Cluster Keyword Profile",
            labels={
                "avg_finance_keywords": "Avg Finance Keywords",
                "avg_brand_keywords": "Avg Brand Keywords",
                "url_pattern_cluster": "Cluster",
            },
        )
        fig_cluster_keywords.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9")
        st.plotly_chart(fig_cluster_keywords, use_container_width=True)

    st.dataframe(cluster_summary, use_container_width=True, hide_index=True)
    st.dataframe(
        panel_df[[
            "url", "target", "url_pattern_cluster", "tld", "url_length",
            "finance_keyword_count", "brand_keyword_count", "uses_https",
        ]].head(75),
        use_container_width=True, hide_index=True,
    )


def render_threatfox_kmeans_panel(features_df: pd.DataFrame, metrics_df: pd.DataFrame) -> None:
    st.markdown("### ThreatFox Malware IOC Clustering")
    st.caption(
        "Source: `utilities/kmeans2.py` using ThreatFox IOC records saved in "
        "`iocs_with_clusters.csv` and `kmeans_validation_metrics.csv`."
    )

    required_columns = ["cluster", "malware_printable", "ioc_type", "threat_type", "confidence_level", "ioc_value"]
    if not has_columns(features_df, required_columns):
        st.info("No ThreatFox K-Means clustering output was found in `data/kmeans_validation`.")
        return

    control_cols    = st.columns([1.2, 1.2, 1, 1])
    cluster_options = sorted(features_df["cluster"].dropna().astype(int).unique().tolist())
    selected_clusters = control_cols[0].multiselect(
        "Clusters", cluster_options, default=cluster_options, key="tf_km_clusters_analytics",
    )
    malware_options = ["All"] + sorted(features_df["malware_printable"].dropna().astype(str).unique().tolist())
    selected_malware  = control_cols[1].selectbox("Dominant malware filter", malware_options, key="tf_km_malware_analytics")
    ioc_type_options  = ["All"] + sorted(features_df["ioc_type"].dropna().astype(str).unique().tolist())
    selected_ioc_type = control_cols[2].selectbox("IOC Type", ioc_type_options, key="tf_km_ioc_type_analytics")
    min_confidence    = control_cols[3].slider("Min confidence", 0, 100, 0, key="tf_km_confidence_analytics")

    panel_df = features_df.copy()
    if selected_clusters:
        panel_df = panel_df[panel_df["cluster"].isin(selected_clusters)]
    if selected_malware != "All":
        panel_df = panel_df[panel_df["malware_printable"] == selected_malware]
    if selected_ioc_type != "All":
        panel_df = panel_df[panel_df["ioc_type"] == selected_ioc_type]
    panel_df["confidence_level"] = pd.to_numeric(panel_df["confidence_level"], errors="coerce")
    panel_df = panel_df[panel_df["confidence_level"].fillna(0) >= min_confidence]

    selected_row = (
        metrics_df.loc[metrics_df["selected_as_final"] == True]  # noqa: E712
        if "selected_as_final" in metrics_df.columns
        else pd.DataFrame()
    )
    if selected_row.empty and not metrics_df.empty:
        selected_row = metrics_df.iloc[[0]]

    final_k        = int(selected_row["k"].iloc[0])           if not selected_row.empty else 0
    silhouette     = float(selected_row["silhouette_score"].iloc[0])    if not selected_row.empty else 0.0
    davies_bouldin = float(selected_row["davies_bouldin_score"].iloc[0]) if not selected_row.empty else 0.0
    calinski       = float(selected_row["calinski_harabasz_score"].iloc[0]) if not selected_row.empty else 0.0

    metrics_cols = st.columns(5)
    metrics_cols[0].metric("ThreatFox IOCs In View", f"{len(panel_df):,}")
    metrics_cols[1].metric("Clusters In View", f"{panel_df['cluster'].nunique() if not panel_df.empty else 0:,}")
    metrics_cols[2].metric("Selected k",       f"{final_k}")
    metrics_cols[3].metric("Silhouette",       f"{silhouette:.3f}")
    metrics_cols[4].metric("Davies-Bouldin",   f"{davies_bouldin:.3f}")
    st.caption(
        f"Calinski-Harabasz score for the selected ThreatFox model: {calinski:.3f}. "
        "Cluster IDs are internal K-Means labels and are interpreted through dominant malware and IOC patterns."
    )

    if panel_df.empty:
        st.info("No ThreatFox clustered records match the current filters.")
        return

    cluster_summary = (
        panel_df.groupby("cluster")
        .agg(
            ioc_count=("ioc_id", "count"),
            dominant_malware=("malware_printable", lambda s: s.mode().iloc[0] if not s.mode().empty else "Unknown"),
            dominant_ioc_type=("ioc_type", lambda s: s.mode().iloc[0] if not s.mode().empty else "Unknown"),
            dominant_threat_type=("threat_type", lambda s: s.mode().iloc[0] if not s.mode().empty else "Unknown"),
            avg_confidence=("confidence_level", "mean"),
            unique_malware_families=("malware_printable", "nunique"),
        )
        .reset_index()
    )

    left, right = st.columns([1.2, 1])
    with left:
        fig_tf_clusters = px.bar(
            cluster_summary, x="cluster", y="ioc_count", color="dominant_malware",
            title="ThreatFox IOCs per Cluster",
            labels={"cluster": "Cluster ID", "ioc_count": "IOC Count", "dominant_malware": "Dominant Malware"},
        )
        fig_tf_clusters.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9")
        st.plotly_chart(fig_tf_clusters, use_container_width=True)
    with right:
        fig_tf_scatter = px.scatter(
            cluster_summary, x="avg_confidence", y="unique_malware_families",
            size="ioc_count", color="cluster", hover_name="dominant_malware",
            title="Cluster Confidence vs Malware Diversity",
            labels={
                "avg_confidence": "Avg Confidence",
                "unique_malware_families": "Unique Malware Families",
                "cluster": "Cluster",
            },
        )
        fig_tf_scatter.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9")
        st.plotly_chart(fig_tf_scatter, use_container_width=True)

    st.dataframe(cluster_summary, use_container_width=True, hide_index=True)
    st.dataframe(
        panel_df[[
            "ioc_value", "ioc_type", "threat_type", "malware_printable",
            "cluster", "confidence_level", "first_seen_utc",
        ]].head(100),
        use_container_width=True, hide_index=True,
    )


# ── Event correlation panel ───────────────────────────────────────────────────

def render_event_correlation_panel(
    group_summary: pd.DataFrame,
    filtered_df: pd.DataFrame,
    panel_source: str,
    top_groups: pd.DataFrame,
    sort_metric: str,
    ascending: bool,
    source_overlap: pd.DataFrame,
    group_ioc_types: pd.DataFrame,
    top_group_keys: set[str],
    nodes: pd.DataFrame,
    edges: pd.DataFrame,
    network_view: str,
    group_network_metrics: pd.DataFrame,
    show_table: bool,
    exact_ioc_overlap: pd.DataFrame,
    group_family_matches: pd.DataFrame,
) -> None:
    metric_cols = st.columns(5)
    metric_cols[0].metric("Finance Victims",        f"{int(group_summary['victim_count'].sum()):,}")
    metric_cols[1].metric("Ransomware Groups",      f"{group_summary['group_norm'].nunique():,}")
    metric_cols[2].metric("Ransomware.live IOCs",   f"{int(group_summary['ioc_count'].sum()):,}")
    metric_cols[3].metric("ThreatFox Matches",      f"{int(group_summary['threatfox_ioc_count'].sum()):,}")
    metric_cols[4].metric("Cross-Source IOC Matches", f"{int(group_summary['cross_source_matches'].sum()):,}")

    st.markdown("### Ransomware Event Correlation")
    st.write(
        "This panel aggregates finance-sector ransomware victims by group, enriches those groups "
        "with ransomware.live IOCs and TTPs, then checks whether the same indicators or malware-family "
        "labels appear in ThreatFox. Use the sidebar controls to change the group threshold, ranking "
        "metric, and network relationship view."
    )
    st.markdown("### Interactive IOC Filtering Panel")
    st.caption(panel_source)
    panel_controls   = st.columns([1.2, 1.2, 1, 1])
    source_options   = ["All"] + sorted(filtered_df["source"].dropna().astype(str).unique().tolist())
    selected_source  = panel_controls[0].selectbox("Data source", source_options, key="event_source_analytics")
    type_options     = sorted(filtered_df["type"].dropna().astype(str).unique().tolist())
    selected_types   = panel_controls[1].multiselect(
        "IOC types", type_options,
        default=type_options[: min(5, len(type_options))] if type_options else [],
        key="event_types_analytics",
    )
    max_confidence   = (
        int(filtered_df["confidence"].max())
        if not filtered_df.empty and filtered_df["confidence"].notna().any()
        else 100
    )
    min_confidence   = panel_controls[2].slider("Min confidence", 0, max_confidence, 0, key="event_confidence_analytics")
    record_limit     = panel_controls[3].slider("Rows shown", 10, 200, 50, 10, key="event_rows_analytics")

    search_text = st.text_input(
        "Search indicator or group",
        placeholder="Filter by IOC value, group, or keyword",
        key="event_search_analytics",
    ).strip()

    panel_df = filtered_df.copy()
    if selected_source != "All":
        panel_df = panel_df[panel_df["source"] == selected_source]
    if selected_types:
        panel_df = panel_df[panel_df["type"].isin(selected_types)]
    panel_df = panel_df[panel_df["confidence"] >= min_confidence]
    if search_text:
        search_mask = (
            panel_df["indicator"].astype(str).str.contains(search_text, case=False, na=False)
            | panel_df["group"].astype(str).str.contains(search_text, case=False, na=False)
            | panel_df["type"].astype(str).str.contains(search_text, case=False, na=False)
        )
        panel_df = panel_df[search_mask]

    panel_df = panel_df.sort_values(["confidence", "type", "group"], ascending=[False, True, True])

    panel_metrics = st.columns(3)
    panel_metrics[0].metric("Matching Records",  f"{len(panel_df):,}")
    avg_confidence = panel_df["confidence"].mean() if not panel_df.empty else 0.0
    panel_metrics[1].metric("Average Confidence", f"{float(avg_confidence):.2f}")
    panel_metrics[2].metric("IOC Types In View",  f"{panel_df['type'].nunique() if not panel_df.empty else 0:,}")

    if panel_df.empty:
        st.info("No IOC records match the current filter selections.")
    else:
        chart_left, chart_right = st.columns([1.2, 1])
        with chart_left:
            type_counts = panel_df["type"].value_counts().rename_axis("type").reset_index(name="count")
            fig_types   = px.bar(
                type_counts, x="type", y="count", color="count",
                color_continuous_scale="OrRd",
                title="IOC Type Distribution",
                labels={"type": "IOC Type", "count": "Records"},
            )
            fig_types.update_layout(coloraxis_showscale=False, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9")
            st.plotly_chart(fig_types, use_container_width=True)
        with chart_right:
            fig_conf = px.histogram(
                panel_df, x="confidence", nbins=min(20, max(len(panel_df), 1)),
                title="Confidence Distribution",
                labels={"confidence": "Confidence"},
            )
            fig_conf.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9")
            st.plotly_chart(fig_conf, use_container_width=True)

        st.dataframe(panel_df.head(record_limit), use_container_width=True, hide_index=True)

    left, right = st.columns([1.2, 1])
    with left:
        fig_groups = px.bar(
            top_groups.sort_values(sort_metric, ascending=not ascending),
            x=sort_metric, y="display_group", orientation="h", color="risk_score",
            color_continuous_scale="OrRd",
            title=f"Top Ransomware Groups by {sort_metric.replace('_', ' ').title()}",
            labels={
                sort_metric: sort_metric.replace("_", " ").title(),
                "display_group": "Ransomware Group",
                "risk_score": "Risk Score",
            },
        )
        fig_groups.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9")
        st.plotly_chart(fig_groups, use_container_width=True)
    with right:
        overlap_plot = source_overlap.copy()
        if not has_columns(overlap_plot, ["metric", "value"]):
            overlap_plot = pd.DataFrame({"metric": ["exact_cross_source_matches"], "value": [0]})
        fig_overlap = px.bar(
            overlap_plot, x="metric", y="value", color="metric",
            title="Cross-Source IOC Overlap",
            labels={"metric": "Source Overlap Metric", "value": "Count"},
        )
        fig_overlap.update_layout(showlegend=False, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9")
        st.plotly_chart(fig_overlap, use_container_width=True)

    st.markdown("### Group vs IOC Type Heatmap")
    if has_columns(group_ioc_types, ["group_norm", "display_group", "ioc_type", "ioc_count"]):
        heatmap_data = group_ioc_types[group_ioc_types["group_norm"].isin(top_group_keys)].copy()
    else:
        heatmap_data = pd.DataFrame()

    if not heatmap_data.empty:
        pivot = heatmap_data.pivot_table(
            index="display_group", columns="ioc_type", values="ioc_count",
            aggfunc="sum", fill_value=0,
        )
        fig_heatmap = px.imshow(
            pivot, aspect="auto", color_continuous_scale="YlOrRd",
            title="IOC Type Concentration by Finance-Relevant Ransomware Group",
            labels={"x": "IOC Type", "y": "Ransomware Group", "color": "IOC Count"},
        )
        fig_heatmap.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9")
        st.plotly_chart(fig_heatmap, use_container_width=True)
    else:
        st.info("No IOC type records found for the selected group filters.")

    # st.markdown("### Relationship Network")
    # network_figure = build_network_figure(nodes, edges, top_group_keys, network_view)
    # if network_figure.data:
    #     st.plotly_chart(network_figure, use_container_width=True)
    # else:
    #     st.info("No network relationship data was available for the selected view.")

    st.markdown("### Network Metrics")
    if has_columns(
        group_network_metrics,
        ["group_norm", "display_group", "degree", "degree_centrality", "component_id", "risk_score", "victim_count", "ioc_count"],
    ):
        network_table = group_network_metrics[group_network_metrics["group_norm"].isin(top_group_keys)][[
            "display_group", "degree", "degree_centrality", "component_id",
            "risk_score", "victim_count", "ioc_count",
        ]].sort_values("degree_centrality", ascending=False)
        st.dataframe(network_table, use_container_width=True, hide_index=True)
    else:
        st.info("No group network metrics found.")

    if show_table:
        st.markdown("### Supporting Tables")
        st.subheader("Group Risk Summary")
        st.dataframe(group_summary, use_container_width=True, hide_index=True)
        st.subheader("Exact IOC Overlap")
        st.dataframe(exact_ioc_overlap, use_container_width=True, hide_index=True)
        st.subheader("Group / ThreatFox Family Matches")
        st.dataframe(group_family_matches, use_container_width=True, hide_index=True)


# ── Executive summary builders ────────────────────────────────────────────────

def alert_id_for_row(row: pd.Series) -> str:
    fingerprint = "|".join(
        [
            str(row.get("source", "")),
            str(row.get("indicator", "")),
            str(row.get("type", "")),
            str(row.get("date", "")),
        ]
    )
    return f"AL-{hashlib.sha1(fingerprint.encode('utf-8')).hexdigest()[:8].upper()}"


def recommended_action_for_row(row: pd.Series) -> str:
    category = str(row.get("category", "")).lower()
    indicator_type = str(row.get("type", "")).lower()
    asset = str(row.get("asset", "")).lower()
    tags = str(row.get("tags", "")).lower()

    if "ransomware" in category or "victim" in indicator_type:
        return "Escalate to incident command, validate affected entity, and review backups."
    if "phishing" in category or "url" in indicator_type:
        return "Block URL/domain, submit takedown request, and search proxy logs."
    if any(token in category + tags for token in ["malware", "botnet", "trojan", "emotet", "qakbot"]):
        return "Hunt for matching IOCs in EDR/SIEM and isolate confirmed hosts."
    if any(token in indicator_type for token in ["ip", "domain", "host"]):
        return "Add detection rule, enrich with passive DNS, and review firewall traffic."
    if "customer data" in asset:
        return "Prioritize data-access log review and credential reset checks."
    return "Enrich indicator, validate source confidence, and monitor for internal matches."

def build_triage_queue(records: pd.DataFrame, assets: pd.DataFrame) -> pd.DataFrame:
    if records.empty:
        return pd.DataFrame()

    queue = records.copy()
    if "asset" not in queue.columns:
        queue["asset"] = queue.apply(
            lambda row: classify_asset(
                row.get("indicator", ""),
                row.get("category", row.get("type", "")),
                row.get("tags", ""),
                row.get("source", ""),
            ),
            axis=1,
        )

    if "category" not in queue.columns:
        queue["category"] = queue.get("type", "unknown")
    if "tags" not in queue.columns:
        queue["tags"] = ""
    if "date" not in queue.columns:
        queue["date"] = pd.NaT

    aligned_assets = build_asset_alignment(assets)
    if {"alignment_group", "criticality_1_low_5_high"}.issubset(aligned_assets.columns):
        criticality = aligned_assets.set_index("alignment_group")["criticality_1_low_5_high"].to_dict()
    else:
        criticality = {}
    queue["asset_criticality"] = queue["asset"].map(criticality).fillna(3).astype(float)
    queue["date"] = pd.to_datetime(queue["date"], errors="coerce", utc=True)
    now_utc = pd.Timestamp.now(tz="UTC")
    queue["age_days"] = (now_utc - queue["date"]).dt.days
    queue["age_days"] = queue["age_days"].fillna(90).clip(lower=0)

    category_text = queue["category"].fillna("").astype(str).str.lower()
    type_text = queue["type"].fillna("").astype(str).str.lower()
    tag_text = queue["tags"].fillna("").astype(str).str.lower()

    queue["risk_score"] = 15
    queue.loc[category_text.str.contains("ransomware|botnet|malware", regex=True), "risk_score"] += 30
    queue.loc[category_text.str.contains("phishing|credential", regex=True), "risk_score"] += 18
    queue.loc[type_text.str.contains("url|domain|ip|sha|md5", regex=True), "risk_score"] += 12
    queue.loc[tag_text.str.contains("bank|finance|emotet|qakbot|dridex|gozi|icedid", regex=True), "risk_score"] += 10
    queue["risk_score"] += (queue["asset_criticality"] * 4).round().astype(int)
    queue.loc[queue["age_days"] <= 7, "risk_score"] += 6
    queue.loc[(queue["age_days"] > 7) & (queue["age_days"] <= 30), "risk_score"] += 3
    queue.loc[queue["age_days"] > 30, "risk_score"] += 0
    queue["risk_score"] = queue["risk_score"].clip(upper=100).astype(int)

    queue["severity"] = pd.cut(
        queue["risk_score"],
        bins=[-1, 34, 59, 79, 100],
        labels=["Low", "Medium", "High", "Critical"],
    ).astype(str)
    queue["triage_status"] = queue["severity"].map(
        {
            "Critical": "Escalate",
            "High": "Investigate",
            "Medium": "Review",
            "Low": "Monitor",
        }
    )
    queue["recommended_action"] = queue.apply(recommended_action_for_row, axis=1)
    queue["sla"] = queue["severity"].map(
        {
            "Critical": "30 minutes",
            "High": "4 hours",
            "Medium": "1 business day",
            "Low": "3 business days",
        }
    )
    queue["alert_id"] = queue.apply(alert_id_for_row, axis=1)
    queue["last_seen"] = queue["date"].dt.strftime("%Y-%m-%d").fillna("Unknown")

    return queue.sort_values(["risk_score", "date"], ascending=[False, False], na_position="last")

def build_top_finding_cards(
    top_groups: pd.DataFrame,
    phishing_df: pd.DataFrame,
    group_ioc_types: pd.DataFrame,
) -> list[dict[str, str]]:
    top_group      = top_groups.iloc[0] if not top_groups.empty else None
    top_group_name = (
        str(top_group["display_group"]).title()
        if top_group is not None and "display_group" in top_group
        else "Akira"
    )
    top_group_score = (
        f"{float(top_group['risk_score']):.2f}"
        if top_group is not None and "risk_score" in top_group
        else "high"
    )
    top_group_victims = (
        f"{int(top_group['victim_count'])}"
        if top_group is not None and "victim_count" in top_group
        else "multiple"
    )

    phishing_count = len(phishing_df) if not phishing_df.empty else 0
    top_target = (
        phishing_df["target"].mode().iloc[0]
        if has_columns(phishing_df, ["target"]) and not phishing_df["target"].mode().empty
        else "banking brands"
    )

    if has_columns(group_ioc_types, ["ioc_type", "ioc_count"]):
        dominant_pattern_row = group_ioc_types.sort_values("ioc_count", ascending=False).iloc[0]
        dominant_pattern = f"{dominant_pattern_row['ioc_type']} ({int(dominant_pattern_row['ioc_count'])})"
    else:
        dominant_pattern = "md5 / sha256 ransomware indicators"

    return [
        {
            "title": f"{top_group_name} is the highest-risk ransomware actor in view",
            "found": (
                f"{top_group_name} leads the current ransomware ranking with a risk score of {top_group_score} "
                f"and {top_group_victims} finance-linked victims in the correlation dataset."
            ),
            "matters": "It indicates which actor should drive leadership prioritization, briefing cadence, and response resourcing.",
            "impact": "A successful campaign would most directly affect payment continuity, recovery timelines, and regulatory exposure.",
            "action": f"Prioritize executive review of {top_group_name}-aligned controls, backup readiness, and identity hardening this week.",
        },
        {
            "title": "Banking phishing pressure remains persistent and high-volume",
            "found": (
                f"The phishing dataset contains {phishing_count:,} finance-themed submissions, with repeated impersonation of "
                f"{top_target} and related banking login workflows."
            ),
            "matters": "Credential theft remains one of the fastest paths to customer compromise and follow-on fraud or ransomware access.",
            "impact": "Brand damage, fraud loss, and increased help-desk / response workload can all rise before a direct intrusion is confirmed.",
            "action": "Increase brand monitoring, speed phishing takedown coordination, and align customer messaging with current lure themes.",
        },
        {
            "title": "Repeated IOC patterns show where defenders can tighten detection",
            "found": f"The most common IOC / technique pattern in the correlation outputs is {dominant_pattern}.",
            "matters": "Repeated indicator types are useful for tuning detection engineering and triage rules instead of treating every alert as unique.",
            "impact": "Better prioritization can reduce analyst fatigue, improve precision, and shorten time to detect finance-relevant activity.",
            "action": "Task detection engineering to convert the dominant patterns into tuned monitoring, enrichment, and escalation logic.",
        },
    ]


def build_asset_priority_table(assets_df: pd.DataFrame) -> pd.DataFrame:
    if assets_df.empty:
        return pd.DataFrame(columns=["asset", "risk_level", "why_priority", "immediate_decision"])

    selected_assets = assets_df.sort_values(
        ["criticality_1_low_5_high", "asset"], ascending=[False, True]
    ).head(5).copy()

    decision_map = {
        "Core banking systems":                        "Confirm resilience investment and restoration priority.",
        "Payment processing systems":                  "Approve segmentation and fraud-control acceleration.",
        "Identity and access management (AD/IAM)":     "Prioritize MFA, PAM, and privileged account review.",
        "Online and mobile banking platforms":          "Fund phishing defense and customer protection measures.",
        "Customer data repositories":                  "Validate containment, monitoring, and data-access controls.",
        "SWIFT/RTGS gateway":                          "Review high-value transfer monitoring and segregation controls.",
    }

    selected_assets["risk_level"]        = selected_assets["criticality_1_low_5_high"].apply(risk_label)
    selected_assets["why_priority"]      = selected_assets["ramification_if_breached"]
    selected_assets["immediate_decision"] = selected_assets["asset"].map(decision_map).fillna(
        "Confirm ownership, monitoring, and recovery expectations."
    )

    return selected_assets[["asset", "risk_level", "why_priority", "immediate_decision"]]


def _derive_posture_fields(asset_priority_df: pd.DataFrame) -> tuple[str, str]:
    """Derive immediate_priority and highest_risk_asset from the asset priority table."""
    if asset_priority_df.empty:
        return "Block high-confidence infrastructure and harden IAM", "Identity and access management (AD/IAM)"

    top_row           = asset_priority_df.iloc[0]
    highest_risk_asset = str(top_row["asset"])
    immediate_priority = str(top_row["immediate_decision"])
    return immediate_priority, highest_risk_asset


def build_asset_threat_figure(records_df: pd.DataFrame, assets_df: pd.DataFrame) -> go.Figure:
    if records_df.empty or assets_df.empty:
        return go.Figure()

    asset_threat_counts = (
        records_df.groupby("asset", as_index=False)
        .size()
        .rename(columns={"size": "threat_count", "asset": "mapped_asset"})
    )
    asset_bar_df = assets_df.merge(
        asset_threat_counts, left_on="asset", right_on="mapped_asset", how="left",
    ).fillna({"threat_count": 0})

    fig = px.bar(
        asset_bar_df.sort_values(["threat_count", "criticality_1_low_5_high"], ascending=[False, False]),
        x="threat_count", y="asset", orientation="h",
        color="criticality_1_low_5_high",
        color_continuous_scale=["#43aa8b", "#90be6d", "#f9c74f", "#f3722c", "#f94144"],
        labels={
            "threat_count": "Mapped Threat Count",
            "asset": "Critical Asset",
            "criticality_1_low_5_high": "Criticality",
        },
    )
    fig.update_layout(
        coloraxis_showscale=False,
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#c9d1d9",
    )
    return fig


def build_top_ransomware_figure(top_groups: pd.DataFrame) -> go.Figure:
    if top_groups.empty:
        return go.Figure()

    plot_df = top_groups.sort_values("risk_score", ascending=False).head(5).copy()
    fig = px.bar(
        plot_df.sort_values("risk_score", ascending=True),
        x="risk_score", y="display_group", orientation="h", color="risk_score",
        color_continuous_scale="OrRd",
        labels={"risk_score": "Risk Score", "display_group": "Ransomware Group"},
    )
    fig.update_layout(
        coloraxis_showscale=False,
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#c9d1d9",
    )
    return fig


# ── Jump helper ───────────────────────────────────────────────────────────────

def jump_to_analyst_view(analysis_mode: str, kmeans_mode: str | None = None) -> None:
    st.session_state["pending_analytics_view"]        = "Analyst Drill-Down"
    st.session_state["pending_analysis_mode_analytics"] = analysis_mode
    if kmeans_mode is not None:
        st.session_state["pending_kmeans_mode_analytics"] = kmeans_mode
    st.rerun()


# ── render_executive_summary ──────────────────────────────────────────────────

def render_executive_summary(
    top_groups: pd.DataFrame,
    phishing_df: pd.DataFrame,
    group_ioc_types: pd.DataFrame,
    critical_assets_df: pd.DataFrame,
    executive_records_df: pd.DataFrame,
) -> None:
    st.markdown(
        """
        <style>
        .ops-metric-card {
            background: #0f172a;
            border: 1px solid #1d4ed8;
            border-radius: 12px;
            padding: 1rem 1.1rem 0.9rem 1.1rem;
            min-height: 112px;
        }
        .ops-metric-label {
            color: #8ba3c0;
            font-size: 0.88rem;
            margin-bottom: 0.55rem;
        }
        .ops-metric-value {
            color: #b7cdf2;
            font-size: 2.2rem;
            line-height: 1;
            font-weight: 500;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    # ── Derive posture fields from data ──
    asset_priority_df                  = build_asset_priority_table(critical_assets_df)
    immediate_priority, highest_risk_asset = _derive_posture_fields(asset_priority_df)

    top_group = top_groups.iloc[0] if not top_groups.empty else None
    top_threat = (
        str(top_group["display_group"]).title()
        if top_group is not None and "display_group" in top_group
        else "Akira"
    )

    # ── Section 1: Executive summary narrative and metrics ──
    st.subheader("1. Operational Summary")
    triage_df = build_triage_queue(executive_records_df, critical_assets_df)

    if triage_df.empty:
        st.info("No executive triage alerts are available from the current intelligence inputs.")
    else:
        operational_metrics = [
            ("Open Alerts", f"{len(triage_df):,}"),
            ("Critical", f"{(triage_df['severity'] == 'Critical').sum():,}"),
            ("High", f"{(triage_df['severity'] == 'High').sum():,}"),
            ("Assets Affected", f"{triage_df['asset'].nunique():,}"),
            #("Top Risk Score", f"{int(triage_df['risk_score'].max()):,}"),
        ]
        triage_metrics = st.columns(5)
        for col, (label, value) in zip(triage_metrics, operational_metrics):
            with col:
                st.markdown(
                    f"""
                    <div class="ops-metric-card">
                        <div class="ops-metric-label">{label}</div>
                        <div class="ops-metric-value">{value}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )



    # ── Section 2: Current Threat Posture ──
    st.markdown("### 2. Current Threat Posture")
    st.write(
        "Current posture: U.S. banking remains under active phishing pressure and elevated ransomware risk, "
        "with credential theft and financially motivated actor activity continuing to shape immediate defensive priorities."
    )

    metric_cols = st.columns(3)
    metric_cols[0].metric("Top Active Threat",       top_threat)
    metric_cols[1].metric("Highest Risk Asset",      highest_risk_asset)
    metric_cols[2].metric("Immediate Action Priority", immediate_priority)

    chart_left, chart_right = st.columns(2, gap="large")
    with chart_left:
        if st.button("Threat Counts Aligned to Critical Assets", key="goto_asset_chart", use_container_width=True):
            jump_to_analyst_view("Event Correlation")
        asset_fig = build_asset_threat_figure(executive_records_df, critical_assets_df)
        if asset_fig.data:
            st.plotly_chart(asset_fig, use_container_width=True)
        else:
            st.info("Threat-to-asset alignment could not be generated.")

    with chart_right:
        if st.button("Top Ransomware Groups by Risk Score", key="goto_risk_groups", use_container_width=True):
            jump_to_analyst_view("Event Correlation")
        ransomware_fig = build_top_ransomware_figure(top_groups)
        if ransomware_fig.data:
            st.plotly_chart(ransomware_fig, use_container_width=True)
        else:
            st.info("Top ransomware group view could not be generated.")

    # ── Section 3: Top Intelligence Findings ──
    st.markdown("### 3. Top Intelligence Findings")
    for card in build_top_finding_cards(top_groups, phishing_df, group_ioc_types):
        st.markdown(
            f"""
            <div class="exec-card">
                <h4>{card['title']}</h4>
                <p><span class="exec-label">What we found:</span> {card['found']}</p>
                <p><span class="exec-label">Why it matters:</span> {card['matters']}</p>
                <p><span class="exec-label">Business / operational impact:</span> {card['impact']}</p>
                <p><span class="exec-label">Recommended leadership action:</span> {card['action']}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # ── Section 4: Asset Prioritization ──
    st.markdown("### 4. Asset Prioritization")
    if not asset_priority_df.empty:
        visual_df = asset_priority_df.copy()
        visual_df["risk_score"] = visual_df["risk_level"].map(
            {"Critical": 5, "High": 4, "Moderate": 3, "Monitored": 2}
        )
        fig_assets = px.bar(
            visual_df, x="risk_score", y="asset", orientation="h", color="risk_level",
            color_discrete_map={
                "Critical": "#f87171",
                "High":     "#f59e0b",
                "Moderate": "#38bdf8",
                "Monitored": "#4ade80",
            },
            title="Critical Asset Priority Snapshot",
            labels={"risk_score": "Relative Risk", "asset": "Asset", "risk_level": "Risk Level"},
        )
        fig_assets.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9",
        )
        st.plotly_chart(fig_assets, use_container_width=True)
    #     st.dataframe(asset_priority_df, use_container_width=True, hide_index=True)
    # else:
    #     st.info("Critical asset priorities could not be loaded.")

    # # ── Section 5: Dissemination Snapshot ──
    # st.markdown("### 5. Dissemination Snapshot")
    # dissemination_df = pd.DataFrame([
    #     {
    #         "Audience":        "CISO / Executive Leadership",
    #         "When":            "2 hours",
    #         "What they receive": "Current threat posture, asset impact, and decision-ready risk summary.",
    #         "Delivery method": "Executive dashboard and short finished-intelligence brief.",
    #     },
    #     {
    #         "Audience":        "IR Team",
    #         "When":            "Immediate - 1 hour",
    #         "What they receive": "Incident-ready IOC package, threat actor context, and likely TTPs.",
    #         "Delivery method": "Analyst dashboard, case notes, and direct operational handoff.",
    #     },
    #     {
    #         "Audience":        "SOC / Detection Engineering",
    #         "When":            "Same shift / 2 hours",
    #         "What they receive": "Detection priorities, indicator patterns, enrichment, and monitoring targets.",
    #         "Delivery method": "Detection queue, dashboard filters, and alerting updates.",
    #     },
    #     {
    #         "Audience":        "Staff / Clients",
    #         "When":            "6 - 24 hours depending on severity",
    #         "What they receive": "Plain-language phishing or fraud warning with action steps.",
    #         "Delivery method": "Bulletin, awareness notice, or customer-facing advisory.",
    #     },
    # ])
    # st.dataframe(dissemination_df, use_container_width=True, hide_index=True)

## second dissemination for comparison
    st.markdown("### 5. Dissemination Snapshot")
    st.caption("Intelligence dissemination sequence from detection to stakeholder notification.")
    st.markdown(
        """
    <style>
    /* ── Timeline container ── */
    .dissem-timeline {
        position: relative;
        display: flex;
        flex-direction: column;
        gap: 0;
        padding: 0.5rem 0 0.5rem 2.8rem;
        margin: 1rem 0 1.5rem;
    }
    
    /* ── Vertical spine ── */
    .dissem-timeline::before {
        content: '';
        position: absolute;
        left: 1rem;
        top: 1.4rem;
        bottom: 1.4rem;
        width: 2px;
        background: linear-gradient(180deg, #f87171 0%, #f59e0b 33%, #38bdf8 66%, #4ade80 100%);
        border-radius: 2px;
    }
    
    /* ── Each row ── */
    .dissem-row {
        display: flex;
        align-items: flex-start;
        gap: 1.2rem;
        position: relative;
        padding: 1.1rem 1.2rem 1.1rem 0;
        margin-bottom: 0.5rem;
    }
    
    /* ── Dot on the spine ── */
    .dissem-dot {
        position: absolute;
        left: -2.15rem;
        top: 1.35rem;
        width: 14px;
        height: 14px;
        border-radius: 50%;
        border: 2px solid #0d1526;
        flex-shrink: 0;
        z-index: 1;
    }
    
    /* ── Card body ── */
    .dissem-card {
        flex: 1;
        background: linear-gradient(180deg, #0d1e35 0%, #0a1828 100%);
        border: 1px solid #1e3a5f;
        border-radius: 12px;
        padding: 1rem 1.2rem 0.9rem;
        border-left-width: 4px;
    }
    
    /* ── Card header row ── */
    .dissem-header {
        display: flex;
        align-items: center;
        gap: 0.9rem;
        margin-bottom: 0.6rem;
        flex-wrap: wrap;
    }
    .dissem-audience {
        font-size: 0.97rem;
        font-weight: 700;
        color: #e6edf3;
    }
    .dissem-timing {
        font-family: 'IBM Plex Mono', monospace;
        font-size: 0.7rem;
        font-weight: 600;
        letter-spacing: 0.08em;
        padding: 0.2rem 0.55rem;
        border-radius: 999px;
        border: 1px solid;
        white-space: nowrap;
    }
    
    /* ── Card body text ── */
    .dissem-what {
        font-size: 0.86rem;
        color: #8ba3c0;
        margin-bottom: 0.35rem;
        line-height: 1.5;
    }
    .dissem-how {
        font-size: 0.82rem;
        color: #4a6785;
        font-style: italic;
    }
    .dissem-label {
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        margin-right: 0.35rem;
    }
    
    /* ── Per-stop accent colours ── */
    .dissem-card.red   { border-left-color: #f87171; }
    .dissem-card.amber { border-left-color: #f59e0b; }
    .dissem-card.blue  { border-left-color: #38bdf8; }
    .dissem-card.green { border-left-color: #4ade80; }
    
    .dissem-dot.red   { background: #f87171; }
    .dissem-dot.amber { background: #f59e0b; }
    .dissem-dot.blue  { background: #38bdf8; }
    .dissem-dot.green { background: #4ade80; }
    
    .dissem-timing.red   { color: #f87171; border-color: rgba(248,113,113,0.35); background: rgba(248,113,113,0.08); }
    .dissem-timing.amber { color: #f59e0b; border-color: rgba(245,158,11,0.35);  background: rgba(245,158,11,0.08);  }
    .dissem-timing.blue  { color: #38bdf8; border-color: rgba(56,189,248,0.35);  background: rgba(56,189,248,0.08);  }
    .dissem-timing.green { color: #4ade80; border-color: rgba(74,222,128,0.35);  background: rgba(74,222,128,0.08);  }
    
    .dissem-label.red   { color: #f87171; }
    .dissem-label.amber { color: #f59e0b; }
    .dissem-label.blue  { color: #38bdf8; }
    .dissem-label.green { color: #4ade80; }
    </style>
    
    <div class="dissem-timeline">
    
    <!-- Stop 1: IR Team — Immediate -->
    <div class="dissem-row">
        <div class="dissem-dot red"></div>
        <div class="dissem-card red">
        <div class="dissem-header">
            <span class="dissem-audience">IR Team</span>
            <span class="dissem-timing red">Immediate</span>
        </div>
        <div class="dissem-what">
            <span class="dissem-label red">Receives</span>
            Incident-ready IOC package, threat actor context, and likely TTPs for triage and containment.
        </div>
        <div class="dissem-how">
            <span class="dissem-label red">Via</span>
            Analyst dashboard, case notes, and direct operational handoff.
        </div>
        </div>
    </div>
    
    <!-- Stop 2: CISO — 2 hours -->
    <div class="dissem-row">
        <div class="dissem-dot amber"></div>
        <div class="dissem-card amber">
        <div class="dissem-header">
            <span class="dissem-audience">CISO / Executive Leadership</span>
            <span class="dissem-timing amber">Within 2 hours</span>
        </div>
        <div class="dissem-what">
            <span class="dissem-label amber">Receives</span>
            Current threat posture, asset impact, and decision-ready risk summary with recommended leadership actions.
        </div>
        <div class="dissem-how">
            <span class="dissem-label amber">Via</span>
            Executive dashboard and short finished-intelligence brief.
        </div>
        </div>
    </div>
    
    <!-- Stop 3: SOC — Same shift -->
    <div class="dissem-row">
        <div class="dissem-dot blue"></div>
        <div class="dissem-card blue">
        <div class="dissem-header">
            <span class="dissem-audience">SOC / Detection Engineering</span>
            <span class="dissem-timing blue">Same shift / 4 hours</span>
        </div>
        <div class="dissem-what">
            <span class="dissem-label blue">Receives</span>
            Detection priorities, indicator patterns, enrichment context, and monitoring targets for tuning.
        </div>
        <div class="dissem-how">
            <span class="dissem-label blue">Via</span>
            Detection queue, dashboard filters, and alerting updates.
        </div>
        </div>
    </div>
    
    <!-- Stop 4: Staff / Clients — 24–48 hours -->
    <div class="dissem-row">
        <div class="dissem-dot green"></div>
        <div class="dissem-card green">
        <div class="dissem-header">
            <span class="dissem-audience">Staff / Clients</span>
            <span class="dissem-timing green">24 – 48 hours if exposure confirmed</span>
        </div>
        <div class="dissem-what">
            <span class="dissem-label green">Receives</span>
            Plain-language phishing or fraud warning with clear action steps and reporting guidance.
        </div>
        <div class="dissem-how">
            <span class="dissem-label green">Via</span>
            Bulletin, awareness notice, or customer-facing advisory.
        </div>
        </div>
    </div>
    
    </div>
            """,
            unsafe_allow_html=True,
        )

    # ── Section 6: Courses of Action — styled to match exec-card ──
    st.markdown("### 6. Courses of Action")
    courses = [
        {
            "title":   "1. Contain high-risk infrastructure",
            "owner":   "SOC / Network Security",
            "urgency": "Immediate",
            "why":     "Known malicious infrastructure is the fastest technical choke point to reduce active exposure.",
        },
        {
            "title":   "2. Harden IAM and privileged access",
            "owner":   "IAM / Security Engineering",
            "urgency": "24–72 hours",
            "why":     "Credential theft and lateral movement remain common links between phishing, access abuse, and ransomware outcomes.",
        },
        {
            "title":   "3. Accelerate phishing takedown and customer protection",
            "owner":   "Fraud, Brand Protection, and Communications",
            "urgency": "24–48 hours",
            "why":     "Fast-moving phishing campaigns create outsized customer harm and reputational damage if left visible.",
        },
        {
            "title":   "4. Validate restoration and resilience posture",
            "owner":   "IR Leadership / Infrastructure",
            "urgency": "This week",
            "why":     "Ransomware readiness is not complete until backup recovery, segmentation, and executive decision paths are tested.",
        },
    ]

    for item in courses:
        st.markdown(
            f"""
            <div class="coa-card">
                <h4>{item['title']}</h4>
                <div class="coa-meta">
                    <span class="coa-meta-item"><strong>Owner</strong> {item['owner']}</span>
                    <span class="coa-meta-item"><strong>Urgency</strong> {item['urgency']}</span>
                </div>
                <p class="coa-why">{item['why']}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )


# ── Analyst interpretation ────────────────────────────────────────────────────

def analyst_context_metrics(
    filtered_df: pd.DataFrame,
    top_groups: pd.DataFrame,
    group_ioc_types: pd.DataFrame,
) -> tuple[str, str, str]:
    indicators_in_view = f"{len(filtered_df):,}"
    top_group = (
        str(top_groups.iloc[0]["display_group"]).title()
        if not top_groups.empty and "display_group" in top_groups.columns
        else "Unknown"
    )
    if has_columns(group_ioc_types, ["ioc_type", "ioc_count"]):
        dominant    = group_ioc_types.sort_values("ioc_count", ascending=False).iloc[0]
        common_pattern = f"{dominant['ioc_type']} ({int(dominant['ioc_count'])})"
    else:
        common_pattern = "Pattern unavailable"
    return indicators_in_view, top_group, common_pattern


def render_analyst_interpretation(
    analysis_mode: str,
    exact_ioc_overlap: pd.DataFrame,
    group_family_matches: pd.DataFrame,
    text_mining_metrics: pd.DataFrame,
    threatfox_kmeans_metrics: pd.DataFrame,
) -> None:
    if analysis_mode == "Event Correlation":
        confidence = "84 / 100" if not exact_ioc_overlap.empty else "72 / 100" if not group_family_matches.empty else "60 / 100"
        meaning    = (
            "This mode shows which ransomware actors, victims, IOC types, and infrastructure are most relevant "
            "to finance and where cross-source reinforcement exists."
        )
        next_step  = "Prioritize top-ranked groups for enrichment, hunt on repeated IOC types, and escalate any cross-source matches first."
    elif analysis_mode == "Text Mining":
        suspicious_share = metric_lookup(text_mining_metrics, "suspicious_tld_share")
        confidence = "78 / 100" if suspicious_share > 0 else "70 / 100"
        meaning    = "This mode highlights lexical and structural phishing patterns that can be turned into faster detection and takedown logic."
        next_step  = "Update phishing detections around suspicious TLDs, repeated brand terms, and common lure structures seen in the current dataset."
    else:
        silhouette = 0.0
        if not threatfox_kmeans_metrics.empty:
            selected_row = (
                threatfox_kmeans_metrics.loc[threatfox_kmeans_metrics["selected_as_final"] == True]  # noqa: E712
                if "selected_as_final" in threatfox_kmeans_metrics.columns
                else pd.DataFrame()
            )
            if selected_row.empty:
                selected_row = threatfox_kmeans_metrics.iloc[[0]]
            silhouette = float(selected_row["silhouette_score"].iloc[0]) if not selected_row.empty else 0.0
        confidence = "69 / 100" if silhouette > 0 else "62 / 100"
        meaning    = "This mode groups similar IOC and phishing records so analysts can spot repeated patterns without reviewing each row individually."
        next_step  = "Use dense clusters to define reusable triage playbooks, then validate whether dominant cluster features align to real adversary behavior."

    st.markdown("### 4. Analyst Interpretation")
    with st.container(border=True):
        st.write(f"**What this analysis mode means:** {meaning}")
        st.write(f"**Confidence score:** {confidence}")
        st.write(f"**What analysts should do next:** {next_step}")


# ── Approach justification ────────────────────────────────────────────────────

def render_approach_justification() -> None:
    st.markdown(
        """
        <div class="cti-banner">
            <h3>Approach Justification</h3>
            <p>
                This analytic design is aimed primarily at <strong>tactical CTI</strong> and secondarily at
                <strong>operational CTI</strong>, giving defenders fast visibility into phishing indicators,
                ransomware-linked infrastructure, and grouped threat patterns relevant to U.S. banking.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <span class="cti-badge badge-blue">CTI Level: Tactical</span>
        <span class="cti-badge badge-blue">CTI Level: Operational</span>
        <span class="cti-badge badge-slate">Sector Focus: U.S. Banking</span>
        <span class="cti-badge badge-teal">Primary Data Sources: PhishTank, ThreatFox, ransomware.live</span>
        """,
        unsafe_allow_html=True,
    )

    card_1, card_2, card_3 = st.columns(3, gap="large")

    with card_1:
        st.markdown(
            """
            <div class="method-card method-blue">
                <h4>Phishing URL Text Mining</h4>
                <p>Turns large volumes of phishing URLs into defender-readable lexical and structural patterns.</p>
                <div class="info-block analysis-block"><strong>Mission:</strong> Identify recurring banking-themed phishing traits that support faster detection and triage.</div>
                <div class="info-block analysis-block"><strong>How it works:</strong> It extracts URL features, keywords, TF-IDF terms, and repeated n-grams from verified phishing data.</div>
                <div class="info-block output-block"><strong>Operational value:</strong> It helps analysts spot suspicious banking lures earlier and prioritize likely credential-harvesting URLs.</div>
                <div class="info-block output-block"><strong>Produces for defenders:</strong> Top keywords, suspicious TLD patterns, URL feature profiles, and triage-ready phishing indicators.</div>
                <div class="info-block validation-block"><strong>Validation:</strong> Performance is checked through keyword coverage, suspicious TLD share, HTTPS share, and analyst review of top terms.</div>
                <div class="info-block limit-block"><strong>Limitations:</strong> Static keyword lists can miss new phishing language, brand drift, or non-English lure patterns.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with card_2:
        st.markdown(
            """
            <div class="method-card method-teal">
                <h4>Ransomware Event Correlation</h4>
                <p>Connects victims, groups, IOCs, IOC types, countries, and TTPs into one operational picture.</p>
                <div class="info-block analysis-block"><strong>Mission:</strong> Link ransomware activity across sources so banking defenders can prioritize the most relevant groups and indicators.</div>
                <div class="info-block analysis-block"><strong>How it works:</strong> It normalizes group names, joins victim and IOC records, and maps relationship networks across observed entities.</div>
                <div class="info-block output-block"><strong>Operational value:</strong> It supports faster actor prioritization, IOC enrichment, and understanding of which groups are most relevant to finance.</div>
                <div class="info-block output-block"><strong>Produces for defenders:</strong> Group risk views, exact IOC overlaps, relationship networks, country exposure, and TTP-linked context.</div>
                <div class="info-block validation-block"><strong>Validation:</strong> Confidence comes from exact IOC matches, group-level counts, network centrality measures, and manual review of unmatched records.</div>
                <div class="info-block limit-block"><strong>Limitations:</strong> Alias mismatches and dataset gaps can reduce overlap, especially when ThreatFox coverage does not align with finance ransomware groups.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with card_3:
        st.markdown(
            """
            <div class="method-card method-navy">
                <h4>K-Means Clustering</h4>
                <p>Groups similar threat records so analysts can detect shared IOC patterns without reading each record one by one.</p>
                <div class="info-block analysis-block"><strong>Mission:</strong> Surface clusters of similar threat artifacts that can support triage and pattern-based investigation.</div>
                <div class="info-block analysis-block"><strong>How it works:</strong> It converts selected IOC attributes into numerical features and groups records by similarity using K-Means.</div>
                <div class="info-block output-block"><strong>Operational value:</strong> It gives defenders a faster way to identify repeated IOC patterns and focus on dense clusters rather than isolated rows.</div>
                <div class="info-block output-block"><strong>Produces for defenders:</strong> Cluster assignments, dominant malware tendencies, record-volume summaries, and cluster-level behavior patterns.</div>
                <div class="info-block validation-block"><strong>Validation:</strong> Cluster quality is checked with silhouette, Davies-Bouldin, Calinski-Harabasz, inertia, and review of dominant cluster makeup.</div>
                <div class="info-block limit-block"><strong>Limitations:</strong> Cluster quality depends on feature design and chosen k, and unsupervised groupings may not map cleanly to real threat families.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("### Validation, Error Analysis & Operational Metrics")
    bottom_col_1, bottom_col_2, bottom_col_3 = st.columns(3, gap="large")

    with bottom_col_1:
        st.markdown(
            """
            <div class="bottom-panel">
                <h4>Cross-Cutting Validation and Risks</h4>
                <div class="info-block validation-block"><strong>Validation:</strong> Exact IOC overlap, keyword coverage, cluster quality metrics, and analyst spot-checks are used together rather than relying on one measure.</div>
                <div class="info-block limit-block"><strong>Caution:</strong> Threat coverage differences, static keyword lists, and alias normalization can reduce analytic confidence.</div>
                <div class="info-block risk-block"><strong>Risk:</strong> False positives can come from broad lexical matches, while false negatives can come from unseen aliases, new vocabulary, or temporal mismatch across datasets.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with bottom_col_2:
        st.markdown(
            """
            <div class="bottom-panel">
                <h4>Operational Metrics Supported</h4>
                <ul>
                    <li><strong>Alert precision:</strong> stronger evidence before escalation through suspicious URL and IOC patterning.</li>
                    <li><strong>MTTD:</strong> faster prioritization of finance-relevant groups, infrastructure, and repeated phishing patterns.</li>
                    <li><strong>False-positive reduction:</strong> manual review highlights over-broad terms and weak correlations that should be tuned.</li>
                    <li><strong>Analyst efficiency:</strong> clustered records and summarized networks reduce row-by-row review burden.</li>
                </ul>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with bottom_col_3:
        st.markdown(
            """
            <div class="bottom-panel">
                <h4>Why This Is Tactical / Operational CTI</h4>
                <ul>
                    <li><strong>Tactical CTI:</strong> the page focuses on IOCs, phishing URL traits, malware-linked infrastructure, and directly observable threat behavior.</li>
                    <li><strong>Operational CTI:</strong> event correlation adds campaign-level context by linking actors, victims, infrastructure, countries, and TTPs.</li>
                    <li><strong>Not primarily strategic:</strong> the emphasis is on defender actionability, triage, and detection support rather than long-range forecasting.</li>
                </ul>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_future_cti_directions() -> None:
    st.markdown(
        """
        <div class="cti-banner">
            <h3>Future CTI Directions</h3>
            <p>
                These roadmap items build directly on the platform's current analytics, triage, and dissemination
                capabilities so the system becomes more actionable without changing its U.S. banking focus.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <span class="cti-badge badge-blue">Roadmap: Near-Term Enhancements</span>
        <span class="cti-badge badge-slate">Focus: Analyst Speed, Fraud Context, Stakeholder Delivery</span>
        <span class="cti-badge badge-teal">Grounded In: Current Platform Capabilities</span>
        """,
        unsafe_allow_html=True,
    )

    future_col_1, future_col_2, future_col_3 = st.columns(3, gap="large")

    with future_col_1:
        st.markdown(
            """
            <div class="method-card method-blue">
                <h4>Automatic Indicator Enrichment</h4>
                <p>Add automatic lookups for suspicious URLs, domains, and IPs so analysts get richer context without switching tools.</p>
                <div class="info-block analysis-block"><strong>What this adds:</strong> Automatic enrichment from sources like VirusTotal and Shodan when indicators are flagged inside the platform.</div>
                <div class="info-block output-block"><strong>Operational value:</strong> Analysts can validate maliciousness faster and prioritize indicators with stronger external confirmation.</div>
                <div class="info-block output-block"><strong>Builds on:</strong> Existing PhishTank and ThreatFox integrations</div>
                <div class="info-block validation-block"><strong>Why it matters next:</strong> It reduces manual lookup time and improves confidence scoring for phishing and infrastructure alerts.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with future_col_2:
        st.markdown(
            """
            <div class="method-card method-teal">
                <h4>Transaction Data Integration</h4>
                <p>Connect external threat indicators to internal banking activity so fraud-relevant threats can be matched to real operational signals.</p>
                <div class="info-block analysis-block"><strong>What this adds:</strong> IOC matching against transaction, account, and authentication telemetry to flag higher-risk events earlier.</div>
                <div class="info-block output-block"><strong>Operational value:</strong> Moves the platform closer to proactive fraud detection instead of external monitoring alone.</div>
                <div class="info-block output-block"><strong>Builds on:</strong> Current fraud-prevention use case, asset prioritization, and IOC monitoring workflows.</div>
                <div class="info-block validation-block"><strong>Why it matters:</strong> It strengthens the bridge between CTI collection and real defensive action inside the banking environment.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with future_col_3:
        st.markdown(
            """
            <div class="method-card method-navy">
                <h4>Personalized Alerts by Role</h4>
                <p>Tailor outputs to analysts, executives, and operational teams so each audience receives the right level of detail automatically.</p>
                <div class="info-block analysis-block"><strong>What this adds:</strong> Role-aware notifications that separate technical evidence, leadership summaries, and user-facing awareness content.</div>
                <div class="info-block output-block"><strong>Operational value:</strong> It shortens dissemination time and reduces the need for manual translation between technical and non-technical stakeholders.</div>
                <div class="info-block output-block"><strong>Builds on:</strong> Executive summary, analyst drill-down, and operational dissemination workflows.</div>
                <div class="info-block validation-block"><strong>Why it matters:</strong>  More scalable platform during active campaigns to enable parallel team-based decision-making.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # st.markdown("### Why These Three Directions Matter")
    # roadmap_left, roadmap_right = st.columns(2, gap="large")

    # with roadmap_left:
    #     st.markdown(
    #         """
    #         <div class="bottom-panel">
    #             <h4>Operational Impact</h4>
    #             <ul>
    #                 <li><strong>Faster validation:</strong> enrichment reduces manual IOC research during triage.</li>
    #                 <li><strong>Stronger fraud context:</strong> transaction integration connects external threats to internal risk.</li>
    #                 <li><strong>Better dissemination:</strong> role-based delivery improves speed and clarity during response.</li>
    #             </ul>
    #         </div>
    #         """,
    #         unsafe_allow_html=True,
    #     )

    # with roadmap_right:
    #     st.markdown(
    #         """
    #         <div class="bottom-panel">
    #             <h4>Platform Readiness</h4>
    #             <ul>
    #                 <li><strong>Already supported by current architecture:</strong> the project already has IOC ingestion, analytics, and role-based presentation layers.</li>
    #                 <li><strong>Realistic next scope:</strong> these additions extend the current platform instead of requiring a full redesign.</li>
    #                 <li><strong>Aligned to Milestone 4:</strong> they show a credible path from final prototype to a more operational CTI workflow.</li>
    #             </ul>
    #         </div>
    #         """,
    #         unsafe_allow_html=True,
    #     )


# Future CTI Directions

# ── Data loading ──────────────────────────────────────────────────────────────

group_summary        = load_csv("group_risk_summary.csv")
group_ioc_types      = load_csv("group_ioc_type_counts.csv")
source_overlap       = load_csv("source_overlap_summary.csv")
nodes                = load_csv("network_nodes.csv")
edges                = load_csv("network_edges.csv")
group_network_metrics = load_csv("group_network_metrics.csv")
exact_ioc_overlap    = load_csv("exact_ioc_overlap.csv")
group_family_matches = load_csv("group_family_matches.csv")
threatfox_iocs       = load_table(THREATFOX_PATH)
text_mining_metrics  = load_table(TEXT_MINING_DIR / "evaluation_metrics.csv")
phishing_url_features = load_table(TEXT_MINING_DIR / "phishing_url_features.csv")
top_tfidf_keywords   = load_table(TEXT_MINING_DIR / "top_tfidf_keywords.csv")
top_ngrams           = load_table(TEXT_MINING_DIR / "top_ngrams.csv")
threatfox_kmeans_metrics = load_table(THREATFOX_KMEANS_DIR / "kmeans_validation_metrics.csv")
threatfox_clustered_iocs = load_table(THREATFOX_KMEANS_DIR / "iocs_with_clusters.csv")
critical_assets_df   = load_critical_assets()
phishing_df          = load_phishing_raw()
executive_records_df = build_executive_records()

if group_summary.empty:
    st.warning(
        "Correlation outputs were not found. Run `python utilities\\ransomware_event_correlation.py` first."
    )
    st.stop()

max_victims        = int(group_summary["victim_count"].max()) if not group_summary.empty else 1
default_min_victims = min(3, max_victims)

with st.sidebar:
    st.header("Correlation Controls")
    min_victims  = st.slider("Minimum victim count", 1, max_victims, default_min_victims)
    sort_metric  = st.selectbox(
        "Rank groups by",
        ["risk_score", "victim_count", "ioc_count", "threatfox_ioc_count", "recency_days"],
    )
    top_n        = st.slider("Top groups to display", 3, 20, 10)
    network_view = st.selectbox(
        "Relationship network view",
        ["Group -> Victim", "Group -> IOC type -> TTP", "Group -> Country -> IOC"],
    )
    show_table   = st.checkbox("Show supporting tables", value=False)

filtered_groups = group_summary[group_summary["victim_count"] >= min_victims].copy()
if filtered_groups.empty:
    filtered_groups = group_summary.copy()
    st.sidebar.info("No groups matched that threshold, so all groups are shown instead.")

ascending      = sort_metric == "recency_days"
top_groups     = filtered_groups.sort_values(sort_metric, ascending=ascending).head(top_n).copy()
top_group_keys = set(top_groups["group_norm"])

panel_source = "Exact ransomware.live and ThreatFox IOC overlap"
if not exact_ioc_overlap.empty:
    filtered_df = exact_ioc_overlap[exact_ioc_overlap["group_norm"].isin(top_group_keys)].copy()
    confidence_series        = filtered_df["confidence_level"]        if "confidence_level"        in filtered_df.columns else pd.Series(index=filtered_df.index, dtype="float64")
    ioc_type_threatfox       = filtered_df["ioc_type_threatfox"]      if "ioc_type_threatfox"      in filtered_df.columns else pd.Series(index=filtered_df.index, dtype="object")
    ioc_type_ransomware_live = filtered_df["ioc_type_ransomware_live"] if "ioc_type_ransomware_live" in filtered_df.columns else pd.Series(index=filtered_df.index, dtype="object")
    group_norm_series        = filtered_df["group_norm"]              if "group_norm"              in filtered_df.columns else pd.Series(index=filtered_df.index, dtype="object")
    group_series             = filtered_df["group"]                   if "group"                   in filtered_df.columns else pd.Series(index=filtered_df.index, dtype="object")
    indicator_series         = filtered_df["indicator"]               if "indicator"               in filtered_df.columns else pd.Series(index=filtered_df.index, dtype="object")
    ioc_value_series         = filtered_df["ioc_value"]               if "ioc_value"               in filtered_df.columns else pd.Series(index=filtered_df.index, dtype="object")
    source_series            = filtered_df["source"]                  if "source"                  in filtered_df.columns else pd.Series(index=filtered_df.index, dtype="object")

    filtered_df["confidence"] = pd.to_numeric(confidence_series, errors="coerce").fillna(0)
    filtered_df["type"]       = ioc_type_threatfox.fillna(ioc_type_ransomware_live).fillna("unknown")
    filtered_df["group"]      = group_norm_series.fillna(group_series).fillna("unknown")
    filtered_df["indicator"]  = indicator_series.fillna(ioc_value_series).fillna("unknown")
    filtered_df["source"]     = source_series.fillna("unknown")
    filtered_df               = filtered_df[["group", "indicator", "type", "confidence", "source"]]
elif not group_family_matches.empty:
    panel_source = "ThreatFox malware-family matches for selected ransomware groups"
    filtered_df  = group_family_matches[group_family_matches["group_norm"].isin(top_group_keys)].copy()
    filtered_df["group"]      = filtered_df["group_norm"].fillna("unknown")
    filtered_df["indicator"]  = filtered_df["ioc_value"].fillna("unknown")
    filtered_df["type"]       = filtered_df["ioc_type"].fillna(filtered_df["threat_type"]).fillna("unknown")
    filtered_df["confidence"] = pd.to_numeric(filtered_df["confidence_level"], errors="coerce").fillna(0)
    filtered_df["source"]     = "ThreatFox family match"
    filtered_df               = filtered_df[["group", "indicator", "type", "confidence", "source"]]
elif not threatfox_iocs.empty:
    panel_source = "ThreatFox IOC feed fallback"
    filtered_df  = threatfox_iocs.copy()
    filtered_df["group"]      = "ThreatFox reference IOC"
    filtered_df["indicator"]  = filtered_df["ioc_value"].fillna("unknown")
    filtered_df["type"]       = filtered_df["ioc_type"].fillna(filtered_df["threat_type"]).fillna("unknown")
    filtered_df["confidence"] = pd.to_numeric(filtered_df["confidence_level"], errors="coerce").fillna(0)
    filtered_df["source"]     = "ThreatFox"
    filtered_df               = filtered_df[["group", "indicator", "type", "confidence", "source"]]
else:
    panel_source = "No IOC data available"
    filtered_df  = pd.DataFrame(columns=["group", "indicator", "type", "confidence", "source"])


# ── Session state ─────────────────────────────────────────────────────────────

if "analytics_view"            not in st.session_state:
    st.session_state["analytics_view"]            = "Executive Summary"
if "analysis_mode_analytics"   not in st.session_state:
    st.session_state["analysis_mode_analytics"]   = "Event Correlation"
if "kmeans_mode_analytics"     not in st.session_state:
    st.session_state["kmeans_mode_analytics"]     = "ThreatFox Malware Clustering"

if "pending_analytics_view" in st.session_state:
    st.session_state["analytics_view"] = st.session_state.pop("pending_analytics_view")
if "pending_analysis_mode_analytics" in st.session_state:
    st.session_state["analysis_mode_analytics"] = st.session_state.pop("pending_analysis_mode_analytics")
if "pending_kmeans_mode_analytics" in st.session_state:
    st.session_state["kmeans_mode_analytics"] = st.session_state.pop("pending_kmeans_mode_analytics")


# ── Role switcher ─────────────────────────────────────────────────────────────

st.radio(
    "View",
    ["Executive Summary", "Analyst Drill-Down", "Approach Justification", "Future CTI Directions"],
    horizontal=True,
    key="analytics_view",
    label_visibility="collapsed",
)

# ── Route to view ─────────────────────────────────────────────────────────────

if st.session_state["analytics_view"] == "Executive Summary":
    render_executive_summary(
        top_groups=top_groups,
        phishing_df=phishing_df,
        group_ioc_types=group_ioc_types,
        critical_assets_df=critical_assets_df,
        executive_records_df=executive_records_df,
    )

elif st.session_state["analytics_view"] == "Analyst Drill-Down":
    # ── Section 1: Context metrics ──
    st.markdown("### 1. Analyst Context")
    st.write(
        "This view provides the technical evidence behind the leadership summary, including campaign "
        "correlation, phishing pattern analysis, and clustering outputs for CTI and SOC workflows."
    )
    indicators_in_view, top_group_name, common_pattern = analyst_context_metrics(
        filtered_df, top_groups, group_ioc_types
    )
    metric_cols = st.columns(3)
    metric_cols[0].metric("Indicators In View",         indicators_in_view)
    metric_cols[1].metric("Top Threat Group",            top_group_name)
    metric_cols[2].metric("Most Common IOC / TTP Pattern", common_pattern)

    # ── Visual break + selector caption ──
    st.divider()
    st.markdown('<div class="analyst-section-label">// Analysis Selector</div>', unsafe_allow_html=True)
    st.caption(
        "Choose an analysis panel below to explore the technical evidence — "
        "Event Correlation for ransomware group data, Text Mining for phishing URL patterns, "
        "or K-Means for IOC clustering outputs."
    )

    # ── Section 2: Analysis selector ──
    st.markdown("### 2. Analysis Selector")
    analysis_mode = st.selectbox(
        "Choose an analysis panel",
        ["Event Correlation", "Text Mining", "K-Means"],
        key="analysis_mode_analytics",
    )

    # ── Section 3: Evidence panels ──
    st.markdown("### 3. Detailed Evidence Panels")
    if analysis_mode == "Event Correlation":
        render_event_correlation_panel(
            group_summary=group_summary,
            filtered_df=filtered_df,
            panel_source=panel_source,
            top_groups=top_groups,
            sort_metric=sort_metric,
            ascending=ascending,
            source_overlap=source_overlap,
            group_ioc_types=group_ioc_types,
            top_group_keys=top_group_keys,
            nodes=nodes,
            edges=edges,
            network_view=network_view,
            group_network_metrics=group_network_metrics,
            show_table=show_table,
            exact_ioc_overlap=exact_ioc_overlap,
            group_family_matches=group_family_matches,
        )
    elif analysis_mode == "Text Mining":
        render_text_mining_panel(
            features_df=phishing_url_features,
            metrics_df=text_mining_metrics,
            tfidf_df=top_tfidf_keywords,
            ngrams_df=top_ngrams,
        )
    else:
        st.markdown(
            "The app contains two K-Means workflows: "
            "**ThreatFox Malware IOC Clustering** groups ThreatFox indicators by IOC and malware-related features, "
            "while **Phishing URL Pattern Clustering** groups finance-themed phishing URLs by lexical and URL-pattern features."
        )
        kmeans_mode = st.radio(
            "K-Means workflow",
            ["ThreatFox Malware Clustering", "Phishing URL Pattern Clustering"],
            horizontal=True,
            key="kmeans_mode_analytics",
        )
        if kmeans_mode == "ThreatFox Malware Clustering":
            render_threatfox_kmeans_panel(
                features_df=threatfox_clustered_iocs,
                metrics_df=threatfox_kmeans_metrics,
            )
        else:
            render_phishing_kmeans_panel(
                features_df=phishing_url_features,
                metrics_df=text_mining_metrics,
            )

    render_analyst_interpretation(
        analysis_mode=analysis_mode,
        exact_ioc_overlap=exact_ioc_overlap,
        group_family_matches=group_family_matches,
        text_mining_metrics=text_mining_metrics,
        threatfox_kmeans_metrics=threatfox_kmeans_metrics,
    )

elif st.session_state["analytics_view"] == "Future CTI Directions":
    render_future_cti_directions()

else:
    render_approach_justification()
