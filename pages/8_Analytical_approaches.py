"""Interactive analytical approaches and methodology justification."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
from pandas.errors import EmptyDataError
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CORRELATION_DIR = PROJECT_ROOT / "data" / "ransomware_event_correlation"
THREATFOX_PATH = PROJECT_ROOT / "data" / "filtered_iocs_threatfox.csv"
TEXT_MINING_DIR = PROJECT_ROOT / "data" / "phishing_url_text_mining"

PAGE_COLORS = {
    "group": "#C73E1D",
    "victim": "#2E86AB",
    "country": "#7FB069",
    "ioc": "#F18F01",
    "ioc_type": "#6A4C93",
    "ttp": "#00A6A6",
    "malware": "#D1495B",
}


st.set_page_config(page_title="Analytical Approaches", layout="wide")
st.title("Analytical Approaches")
st.caption(
    "Interactive CTI analytics for finance-sector ransomware correlation, with methodology "
    "justification aligned to the Milestone 3 rubric."
)


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


def has_columns(df: pd.DataFrame, required: list[str]) -> bool:
    return not df.empty and all(column in df.columns for column in required)


def selected_relations(view: str) -> set[str]:
    if view == "Group -> IOC type -> TTP":
        return {"group_to_ioc", "ioc_to_type", "group_to_ttp"}
    if view == "Group -> Country -> IOC":
        return {"group_to_country", "group_to_ioc"}
    return {"group_to_victim"}


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
    group_node_ids = {f"group:{group}" for group in groups}
    selected_edges = edges_df[edges_df["relation"].isin(relation_filter)].copy()
    selected_edges = selected_edges[
        selected_edges["source"].isin(group_node_ids) | selected_edges["target"].isin(group_node_ids)
    ]

    if "group_to_ioc" in relation_filter:
        ioc_edges = selected_edges[selected_edges["relation"] == "group_to_ioc"].head(max_iocs)
        allowed_iocs = set(ioc_edges["target"])
        selected_edges = selected_edges[
            (selected_edges["relation"] != "group_to_ioc")
            | selected_edges["target"].isin(allowed_iocs)
            | selected_edges["source"].isin(allowed_iocs)
        ]

    selected_nodes = set(selected_edges["source"]) | set(selected_edges["target"])
    network_nodes = nodes_df[nodes_df["node_id"].isin(selected_nodes)].copy()

    if network_nodes.empty or selected_edges.empty:
        return go.Figure()

    type_order = ["group", "country", "ioc_type", "ttp", "ioc", "victim", "malware"]
    x_positions = {node_type: idx for idx, node_type in enumerate(type_order)}
    network_nodes["x"] = network_nodes["node_type"].map(x_positions).fillna(len(type_order))
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
            x=edge_x,
            y=edge_y,
            mode="lines",
            line=dict(width=0.6, color="rgba(90, 90, 90, 0.35)"),
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
                x=subset["x"],
                y=subset["y"],
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

    fig.update_layout(
        title=f"Relationship Network: {view}",
        xaxis=dict(visible=False),
        yaxis=dict(visible=False),
        height=650,
        margin=dict(l=10, r=10, t=60, b=10),
        legend_title_text="Node Type",
    )
    return fig


def metric_lookup(metrics_df: pd.DataFrame, metric_name: str, default: float = 0.0) -> float:
    if not has_columns(metrics_df, ["metric", "value"]):
        return default
    match = metrics_df.loc[metrics_df["metric"] == metric_name, "value"]
    if match.empty:
        return default
    return float(match.iloc[0])


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
    target_options = ["All"] + sorted(features_df["target"].dropna().astype(str).unique().tolist())
    selected_target = control_cols[0].selectbox("Target", target_options, key="tm_target")
    tld_options = sorted(features_df["tld"].dropna().astype(str).unique().tolist())
    selected_tlds = control_cols[1].multiselect(
        "TLDs",
        tld_options,
        default=tld_options[: min(6, len(tld_options))] if tld_options else [],
        key="tm_tlds",
    )
    banking_only = control_cols[2].checkbox("Banking keywords only", value=False, key="tm_kw_only")
    suspicious_only = control_cols[3].checkbox("Suspicious TLDs only", value=False, key="tm_suspicious_only")

    query = st.text_input(
        "Search URL or matched term",
        placeholder="Filter by URL, domain, target, or matched term",
        key="tm_search",
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

    metrics_cols = st.columns(4)
    https_pct = panel_df["uses_https"].mean() * 100 if not panel_df.empty else 0.0
    suspicious_pct = panel_df["is_suspicious_tld"].mean() * 100 if not panel_df.empty else 0.0
    metrics_cols[0].metric("URLs In View", f"{len(panel_df):,}")
    metrics_cols[1].metric("Average URL Length", f"{panel_df['url_length'].mean() if not panel_df.empty else 0:.1f}")
    metrics_cols[2].metric("HTTPS Share", f"{https_pct:.1f}%")
    metrics_cols[3].metric("Suspicious TLD Share", f"{suspicious_pct:.1f}%")

    if panel_df.empty:
        st.info("No phishing URL records match the current filters.")
        return

    keyword_cols = [column for column in panel_df.columns if column.startswith("kw_")]
    keyword_counts = (
        panel_df[keyword_cols]
        .sum()
        .sort_values(ascending=False)
        .head(10)
        .rename_axis("keyword")
        .reset_index(name="count")
    )
    keyword_counts["keyword"] = keyword_counts["keyword"].str.replace("kw_", "", regex=False)
    tld_counts = (
        panel_df["tld"].value_counts().head(10).rename_axis("tld").reset_index(name="count")
    )

    left, right = st.columns([1.2, 1])
    with left:
        fig_keywords = px.bar(
            keyword_counts,
            x="keyword",
            y="count",
            color="count",
            color_continuous_scale="Tealgrn",
            title="Top Banking and Brand Keywords",
            labels={"keyword": "Keyword", "count": "URLs"},
        )
        fig_keywords.update_layout(coloraxis_showscale=False)
        st.plotly_chart(fig_keywords, use_container_width=True)
    with right:
        fig_tlds = px.bar(
            tld_counts,
            x="tld",
            y="count",
            color="count",
            color_continuous_scale="Sunset",
            title="Top TLDs In View",
            labels={"tld": "TLD", "count": "URLs"},
        )
        fig_tlds.update_layout(coloraxis_showscale=False)
        st.plotly_chart(fig_tlds, use_container_width=True)

    insight_left, insight_right = st.columns([1.1, 1])
    with insight_left:
        top_terms = tfidf_df.head(15) if not tfidf_df.empty else pd.DataFrame(columns=["term", "mean_tfidf"])
        if not top_terms.empty:
            fig_tfidf = px.bar(
                top_terms.sort_values("mean_tfidf"),
                x="mean_tfidf",
                y="term",
                orientation="h",
                title="Top TF-IDF Terms",
                labels={"mean_tfidf": "Mean TF-IDF", "term": "Term"},
            )
            st.plotly_chart(fig_tfidf, use_container_width=True)
        else:
            st.info("No TF-IDF keywords were found.")
    with insight_right:
        top_ngrams = ngrams_df.head(15) if not ngrams_df.empty else pd.DataFrame(columns=["ngram", "count"])
        if not top_ngrams.empty:
            fig_ngrams = px.bar(
                top_ngrams.sort_values("count"),
                x="count",
                y="ngram",
                orientation="h",
                title="Most Repeated N-Grams",
                labels={"count": "Count", "ngram": "N-Gram"},
            )
            st.plotly_chart(fig_ngrams, use_container_width=True)
        else:
            st.info("No n-gram output was found.")

    st.dataframe(
        panel_df[
            [
                "url",
                "target",
                "banking_match_source",
                "banking_match_term",
                "tld",
                "url_length",
                "uses_https",
                "suspicious_keyword_count",
                "finance_keyword_count",
                "brand_keyword_count",
            ]
        ].head(75),
        use_container_width=True,
        hide_index=True,
    )

    if has_columns(metrics_df, ["metric", "value", "interpretation"]):
        st.markdown("### Text-Mining Evaluation Metrics")
        st.dataframe(metrics_df, use_container_width=True, hide_index=True)


def render_kmeans_panel(features_df: pd.DataFrame, metrics_df: pd.DataFrame) -> None:
    st.markdown("### K-Means Cluster Explorer")
    st.caption("Using the URL-pattern clustering output saved in `phishing_url_features.csv`.")

    required_columns = [
        "url_pattern_cluster",
        "target",
        "uses_https",
        "url_length",
        "finance_keyword_count",
        "brand_keyword_count",
    ]
    if not has_columns(features_df, required_columns):
        st.info("No K-Means clustering output was found in the phishing URL analysis files.")
        return

    control_cols = st.columns([1.2, 1.2, 1, 1])
    cluster_options = sorted(features_df["url_pattern_cluster"].dropna().astype(int).unique().tolist())
    selected_clusters = control_cols[0].multiselect(
        "Clusters",
        cluster_options,
        default=cluster_options,
        key="km_clusters",
    )
    target_options = ["All"] + sorted(features_df["target"].dropna().astype(str).unique().tolist())
    selected_target = control_cols[1].selectbox("Target", target_options, key="km_target")
    https_only = control_cols[2].checkbox("HTTPS only", value=False, key="km_https")
    min_finance_terms = control_cols[3].slider("Min finance keywords", 0, 10, 0, key="km_finance_min")

    panel_df = features_df.copy()
    if selected_clusters:
        panel_df = panel_df[panel_df["url_pattern_cluster"].isin(selected_clusters)]
    if selected_target != "All":
        panel_df = panel_df[panel_df["target"] == selected_target]
    if https_only:
        panel_df = panel_df[panel_df["uses_https"] == 1]
    panel_df = panel_df[panel_df["finance_keyword_count"] >= min_finance_terms]

    silhouette = metric_lookup(metrics_df, "silhouette_score")
    davies_bouldin = metric_lookup(metrics_df, "davies_bouldin_score")
    calinski = metric_lookup(metrics_df, "calinski_harabasz_score")

    metrics_cols = st.columns(4)
    metrics_cols[0].metric("URLs In View", f"{len(panel_df):,}")
    metrics_cols[1].metric("Clusters In View", f"{panel_df['url_pattern_cluster'].nunique() if not panel_df.empty else 0:,}")
    metrics_cols[2].metric("Silhouette Score", f"{silhouette:.3f}")
    metrics_cols[3].metric("Davies-Bouldin", f"{davies_bouldin:.3f}")
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
            cluster_summary,
            x="url_pattern_cluster",
            y="url_count",
            color="dominant_target",
            title="Records Per Cluster",
            labels={"url_pattern_cluster": "Cluster", "url_count": "URLs", "dominant_target": "Dominant Target"},
        )
        st.plotly_chart(fig_clusters, use_container_width=True)
    with right:
        fig_cluster_keywords = px.scatter(
            cluster_summary,
            x="avg_finance_keywords",
            y="avg_brand_keywords",
            size="url_count",
            color="url_pattern_cluster",
            hover_name="dominant_target",
            title="Cluster Keyword Profile",
            labels={
                "avg_finance_keywords": "Avg Finance Keywords",
                "avg_brand_keywords": "Avg Brand Keywords",
                "url_pattern_cluster": "Cluster",
            },
        )
        st.plotly_chart(fig_cluster_keywords, use_container_width=True)

    st.dataframe(cluster_summary, use_container_width=True, hide_index=True)
    st.dataframe(
        panel_df[
            [
                "url",
                "target",
                "url_pattern_cluster",
                "tld",
                "url_length",
                "finance_keyword_count",
                "brand_keyword_count",
                "uses_https",
            ]
        ].head(75),
        use_container_width=True,
        hide_index=True,
    )


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
    metric_cols[0].metric("Finance Victims", f"{int(group_summary['victim_count'].sum()):,}")
    metric_cols[1].metric("Ransomware Groups", f"{group_summary['group_norm'].nunique():,}")
    metric_cols[2].metric("Ransomware.live IOCs", f"{int(group_summary['ioc_count'].sum()):,}")
    metric_cols[3].metric("ThreatFox Matches", f"{int(group_summary['threatfox_ioc_count'].sum()):,}")
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
    panel_controls = st.columns([1.2, 1.2, 1, 1])
    source_options = ["All"] + sorted(filtered_df["source"].dropna().astype(str).unique().tolist())
    selected_source = panel_controls[0].selectbox("Data source", source_options)
    type_options = sorted(filtered_df["type"].dropna().astype(str).unique().tolist())
    selected_types = panel_controls[1].multiselect(
        "IOC types",
        type_options,
        default=type_options[: min(5, len(type_options))] if type_options else [],
    )
    max_confidence = (
        int(filtered_df["confidence"].max()) if not filtered_df.empty and filtered_df["confidence"].notna().any() else 100
    )
    min_confidence = panel_controls[2].slider("Min confidence", 0, max_confidence, 0)
    record_limit = panel_controls[3].slider("Rows shown", 10, 200, 50, 10)

    search_text = st.text_input(
        "Search indicator or group",
        placeholder="Filter by IOC value, group, or keyword",
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
    panel_metrics[0].metric("Matching Records", f"{len(panel_df):,}")
    avg_confidence = panel_df["confidence"].mean() if not panel_df.empty else 0.0
    panel_metrics[1].metric("Average Confidence", f"{float(avg_confidence):.2f}")
    panel_metrics[2].metric("IOC Types In View", f"{panel_df['type'].nunique() if not panel_df.empty else 0:,}")

    if panel_df.empty:
        st.info("No IOC records match the current filter selections.")
    else:
        chart_left, chart_right = st.columns([1.2, 1])
        with chart_left:
            type_counts = (
                panel_df["type"].value_counts().rename_axis("type").reset_index(name="count")
            )
            fig_types = px.bar(
                type_counts,
                x="type",
                y="count",
                color="count",
                color_continuous_scale="OrRd",
                title="IOC Type Distribution",
                labels={"type": "IOC Type", "count": "Records"},
            )
            fig_types.update_layout(coloraxis_showscale=False)
            st.plotly_chart(fig_types, use_container_width=True)
        with chart_right:
            fig_conf = px.histogram(
                panel_df,
                x="confidence",
                nbins=min(20, max(len(panel_df), 1)),
                title="Confidence Distribution",
                labels={"confidence": "Confidence"},
            )
            st.plotly_chart(fig_conf, use_container_width=True)

        st.dataframe(panel_df.head(record_limit), use_container_width=True, hide_index=True)

    left, right = st.columns([1.2, 1])
    with left:
        fig_groups = px.bar(
            top_groups.sort_values(sort_metric, ascending=not ascending),
            x=sort_metric,
            y="display_group",
            orientation="h",
            color="risk_score",
            color_continuous_scale="OrRd",
            title=f"Top Ransomware Groups by {sort_metric.replace('_', ' ').title()}",
            labels={
                sort_metric: sort_metric.replace("_", " ").title(),
                "display_group": "Ransomware Group",
                "risk_score": "Risk Score",
            },
        )
        st.plotly_chart(fig_groups, use_container_width=True)

    with right:
        overlap_plot = source_overlap.copy()
        if not has_columns(overlap_plot, ["metric", "value"]):
            overlap_plot = pd.DataFrame({"metric": ["exact_cross_source_matches"], "value": [0]})
        fig_overlap = px.bar(
            overlap_plot,
            x="metric",
            y="value",
            color="metric",
            title="Cross-Source IOC Overlap",
            labels={"metric": "Source Overlap Metric", "value": "Count"},
        )
        fig_overlap.update_layout(showlegend=False)
        st.plotly_chart(fig_overlap, use_container_width=True)

    st.markdown("### Group vs IOC Type Heatmap")
    if has_columns(group_ioc_types, ["group_norm", "display_group", "ioc_type", "ioc_count"]):
        heatmap_data = group_ioc_types[group_ioc_types["group_norm"].isin(top_group_keys)].copy()
    else:
        heatmap_data = pd.DataFrame()
    if not heatmap_data.empty:
        pivot = heatmap_data.pivot_table(
            index="display_group",
            columns="ioc_type",
            values="ioc_count",
            aggfunc="sum",
            fill_value=0,
        )
        fig_heatmap = px.imshow(
            pivot,
            aspect="auto",
            color_continuous_scale="YlOrRd",
            title="IOC Type Concentration by Finance-Relevant Ransomware Group",
            labels={"x": "IOC Type", "y": "Ransomware Group", "color": "IOC Count"},
        )
        st.plotly_chart(fig_heatmap, use_container_width=True)
    else:
        st.info("No IOC type records found for the selected group filters.")

    st.markdown("### Relationship Network")
    network_fig = build_network_figure(nodes, edges, top_group_keys, network_view)
    if len(network_fig.data) == 0:
        st.info("No network edges are available for the selected controls.")
    else:
        st.plotly_chart(network_fig, use_container_width=True)

    st.markdown("### Network Metrics")
    if has_columns(
        group_network_metrics,
        [
            "group_norm",
            "display_group",
            "degree",
            "degree_centrality",
            "component_id",
            "risk_score",
            "victim_count",
            "ioc_count",
        ],
    ):
        network_table = group_network_metrics[
            group_network_metrics["group_norm"].isin(top_group_keys)
        ][
            [
                "display_group",
                "degree",
                "degree_centrality",
                "component_id",
                "risk_score",
                "victim_count",
                "ioc_count",
            ]
        ].sort_values("degree_centrality", ascending=False)
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


group_summary = load_csv("group_risk_summary.csv")
group_ioc_types = load_csv("group_ioc_type_counts.csv")
source_overlap = load_csv("source_overlap_summary.csv")
nodes = load_csv("network_nodes.csv")
edges = load_csv("network_edges.csv")
group_network_metrics = load_csv("group_network_metrics.csv")
exact_ioc_overlap = load_csv("exact_ioc_overlap.csv")
group_family_matches = load_csv("group_family_matches.csv")
threatfox_iocs = load_table(THREATFOX_PATH)
text_mining_metrics = load_table(TEXT_MINING_DIR / "evaluation_metrics.csv")
phishing_url_features = load_table(TEXT_MINING_DIR / "phishing_url_features.csv")
top_tfidf_keywords = load_table(TEXT_MINING_DIR / "top_tfidf_keywords.csv")
top_ngrams = load_table(TEXT_MINING_DIR / "top_ngrams.csv")

if group_summary.empty:
    st.warning(
        "Correlation outputs were not found. Run `python utilities\\ransomware_event_correlation.py` first."
    )
    st.stop()

max_victims = int(group_summary["victim_count"].max()) if not group_summary.empty else 1
default_min_victims = min(3, max_victims)

with st.sidebar:
    st.header("Correlation Controls")
    min_victims = st.slider("Minimum victim count", 1, max_victims, default_min_victims)
    sort_metric = st.selectbox(
        "Rank groups by",
        ["risk_score", "victim_count", "ioc_count", "threatfox_ioc_count", "recency_days"],
    )
    top_n = st.slider("Top groups to display", 3, 20, 10)
    network_view = st.selectbox(
        "Relationship network view",
        ["Group -> Victim", "Group -> IOC type -> TTP", "Group -> Country -> IOC"],
    )
    show_table = st.checkbox("Show supporting tables", value=False)

filtered_groups = group_summary[group_summary["victim_count"] >= min_victims].copy()
if filtered_groups.empty:
    filtered_groups = group_summary.copy()
    st.sidebar.info("No groups matched that threshold, so all groups are shown instead.")

interactive_tab, justification_tab = st.tabs(
    ["Interactive Analytics Panel", "Approach Justification"]
)

ascending = sort_metric == "recency_days"
top_groups = filtered_groups.sort_values(sort_metric, ascending=ascending).head(top_n).copy()
top_group_keys = set(top_groups["group_norm"])

panel_source = "Exact ransomware.live and ThreatFox IOC overlap"
if not exact_ioc_overlap.empty:
    filtered_df = exact_ioc_overlap[exact_ioc_overlap["group_norm"].isin(top_group_keys)].copy()
    confidence_series = (
        filtered_df["confidence_level"] if "confidence_level" in filtered_df.columns else pd.Series(index=filtered_df.index, dtype="float64")
    )
    ioc_type_threatfox = (
        filtered_df["ioc_type_threatfox"] if "ioc_type_threatfox" in filtered_df.columns else pd.Series(index=filtered_df.index, dtype="object")
    )
    ioc_type_ransomware_live = (
        filtered_df["ioc_type_ransomware_live"] if "ioc_type_ransomware_live" in filtered_df.columns else pd.Series(index=filtered_df.index, dtype="object")
    )
    group_norm_series = (
        filtered_df["group_norm"] if "group_norm" in filtered_df.columns else pd.Series(index=filtered_df.index, dtype="object")
    )
    group_series = (
        filtered_df["group"] if "group" in filtered_df.columns else pd.Series(index=filtered_df.index, dtype="object")
    )
    indicator_series = (
        filtered_df["indicator"] if "indicator" in filtered_df.columns else pd.Series(index=filtered_df.index, dtype="object")
    )
    ioc_value_series = (
        filtered_df["ioc_value"] if "ioc_value" in filtered_df.columns else pd.Series(index=filtered_df.index, dtype="object")
    )
    source_series = (
        filtered_df["source"] if "source" in filtered_df.columns else pd.Series(index=filtered_df.index, dtype="object")
    )

    filtered_df["confidence"] = pd.to_numeric(confidence_series, errors="coerce").fillna(0)
    filtered_df["type"] = ioc_type_threatfox.fillna(ioc_type_ransomware_live).fillna("unknown")
    filtered_df["group"] = group_norm_series.fillna(group_series).fillna("unknown")
    filtered_df["indicator"] = indicator_series.fillna(ioc_value_series).fillna("unknown")
    filtered_df["source"] = source_series.fillna("unknown")
    filtered_df = filtered_df[["group", "indicator", "type", "confidence", "source"]]
elif not group_family_matches.empty:
    panel_source = "ThreatFox malware-family matches for selected ransomware groups"
    filtered_df = group_family_matches[group_family_matches["group_norm"].isin(top_group_keys)].copy()
    filtered_df["group"] = filtered_df["group_norm"].fillna("unknown")
    filtered_df["indicator"] = filtered_df["ioc_value"].fillna("unknown")
    filtered_df["type"] = filtered_df["ioc_type"].fillna(filtered_df["threat_type"]).fillna("unknown")
    filtered_df["confidence"] = pd.to_numeric(
        filtered_df["confidence_level"], errors="coerce"
    ).fillna(0)
    filtered_df["source"] = "ThreatFox family match"
    filtered_df = filtered_df[["group", "indicator", "type", "confidence", "source"]]
elif not threatfox_iocs.empty:
    panel_source = "ThreatFox IOC feed fallback"
    filtered_df = threatfox_iocs.copy()
    filtered_df["group"] = "ThreatFox reference IOC"
    filtered_df["indicator"] = filtered_df["ioc_value"].fillna("unknown")
    filtered_df["type"] = filtered_df["ioc_type"].fillna(filtered_df["threat_type"]).fillna("unknown")
    filtered_df["confidence"] = pd.to_numeric(
        filtered_df["confidence_level"], errors="coerce"
    ).fillna(0)
    filtered_df["source"] = "ThreatFox"
    filtered_df = filtered_df[["group", "indicator", "type", "confidence", "source"]]
else:
    panel_source = "No IOC data available"
    filtered_df = pd.DataFrame(columns=["group", "indicator", "type", "confidence", "source"])


with interactive_tab:
    analysis_mode = st.selectbox(
        "Choose an analysis panel",
        ["Event Correlation", "Text Mining", "K-Means"],
    )

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
        render_kmeans_panel(
            features_df=phishing_url_features,
            metrics_df=text_mining_metrics,
        )


with justification_tab:
    st.markdown("### Selected Analytical Approaches")
    st.write(
        "The project uses two primary analytical approaches from the CTI and data-mining module: "
        "phishing URL text mining and ransomware event correlation. This page visualizes the event "
        "correlation approach, while the phishing URL text-mining utility produces companion outputs "
        "for keyword, n-gram, URL-feature, and clustering analysis."
    )

    st.markdown("### Approach 1: Phishing URL Text Mining")
    st.table(
        pd.DataFrame(
            [
                {
                    "Rubric Item": "Why selected",
                    "Project Response": (
                        "Banking phishing URLs contain repeated lexical patterns such as login, "
                        "secure, account, bank, wallet, payment, suspicious TLDs, and long encoded paths. "
                        "Text mining converts those URL strings into analyst-readable patterns."
                    ),
                },
                {
                    "Rubric Item": "Data sources",
                    "Project Response": (
                        "data/verified_online_banking_finance.csv, data/phishtank.csv, and generated "
                        "outputs under data/phishing_url_text_mining/."
                    ),
                },
                {
                    "Rubric Item": "Major steps",
                    "Project Response": (
                        "Normalize URLs; extract domain/path/query features; count suspicious, finance, "
                        "and brand keywords; compute TF-IDF terms; compute repeated n-grams; optionally "
                        "cluster URL feature vectors with K-Means."
                    ),
                },
                {
                    "Rubric Item": "Why those steps",
                    "Project Response": (
                        "Feature extraction makes URL structure measurable, TF-IDF highlights distinctive "
                        "terms, n-grams reveal repeated phishing phrases, and clustering groups similar URL "
                        "construction patterns for analyst triage."
                    ),
                },
                {
                    "Rubric Item": "Tools used",
                    "Project Response": "Python, pandas, scikit-learn TF-IDF/CountVectorizer/K-Means, Plotly, Streamlit.",
                },
                {
                    "Rubric Item": "Evaluation methods",
                    "Project Response": (
                        "Keyword coverage percentage, suspicious TLD percentage, HTTPS percentage, manual "
                        "spot-checking of top terms, and K-Means metrics such as silhouette score, Davies-Bouldin "
                        "score, Calinski-Harabasz score, and inertia."
                    ),
                },
            ]
        )
    )

    st.markdown("### Approach 2: Ransomware Event Correlation")
    st.table(
        pd.DataFrame(
            [
                {
                    "Rubric Item": "Why selected",
                    "Project Response": (
                        "Victim, IOC, TTP, and external threat-intelligence records become more useful when "
                        "connected by ransomware group, indicator value, country, IOC type, and TTP."
                    ),
                },
                {
                    "Rubric Item": "Data sources",
                    "Project Response": (
                        "data/finance_victims.csv, data/finance_group_iocs.csv, "
                        "data/filtered_iocs_threatfox.csv, and generated outputs under "
                        "data/ransomware_event_correlation/."
                    ),
                },
                {
                    "Rubric Item": "Major steps",
                    "Project Response": (
                        "Normalize group names; map aliases; remove punctuation; aggregate victims by group; "
                        "count countries, IOCs, IOC types, and TTPs; join ransomware.live and ThreatFox IOCs by "
                        "exact indicator value; match group names to malware-family fields, aliases, and tags; "
                        "build group-victim-country-IOC-TTP network edges."
                    ),
                },
                {
                    "Rubric Item": "Why those steps",
                    "Project Response": (
                        "Entity resolution prevents missed matches from naming differences, aggregation produces "
                        "group-level prioritization, exact IOC matching gives high-confidence source overlap, and "
                        "network modeling exposes relationships analysts can triage."
                    ),
                },
                {
                    "Rubric Item": "Tools used",
                    "Project Response": "Python, pandas, custom graph metrics, Plotly, Streamlit.",
                },
                {
                    "Rubric Item": "Evaluation methods",
                    "Project Response": (
                        "Exact IOC overlap count, group-family match count, degree centrality, connected-component "
                        "analysis, recency, victim counts, IOC counts, TTP counts, and manual review of unmatched "
                        "ThreatFox records."
                    ),
                },
            ]
        )
    )

    st.markdown("### Operational Metrics")
    st.write(
        "These analytics support CTI program evaluation by improving alert precision and reducing mean time "
        "to detection. URL text mining helps prioritize URLs that resemble verified finance phishing, while "
        "event correlation prioritizes ransomware groups with recent finance victims, many IOCs, broad country "
        "impact, or strong TTP coverage."
    )
    st.table(
        pd.DataFrame(
            [
                {
                    "Metric": "Alert precision",
                    "How analytics improve it": (
                        "Suspicious URL features, repeated phishing keywords, and cross-source IOC matches "
                        "give analysts stronger criteria before escalation."
                    ),
                },
                {
                    "Metric": "MTTD",
                    "How analytics improve it": (
                        "Group risk scoring and network centrality surface active finance-targeting groups "
                        "and their associated IOC types faster."
                    ),
                },
                {
                    "Metric": "False-positive rate",
                    "How analytics improve it": (
                        "Manual validation of broad keyword matches such as card, pay, and ing helps identify "
                        "which filters are too broad and should be tuned."
                    ),
                },
            ]
        )
    )

    st.markdown("### Validation and Error Analysis")
    st.write(
        "Exact IOC overlap is treated as high-confidence correlation. Group/family matching is lower confidence "
        "because ransomware group names and malware-family labels can use aliases. In the current local ThreatFox "
        "subset, no exact IOC or group-family matches were found, which suggests the available ThreatFox data may "
        "cover malware families such as botnets rather than the ransomware groups observed in the finance victim set."
    )

    st.markdown("#### Assumptions")
    st.table(
        pd.DataFrame([
            {
                "Assumption": "Group name normalization resolves aliases correctly",
                "Applies To": "Event Correlation",
                "Risk if Wrong": "Missed cross-source matches; groups counted separately",
            },
            {
                "Assumption": "Phishing URLs follow Latin-script / English patterns",
                "Applies To": "Text Mining",
                "Risk if Wrong": "Non-ASCII or IDN homograph URLs evade keyword matching",
            },
            {
                "Assumption": "URL feature vectors are roughly spherical for K-Means",
                "Applies To": "K-Means Clustering",
                "Risk if Wrong": "Elongated clusters produce low silhouette scores and poor separation",
            },
            {
                "Assumption": "ThreatFox local subset is representative of finance-sector threats",
                "Applies To": "Event Correlation",
                "Risk if Wrong": "Zero overlap counts do not reflect true absence of shared IOCs",
            },
        ])
    )

    st.markdown("#### Limitations")
    st.table(
        pd.DataFrame([
            {
                "Limitation": "ThreatFox subset covers botnets/malware families, not finance ransomware groups",
                "Impact": "Exact IOC overlap and group-family match counts are currently zero",
            },
            {
                "Limitation": "Keyword lists (banking, suspicious, brand) are static",
                "Impact": "Novel phishing vocabulary introduced after list creation is missed",
            },
            {
                "Limitation": "K-Means requires a pre-chosen k; no ground-truth cluster labels exist",
                "Impact": "Optimal k is estimated via silhouette/Davies-Bouldin, not verified externally",
            },
            {
                "Limitation": "Ransomware.live data is scraped and may contain inconsistent group naming",
                "Impact": "Some alias normalization may fail for lesser-known groups",
            },
        ])
    )

    st.markdown("#### Error Sources")
    st.table(
        pd.DataFrame([
            {
                "Error Source": "False positives in keyword matching",
                "Example": "Terms like 'pay', 'card', 'ing' appear in legitimate banking URLs",
                "Mitigation": "Tune keyword lists; add whitelist for known-good domains",
            },
            {
                "Error Source": "Fuzzy group/family matching misses",
                "Example": "Lesser-known groups not represented in ThreatFox alias fields",
                "Mitigation": "Expand alias table; incorporate MISP galaxy cluster mappings",
            },
            {
                "Error Source": "IOC formatting inconsistencies",
                "Example": "Trailing slash, protocol prefix, or case differences in URLs",
                "Mitigation": "Normalize all indicators to lowercase, strip trailing slashes pre-join",
            },
            {
                "Error Source": "Temporal mismatch between data sources",
                "Example": "Ransomware.live victims dated 2024 vs. ThreatFox IOCs from 2022",
                "Mitigation": "Filter by recency; weight recent IOCs more heavily in risk scoring",
            },
        ])
    )

    st.markdown("#### Validation Method")
    st.write(
        "Hold-Out Spot-Check: Manually review the top 10–15 highest-risk ransomware groups and the top 20 TF-IDF "
            "terms. Confirm that groups correspond to known finance-targeting actors (e.g., LockBit, "
            "BlackCat) and that top keywords match verified phishing vocabulary."
    )