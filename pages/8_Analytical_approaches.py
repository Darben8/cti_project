"""Interactive analytical approaches and methodology justification."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CORRELATION_DIR = PROJECT_ROOT / "data" / "ransomware_event_correlation"

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
    return pd.read_csv(path)


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


group_summary = load_csv("group_risk_summary.csv")
group_ioc_types = load_csv("group_ioc_type_counts.csv")
source_overlap = load_csv("source_overlap_summary.csv")
nodes = load_csv("network_nodes.csv")
edges = load_csv("network_edges.csv")
group_network_metrics = load_csv("group_network_metrics.csv")
exact_ioc_overlap = load_csv("exact_ioc_overlap.csv")
group_family_matches = load_csv("group_family_matches.csv")

if group_summary.empty:
    st.warning(
        "Correlation outputs were not found. Run `python utilities\\ransomware_event_correlation.py` first."
    )
    st.stop()


interactive_tab, justification_tab = st.tabs(
    ["Interactive Analytics Panel", "Approach Justification"]
)


with st.sidebar:
    st.header("Analytics Controls")
    top_n = st.slider("Top ransomware groups", min_value=5, max_value=30, value=10, step=1)
    min_victims = st.slider("Minimum victim count", min_value=0, max_value=100, value=0, step=1)
    sort_metric = st.selectbox(
        "Sort group summary by",
        ["victim_count", "risk_score", "ioc_count", "recency_days", "ttp_count"],
        index=0,
    )
    network_view = st.selectbox(
        "Network view",
        [
            "Group -> IOC type -> TTP",
            "Group -> Country -> IOC",
            "Group -> Victim",
        ],
    )
    show_table = st.checkbox("Show supporting tables", value=False)


filtered_groups = group_summary[group_summary["victim_count"] >= min_victims].copy()
ascending = sort_metric == "recency_days"
top_groups = filtered_groups.sort_values(sort_metric, ascending=ascending).head(top_n)
top_group_keys = set(top_groups["group_norm"])


with interactive_tab:
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
        if overlap_plot.empty:
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
    heatmap_data = group_ioc_types[group_ioc_types["group_norm"].isin(top_group_keys)].copy()
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
    if not group_network_metrics.empty:
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
        "cover malware families such as botnets rather than the ransomware groups observed in the finance victim set. "
        "A simple validation method is to manually spot-check high-risk groups, top URL keywords, and unmatched "
        "ThreatFox malware-family labels."
    )
