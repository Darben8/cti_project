"""Analytical approaches for ransomware event correlation."""

from __future__ import annotations

import math
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
    "Ransomware event correlation connecting finance-sector victims, ransomware groups, "
    "IOCs, IOC types, TTPs, and ThreatFox intelligence."
)


@st.cache_data
def load_csv(name: str) -> pd.DataFrame:
    path = CORRELATION_DIR / name
    if not path.exists():
        return pd.DataFrame()
    return pd.read_csv(path)


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


with st.sidebar:
    st.header("Analytics Controls")
    top_n = st.slider("Top ransomware groups", min_value=5, max_value=30, value=10, step=1)
    min_victims = st.slider("Minimum victim count", min_value=0, max_value=100, value=0, step=1)
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
top_groups = filtered_groups.sort_values("victim_count", ascending=False).head(top_n)
top_group_keys = set(top_groups["group_norm"])

metric_cols = st.columns(5)
metric_cols[0].metric("Finance Victims", f"{int(group_summary['victim_count'].sum()):,}")
metric_cols[1].metric("Ransomware Groups", f"{group_summary['group_norm'].nunique():,}")
metric_cols[2].metric("Ransomware.live IOCs", f"{int(group_summary['ioc_count'].sum()):,}")
metric_cols[3].metric("ThreatFox Matches", f"{int(group_summary['threatfox_ioc_count'].sum()):,}")
metric_cols[4].metric("Cross-Source IOC Matches", f"{int(group_summary['cross_source_matches'].sum()):,}")

st.markdown("### Approach 1: Ransomware Event Correlation")
st.write(
    "This analysis aggregates finance-sector ransomware victims by group, enriches those groups "
    "with ransomware.live IOCs and TTPs, then checks whether the same indicators or malware-family "
    "labels appear in ThreatFox."
)

left, right = st.columns([1.2, 1])

with left:
    fig_groups = px.bar(
        top_groups.sort_values("victim_count"),
        x="victim_count",
        y="display_group",
        orientation="h",
        color="risk_score",
        color_continuous_scale="OrRd",
        title="Top Ransomware Groups by Finance Victim Count",
        labels={
            "victim_count": "Finance Victims",
            "display_group": "Ransomware Group",
            "risk_score": "Risk Score",
        },
    )
    st.plotly_chart(fig_groups, use_container_width=True)

with right:
    overlap_plot = source_overlap.copy()
    if overlap_plot.empty:
        overlap_plot = pd.DataFrame(
            {"metric": ["exact_cross_source_matches"], "value": [0]}
        )
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

    edge_x = []
    edge_y = []
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

st.markdown("### Validation and Error Analysis")
st.write(
    "Exact IOC overlap is treated as high-confidence correlation. Group/family matching is lower "
    "confidence because ransomware group names and malware-family labels can use aliases. In the "
    "current local ThreatFox subset, no exact IOC or group-family matches were found, which suggests "
    "the available ThreatFox data may cover malware families such as botnets rather than the ransomware "
    "groups observed in the finance victim set."
)

if show_table:
    st.markdown("### Supporting Tables")
    st.subheader("Group Risk Summary")
    st.dataframe(group_summary, use_container_width=True, hide_index=True)
    st.subheader("Exact IOC Overlap")
    st.dataframe(exact_ioc_overlap, use_container_width=True, hide_index=True)
    st.subheader("Group / ThreatFox Family Matches")
    st.dataframe(group_family_matches, use_container_width=True, hide_index=True)
