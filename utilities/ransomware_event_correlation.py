"""Correlate finance ransomware victims, ransomware.live IOCs, and ThreatFox IOCs."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
DEFAULT_OUTPUT_DIR = DATA_DIR / "ransomware_event_correlation"

DEFAULT_VICTIMS = DATA_DIR / "finance_victims.csv"
DEFAULT_RANSOMWARE_IOCS = DATA_DIR / "finance_group_iocs.csv"
DEFAULT_THREATFOX = DATA_DIR / "filtered_iocs_threatfox.csv"

GROUP_ALIASES = {
    "3am": "threeam",
    "3amransomware": "threeam",
    "agenda": "qilin",
    "blackcat": "alphv",
    "blackbasta": "blackbasta",
    "black basta": "blackbasta",
    "cl0p": "clop",
    "lockbit": "lockbit3",
    "lockbit30": "lockbit3",
    "lockbit3": "lockbit3",
    "lockbitgreen": "lockbit3",
    "qilin": "qilin",
    "royal": "blackSuit",
    "royalransomware": "blacksuit",
    "vice society": "vicesociety",
}

PUNCTUATION_PATTERN = re.compile(r"[^a-z0-9]+")
TECHNIQUE_PATTERN = re.compile(r"\bT[A0-9]{4}(?:\.\d{3})?\b", re.IGNORECASE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Connect finance-sector ransomware victims with ransomware.live IOCs, "
            "ThreatFox intelligence, group-level TTPs, and network metrics."
        )
    )
    parser.add_argument("--victims", type=Path, default=DEFAULT_VICTIMS)
    parser.add_argument("--ransomware-iocs", type=Path, default=DEFAULT_RANSOMWARE_IOCS)
    parser.add_argument("--threatfox", type=Path, default=DEFAULT_THREATFOX)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def normalize_entity(value: object) -> str:
    text = str(value or "").strip().lower()
    text = text.replace("&amp;", "and")
    text = PUNCTUATION_PATTERN.sub("", text)
    return GROUP_ALIASES.get(text, text)


def normalize_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower().rstrip(".")
        path = parsed.path.rstrip("/") if parsed.path != "/" else parsed.path
        return urlunsplit((scheme, netloc, path, parsed.query, ""))
    except Exception:
        return value.strip().lower().rstrip("/")


def normalize_indicator(value: object) -> str:
    text = str(value or "").strip()
    if not text or text.lower() in {"nan", "none"}:
        return ""
    if text.lower().startswith(("http://", "https://")):
        return normalize_url(text)
    return text.lower().strip().rstrip("/")


def split_terms(value: object) -> list[str]:
    if pd.isna(value):
        return []
    return [item.strip() for item in re.split(r"[;,|]", str(value)) if item.strip()]


def split_ttps(value: object) -> list[str]:
    if pd.isna(value):
        return []
    return sorted(set(TECHNIQUE_PATTERN.findall(str(value).upper())))


def first_non_empty(values: pd.Series) -> str:
    for value in values:
        if pd.notna(value) and str(value).strip():
            return str(value)
    return ""


def prepare_victims(path: Path) -> pd.DataFrame:
    victims = pd.read_csv(path)
    victims["group_norm"] = victims["group"].map(normalize_entity)
    victims["victim_date"] = pd.to_datetime(
        victims.get("attack_date", victims.get("discovered")),
        errors="coerce",
    )
    victims["country"] = victims["country"].fillna("Unknown").astype(str).str.strip()
    victims["victim_name"] = victims["victim_name"].fillna("Unknown victim").astype(str).str.strip()
    return victims[victims["group_norm"] != ""].copy()


def prepare_ransomware_iocs(path: Path) -> pd.DataFrame:
    iocs = pd.read_csv(path)
    iocs["group_norm"] = iocs["group"].map(normalize_entity)
    iocs["indicator_norm"] = iocs["indicator"].map(normalize_indicator)
    iocs["ioc_type"] = iocs["ioc_type"].fillna("unknown").astype(str).str.strip().str.lower()
    iocs["ttp_list"] = iocs["ttps"].map(split_ttps) if "ttps" in iocs else [[] for _ in range(len(iocs))]
    return iocs[(iocs["group_norm"] != "") & (iocs["indicator_norm"] != "")].copy()


def prepare_threatfox(path: Path) -> pd.DataFrame:
    threatfox = pd.read_csv(path)
    threatfox["indicator_norm"] = threatfox["ioc_value"].map(normalize_indicator)
    threatfox["ioc_type"] = threatfox["ioc_type"].fillna("unknown").astype(str).str.strip().str.lower()
    threatfox["malware_family"] = threatfox["malware_printable"].fillna("").astype(str).str.strip()
    threatfox["malware_norm"] = threatfox["malware_family"].map(normalize_entity)
    threatfox["fk_malware_norm"] = threatfox["fk_malware"].map(normalize_entity)
    threatfox["alias_norms"] = threatfox["malware_alias"].apply(
        lambda value: sorted({normalize_entity(item) for item in split_terms(value) if normalize_entity(item)})
    )
    threatfox["tag_norms"] = threatfox["tags"].apply(
        lambda value: sorted({normalize_entity(item) for item in split_terms(value) if normalize_entity(item)})
    )
    threatfox["first_seen_dt"] = pd.to_datetime(threatfox["first_seen_utc"], errors="coerce")
    return threatfox[threatfox["indicator_norm"] != ""].copy()


def build_exact_ioc_overlap(ransomware_iocs: pd.DataFrame, threatfox: pd.DataFrame) -> pd.DataFrame:
    overlap = ransomware_iocs.merge(
        threatfox,
        on="indicator_norm",
        how="inner",
        suffixes=("_ransomware_live", "_threatfox"),
    )
    if overlap.empty:
        return overlap
    overlap["source_overlap"] = "ransomware.live + ThreatFox"
    overlap["match_type"] = "exact_indicator"
    return overlap


def threatfox_group_candidates(row: pd.Series) -> set[str]:
    candidates = {
        row.get("malware_norm", ""),
        row.get("fk_malware_norm", ""),
    }
    candidates.update(row.get("alias_norms", []) or [])
    candidates.update(row.get("tag_norms", []) or [])
    return {candidate for candidate in candidates if candidate}


def build_group_family_matches(groups: set[str], threatfox: pd.DataFrame) -> pd.DataFrame:
    records = []
    for _, row in threatfox.iterrows():
        candidates = threatfox_group_candidates(row)
        matched_groups = groups.intersection(candidates)
        for group in matched_groups:
            records.append(
                {
                    "group_norm": group,
                    "ioc_value": row.get("ioc_value"),
                    "indicator_norm": row.get("indicator_norm"),
                    "ioc_type": row.get("ioc_type"),
                    "malware_family": row.get("malware_family"),
                    "threat_type": row.get("threat_type"),
                    "confidence_level": row.get("confidence_level"),
                    "match_type": "group_or_family",
                }
            )
    return pd.DataFrame(records).drop_duplicates() if records else pd.DataFrame()


def aggregate_group_summary(
    victims: pd.DataFrame,
    ransomware_iocs: pd.DataFrame,
    threatfox_matches: pd.DataFrame,
    exact_overlap: pd.DataFrame,
) -> pd.DataFrame:
    groups = sorted(set(victims["group_norm"]) | set(ransomware_iocs["group_norm"]))
    rows = []

    for group in groups:
        group_victims = victims[victims["group_norm"] == group]
        group_iocs = ransomware_iocs[ransomware_iocs["group_norm"] == group]
        group_tf = threatfox_matches[threatfox_matches["group_norm"] == group] if not threatfox_matches.empty else pd.DataFrame()
        group_overlap = exact_overlap[exact_overlap["group_norm"] == group] if not exact_overlap.empty else pd.DataFrame()

        ttps = []
        for value in group_iocs.get("ttp_list", []):
            ttps.extend(value)
        ttp_counts = Counter(ttps)

        first_date = group_victims["victim_date"].min()
        last_date = group_victims["victim_date"].max()
        recency_days = (
            (pd.Timestamp.utcnow().tz_localize(None) - last_date).days
            if pd.notna(last_date)
            else None
        )

        rows.append(
            {
                "group_norm": group,
                "display_group": first_non_empty(group_victims.get("group", pd.Series(dtype=str)))
                or first_non_empty(group_iocs.get("group", pd.Series(dtype=str)))
                or group,
                "victim_count": group_victims["victim_name"].nunique(),
                "countries_affected": group_victims["country"].nunique(),
                "countries_targeted": "; ".join(sorted(group_victims["country"].dropna().unique())),
                "first_victim_date": first_date,
                "last_victim_date": last_date,
                "recency_days": recency_days,
                "ioc_count": group_iocs["indicator_norm"].nunique(),
                "ioc_types_observed": "; ".join(sorted(group_iocs["ioc_type"].dropna().unique())),
                "threatfox_ioc_count": group_tf["indicator_norm"].nunique() if not group_tf.empty else 0,
                "cross_source_matches": group_overlap["indicator_norm"].nunique() if not group_overlap.empty else 0,
                "ttp_count": len(ttp_counts),
                "most_common_ttps": "; ".join([ttp for ttp, _ in ttp_counts.most_common(10)]),
            }
        )

    summary = pd.DataFrame(rows)
    if summary.empty:
        return summary

    summary["risk_score"] = (
        summary["victim_count"].rank(pct=True).fillna(0) * 35
        + summary["ioc_count"].rank(pct=True).fillna(0) * 20
        + summary["threatfox_ioc_count"].rank(pct=True).fillna(0) * 20
        + summary["cross_source_matches"].rank(pct=True).fillna(0) * 15
        + summary["ttp_count"].rank(pct=True).fillna(0) * 10
    ).round(2)
    return summary.sort_values(["risk_score", "victim_count"], ascending=False)


def add_edge(edges: list[dict[str, object]], source: str, target: str, relation: str, weight: int = 1) -> None:
    if source and target and source != target:
        edges.append({"source": source, "target": target, "relation": relation, "weight": weight})


def build_network(
    victims: pd.DataFrame,
    ransomware_iocs: pd.DataFrame,
    threatfox_matches: pd.DataFrame,
    group_summary: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    edges: list[dict[str, object]] = []

    for _, row in victims.iterrows():
        group = f"group:{row['group_norm']}"
        add_edge(edges, group, f"victim:{row['victim_name']}", "group_to_victim")
        add_edge(edges, group, f"country:{row['country']}", "group_to_country")

    for _, row in ransomware_iocs.iterrows():
        group = f"group:{row['group_norm']}"
        indicator = f"ioc:{row['indicator_norm']}"
        add_edge(edges, group, indicator, "group_to_ioc")
        add_edge(edges, indicator, f"ioc_type:{row['ioc_type']}", "ioc_to_type")
        for ttp in row.get("ttp_list", []):
            add_edge(edges, group, f"ttp:{ttp}", "group_to_ttp")

    if not threatfox_matches.empty:
        for _, row in threatfox_matches.iterrows():
            indicator = f"ioc:{row['indicator_norm']}"
            family = f"malware:{row.get('malware_family') or 'unknown'}"
            add_edge(edges, indicator, family, "ioc_to_threatfox_malware")

    edges_df = pd.DataFrame(edges).drop_duplicates()
    adjacency: dict[str, set[str]] = {}
    for _, row in edges_df.iterrows():
        adjacency.setdefault(row["source"], set()).add(row["target"])
        adjacency.setdefault(row["target"], set()).add(row["source"])

    visited: set[str] = set()
    component_lookup: dict[str, int] = {}
    component_id = 0
    for start_node in adjacency:
        if start_node in visited:
            continue
        component_id += 1
        stack = [start_node]
        visited.add(start_node)
        while stack:
            node = stack.pop()
            component_lookup[node] = component_id
            for neighbor in adjacency.get(node, set()):
                if neighbor not in visited:
                    visited.add(neighbor)
                    stack.append(neighbor)

    node_count = len(adjacency)
    centrality_denominator = max(node_count - 1, 1)
    node_rows = []
    for node, neighbors in adjacency.items():
        node_type, _, label = node.partition(":")
        node_rows.append(
            {
                "node_id": node,
                "label": label,
                "node_type": node_type,
                "degree": len(neighbors),
                "degree_centrality": len(neighbors) / centrality_denominator,
                "component_id": component_lookup.get(node),
            }
        )
    nodes_df = pd.DataFrame(node_rows)

    group_metrics = nodes_df[nodes_df["node_type"] == "group"].copy()
    if not group_metrics.empty:
        group_metrics["group_norm"] = group_metrics["label"]
        group_metrics = group_metrics.merge(
            group_summary[["group_norm", "display_group", "risk_score", "victim_count", "ioc_count"]],
            on="group_norm",
            how="left",
        ).sort_values("degree_centrality", ascending=False)

    return nodes_df, edges_df, group_metrics


def save_outputs(output_dir: Path, outputs: dict[str, pd.DataFrame]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, df in outputs.items():
        df.to_csv(output_dir / f"{name}.csv", index=False)


def main() -> None:
    args = parse_args()

    victims = prepare_victims(args.victims)
    ransomware_iocs = prepare_ransomware_iocs(args.ransomware_iocs)
    threatfox = prepare_threatfox(args.threatfox)

    exact_overlap = build_exact_ioc_overlap(ransomware_iocs, threatfox)
    finance_groups = set(victims["group_norm"].dropna()) | set(ransomware_iocs["group_norm"].dropna())
    threatfox_matches = build_group_family_matches(finance_groups, threatfox)
    group_summary = aggregate_group_summary(victims, ransomware_iocs, threatfox_matches, exact_overlap)

    group_ioc_type_counts = (
        ransomware_iocs.groupby(["group_norm", "ioc_type"])
        .size()
        .reset_index(name="ioc_count")
        .merge(group_summary[["group_norm", "display_group"]], on="group_norm", how="left")
    )

    nodes_df, edges_df, group_network_metrics = build_network(
        victims,
        ransomware_iocs,
        threatfox_matches,
        group_summary,
    )

    source_overlap_summary = pd.DataFrame(
        [
            {
                "metric": "ransomware_live_iocs",
                "value": ransomware_iocs["indicator_norm"].nunique(),
            },
            {
                "metric": "threatfox_iocs",
                "value": threatfox["indicator_norm"].nunique(),
            },
            {
                "metric": "exact_cross_source_matches",
                "value": exact_overlap["indicator_norm"].nunique() if not exact_overlap.empty else 0,
            },
            {
                "metric": "group_family_threatfox_matches",
                "value": threatfox_matches["indicator_norm"].nunique() if not threatfox_matches.empty else 0,
            },
            {
                "metric": "network_components",
                "value": nodes_df["component_id"].nunique() if not nodes_df.empty else 0,
            },
        ]
    )

    save_outputs(
        args.output_dir,
        {
            "group_risk_summary": group_summary,
            "exact_ioc_overlap": exact_overlap,
            "group_family_matches": threatfox_matches,
            "group_ioc_type_counts": group_ioc_type_counts,
            "network_nodes": nodes_df,
            "network_edges": edges_df,
            "group_network_metrics": group_network_metrics,
            "source_overlap_summary": source_overlap_summary,
        },
    )

    print("Ransomware event correlation complete.")
    print(f"Finance victim records: {len(victims)}")
    print(f"Ransomware.live IOCs: {ransomware_iocs['indicator_norm'].nunique()}")
    print(f"ThreatFox IOCs: {threatfox['indicator_norm'].nunique()}")
    print(f"Exact cross-source IOC matches: {source_overlap_summary.loc[2, 'value']}")
    print(f"ThreatFox group/family matches: {source_overlap_summary.loc[3, 'value']}")
    print(f"Outputs saved to: {args.output_dir}")


if __name__ == "__main__":
    main()
