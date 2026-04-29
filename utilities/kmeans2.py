import os
import warnings

import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.cluster import KMeans
from sklearn.metrics import (
    adjusted_rand_score,
    calinski_harabasz_score,
    davies_bouldin_score,
    silhouette_score,
)
from sklearn.preprocessing import LabelEncoder, StandardScaler

matplotlib.use("Agg")
warnings.filterwarnings("ignore")


DATA_PATH = "data/filtered_iocs_threatfox.csv"
OUTPUT_DIR = os.path.join("data", "kmeans_validation")
METRICS_CSV = os.path.join(OUTPUT_DIR, "kmeans_validation_metrics.csv")
VALIDATION_PLOT = os.path.join(OUTPUT_DIR, "kmeans_validation_plot.png")
CLUSTER_CHART = os.path.join(OUTPUT_DIR, "malware_kmeans_chart.png")
ENRICHED_CSV = os.path.join(OUTPUT_DIR, "iocs_with_clusters.csv")


def load_and_prepare_data() -> tuple[pd.DataFrame, np.ndarray, np.ndarray, list[str]]:
    df = pd.read_csv(DATA_PATH)
    print(f"Dataset shape: {df.shape}")
    print(f"\nMalware distribution:\n{df['malware_printable'].value_counts()}")

    le_ioc = LabelEncoder()
    le_ttype = LabelEncoder()
    le_mal = LabelEncoder()

    df["ioc_type_enc"] = le_ioc.fit_transform(df["ioc_type"])
    df["threat_type_enc"] = le_ttype.fit_transform(df["threat_type"])
    df["malware_enc"] = le_mal.fit_transform(df["malware_printable"])
    df["is_compromised_int"] = df["is_compromised"].astype(int)
    df["confidence_filled"] = df["confidence_level"].fillna(df["confidence_level"].median())

    df["tag_count"] = df["tags"].fillna("").apply(lambda x: len(x.split(",")) if x else 0)
    df["has_c2"] = df["tags"].fillna("").str.lower().str.contains("c2").astype(int)
    df["has_censys"] = df["tags"].fillna("").str.lower().str.contains("censys").astype(int)

    df["ioc_len"] = df["ioc_value"].astype(str).apply(len)
    df["ioc_has_dot"] = df["ioc_value"].astype(str).str.contains(r"\.").astype(int)
    df["ioc_has_colon"] = df["ioc_value"].astype(str).str.contains(":").astype(int)

    df["first_seen_dt"] = pd.to_datetime(df["first_seen_utc"], errors="coerce")
    df["last_seen_dt"] = pd.to_datetime(df["last_seen_utc"], errors="coerce")
    df["active_days"] = (df["last_seen_dt"] - df["first_seen_dt"]).dt.days.fillna(0)

    feature_cols = [
        "ioc_type_enc",
        "threat_type_enc",
        "confidence_filled",
        "is_compromised_int",
        "tag_count",
        "has_c2",
        "has_censys",
        "ioc_len",
        "ioc_has_dot",
        "ioc_has_colon",
        "active_days",
    ]

    X = df[feature_cols].values
    y_true = df["malware_enc"].values
    X_scaled = StandardScaler().fit_transform(X)

    print(f"\nFeatures used ({len(feature_cols)}): {feature_cols}")
    return df, X_scaled, y_true, feature_cols


def evaluate_candidate_k(X_scaled: np.ndarray, candidate_ks: list[int]) -> pd.DataFrame:
    rows: list[dict[str, float | int]] = []

    dense_matrix = np.asarray(X_scaled)
    for k in candidate_ks:
        model = KMeans(n_clusters=k, random_state=42, n_init=20)
        labels = model.fit_predict(X_scaled)
        rows.append(
            {
                "k": k,
                "silhouette_score": silhouette_score(X_scaled, labels),
                "davies_bouldin_score": davies_bouldin_score(dense_matrix, labels),
                "calinski_harabasz_score": calinski_harabasz_score(dense_matrix, labels),
                "inertia": model.inertia_,
            }
        )

    metrics_df = pd.DataFrame(rows).sort_values("k").reset_index(drop=True)
    metrics_df["inertia_improvement"] = metrics_df["inertia"].shift(1) - metrics_df["inertia"]
    metrics_df["inertia_improvement_pct"] = (
        metrics_df["inertia_improvement"] / metrics_df["inertia"].shift(1) * 100
    )
    return metrics_df


def detect_elbow_k(metrics_df: pd.DataFrame) -> int:
    points = metrics_df[["k", "inertia"]].to_numpy(dtype=float)
    if len(points) < 3:
        return int(metrics_df.loc[metrics_df["silhouette_score"].idxmax(), "k"])

    start = points[0]
    end = points[-1]
    line = end - start
    line_norm = np.linalg.norm(line)
    if line_norm == 0:
        return int(metrics_df.loc[metrics_df["silhouette_score"].idxmax(), "k"])

    distances = []
    for point in points:
        distance = np.abs(np.cross(line, point - start)) / line_norm
        distances.append(float(distance))

    elbow_index = int(np.argmax(distances))
    return int(metrics_df.iloc[elbow_index]["k"])


def choose_final_k(metrics_df: pd.DataFrame) -> tuple[int, int, list[int]]:
    elbow_k = detect_elbow_k(metrics_df)
    plausible_ks = [
        int(k)
        for k in metrics_df["k"].tolist()
        if abs(int(k) - elbow_k) <= 1
    ]
    plausible_df = metrics_df[metrics_df["k"].isin(plausible_ks)].copy()
    k_final = int(plausible_df.loc[plausible_df["silhouette_score"].idxmax(), "k"])
    return k_final, elbow_k, plausible_ks


def save_validation_plot(metrics_df: pd.DataFrame, elbow_k: int, k_final: int) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.8))
    fig.patch.set_facecolor("#0d1117")

    for ax in axes:
        ax.set_facecolor("#161b22")
        ax.tick_params(colors="#8b949e")
        for spine in ax.spines.values():
            spine.set_edgecolor("#30363d")
        ax.xaxis.label.set_color("#8b949e")
        ax.yaxis.label.set_color("#8b949e")
        ax.title.set_color("white")

    axes[0].plot(metrics_df["k"], metrics_df["inertia"], marker="o", color="#58a6ff", linewidth=2)
    axes[0].axvline(elbow_k, color="#f2cc60", linestyle="--", linewidth=1.5, label=f"Elbow k={elbow_k}")
    axes[0].axvline(k_final, color="#3fb950", linestyle=":", linewidth=2, label=f"Final k={k_final}")
    axes[0].set_title("Elbow Curve")
    axes[0].set_xlabel("k")
    axes[0].set_ylabel("Inertia")
    axes[0].legend(facecolor="#161b22", edgecolor="#30363d", labelcolor="white")

    axes[1].plot(
        metrics_df["k"],
        metrics_df["silhouette_score"],
        marker="o",
        color="#ff7b72",
        linewidth=2,
    )
    axes[1].axvline(elbow_k, color="#f2cc60", linestyle="--", linewidth=1.5, label=f"Elbow k={elbow_k}")
    axes[1].axvline(k_final, color="#3fb950", linestyle=":", linewidth=2, label=f"Final k={k_final}")
    axes[1].set_title("Silhouette Sweep")
    axes[1].set_xlabel("k")
    axes[1].set_ylabel("Silhouette Score")
    axes[1].legend(facecolor="#161b22", edgecolor="#30363d", labelcolor="white")

    plt.tight_layout()
    plt.savefig(VALIDATION_PLOT, dpi=150, bbox_inches="tight", facecolor="#0d1117")
    plt.close(fig)
    print(f"\nValidation plot saved to: {VALIDATION_PLOT}")


def build_cluster_chart(df: pd.DataFrame) -> None:
    cluster_ids = sorted(df["cluster"].unique())
    palette_cluster = dict(zip(cluster_ids, sns.color_palette("Set2", len(cluster_ids))))

    fig, ax = plt.subplots(figsize=(8, 5))
    fig.patch.set_facecolor("#0d1117")
    ax.set_facecolor("#161b22")
    ax.set_title("Records per Cluster", color="white", fontsize=13, fontweight="bold", pad=10)
    ax.tick_params(colors="#8b949e")
    for spine in ax.spines.values():
        spine.set_edgecolor("#30363d")
    ax.xaxis.label.set_color("#8b949e")
    ax.yaxis.label.set_color("#8b949e")

    counts = df["cluster"].value_counts().sort_index()
    colors_bar = [palette_cluster[c] for c in counts.index]
    bars = ax.bar(
        counts.index.astype(str),
        counts.values,
        color=colors_bar,
        edgecolor="#30363d",
        linewidth=0.5,
    )
    for bar, value in zip(bars, counts.values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 5,
            str(value),
            ha="center",
            va="bottom",
            color="white",
            fontsize=10,
        )

    ax.set_xlabel("Cluster ID")
    ax.set_ylabel("Count")
    plt.tight_layout()
    plt.savefig(CLUSTER_CHART, dpi=150, bbox_inches="tight", facecolor="#0d1117")
    plt.close(fig)
    print(f"Cluster chart saved to: {CLUSTER_CHART}")


def print_cluster_summary(df: pd.DataFrame) -> None:
    print("\nCluster -> dominant malware mapping:")
    cluster_malware = df.groupby("cluster")["malware_printable"].agg(lambda s: s.value_counts().idxmax())
    print(cluster_malware.to_string())

    print("\nCluster Summary")
    summary = (
        df.groupby("cluster")
        .agg(
            count=("ioc_id", "count"),
            dominant_malware=("malware_printable", lambda s: s.value_counts().idxmax()),
            purity=("malware_printable", lambda s: s.value_counts().max() / len(s)),
            avg_confidence=("confidence_filled", "mean"),
        )
        .round(3)
    )
    print(summary.to_string())


def main() -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    df, X_scaled, y_true, _feature_cols = load_and_prepare_data()

    max_candidate_k = min(10, len(df) - 1)
    candidate_ks = list(range(2, max_candidate_k + 1))
    if not candidate_ks:
        raise ValueError("Not enough rows to evaluate K-Means with k >= 2.")

    print("\nEvaluating candidate k values:")
    print(candidate_ks)

    metrics_df = evaluate_candidate_k(X_scaled, candidate_ks)
    elbow_k = detect_elbow_k(metrics_df)
    k_final, _elbow_k, plausible_ks = choose_final_k(metrics_df)

    metrics_df["elbow_plausible"] = metrics_df["k"].isin(plausible_ks)
    metrics_df["selected_as_final"] = metrics_df["k"] == k_final
    metrics_df.to_csv(METRICS_CSV, index=False)

    print("\nK comparison table:")
    print(metrics_df.to_string(index=False, float_format=lambda x: f"{x:.4f}"))

    print("\nChoose k logic:")
    print(
        f"  Elbow heuristic identified k={elbow_k}. "
        f"Elbow-plausible values were defined as k within +/-1 of the elbow: {plausible_ks}."
    )
    print(
        f"  Final choice: k={k_final}, selected as the best silhouette score among elbow-plausible values."
    )
    print(f"  Metrics CSV saved to: {METRICS_CSV}")

    save_validation_plot(metrics_df, elbow_k=elbow_k, k_final=k_final)

    km_final = KMeans(n_clusters=k_final, random_state=42, n_init=20)
    df["cluster"] = km_final.fit_predict(X_scaled)

    sil_final = silhouette_score(X_scaled, df["cluster"])
    ari_final = adjusted_rand_score(y_true, df["cluster"])

    print(f"\nFinal KMeans (k={k_final})")
    print(f"  Silhouette Score      : {sil_final:.4f}")
    print(f"  Adjusted Rand Index   : {ari_final:.4f}  (external check against known labels)")
    print("  Note: ARI is reported only after unsupervised k-selection and is not used to choose k.")

    build_cluster_chart(df)

    out_cols = list(df.columns[:15]) + ["cluster"]
    df[out_cols].to_csv(ENRICHED_CSV, index=False)
    print(f"Enriched CSV saved to: {ENRICHED_CSV}")

    print_cluster_summary(df)


if __name__ == "__main__":
    main()
