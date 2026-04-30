import os
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns
import warnings
warnings.filterwarnings('ignore')

from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.metrics import (
    silhouette_score,
    adjusted_rand_score,
    classification_report,
    confusion_matrix,
)

# ── 1. Load Data ───────────────────────────────────────────────────────────────
df = pd.read_csv('data/filtered_iocs_threatfox.csv')
print(f"Dataset shape: {df.shape}")
print(f"\nMalware distribution:\n{df['malware_printable'].value_counts()}")

# ── 2. Feature Engineering ────────────────────────────────────────────────────
le_ioc   = LabelEncoder()
le_ttype = LabelEncoder()
le_mal   = LabelEncoder()

df['ioc_type_enc']    = le_ioc.fit_transform(df['ioc_type'])
df['threat_type_enc'] = le_ttype.fit_transform(df['threat_type'])
df['malware_enc']     = le_mal.fit_transform(df['malware_printable'])   # ground truth
df['is_compromised_int'] = df['is_compromised'].astype(int)
df['confidence_filled']  = df['confidence_level'].fillna(df['confidence_level'].median())

# Tag-based features
df['tag_count']      = df['tags'].fillna('').apply(lambda x: len(x.split(',')) if x else 0)
df['has_c2']         = df['tags'].fillna('').str.lower().str.contains('c2').astype(int)
df['has_censys']     = df['tags'].fillna('').str.lower().str.contains('censys').astype(int)

# IOC-value features
df['ioc_len']        = df['ioc_value'].astype(str).apply(len)
df['ioc_has_dot']    = df['ioc_value'].astype(str).str.contains(r'\.').astype(int)
df['ioc_has_colon']  = df['ioc_value'].astype(str).str.contains(':').astype(int)

# Temporal features
df['first_seen_dt']  = pd.to_datetime(df['first_seen_utc'], errors='coerce')
df['last_seen_dt']   = pd.to_datetime(df['last_seen_utc'],  errors='coerce')
df['active_days']    = (df['last_seen_dt'] - df['first_seen_dt']).dt.days.fillna(0)

FEATURE_COLS = [
    'ioc_type_enc', 'threat_type_enc', 'confidence_filled',
    'is_compromised_int', 'tag_count', 'has_c2', 'has_censys',
    'ioc_len', 'ioc_has_dot', 'ioc_has_colon', 'active_days',
]

X = df[FEATURE_COLS].values
y_true = df['malware_enc'].values          # ground-truth labels (for evaluation only)
n_malware = df['malware_printable'].nunique()

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

print(f"\nFeatures used ({len(FEATURE_COLS)}): {FEATURE_COLS}")

# ── 3. Choose k = number of unique malware families ──────────────────────────

# ── 4. Train final model with k = n_malware ───────────────────────────────────
k_final = n_malware
km_final = KMeans(n_clusters=k_final, random_state=42, n_init=20)
km_final.fit(X_scaled)
df['cluster'] = km_final.labels_

sil_final = silhouette_score(X_scaled, km_final.labels_)
ari_final  = adjusted_rand_score(y_true, km_final.labels_)

print(f"\n── Final KMeans (k={k_final}) ──────────────────────")
print(f"  Silhouette Score : {sil_final:.4f}  (higher is better, max=1)")
print(f"  Adjusted Rand Index: {ari_final:.4f}  (1=perfect match to true labels)")
print(f"\nCluster → Malware mapping:")
cluster_malware = (
    df.groupby('cluster')['malware_printable']
      .agg(lambda s: s.value_counts().idxmax())
)
print(cluster_malware.to_string())



# ── 6. Build figure – Panel F only ────────────────────────────────────────────
CLUSTER_IDS   = sorted(df['cluster'].unique())
palette_cluster = dict(zip(CLUSTER_IDS, sns.color_palette("Set2", len(CLUSTER_IDS))))

fig, ax = plt.subplots(figsize=(8, 5))
fig.patch.set_facecolor('#0d1117')
ax.set_facecolor('#161b22')
ax.set_title("Records per Cluster", color='white', fontsize=13, fontweight='bold', pad=10)
ax.tick_params(colors='#8b949e')
for sp in ax.spines.values():
    sp.set_edgecolor('#30363d')
ax.xaxis.label.set_color('#8b949e')
ax.yaxis.label.set_color('#8b949e')

counts = df['cluster'].value_counts().sort_index()
colors_bar = [palette_cluster[c] for c in counts.index]
bars = ax.bar(counts.index.astype(str), counts.values, color=colors_bar,
              edgecolor='#30363d', linewidth=0.5)
for bar, val in zip(bars, counts.values):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 5,
            str(val), ha='center', va='bottom', color='white', fontsize=10)
ax.set_xlabel("Cluster ID")
ax.set_ylabel("Count")

plt.tight_layout()
plt.savefig(
    os.path.expanduser('~/Downloads/malware_kmeans_chart.png'),
    dpi=150, bbox_inches='tight', facecolor='#0d1117')
print("\nPanel F saved.")

# ── 7. Save enriched CSV ───────────────────────────────────────────────────────
out_cols = list(df.columns[:15]) + ['cluster']
df[out_cols].to_csv(
    os.path.expanduser('~/Downloads/iocs_with_clusters.csv'),
    index=False)
print("Enriched CSV saved.")

# ── 8. Print cluster summary ───────────────────────────────────────────────────
print("\n── Cluster Summary ─────────────────────────────────────────────────────────")
summary = df.groupby('cluster').agg(
    count=('ioc_id', 'count'),
    dominant_malware=('malware_printable', lambda s: s.value_counts().idxmax()),
    purity=('malware_printable', lambda s: s.value_counts().max() / len(s)),
    avg_confidence=('confidence_filled', 'mean'),
).round(3)
print(summary.to_string())
