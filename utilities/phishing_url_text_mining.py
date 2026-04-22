"""Text mining and pattern analysis for banking/finance phishing URLs."""

from __future__ import annotations

import argparse
import math
import re
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

import numpy as np
import pandas as pd
import plotly.express as px
from sklearn.cluster import KMeans
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.metrics import calinski_harabasz_score, davies_bouldin_score, silhouette_score


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = PROJECT_ROOT / "data" / "verified_online_banking_finance.csv"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "data" / "phishing_url_text_mining"

SUSPICIOUS_KEYWORDS = {
    "account",
    "auth",
    "authenticate",
    "bank",
    "billing",
    "card",
    "client",
    "confirm",
    "credential",
    "customer",
    "login",
    "logon",
    "password",
    "payment",
    "portal",
    "recover",
    "secure",
    "security",
    "signin",
    "support",
    "update",
    "validate",
    "verification",
    "verify",
    "wallet",
}

FINANCE_KEYWORDS = {
    "amex",
    "bank",
    "banking",
    "banco",
    "capitalone",
    "card",
    "cashapp",
    "chase",
    "citi",
    "coinbase",
    "credit",
    "debit",
    "finance",
    "financial",
    "hsbc",
    "mastercard",
    "paypal",
    "payment",
    "santander",
    "visa",
    "wallet",
    "wellsfargo",
}

BRAND_KEYWORDS = {
    "abn",
    "absa",
    "amex",
    "barclays",
    "bbva",
    "binance",
    "bradesco",
    "capitalone",
    "chase",
    "citi",
    "citibank",
    "coinbase",
    "hsbc",
    "ing",
    "jpmorgan",
    "mastercard",
    "natwest",
    "paypal",
    "santander",
    "scotiabank",
    "unicredit",
    "visa",
    "wellsfargo",
}

SUSPICIOUS_TLDS = {
    "app",
    "biz",
    "cc",
    "click",
    "club",
    "cn",
    "cyou",
    "fit",
    "gq",
    "icu",
    "info",
    "live",
    "lol",
    "mom",
    "online",
    "pro",
    "rest",
    "ru",
    "sbs",
    "shop",
    "site",
    "space",
    "support",
    "tk",
    "top",
    "website",
    "win",
    "work",
    "xyz",
}

KEYWORDS_TO_TRACK = sorted(SUSPICIOUS_KEYWORDS | FINANCE_KEYWORDS | BRAND_KEYWORDS)
TOKEN_PATTERN = re.compile(r"[a-zA-Z0-9]+")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Extract phishing URL features, run TF-IDF and n-gram text mining, "
            "evaluate optional K-Means clusters, and save analysis outputs."
        )
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
        help=f"Input CSV path. Default: {DEFAULT_INPUT}",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Directory for CSV and HTML outputs. Default: {DEFAULT_OUTPUT_DIR}",
    )
    parser.add_argument(
        "--clusters",
        type=int,
        default=5,
        help="K-Means clusters for descriptive URL pattern grouping. Default: 5",
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=25,
        help="Number of top keywords, n-grams, and TLDs to save/plot. Default: 25",
    )
    return parser.parse_args()


def normalize_url(url: object) -> str:
    return str(url or "").strip()


def tokenize_text(value: str) -> list[str]:
    return [token.lower() for token in TOKEN_PATTERN.findall(value)]


def safe_parse_url(url: str):
    parsed = urlparse(url)
    if not parsed.netloc and "://" not in url:
        parsed = urlparse(f"http://{url}")
    return parsed


def get_domain_parts(domain: str) -> tuple[str, str, int]:
    cleaned = domain.lower().split("@")[-1].split(":")[0].strip(".")
    parts = [part for part in cleaned.split(".") if part]
    tld = parts[-1] if len(parts) >= 2 else ""
    subdomain_count = max(len(parts) - 2, 0)
    return cleaned, tld, subdomain_count


def count_keywords(text: str, keywords: set[str]) -> int:
    lowered = text.lower()
    return sum(1 for keyword in keywords if keyword in lowered)


def extract_url_text(parsed_url, domain: str) -> str:
    query_text = " ".join(f"{key} {value}" for key, value in parse_qsl(parsed_url.query, keep_blank_values=True))
    raw_text = " ".join(
        [
            domain.replace(".", " ").replace("-", " "),
            parsed_url.path.replace("/", " ").replace("-", " ").replace("_", " "),
            parsed_url.query.replace("&", " ").replace("=", " ").replace("-", " ").replace("_", " "),
            query_text,
        ]
    )
    return " ".join(tokenize_text(raw_text))


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, object]] = []

    for _, row in df.iterrows():
        url = normalize_url(row.get("url"))
        parsed = safe_parse_url(url)
        domain, tld, subdomain_count = get_domain_parts(parsed.netloc)
        url_text = extract_url_text(parsed, domain)
        full_search_text = f"{url.lower()} {url_text}"

        feature_row = row.to_dict()
        feature_row.update(
            {
                "domain": domain,
                "path": parsed.path,
                "query": parsed.query,
                "url_text": url_text,
                "url_length": len(url),
                "domain_length": len(domain),
                "num_dots": url.count("."),
                "num_hyphens": url.count("-"),
                "num_digits": sum(character.isdigit() for character in url),
                "path_depth": len([part for part in parsed.path.split("/") if part]),
                "query_string_length": len(parsed.query),
                "uses_https": int(parsed.scheme.lower() == "https"),
                "suspicious_keyword_count": count_keywords(full_search_text, SUSPICIOUS_KEYWORDS),
                "finance_keyword_count": count_keywords(full_search_text, FINANCE_KEYWORDS),
                "brand_keyword_count": count_keywords(full_search_text, BRAND_KEYWORDS),
                "tld": tld,
                "subdomain_count": subdomain_count,
                "contains_banking_keyword": int(count_keywords(full_search_text, FINANCE_KEYWORDS) > 0),
                "is_suspicious_tld": int(tld in SUSPICIOUS_TLDS),
            }
        )

        for keyword in KEYWORDS_TO_TRACK:
            feature_row[f"kw_{keyword}"] = int(keyword in full_search_text)

        rows.append(feature_row)

    return pd.DataFrame(rows)


def build_tfidf_summary(texts: pd.Series, top_n: int) -> tuple[pd.DataFrame, object]:
    vectorizer = TfidfVectorizer(
        max_features=500,
        min_df=2,
        ngram_range=(1, 2),
        token_pattern=r"(?u)\b[a-zA-Z][a-zA-Z0-9]{2,}\b",
    )
    matrix = vectorizer.fit_transform(texts.fillna(""))
    scores = np.asarray(matrix.mean(axis=0)).ravel()
    terms = np.array(vectorizer.get_feature_names_out())
    top_indices = scores.argsort()[::-1][:top_n]

    summary = pd.DataFrame(
        {
            "term": terms[top_indices],
            "mean_tfidf": scores[top_indices],
        }
    )
    return summary, matrix


def build_ngram_summary(texts: pd.Series, top_n: int) -> pd.DataFrame:
    vectorizer = CountVectorizer(
        max_features=1000,
        min_df=2,
        ngram_range=(2, 3),
        token_pattern=r"(?u)\b[a-zA-Z][a-zA-Z0-9]{2,}\b",
    )
    matrix = vectorizer.fit_transform(texts.fillna(""))
    counts = np.asarray(matrix.sum(axis=0)).ravel()
    terms = np.array(vectorizer.get_feature_names_out())
    top_indices = counts.argsort()[::-1][:top_n]

    return pd.DataFrame(
        {
            "ngram": terms[top_indices],
            "count": counts[top_indices],
        }
    )


def evaluate_kmeans(tfidf_matrix, requested_clusters: int) -> tuple[pd.DataFrame, np.ndarray | None]:
    row_count = tfidf_matrix.shape[0]
    if row_count < 3:
        return pd.DataFrame(), None

    max_clusters = min(requested_clusters, row_count - 1)
    if max_clusters < 2:
        return pd.DataFrame(), None

    kmeans = KMeans(n_clusters=max_clusters, random_state=42, n_init=10)
    labels = kmeans.fit_predict(tfidf_matrix)

    dense_matrix = tfidf_matrix.toarray()
    metrics = {
        "metric": [
            "kmeans_clusters",
            "silhouette_score",
            "davies_bouldin_score",
            "calinski_harabasz_score",
            "cluster_inertia",
        ],
        "value": [
            max_clusters,
            silhouette_score(tfidf_matrix, labels),
            davies_bouldin_score(dense_matrix, labels),
            calinski_harabasz_score(dense_matrix, labels),
            kmeans.inertia_,
        ],
        "interpretation": [
            "Number of descriptive URL-pattern clusters used.",
            "Higher is better; measures cluster separation and cohesion.",
            "Lower is better; measures average similarity between clusters.",
            "Higher is better; measures between-cluster separation versus within-cluster spread.",
            "Lower is tighter for a fixed k; not comparable across different k without an elbow test.",
        ],
    }
    return pd.DataFrame(metrics), labels


def build_operational_metrics(features_df: pd.DataFrame, tfidf_terms: pd.DataFrame) -> pd.DataFrame:
    total_urls = len(features_df)
    banking_keyword_pct = (
        features_df["contains_banking_keyword"].mean() * 100 if total_urls else math.nan
    )
    suspicious_tld_pct = features_df["is_suspicious_tld"].mean() * 100 if total_urls else math.nan
    https_pct = features_df["uses_https"].mean() * 100 if total_urls else math.nan

    return pd.DataFrame(
        [
            {
                "metric": "url_count",
                "value": total_urls,
                "interpretation": "Number of finance-focused PhishTank URLs analyzed.",
            },
            {
                "metric": "banking_keyword_url_pct",
                "value": banking_keyword_pct,
                "interpretation": "Percent of URLs containing at least one banking/finance keyword.",
            },
            {
                "metric": "suspicious_tld_url_pct",
                "value": suspicious_tld_pct,
                "interpretation": "Percent of URLs using a TLD commonly seen in abuse-heavy phishing infrastructure.",
            },
            {
                "metric": "https_url_pct",
                "value": https_pct,
                "interpretation": "Percent of URLs using HTTPS; phishing sites often use HTTPS to appear legitimate.",
            },
            {
                "metric": "tfidf_vocabulary_terms",
                "value": len(tfidf_terms),
                "interpretation": "Number of high-scoring descriptive URL terms exported for analyst review.",
            },
        ]
    )


def build_keyword_presence_summary(features_df: pd.DataFrame) -> pd.DataFrame:
    records = []
    for keyword in KEYWORDS_TO_TRACK:
        column = f"kw_{keyword}"
        if column not in features_df:
            continue
        url_count = int(features_df[column].sum())
        records.append(
            {
                "keyword": keyword,
                "url_count": url_count,
                "url_percent": (url_count / len(features_df) * 100) if len(features_df) else 0,
            }
        )
    return pd.DataFrame(records).sort_values("url_count", ascending=False)


def save_visualizations(
    output_dir: Path,
    top_keywords: pd.DataFrame,
    tld_summary: pd.DataFrame,
    features_df: pd.DataFrame,
    keyword_presence: pd.DataFrame,
    top_n: int,
) -> None:
    fig_keywords = px.bar(
        top_keywords.sort_values("mean_tfidf"),
        x="mean_tfidf",
        y="term",
        orientation="h",
        title="Top TF-IDF URL Keywords in Banking/Finance Phishing",
        labels={"mean_tfidf": "Mean TF-IDF Score", "term": "URL Token / Phrase"},
    )
    fig_keywords.write_html(output_dir / "top_url_keywords.html")

    fig_tlds = px.bar(
        tld_summary.head(top_n).sort_values("url_count"),
        x="url_count",
        y="tld",
        color="is_suspicious_tld",
        orientation="h",
        title="Most Common and Suspicious TLDs in Banking/Finance Phishing URLs",
        labels={"url_count": "URL Count", "tld": "Top-Level Domain", "is_suspicious_tld": "Suspicious TLD"},
    )
    fig_tlds.write_html(output_dir / "suspicious_tlds.html")

    fig_lengths = px.histogram(
        features_df,
        x="url_length",
        nbins=40,
        title="Banking/Finance Phishing URL Length Distribution",
        labels={"url_length": "URL Length"},
    )
    fig_lengths.write_html(output_dir / "url_length_distribution.html")

    banking_presence = keyword_presence[keyword_presence["keyword"].isin(FINANCE_KEYWORDS)].head(top_n)
    fig_keyword_presence = px.bar(
        banking_presence.sort_values("url_percent"),
        x="url_percent",
        y="keyword",
        orientation="h",
        title="% of URLs Containing Banking/Finance Keywords",
        labels={"url_percent": "% of URLs", "keyword": "Keyword"},
    )
    fig_keyword_presence.write_html(output_dir / "banking_keyword_presence.html")


def main() -> None:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(args.input)
    if "url" not in df.columns:
        raise ValueError(f"Input file must contain a 'url' column: {args.input}")

    features_df = extract_features(df)
    top_keywords, tfidf_matrix = build_tfidf_summary(features_df["url_text"], args.top_n)
    top_ngrams = build_ngram_summary(features_df["url_text"], args.top_n)
    cluster_metrics, cluster_labels = evaluate_kmeans(tfidf_matrix, args.clusters)
    if cluster_labels is not None:
        features_df["url_pattern_cluster"] = cluster_labels

    keyword_presence = build_keyword_presence_summary(features_df)
    tld_summary = (
        features_df.groupby(["tld", "is_suspicious_tld"], dropna=False)
        .size()
        .reset_index(name="url_count")
        .sort_values("url_count", ascending=False)
    )

    operational_metrics = build_operational_metrics(features_df, top_keywords)
    evaluation_metrics = pd.concat([operational_metrics, cluster_metrics], ignore_index=True)

    features_df.to_csv(args.output_dir / "phishing_url_features.csv", index=False)
    top_keywords.to_csv(args.output_dir / "top_tfidf_keywords.csv", index=False)
    top_ngrams.to_csv(args.output_dir / "top_ngrams.csv", index=False)
    keyword_presence.to_csv(args.output_dir / "keyword_presence.csv", index=False)
    tld_summary.to_csv(args.output_dir / "tld_summary.csv", index=False)
    evaluation_metrics.to_csv(args.output_dir / "evaluation_metrics.csv", index=False)

    save_visualizations(
        args.output_dir,
        top_keywords,
        tld_summary,
        features_df,
        keyword_presence,
        args.top_n,
    )

    banking_keyword_pct = features_df["contains_banking_keyword"].mean() * 100
    print("Phishing URL text mining complete.")
    print(f"URLs analyzed: {len(features_df)}")
    print(f"URLs with banking/finance keywords: {banking_keyword_pct:.2f}%")
    print(f"Outputs saved to: {args.output_dir}")
    if not cluster_metrics.empty:
        silhouette = cluster_metrics.loc[
            cluster_metrics["metric"] == "silhouette_score", "value"
        ].iloc[0]
        print(f"K-Means silhouette score: {silhouette:.4f}")


if __name__ == "__main__":
    main()
