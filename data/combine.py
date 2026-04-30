"""Combine CTI CSV sources into one strict IOC feed.

Output schema:
    indicator, type, ioc type, source, first seen, tags

Notes:
    - `finance_victims.csv` is reviewed but intentionally omitted from the
      output because it is not a strict IOC feed.
    - The output is written to `data/all_iocs.csv`.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd


DATA_DIR = Path(__file__).resolve().parent
OUTPUT_PATH = DATA_DIR / "all_iocs.csv"


def normalize_timestamp(series: pd.Series) -> pd.Series:
    """Return timestamps normalized to YYYY-MM-DD HH:MM:SS where possible."""
    parsed = pd.to_datetime(series, errors="coerce", utc=True, dayfirst=True)
    formatted = parsed.dt.strftime("%Y-%m-%d %H:%M:%S")
    return formatted.fillna("")


def collapse_tags(*parts: pd.Series | str) -> pd.Series:
    """Combine source-specific fields into one semicolon-delimited tag column."""
    normalized_parts: list[pd.Series] = []
    length = None

    for part in parts:
        if isinstance(part, pd.Series):
            if length is None:
                length = len(part)
            normalized_parts.append(part.fillna("").astype(str))
        else:
            if length is None:
                raise ValueError("String tag parts require at least one Series part first.")
            normalized_parts.append(pd.Series([str(part)] * length, index=normalized_parts[0].index))

    if not normalized_parts:
        return pd.Series(dtype="object")

    combined = pd.concat(normalized_parts, axis=1)
    cleaned = combined.apply(
        lambda row: ";".join(
            value.strip()
            for value in row
            if value.strip() and value.strip().lower() not in {"nan", "none"}
        ),
        axis=1,
    )
    return cleaned


def strict_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Return the target schema in the required column order."""
    required = ["indicator", "type", "ioc type", "source", "first seen", "tags"]
    return df[required].copy()


def from_verified_online_banking_finance(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    normalized = pd.DataFrame(
        {
            "indicator": df["url"].fillna("").astype(str),
            "type": "url",
            "ioc type": "phishing",
            "source": "verified_online_banking_finance",
            "first seen": normalize_timestamp(df["submission_time"]),
            "tags": collapse_tags(
                df["target"],
                df["banking_match_source"],
                df["banking_match_term"],
                "verified=yes",
            ),
        }
    )
    return strict_columns(normalized)


def from_phishtank(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    normalized = pd.DataFrame(
        {
            "indicator": df["indicator"].fillna("").astype(str),
            "type": df["type"].fillna("").astype(str),
            "ioc type": df["IOC type"].fillna("").astype(str),
            "source": df["source"].fillna("PhishTank").astype(str),
            "first seen": normalize_timestamp(df["first seen"]),
            "tags": df["tags"].fillna("").astype(str),
        }
    )
    return strict_columns(normalized)


def from_finance_group_iocs(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    normalized = pd.DataFrame(
        {
            "indicator": df["indicator"].fillna("").astype(str),
            "type": df["ioc_type"].fillna("").astype(str),
            "ioc type": "ransomware",
            "source": df["source"].fillna("ransomware.live").astype(str),
            "first seen": normalize_timestamp(df["first_seen"]),
            "tags": collapse_tags(df["group"], df["ttps"], df["description"]),
        }
    )

    missing_first_seen = normalized["first seen"].eq("")
    if "last_seen" in df.columns:
        normalized.loc[missing_first_seen, "first seen"] = normalize_timestamp(
            df.loc[missing_first_seen, "last_seen"]
        )

    return strict_columns(normalized)


def from_filtered_iocs_threatfox(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    normalized = pd.DataFrame(
        {
            "indicator": df["ioc_value"].fillna("").astype(str),
            "type": df["ioc_type"].fillna("").astype(str),
            "ioc type": df["threat_type"].fillna("").astype(str),
            "source": "ThreatFox",
            "first seen": normalize_timestamp(df["first_seen_utc"]),
            "tags": collapse_tags(
                df["malware_printable"],
                df["malware_alias"],
                df["tags"],
                "confidence=" + df["confidence_level"].fillna("").astype(str),
            ),
        }
    )
    return strict_columns(normalized)


def review_finance_victims(path: Path) -> None:
    df = pd.read_csv(path)
    print(
        f"Reviewed {path.name}: {len(df):,} rows found. "
        "Omitted from output because this script produces a strict IOC feed."
    )


def clean_output(df: pd.DataFrame) -> pd.DataFrame:
    cleaned = df.copy()
    cleaned["indicator"] = cleaned["indicator"].fillna("").astype(str).str.strip()
    cleaned["type"] = cleaned["type"].fillna("").astype(str).str.strip().str.lower()
    cleaned["ioc type"] = cleaned["ioc type"].fillna("").astype(str).str.strip().str.lower()
    cleaned["source"] = cleaned["source"].fillna("").astype(str).str.strip()
    cleaned["first seen"] = cleaned["first seen"].fillna("").astype(str).str.strip()
    cleaned["tags"] = cleaned["tags"].fillna("").astype(str).str.strip()

    cleaned = cleaned[cleaned["indicator"] != ""]
    cleaned = cleaned[cleaned["type"] != ""]
    cleaned = cleaned.drop_duplicates(subset=["indicator", "type", "source"], keep="first")
    cleaned = cleaned.sort_values(["source", "type", "indicator"], kind="stable").reset_index(drop=True)
    return cleaned


def main() -> None:
    sources = [
        from_verified_online_banking_finance(DATA_DIR / "verified_online_banking_finance.csv"),
        from_phishtank(DATA_DIR / "phishtank.csv"),
        from_finance_group_iocs(DATA_DIR / "finance_group_iocs.csv"),
        from_filtered_iocs_threatfox(DATA_DIR / "filtered_iocs_threatfox.csv"),
    ]

    review_finance_victims(DATA_DIR / "finance_victims.csv")

    combined = pd.concat(sources, ignore_index=True)
    combined = clean_output(combined)
    combined.to_csv(OUTPUT_PATH, index=False)

    print(f"Wrote strict IOC feed to {OUTPUT_PATH}")
    print(f"Output rows: {len(combined):,}")


if __name__ == "__main__":
    main()
