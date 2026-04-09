"""Collects Shodan exposure metadata and live ThreatFox records into local CSV files."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pandas as pd
import requests
from dotenv import load_dotenv

load_dotenv()

DATA_DIR = os.path.dirname(__file__)
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "").strip()
THREATFOX_API_KEY = os.getenv("THREATFOX_API_KEY", "").strip()

SHODAN_QUERY = 'org:"Bank" port:443 country:"US"'
SHODAN_OUTPUT = os.path.join(DATA_DIR, "shodan_exposure_records.csv")
THREATFOX_OUTPUT = os.path.join(DATA_DIR, "threatfox_live_records.csv")

SHODAN_PAGE_SIZE = 100
SHODAN_MAX_PAGES = 20
SHODAN_TARGET_ROWS = 2000

THREATFOX_BATCH_SIZE = 100
THREATFOX_TARGET_ROWS = 2000
THREATFOX_MAX_DAYS_BACK = 180
THREATFOX_STEP_DAYS = 7


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


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


def ensure_dir(path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)


def save_csv(df: pd.DataFrame, path: str) -> None:
    ensure_dir(path)
    df.to_csv(path, index=False)


def collect_shodan_exposure_records() -> pd.DataFrame:
    if not SHODAN_API_KEY:
        raise RuntimeError("Missing SHODAN_API_KEY.")

    session = requests.Session()
    records: list[dict] = []

    for page in range(1, SHODAN_MAX_PAGES + 1):
        response = session.get(
            "https://api.shodan.io/shodan/host/search",
            params={
                "key": SHODAN_API_KEY,
                "query": SHODAN_QUERY,
                "page": page,
                "minify": "true",
            },
            timeout=20,
        )
        response.raise_for_status()
        payload = response.json()
        matches = payload.get("matches", [])
        if not matches:
            break

        for match in matches:
            location = match.get("location") or {}
            hostnames = match.get("hostnames") or []
            domains = match.get("domains") or []

            # Summary-safe export: do not store raw victim IPs, banners, or verbose payloads.
            records.append(
                {
                    "source": "Shodan",
                    "query": SHODAN_QUERY,
                    "retrieved_at_utc": utc_now().isoformat(),
                    "page": page,
                    "port": match.get("port"),
                    "organization": match.get("org"),
                    "hostname_count": len(hostnames),
                    "domain_count": len(domains),
                    "country": location.get("country_name"),
                    "region_code": location.get("region_code"),
                    "city": location.get("city"),
                    "timestamp": match.get("timestamp"),
                    "asn": match.get("asn"),
                    "isp": match.get("isp"),
                    "product": match.get("product"),
                    "os": match.get("os"),
                    "transport": match.get("transport"),
                }
            )

        if len(records) >= SHODAN_TARGET_ROWS:
            break

        total = int(payload.get("total", 0))
        if page * SHODAN_PAGE_SIZE >= total:
            break

    df = pd.DataFrame(records)
    if df.empty:
        return df

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    return df


def threatfox_headers() -> dict:
    headers = {
        "User-Agent": "CTI-Streamlit-App/1.0 (Academic Project)",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if THREATFOX_API_KEY:
        headers["Auth-Key"] = THREATFOX_API_KEY
    return headers


def fetch_threatfox_slice(days_back: int) -> list[dict]:
    response = requests.post(
        "https://threatfox-api.abuse.ch/api/v1/",
        json={"query": "get_iocs", "days": days_back},
        headers=threatfox_headers(),
        timeout=20,
    )
    response.raise_for_status()
    payload = response.json()

    if payload.get("query_status") not in {"ok", "no_result"}:
        raise RuntimeError(f"ThreatFox returned unexpected status: {payload}")

    return payload.get("data", []) or []


def normalize_threatfox(records: list[dict]) -> pd.DataFrame:
    if not records:
        return pd.DataFrame(columns=["indicator", "type", "category", "source", "date", "tags", "asset"])

    df = pd.DataFrame(records)
    normalized = pd.DataFrame()
    normalized["indicator"] = df.get("ioc", "")
    normalized["type"] = df.get("ioc_type", df.get("threat_type", "unknown"))
    normalized["category"] = df.get("threat_type", "unknown")
    normalized["source"] = "ThreatFox API"
    normalized["date"] = pd.to_datetime(df.get("first_seen"), errors="coerce", utc=True)
    normalized["tags"] = (
        df.get("malware_printable")
        .fillna(df.get("tags"))
        .fillna(df.get("malware"))
        .fillna("")
    )
    normalized["asset"] = normalized.apply(
        lambda row: classify_asset(row["indicator"], row["category"], row["tags"], row["source"]),
        axis=1,
    )
    return normalized[["indicator", "type", "category", "source", "date", "tags", "asset"]]


def collect_threatfox_live_records() -> pd.DataFrame:
    if not THREATFOX_API_KEY:
        raise RuntimeError("Missing THREATFOX_API_KEY.")

    all_frames: list[pd.DataFrame] = []
    seen_days: set[int] = set()

    for days_back in range(THREATFOX_STEP_DAYS, THREATFOX_MAX_DAYS_BACK + THREATFOX_STEP_DAYS, THREATFOX_STEP_DAYS):
        if days_back in seen_days:
            continue
        seen_days.add(days_back)

        slice_records = fetch_threatfox_slice(days_back)
        slice_df = normalize_threatfox(slice_records)
        if not slice_df.empty:
            all_frames.append(slice_df)

        merged = pd.concat(all_frames, ignore_index=True) if all_frames else pd.DataFrame()
        if not merged.empty:
            merged = merged.drop_duplicates(subset=["indicator", "type", "category", "date"])
            if len(merged) >= THREATFOX_TARGET_ROWS:
                return merged.sort_values("date", ascending=False).head(THREATFOX_TARGET_ROWS)

    if not all_frames:
        return pd.DataFrame(columns=["indicator", "type", "category", "source", "date", "tags", "asset"])

    final_df = pd.concat(all_frames, ignore_index=True).drop_duplicates(
        subset=["indicator", "type", "category", "date"]
    )
    cutoff = utc_now() - timedelta(days=365)
    final_df = final_df[final_df["date"].isna() | (final_df["date"] >= cutoff)]
    return final_df.sort_values("date", ascending=False)


def main() -> None:
    shodan_df = collect_shodan_exposure_records()
    save_csv(shodan_df, SHODAN_OUTPUT)

    threatfox_df = collect_threatfox_live_records()
    save_csv(threatfox_df, THREATFOX_OUTPUT)

    print(f"Saved {len(shodan_df):,} Shodan exposure rows to {SHODAN_OUTPUT}")
    print(f"Saved {len(threatfox_df):,} ThreatFox rows to {THREATFOX_OUTPUT}")

    if len(shodan_df) < SHODAN_TARGET_ROWS:
        print(
            f"Note: Shodan export produced {len(shodan_df):,} rows, below the {SHODAN_TARGET_ROWS:,} target."
        )
    if len(threatfox_df) < THREATFOX_TARGET_ROWS:
        print(
            f"Note: ThreatFox export produced {len(threatfox_df):,} rows, below the {THREATFOX_TARGET_ROWS:,} target due to API limits."
        )


if __name__ == "__main__":
    main()
