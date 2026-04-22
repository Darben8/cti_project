"""Retrieve finance-sector ransomware victims, group IOCs, and TTP enrichment."""

from __future__ import annotations

import argparse
import csv
import html
import json
import os
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pandas as pd
import requests
from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
DEFAULT_VICTIMS_OUTPUT = DATA_DIR / "finance_victims.csv"
DEFAULT_IOCS_OUTPUT = DATA_DIR / "finance_group_iocs.csv"

PRO_API_BASE = "https://api-pro.ransomware.live"
PUBLIC_API_BASE = "https://api.ransomware.live/v2"
TTPS_URL = "https://www.ransomware.live/ttps"

SECTORS_OF_INTEREST = ("Financial", "Financial Services")
REQUEST_TIMEOUT = 30
REQUEST_DELAY_SECONDS = 0.25

MITRE_TECHNIQUE_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
HTML_TAG_PATTERN = re.compile(r"<[^>]+>")


load_dotenv(PROJECT_ROOT / ".env")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Pull ransomware.live victims for finance sectors, deduplicate them, "
            "fetch IOCs for the related ransomware groups, enrich rows with TTPs, "
            "and save CSV outputs under data/."
        )
    )
    parser.add_argument(
        "--api-base",
        default=os.getenv("RANSOMWARE_API_BASE", PRO_API_BASE).rstrip("/"),
        help=f"Ransomware.live Pro API base URL. Default: {PRO_API_BASE}",
    )
    parser.add_argument(
        "--public-api-base",
        default=PUBLIC_API_BASE,
        help=f"Public API base URL used as a victim-sector fallback. Default: {PUBLIC_API_BASE}",
    )
    parser.add_argument(
        "--victims-output",
        type=Path,
        default=DEFAULT_VICTIMS_OUTPUT,
        help=f"Victim CSV output path. Default: {DEFAULT_VICTIMS_OUTPUT}",
    )
    parser.add_argument(
        "--iocs-output",
        type=Path,
        default=DEFAULT_IOCS_OUTPUT,
        help=f"IOC CSV output path. Default: {DEFAULT_IOCS_OUTPUT}",
    )
    return parser.parse_args()


def build_headers() -> dict[str, str]:
    api_token = os.getenv("RANSOMWARE_API_KEY", "").strip()
    headers = {
        "Accept": "application/json",
        "User-Agent": "banking-cti-project/1.0",
    }
    if api_token:
        headers["Authorization"] = f"Bearer {api_token}"
        headers["X-API-KEY"] = api_token
    return headers


def safe_sleep() -> None:
    time.sleep(REQUEST_DELAY_SECONDS)


def get_json(
    url: str,
    headers: dict[str, str],
    params: dict[str, Any] | None = None,
) -> Any:
    response = requests.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    return response.json()


def ensure_records(payload: Any) -> list[dict[str, Any]]:
    """Normalize common ransomware.live response shapes to a list of dictionaries."""
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]

    if isinstance(payload, dict):
        for key in ("data", "items", "results", "victims", "iocs"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]

    return []


def first_present(record: dict[str, Any], candidates: tuple[str, ...], default: Any = None) -> Any:
    for key in candidates:
        value = record.get(key)
        if value not in (None, "", [], {}):
            return value
    return default


def normalize_group_name(value: Any) -> str | None:
    if value in (None, "", [], {}):
        return None

    if isinstance(value, dict):
        value = first_present(value, ("name", "group", "slug", "title"))
    elif isinstance(value, list):
        value = ", ".join(str(item).strip() for item in value if str(item).strip())

    group = str(value).strip()
    return group or None


def group_slug(group: str) -> str:
    return quote(group.strip(), safe="")


def serialize_raw(record: dict[str, Any]) -> str:
    return json.dumps(record, ensure_ascii=False, sort_keys=True)


def normalize_victim_record(record: dict[str, Any], requested_sector: str) -> dict[str, Any]:
    group = normalize_group_name(
        first_present(record, ("group", "ransomware_group", "gang", "threat_actor", "actor"))
    )

    return {
        "victim_name": first_present(record, ("victim", "name", "organization", "company", "post_title")),
        "group": group,
        "sector": first_present(record, ("sector", "activity", "industry"), default=requested_sector),
        "requested_sector": requested_sector,
        "country": first_present(record, ("country", "country_code", "cc")),
        "attack_date": first_present(record, ("attackdate", "attack_date")),
        "discovered": first_present(record, ("discovered", "discovered_at", "published", "published_at", "date")),
        "website": first_present(record, ("website", "domain")),
        "source_url": first_present(record, ("url", "link", "source_url", "post_url")),
        "description": first_present(record, ("description", "summary", "title")),
        "raw_record": serialize_raw(record),
    }


def normalize_ioc_record(record: dict[str, Any], group: str) -> dict[str, Any]:
    indicator = first_present(record, ("indicator", "ioc", "value", "artifact", "data", "observable"))

    return {
        "group": group,
        "indicator": indicator,
        "ioc_type": first_present(record, ("type", "ioc_type", "indicator_type", "kind")),
        "first_seen": first_present(record, ("first_seen", "date", "created_at", "created")),
        "last_seen": first_present(record, ("last_seen", "updated_at", "updated")),
        "source": first_present(record, ("source",), default="ransomware.live"),
        "description": first_present(record, ("description", "notes", "summary")),
        "raw_record": serialize_raw(record),
    }


def normalize_ioc_payload(payload: Any, group: str) -> list[dict[str, Any]]:
    if isinstance(payload, dict) and isinstance(payload.get("iocs"), dict):
        normalized_rows: list[dict[str, Any]] = []
        for ioc_type, values in payload["iocs"].items():
            if not isinstance(values, list):
                values = [values]

            for value in values:
                if value in (None, ""):
                    continue
                normalized_rows.append(
                    {
                        "group": group,
                        "indicator": str(value),
                        "ioc_type": ioc_type,
                        "first_seen": first_present(payload, ("first_seen", "date", "created_at", "created")),
                        "last_seen": first_present(payload, ("last_seen", "updated_at", "updated")),
                        "source": "ransomware.live",
                        "description": None,
                        "raw_record": json.dumps(
                            {"group": group, "ioc_type": ioc_type, "indicator": value},
                            ensure_ascii=False,
                            sort_keys=True,
                        ),
                    }
                )
        return normalized_rows

    records = ensure_records(payload)
    if records:
        return [normalize_ioc_record(record, group) for record in records]

    if isinstance(payload, list):
        normalized_rows = []
        for item in payload:
            if isinstance(item, dict):
                normalized_rows.append(normalize_ioc_record(item, group))
            elif item not in (None, ""):
                normalized_rows.append(
                    {
                        "group": group,
                        "indicator": str(item),
                        "ioc_type": None,
                        "first_seen": None,
                        "last_seen": None,
                        "source": "ransomware.live",
                        "description": None,
                        "raw_record": json.dumps(item, ensure_ascii=False),
                    }
                )
        return normalized_rows

    return []


def fetch_victims_by_sector(
    sector: str,
    api_base: str,
    public_api_base: str,
    headers: dict[str, str],
) -> list[dict[str, Any]]:
    """Fetch sector victims, preferring Pro API filters and falling back to public v2."""
    sector_path_values = (
        quote(sector, safe=""),
        quote(sector.lower(), safe=""),
        quote(sector.lower().replace(" ", "-"), safe=""),
        quote(sector.lower().replace(" ", "_"), safe=""),
    )
    attempts = (
        (f"{api_base}/victims/", {"sector": sector}),
        (f"{api_base}/victims", {"sector": sector}),
        (f"{api_base}/sectorvictims/{quote(sector, safe='')}", None),
        *(
            (f"{public_api_base.rstrip('/')}/sectorvictims/{sector_path_value}", None)
            for sector_path_value in sector_path_values
        ),
    )

    errors: list[str] = []
    for url, params in attempts:
        try:
            payload = get_json(url, headers=headers, params=params)
            safe_sleep()
            victims = ensure_records(payload)
            if victims:
                return [normalize_victim_record(victim, requested_sector=sector) for victim in victims]
        except requests.HTTPError as exc:
            errors.append(f"{url}: HTTP {exc.response.status_code}")
        except requests.RequestException as exc:
            errors.append(f"{url}: {exc}")

    raise RuntimeError(f"No victims returned for sector '{sector}'. Attempts: {'; '.join(errors)}")


def fetch_iocs_by_group(group: str, api_base: str, headers: dict[str, str]) -> list[dict[str, Any]]:
    payload = get_json(f"{api_base}/iocs/{group_slug(group)}", headers=headers)
    safe_sleep()
    return normalize_ioc_payload(payload, group)


def clean_html_text(value: str) -> str:
    without_tags = HTML_TAG_PATTERN.sub(" ", value)
    return " ".join(html.unescape(without_tags).split())


def parse_ttp_catalog(page_text: str) -> dict[str, str]:
    """Best-effort group-to-MITRE mapping from the ransomware.live TTP matrix page."""
    script_match = re.search(
        r"(?:const|let|var)\s+groupTTPs\s*=\s*(\{.*?\});",
        page_text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if script_match:
        try:
            group_ttps = json.loads(script_match.group(1))
            return {
                str(group).strip().lower(): "; ".join(sorted(set(map(str, ttps))))
                for group, ttps in group_ttps.items()
                if isinstance(ttps, list)
            }
        except json.JSONDecodeError:
            pass

    group_to_ttps: dict[str, set[str]] = {}

    # The page is rendered as an HTML matrix; group names often appear near ATT&CK IDs.
    for match in re.finditer(r"<tr\b.*?</tr>", page_text, flags=re.IGNORECASE | re.DOTALL):
        row_html = match.group(0)
        techniques = set(MITRE_TECHNIQUE_PATTERN.findall(row_html))
        if not techniques:
            continue

        row_text = clean_html_text(row_html).lower()
        for group_match in re.finditer(r"data-(?:group|gang|actor)=[\"']([^\"']+)[\"']", row_html, re.I):
            group = clean_html_text(group_match.group(1)).lower()
            if group:
                group_to_ttps.setdefault(group, set()).update(techniques)

        for class_match in re.finditer(r"(?:group|gang|actor)-([a-z0-9_-]+)", row_html, re.I):
            group = class_match.group(1).replace("-", " ").replace("_", " ").lower()
            if group and group in row_text:
                group_to_ttps.setdefault(group, set()).update(techniques)

    return {group: "; ".join(sorted(ttps)) for group, ttps in group_to_ttps.items()}


def fetch_ttp_catalog(headers: dict[str, str]) -> dict[str, str]:
    response = requests.get(TTPS_URL, headers=headers, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    safe_sleep()
    return parse_ttp_catalog(response.text)


def lookup_group_ttps(group: str, ttp_catalog: dict[str, str]) -> str:
    candidates = {
        group.strip().lower(),
        group.strip().lower().replace(" ", ""),
        group.strip().lower().replace("-", " "),
        group.strip().lower().replace("_", " "),
    }

    for candidate in candidates:
        if candidate in ttp_catalog:
            return ttp_catalog[candidate]

    return ""


def dedupe_victims(victims_df: pd.DataFrame) -> pd.DataFrame:
    dedupe_cols = [
        column
        for column in ("victim_name", "group", "attack_date", "discovered", "country")
        if column in victims_df.columns
    ]
    if dedupe_cols:
        return victims_df.drop_duplicates(subset=dedupe_cols, keep="first")
    return victims_df.drop_duplicates()


def dedupe_iocs(iocs_df: pd.DataFrame) -> pd.DataFrame:
    dedupe_cols = [
        column
        for column in ("group", "indicator", "ioc_type", "first_seen")
        if column in iocs_df.columns
    ]
    if dedupe_cols:
        return iocs_df.drop_duplicates(subset=dedupe_cols, keep="first")
    return iocs_df.drop_duplicates()


def save_csv(df: pd.DataFrame, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False, quoting=csv.QUOTE_MINIMAL)


def main() -> None:
    args = parse_args()
    headers = build_headers()

    print("Pulling ransomware.live victims for finance sectors...")
    all_victims: list[dict[str, Any]] = []

    for sector in SECTORS_OF_INTEREST:
        try:
            victims = fetch_victims_by_sector(sector, args.api_base, args.public_api_base, headers)
            all_victims.extend(victims)
            print(f"  {sector}: {len(victims)} records")
        except Exception as exc:
            print(f"  {sector}: failed ({exc})")

    if not all_victims:
        raise RuntimeError("No victims were retrieved for Financial or Financial Services sectors.")

    victims_df = dedupe_victims(pd.DataFrame(all_victims))
    groups = sorted(
        {
            str(group).strip()
            for group in victims_df.get("group", pd.Series(dtype=str)).dropna()
            if str(group).strip()
        },
        key=str.lower,
    )

    print(f"Found {len(victims_df)} unique finance victim records.")
    print(f"Found {len(groups)} unique ransomware groups from finance victims.")

    print("Pulling TTP matrix for group enrichment...")
    try:
        ttp_catalog = fetch_ttp_catalog(headers)
        print(f"  Parsed TTP mappings for {len(ttp_catalog)} groups.")
    except Exception as exc:
        ttp_catalog = {}
        print(f"  TTP enrichment unavailable: {exc}")

    print("Pulling IOCs for finance-relevant ransomware groups...")
    all_iocs: list[dict[str, Any]] = []
    failed_groups: list[dict[str, str]] = []

    for group in groups:
        try:
            group_iocs = fetch_iocs_by_group(group, args.api_base, headers)
            group_ttps = lookup_group_ttps(group, ttp_catalog)
            for row in group_iocs:
                row["ttps"] = group_ttps
            all_iocs.extend(group_iocs)
            print(f"  {group}: {len(group_iocs)} IOC records")
        except Exception as exc:
            failed_groups.append({"group": group, "error": str(exc)})
            print(f"  {group}: failed ({exc})")

    iocs_df = pd.DataFrame(all_iocs)
    if not iocs_df.empty:
        iocs_df = dedupe_iocs(iocs_df)
    elif groups:
        iocs_df = pd.DataFrame(
            columns=[
                "group",
                "indicator",
                "ioc_type",
                "first_seen",
                "last_seen",
                "source",
                "description",
                "raw_record",
                "ttps",
            ]
        )

    save_csv(victims_df, args.victims_output)
    save_csv(iocs_df, args.iocs_output)

    if failed_groups:
        failed_output = DATA_DIR / "finance_failed_ioc_groups.csv"
        save_csv(pd.DataFrame(failed_groups), failed_output)
        print(f"Saved failed IOC pulls: {failed_output} ({len(failed_groups)} rows)")

    print("\nDone.")
    print(f"Saved victims CSV: {args.victims_output} ({len(victims_df)} rows)")
    print(f"Saved IOC CSV:     {args.iocs_output} ({len(iocs_df)} rows)")


if __name__ == "__main__":
    main()
