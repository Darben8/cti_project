"""Extract banking and finance-related phishing records from verified_online.csv."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
from urllib.parse import urlparse


DEFAULT_INPUT = Path("data/verified_online.csv")
DEFAULT_OUTPUT = Path("data/verified_online_banking_finance.csv")
ENCODINGS = ("utf-8-sig", "cp1252", "latin-1")

# Exact targets that are clearly banking, cards, brokerages, payments, or fintech.
BANKING_TARGETS = {
    "abn amro bank",
    "absa bank",
    "aeon card",
    "allied bank limited",
    "american express",
    "banco de brasil",
    "banco bilbao vizcaya argentaria",
    "banco santander, s.a.",
    "bank of america corporation",
    "barclays bank plc",
    "binance",
    "bradesco",
    "caixa",
    "capitec bank",
    "capital one financial corporation",
    "chime",
    "citibank",
    "coinbase",
    "development bank of singapore",
    "discover",
    "fidelity",
    "hsbc group",
    "huntington national bank",
    "ing direct",
    "interactive brokers",
    "intesa sanpaolo",
    "itau",
    "jpmorgan chase and co.",
    "lloyds bank",
    "mastercard international",
    "natwest",
    "navy federal credit union",
    "payoneer",
    "paypal",
    "paypay bank",
    "resona holdings",
    "scotiabank",
    "sofi",
    "sumitomo mitsui banking corporation",
    "tsb",
    "unicredit",
    "visa",
    "volksbanken raiffeisenbanken",
    "wells fargo",
}

# Broader terms for target-column matches, including labels that may be less standardized.
TARGET_KEYWORDS = {
    "american express",
    "amex",
    "bank",
    "banco",
    "banamex",
    "barclays",
    "bbva",
    "binance",
    "broker",
    "bradesco",
    "capital one",
    "card",
    "cash app",
    "chase",
    "citi",
    "citibank",
    "coinbase",
    "credit union",
    "debit",
    "discover",
    "fidelity",
    "finance",
    "financial",
    "hsbc",
    "ibkr",
    "ing",
    "insurance",
    "interac",
    "invest",
    "jpmorgan",
    "mastercard",
    "monzo",
    "natwest",
    "pay",
    "paypal",
    "payoneer",
    "paytm",
    "resona",
    "revolut",
    "santander",
    "scotiabank",
    "sofi",
    "swift",
    "trade",
    "transferwise",
    "tsb",
    "unicredit",
    "venmo",
    "visa",
    "wallet",
    "wells fargo",
    "wise",
}

# URL-only heuristics for "Other" and similarly vague targets.
URL_KEYWORDS = {
    "amex",
    "bank",
    "banca",
    "banco",
    "banking",
    "barclays",
    "bbva",
    "binance",
    "boa",
    "capitalone",
    "card",
    "cashapp",
    "chase",
    "citi",
    "citibank",
    "coinbase",
    "credit",
    "debit",
    "discover",
    "fidelity",
    "finance",
    "financial",
    "hsbc",
    "ibkr",
    "ing",
    "interac",
    "invest",
    "jpmorgan",
    "mastercard",
    "monzo",
    "natwest",
    "navyfederal",
    "paypal",
    "payoneer",
    "paytm",
    "resona",
    "revolut",
    "santander",
    "scotiabank",
    "sofi",
    "swift",
    "unicredit",
    "venmo",
    "visa",
    "wallet",
    "wellsfargo",
    "wise",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Filter verified_online phishing records for banking and finance-related "
            "targets using the target column and URL heuristics."
        )
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
        help=f"Input CSV path. Default: {DEFAULT_INPUT}",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Output CSV path. Default: {DEFAULT_OUTPUT}",
    )
    return parser.parse_args()


def normalize_text(value: str | None) -> str:
    return " ".join((value or "").strip().lower().split())


def read_rows(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    last_error: Exception | None = None

    for encoding in ENCODINGS:
        try:
            with path.open("r", encoding=encoding, errors="strict", newline="") as handle:
                reader = csv.DictReader(handle)
                if not reader.fieldnames:
                    raise ValueError(f"No CSV header found in {path}.")
                rows = list(reader)
                return reader.fieldnames, rows
        except UnicodeDecodeError as exc:
            last_error = exc

    with path.open("r", encoding="cp1252", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError(f"No CSV header found in {path}.")
        rows = list(reader)
        if last_error:
            print(
                f"Warning: mixed encoding detected in {path}. "
                "Falling back to cp1252 with replacement for undecodable characters."
            )
        return reader.fieldnames, rows


def extract_url_text(url: str) -> str:
    normalized_url = normalize_text(url)
    parsed = urlparse(normalized_url)
    host = parsed.netloc.replace(".", " ").replace("-", " ")
    path = parsed.path.replace("/", " ").replace("-", " ").replace("_", " ")
    query = parsed.query.replace("&", " ").replace("=", " ").replace("-", " ").replace("_", " ")
    return f"{normalized_url} {host} {path} {query}"


def classify_row(row: dict[str, str]) -> tuple[bool, str, str]:
    target = normalize_text(row.get("target"))
    url_text = extract_url_text(row.get("url", ""))

    if target in BANKING_TARGETS:
        return True, "target_exact", target

    for keyword in sorted(TARGET_KEYWORDS):
        if keyword in target:
            return True, "target_keyword", keyword

    for keyword in sorted(URL_KEYWORDS):
        if keyword in url_text:
            return True, "url_keyword", keyword

    return False, "", ""


def write_rows(
    output_path: Path,
    fieldnames: list[str],
    rows: list[dict[str, str]],
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    enriched_fieldnames = fieldnames + ["banking_match_source", "banking_match_term"]

    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=enriched_fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    args = parse_args()
    fieldnames, rows = read_rows(args.input)

    filtered_rows: list[dict[str, str]] = []

    for row in rows:
        matched, source, term = classify_row(row)
        if not matched:
            continue

        enriched_row = dict(row)
        enriched_row["banking_match_source"] = source
        enriched_row["banking_match_term"] = term
        filtered_rows.append(enriched_row)

    write_rows(args.output, fieldnames, filtered_rows)
    print(f"Input rows scanned: {len(rows)}")
    print(f"Banking/finance rows written: {len(filtered_rows)}")
    print(f"Output file: {args.output}")


if __name__ == "__main__":
    main()
