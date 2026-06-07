"""
parse_logs.py
-------------
Reads raw CloudTrail JSON files from data/raw/, extracts the three fields
we need (user, event_name, timestamp), and writes a single flat CSV to
data/parsed_logs.csv.

Streams one file at a time — never loads all files into RAM at once —
making it safe on a t2.micro instance.
"""

import os
import json
import csv
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

RAW_DIR     = os.getenv("LOCAL_LOG_DIR", "data/raw")
OUTPUT_CSV  = os.getenv("PARSED_CSV", "data/parsed_logs.csv")

FIELDNAMES  = ["user", "event_name", "timestamp", "source_ip", "error_code"]


def extract_user(record: dict) -> str:
    """Pull the most meaningful user identifier from userIdentity."""
    identity = record.get("userIdentity", {})
    return (
        identity.get("userName")
        or identity.get("sessionContext", {})
                  .get("sessionIssuer", {})
                  .get("userName")
        or identity.get("arn", "unknown")
        or "unknown"
    )


def parse_record(record: dict) -> dict | None:
    """Return a flat dict for one CloudTrail record, or None if malformed."""
    try:
        ts_raw = record.get("eventTime", "")
        # Accept both with and without fractional seconds
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ"):
            try:
                ts = datetime.strptime(ts_raw, fmt).isoformat()
                break
            except ValueError:
                ts = ts_raw

        return {
            "user":        extract_user(record),
            "event_name":  record.get("eventName", "Unknown"),
            "timestamp":   ts,
            "source_ip":   record.get("sourceIPAddress", ""),
            "error_code":  record.get("errorCode", ""),
        }
    except Exception as e:
        logger.debug("Skipping malformed record: %s", e)
        return None


def parse_file(filepath: str, writer: csv.DictWriter) -> int:
    """Parse a single JSON file and write rows. Returns number of records written."""
    count = 0
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        records = data.get("Records", [])
        for rec in records:
            row = parse_record(rec)
            if row:
                writer.writerow(row)
                count += 1
    except (json.JSONDecodeError, OSError) as e:
        logger.error("Could not parse %s: %s", filepath, e)
    return count


def parse_logs():
    if not os.path.isdir(RAW_DIR):
        raise FileNotFoundError(
            f"Raw log directory '{RAW_DIR}' not found. Run fetch_logs.py first."
        )

    json_files = [
        os.path.join(RAW_DIR, f)
        for f in sorted(os.listdir(RAW_DIR))
        if f.endswith(".json")
    ]
    if not json_files:
        raise ValueError(f"No .json files found in {RAW_DIR}")

    logger.info("Parsing %d files → %s", len(json_files), OUTPUT_CSV)
    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)

    total = 0
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=FIELDNAMES)
        writer.writeheader()
        for path in json_files:
            n = parse_file(path, writer)
            total += n
            logger.debug("  %s → %d records", os.path.basename(path), n)

    logger.info("Parsed %d total records into %s", total, OUTPUT_CSV)
    return total


if __name__ == "__main__":
    parse_logs()
