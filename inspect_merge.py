#!/usr/bin/env python3
import json
import base64
import logging
import pandas as pd

from main import connect_to_db  # adjust this import to wherever your connect_to_db lives

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def UG_Key(encoded: str, ut_df: pd.DataFrame) -> str:
    """
    Turn a decoded string like:
      "10x15x0 - $69.00 - 244301 - [156843 - 172636]"
    into:
      "10x15x0 - SELF STORAGE - [156843 - 172636]"
    preserving all IDs inside the brackets.
    """
    parts = encoded.split(" - ")
    # drop the price
    parts.pop(1)
    # now parts == ["10x15x0", "244301", "[156843", "172636]"]
    ut_id = int(parts[1])
    ut_name = ut_df.loc[ut_df["ut_id"] == ut_id, "ut_name"].iat[0]
    trailing = " - ".join(
        parts[2:])  # preserves "[156843 - 172636]" or similar
    return f"{parts[0]} - {ut_name} - {trailing}"


def main():
    # 1) Load & decode the full Storedge report
    logging.info("Loading latest_report.json…")
    with open("latest_report.json") as f:
        data = json.load(f)
    report_rows = data["report_request"]["report"]["report_request"]["report"]
    full_df = pd.DataFrame(report_rows)
    logging.info(f"Loaded {len(full_df)} rows from full report")

    # 2) Base64 decode the Group Key column
    logging.info("Decoding base64 Group Key…")
    decoded = []
    for b64 in full_df["Group Key"]:
        raw = base64.b64decode(b64)
        decoded.append(raw.decode("ascii"))
    full_df["decoded_key"] = decoded

    # 3) Pull unit_types from SQL for lookups
    logging.info("Querying unit_types from database…")
    with connect_to_db("sE") as conn:
        ut_df = pd.read_sql_query(
            "SELECT ut_id, ut_name FROM sE.dbo.unit_types", conn)
    logging.info(f"Fetched {len(ut_df)} unit_types")

    # 4) Rebuild a matchable Group Key
    logging.info("Normalizing decoded keys to final UG_KEY…")
    full_df["Group Key"] = full_df["decoded_key"].apply(
        lambda x: UG_Key(x, ut_df))

    # 5) Load your bucket‐calculated rates
    logging.info("Loading bucket_rate_results.json…")
    with open("bucket_rate_results.json") as f:
        bucket_data = json.load(f)
    patch_df = pd.DataFrame(bucket_data)
    logging.info(f"Loaded {len(patch_df)} rows from bucket results")

    # 6) Normalize its key column (no splitting or dropping — brackets intact)
    patch_df["Group Key"] = patch_df["ug_key"].astype(str).str.strip()

    # 7) Compute match / mismatch
    full_keys = set(full_df["Group Key"])
    patch_keys = set(patch_df["Group Key"])
    common = full_keys & patch_keys
    missing = patch_keys - full_keys

    logging.info(f"✅ Matching keys: {len(common)}")
    logging.info(f"🔍 Sample matches: {list(common)[:5]}")
    logging.warning(f"⚠️ Keys in patch not in report: {len(missing)}")
    logging.warning(f"🧨 Sample missing: {list(missing)[:5]}")

    # optionally dump unmatched
    if missing:
        pd.DataFrame({"Group Key": list(missing)}) \
          .to_csv("unmatched_keys.csv", index=False)
        logging.info("📄 Saved unmatched_keys.csv")


if __name__ == "__main__":
    main()
