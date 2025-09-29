from flask import Flask, request, jsonify, send_from_directory
from requests_oauthlib import OAuth1
import requests
import os
import time
import json
import pandas as pd
from io import BytesIO, StringIO
from dotenv import load_dotenv
# import sqlalchemy
# from sqlalchemy import text
import re  # Added for enhanced token parsing
import pytds
from pytds import tds_base
from datetime import datetime
import numpy as np
import base64
import binascii
import traceback
from uuid import UUID

load_dotenv()

app = Flask(__name__)

# === Storedge API Config ===
API_KEY = os.getenv("STOREDGE_API_KEY")
API_SECRET = os.getenv("STOREDGE_API_SECRET")
BASE_URL = "https://api.storedgefms.com"
COMPANY_ID = "90df0cad-f32f-4c1f-8d78-9beda9622b34"  # Hardcoded

# === Shorthand Mapping and Expansion ===
SHORTHAND_MAP = {
    "cc": "climate controlled",
    "e": "elevator access",
    "du": "drive up",
    "g": "1st floor",
    "locker": "reduced height",
    "econ": "economy"
}


def expand_shorthand(text):
    """
    Expands known shorthand terms in unit descriptions.
    Handles comma- or slash-separated tokens too.
    """
    tokens = re.split(r"[,\s/]+", text.lower())
    expanded = [
        SHORTHAND_MAP.get(token.strip(), token.strip()) for token in tokens
        if token
    ]
    return " ".join(expanded)


def match_unit_group(description, df):
    """
    Token-matches unit descriptions like '5x5 cc e' to full-size and amenity fields.
    """
    normalized_desc = expand_shorthand(description)
    tokens = normalized_desc.split()

    def is_match(row):
        size = (row.get("Size") or "").lower()
        amenities = (row.get("Amenities") or "").lower()
        combined = f"{size} {amenities}"
        return all(token in combined for token in tokens)

    matches = df[df.apply(is_match, axis=1)]
    print(
        f"[Unit Match] Found {len(matches)} rows for: '{description}' → '{normalized_desc}'"
    )
    return matches


# === MSSQL Helper: Connect to dynamic database ===
def connect_to_db(db_name):
    """
    Return a live pytds connection to `db_name`.
    """
    user = os.getenv("MSSQL_USER")
    password = os.getenv("MSSQL_PASSWORD")
    host = os.getenv("MSSQL_HOST")

    if not all((user, password, host, db_name)):
        raise ValueError("Missing MSSQL connection details.")

    return pytds.connect(
        server=host,
        port=1433,
        database=db_name,
        user=user,
        password=password,
        tds_version=tds_base.TDS74,  # SQL Server 2012+
    )


# === Helper: Smart Polling for Report Completion ===
def poll_until_report_ready(report_id, timeout=120, interval=10):
    """
    Polls the Storedge API to check if the report is ready.
    Waits `interval` seconds between each check, for up to `timeout` seconds.
    Logs timing and status info for debugging/reporting.
    """
    auth = OAuth1(API_KEY, API_SECRET)
    elapsed = 0

    while elapsed < timeout:
        print(
            f"[Polling] Checking status for report {report_id} at {time.strftime('%X')} (elapsed: {elapsed}s)"
        )

        url = f"{BASE_URL}/v1/companies/{COMPANY_ID}/report_requests/{report_id}"
        try:
            response = requests.get(url, auth=auth, timeout=10)
            if response.status_code != 200:
                print(f"[Polling] Error: status code {response.status_code}")
                return None

            status = response.json().get("report_request",
                                         {}).get("status", "unknown")
            print(f"[Polling] Report status: {status}")

            if status == "complete":
                print("[Polling] Report is complete.")
                return True

        except Exception as e:
            print(f"[Polling] Exception during status check: {e}")

        print(f"[Polling] Sleeping {interval}s before next check...")
        time.sleep(interval)
        elapsed += interval

    print(f"[Polling] Timeout reached after {timeout}s — report not ready.")
    return False


# === Helper: Retry Logic for Uploads ===
def upload_with_retries(file, created_by_id, max_retries=3, backoff=5):
    # Reset the stream pointer in case it's a BytesIO
    file.seek(0)

    files = {
        "unoccupied_revenue_management[file]":
        (file.name, file.read(), "text/csv")
    }
    payload = {"unoccupied_revenue_management[created_by_id]": created_by_id}
    url = f"{BASE_URL}/v1/companies/{COMPANY_ID}/unoccupied_revenue_management/import"
    auth = OAuth1(API_KEY, API_SECRET)

    for attempt in range(1, max_retries + 1):
        try:
            print(f"[Upload] Attempt {attempt}")
            r = requests.post(url, files=files, data=payload, auth=auth)
            r.raise_for_status()
            print("[Upload] Success")
            return r
        except Exception as e:
            print(f"[Upload] Failed attempt {attempt}: {e}")
            time.sleep(backoff)
    return None


# === API Endpoints ===
@app.route("/ping")
def ping():
    # a simple health endpoint for Replit and you
    return jsonify(status="ok"), 200


@app.route("/.well-known/ai-plugin.json")
def plugin_manifest():
    return send_from_directory(app.root_path,
                               "ai-plugin.json",
                               mimetype="application/json")


# https://rate-changer.replit.app/openapi.json
@app.route("/openapi.json")
def openapi_spec():
    return send_from_directory(app.root_path,
                               "openapi.json",
                               mimetype="application/json")


@app.route("/pricing_instructions.json")
def pricing_instructions():
    # Assumes pricing_instructions.json lives in your project root
    return send_from_directory(app.root_path,
                               "pricing_instructions.json",
                               mimetype="application/json")


@app.route('/get_site_keys', methods=['GET'])
def get_site_keys():
    """
    Lookup sE_ID for a single 4-digit site_number.
    Always requires exactly one site_number query parameter.
    """
    try:
        site_number = (request.args.get("site_number") or "").strip()

        # Validate format: exactly 4 digits
        if not site_number.isdigit() or len(site_number) != 4:
            return jsonify({
                "error":
                "MISSING_OR_INVALID_SITE_NUMBER",
                "message":
                "You must provide exactly one 4-digit site_number (e.g., 1089)."
            }), 400

        # Use pytds paramstyle: %s (NOT ?)
        with connect_to_db("sites") as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT sE_ID, Site_Number, Name
                FROM sites.dbo.sites
                WHERE Site_Number = %s
            """, (site_number, ))
            row = cur.fetchone()

        if not row:
            return jsonify({
                "error":
                "SITE_NOT_FOUND",
                "message":
                f"No site found for site_number {site_number}"
            }), 404

        # pytds rows are tuples by default; use positional indexes
        return jsonify({
            "sE_ID": row[0],
            "site_number": str(row[1]),
            "site_name": row[2]
        }), 200

    except Exception as e:
        import traceback
        return jsonify({
            "error": "UNHANDLED_EXCEPTION",
            "message": str(e),
            "traceback": traceback.format_exc()
        }), 500


@app.route("/bucket-base-units", methods=["GET"])
def get_bucket_base_units():
    site_number = request.args.get("site_number")
    min_sf = int(request.args.get("min_sf", 0))
    if not site_number:
        return jsonify({"error": "Missing site_number parameter"}), 400

    def extract_dimensions(ug_key: str) -> str:
        base = ug_key.split(" - ")[0]
        match = re.match(
            r"^(\d+(?:\.\d+)?x\d+(?:\.\d+)?)(?:x(0|\d+(?:\.\d+)?))?", base)
        if match:
            if match.group(2) == "0" or match.group(2) is None:
                return match.group(1)
            return f"{match.group(1)}x{match.group(2)}"
        return "?"

    try:
        with connect_to_db("sE") as conn:
            buckets_query = f"""
                SELECT b.Site_Number, b.UG_KEY, b.Bucket, b.Base,
                       s.STANDARD_RATE as Current_Rate, u.[DESC]
                FROM sE.dbo.buckets b
                LEFT JOIN sE.dbo.unit_group_summary s
                    ON b.UG_KEY = s.UG_KEY
                    AND s.FACILITY_ID = (SELECT sE_ID FROM Sites.dbo.Sites WHERE Site_Number = {site_number})
                    AND s.SS_DATE > GETDATE() - 2
                LEFT JOIN sE.dbo.unit_groups u ON b.UG_KEY = u.UG_KEY
                WHERE b.Site_Number = {site_number} AND b.Base = 1
            """
            df = pd.read_sql(buckets_query, conn)

            if df.empty:
                return jsonify({
                    "error":
                    f"No base unit groups found for site {site_number}"
                }), 404

            df["Dimensions"] = df["UG_KEY"].apply(extract_dimensions)

            response = df[["Bucket", "Dimensions", "DESC",
                           "Current_Rate"]].rename(columns={
                               "DESC": "Description"
                           }).to_dict(orient="records")

            return jsonify(response), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/bucket-calculate-rates-v2", methods=["POST"])
def calculate_bucket_rates_v2():
    user = require_user_identity()
    if user is None:
        return jsonify({"error": "MISSING_IDENTITY"}), 428

    try:
        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({
                "error":
                "Expected JSON object with 'site_number' and 'proposed_rates'"
            }), 400

        # Support both wrapped and flat formats
        site_number = data.get("site_number")
        proposed_raw = data.get("proposed_rates") or data.get(
            "proposed_base_rates")

        if not site_number or not proposed_raw:
            params = data.get("params", {})
            site_number = site_number or params.get("site_number")
            proposed_raw = proposed_raw or params.get(
                "proposed_rates") or params.get("proposed_base_rates")

        if not site_number or not proposed_raw:
            return jsonify({"error":
                            "Missing site_number or proposed_rates"}), 400

        if isinstance(proposed_raw, str):
            try:
                proposed = json.loads(proposed_raw)
            except Exception:
                return jsonify(
                    {"error":
                     "proposed_rates must be a valid JSON object"}), 400
        else:
            proposed = proposed_raw

        if not isinstance(proposed, dict) or not proposed:
            return jsonify(
                {"error":
                 "proposed_rates must be a non-empty dictionary"}), 400

        # 2) Pull from SQL, lowercase all column names
        with connect_to_db("sE") as conn:
            buckets = pd.read_sql(
                f"SELECT * FROM sE.dbo.buckets WHERE Site_Number = {site_number}",
                conn)
            buckets.columns = buckets.columns.str.lower()

            cur = pd.read_sql(
                f"""
                SELECT ug_key, standard_rate AS current_rate
                FROM sE.dbo.unit_group_summary
                WHERE facility_id = (
                    SELECT sE_ID FROM Sites.dbo.Sites WHERE Site_Number = {site_number}
                )
                AND ss_date > GETDATE() - 2
                """,
                conn,
            )
            cur.columns = cur.columns.str.lower()

            ug = pd.read_sql("SELECT ug_key, [desc] FROM sE.dbo.unit_groups",
                             conn)
            ug.columns = ug.columns.str.lower()

            site_meta = pd.read_sql(
                f"SELECT onboard_date FROM Sites.dbo.Sites WHERE Site_Number = {site_number}",
                conn,
            )
            site_meta.columns = site_meta.columns.str.lower()

        onboard_date = pd.to_datetime(site_meta["onboard_date"].iloc[0])

        # 3) Merge tables
        merged = buckets.merge(cur, on="ug_key", how="left").merge(ug,
                                                                   on="ug_key",
                                                                   how="left")

        # 4) Compute weighted Final_rpu
        def compute_final_rpu(row):
            yrs = datetime.today().year - onboard_date.year
            w = min(yrs + 1, 3)
            a, s_, m = row["rpu_all"], row["rpu_site"], row["rpu_msa"]
            if pd.isna(m):
                return (a * (4 - w) + s_ * w) / 4
            return (a * (4 - w) + m * (4 - w) + s_ * w) / (2 * (4 - w) + w)

        merged["final_rpu"] = merged.apply(compute_final_rpu, axis=1)

        # 5) Merge in proposed base rates
        base_df = pd.DataFrame(proposed.items(),
                               columns=["bucket", "new_base_rate"])
        base_df["bucket"] = pd.to_numeric(base_df["bucket"], errors="coerce")
        base_df.columns = base_df.columns.str.lower()
        merged = merged.merge(base_df, on="bucket", how="left")

        # 6) Compute base RPU per bucket
        base_rpu = merged[merged["base"] == 1].groupby(
            "bucket")["final_rpu"].first().rename("base_rpu")
        merged = merged.merge(base_rpu, on="bucket", how="left")

        # 7) Calculate final STANDARD_RATE
        merged["standard_rate"] = ((merged["final_rpu"] / merged["base_rpu"]) *
                                   merged["new_base_rate"]).round()

        # 8) Select and save output
        out = merged[[
            "ug_key", "desc", "bucket", "current_rate", "standard_rate"
        ]]
        output = out.dropna(subset=["standard_rate"]).to_dict(orient="records")

        try:
            with open("bucket_rate_results.json", "w") as f:
                json.dump(output, f)
        except Exception as save_err:
            print(f"[Bucket Save] Failed to write results: {save_err}")

        return jsonify(output), 200

    except Exception as e:
        return jsonify({"error": f"Calculation failed: {e}"}), 500


def is_valid_se_id(s):
    # Accepts only UUIDs (change as needed for your sE_ID format)
    try:
        UUID(str(s))
        return True
    except Exception:
        return False


@app.route("/create-report", methods=["POST"])
def create_report():
    data = request.get_json()
    filter_facilities = data.get("filter_facilities")

    # Defensive: Must be a non-empty list
    if not isinstance(filter_facilities, list) or not filter_facilities:
        return jsonify({
            "error":
            "filter_facilities must be a non-empty list of sE_ID(s) (UUIDs), e.g., ['001cf8da-cb0b-470a-a238-2cd987f6fd20']"
        }), 400

    # All entries must be valid sE_IDs (UUID format)
    if not all(is_valid_se_id(f) for f in filter_facilities):
        return jsonify({
            "error":
            (f"Each entry in filter_facilities must be a valid sE_ID (UUID). "
             f"Received: {filter_facilities}. Example: ['001cf8da-cb0b-470a-a238-2cd987f6fd20']"
             )
        }), 400

    payload = {
        "report_request": {
            "report_name":
            "corporate_unoccupied_revenue_management_controller",
            "report_format": "csv",
            "report_params": {
                "filter_facilities": filter_facilities
            }
        }
    }

    url = f"{BASE_URL}/v1/companies/{COMPANY_ID}/report_requests"
    auth = OAuth1(API_KEY, API_SECRET)
    r = requests.post(url, json=payload, auth=auth)
    return jsonify(r.json()), r.status_code


@app.route("/report-status/<report_id>", methods=["GET"])
def report_status(report_id):
    print(f"[Direct Status Check] Received at {time.strftime('%X')}")

    # Optional: Delay to prevent hammering
    delay = 5  # seconds
    print(f"[Throttling] Sleeping for {delay} seconds...")
    time.sleep(delay)

    url = f"{BASE_URL}/v1/companies/{COMPANY_ID}/report_requests/{report_id}"
    auth = OAuth1(API_KEY, API_SECRET)
    r = requests.get(url, auth=auth, timeout=10)
    return jsonify(r.json()), r.status_code


@app.route("/report-data/<report_id>", methods=["GET"])
def report_data(report_id):
    time.sleep(5)
    print(f"[CALL] /report-data/{report_id} at {time.strftime('%X')}")

    auth = OAuth1(API_KEY, API_SECRET)
    status_url = f"{BASE_URL}/v1/companies/{COMPANY_ID}/report_requests/{report_id}"
    data_url = f"{BASE_URL}/v1/companies/{COMPANY_ID}/report_requests/{report_id}/completed_json"

    # Check status before fetching data
    try:
        print("[Report Fetch] Verifying report is ready...")
        status_resp = requests.get(status_url, auth=auth, timeout=10)
        status = status_resp.json().get("report_request", {}).get("status", "")
        print(f"[Report Fetch] Status: {status}")

        if status != "complete":
            print("[Report Fetch] Report is NOT ready — skipping fetch.")
            return jsonify({"error": "Report not ready"}), 202

        # If ready, fetch the full report
        r = requests.get(data_url, auth=auth, timeout=10)
        if r.status_code != 200:
            print(
                f"[Error] Failed to fetch report data for ID {report_id}: {r.status_code}"
            )
            return jsonify({"error": "Failed to fetch report"}), 500

        data = r.json()

        with open("latest_report.json", "w") as f:
            json.dump(data, f)

        with open("latest_report_id.txt", "w") as id_file:
            id_file.write(report_id)

        print(f"[Cache] Cached latest_report.json and report ID: {report_id}")

        # Save a slimmed-down CSV for filtering
        try:
            report_data = data["report_request"]["report"]
            df = pd.DataFrame(report_data)

            filtered_df = df[[
                "Group Key", "Size", "Amenities", "Unit Type",
                "Current Standard Rate", "Total Units", "Occupied",
                "Available", "Vacancy", "Occupancy", "Days Since Last Move-In",
                "Average Rent"
            ]]

            filtered_df.to_csv("filtered_unit_summary.csv", index=False)
            print(
                f"[Cache] Saved filtered_unit_summary.csv with {len(filtered_df)} rows"
            )

        except Exception as e:
            print(f"[Cache] Failed to write filtered summary: {e}")

        return jsonify(data), 200

    except Exception as e:
        print(f"[Report Fetch] Error during processing: {e}")
        return jsonify({"error":
                        "Unexpected error while fetching report"}), 500


def load_cached_report(report_id):
    try:
        if os.path.exists("latest_report_id.txt") and os.path.exists(
                "latest_report.json"):
            with open("latest_report_id.txt", "r") as id_file:
                cached_id = id_file.read().strip()
            if cached_id == report_id:
                print(
                    f"[Cache] Using cached latest_report.json for ID: {report_id}"
                )
                with open("latest_report.json", "r") as f:
                    return json.load(f)
    except Exception as e:
        print(f"[Cache] Failed to load cached report: {e}")

    return None  # fallback to re-download if needed


def parse_sqft(size_str: str) -> float:
    """
    Accepts things like '5x10', '4.5x7', '10X15', returns width*depth as float.
    Returns None if it can't parse.
    """
    if not size_str:
        return None
    m = re.match(r'^\s*(\d+(?:\.\d+)?)\s*[xX]\s*(\d+(?:\.\d+)?)\s*$',
                 size_str.strip())
    if not m:
        return None
    try:
        return float(m.group(1)) * float(m.group(2))
    except ValueError:
        return None


@app.route("/filter-report", methods=["GET", "POST"])
def filter_report():
    """
    Loads the latest unit summary report (cached at latest_report.json),
    applies optional filters (size, amenities, unit_type, min_sf, max_sf),
    and returns only key preview columns, capped by max_rows.

    Notes:
      - If `size` is supplied (e.g., "10x10 du"), it must EXACTLY match the normalized
        "Size + Amenities" pair (case-insensitive, extra spaces collapsed).
        Example: size="10x10 du" will NOT match "10x10 du econ".
      - If `amenities` is supplied, it must EXACTLY match the normalized Amenities field.
    """

    # ---------- helpers ----------
    def norm(s: str) -> str:
        # lower, trim, collapse internal whitespace
        return " ".join((s or "").strip().lower().split())

    def get_param(name, default=None):
        if request.method == "POST":
            body = request.get_json(silent=True) or {}
            return body.get(name, default)
        # GET
        return request.args.get(name, default)

    # ---------- 1) Parse inputs ----------
    size_raw = get_param("size", "")
    amenities_raw = get_param("amenities", "")
    unit_type_raw = get_param("unit_type", "")
    min_sf_raw = get_param("min_sf")
    max_sf_raw = get_param("max_sf")
    max_rows_raw = get_param("max_rows", 20)

    # Normalize strings
    size = norm(size_raw)
    amenities = norm(amenities_raw)
    unit_type = norm(unit_type_raw)

    # Amenity aliases
    AMENITY_ALIASES = {
        "du": "drive up",
        "drive-up": "drive up",
        "cc": "climate controlled",
        "climate": "climate controlled"
    }
    if amenities in AMENITY_ALIASES:
        amenities = AMENITY_ALIASES[amenities]

    # max_rows: enforce 1..100
    try:
        max_rows = int(max_rows_raw)
    except (TypeError, ValueError):
        max_rows = 20
    max_rows = min(max(max_rows, 1), 100)

    # numeric bounds (nullable-friendly)
    try:
        min_sf = float(min_sf_raw) if min_sf_raw is not None else None
    except (TypeError, ValueError):
        min_sf = None
    try:
        max_sf = float(max_sf_raw) if max_sf_raw is not None else None
    except (TypeError, ValueError):
        max_sf = None

    app.logger.info(
        "[Filter-report] size=%r amenities=%r unit_type=%r min_sf=%s max_sf=%s max_rows=%d",
        size, amenities, unit_type, min_sf, max_sf, max_rows)

    # ---------- 2) Load cached report ----------
    if not os.path.exists("latest_report.json"):
        return jsonify({
            "error":
            "No cached report found. Please generate a report first."
        }), 404

    try:
        with open("latest_report.json", "r") as f:
            report_json = json.load(f)
        report_data = report_json.get("report_request", {}).get("report", [])
        df = pd.DataFrame(report_data)
        app.logger.info("[Filter-report] loaded %d total rows", len(df))
    except Exception as e:
        app.logger.exception("[Filter-report] load error: %s", e)
        return jsonify({"error": "Failed to load cached report"}), 500

    # ---------- 3) Derive square footage ----------
    if "Size" in df.columns:
        df["Square_Footage"] = df["Size"].apply(parse_sqft)
    else:
        df["Square_Footage"] = None

    # Precompute normalized columns used for matching
    df["_norm_size"] = df.get("Size", "").astype(str).map(norm)
    df["_norm_amenities"] = df.get("Amenities", "").astype(str).map(norm)
    df["_norm_unit_type"] = df.get("Unit Type", "").astype(str).map(norm)
    # combined "size + amenities" for exact-matching the size filter
    df["_norm_size_plus_amen"] = (df["_norm_size"] + " " +
                                  df["_norm_amenities"]).str.strip()

    # ---------- 4) Apply matching ----------
    mask = pd.Series(True, index=df.index)

    # If `size` provided, require EXACT match against normalized "Size + Amenities"
    if size:
        mask &= (df["_norm_size_plus_amen"] == size)

    # If `amenities` provided, require EXACT match of normalized Amenities
    if amenities:
        mask &= (df["_norm_amenities"] == amenities)

    # If `unit_type` provided, allow substring match (normalized)
    if unit_type:
        mask &= df["_norm_unit_type"].str.contains(re.escape(unit_type),
                                                   na=False)

    # Square footage bounds
    if min_sf is not None:
        mask &= df["Square_Footage"].apply(lambda v: (v is not None) and
                                           (v >= min_sf))
    if max_sf is not None:
        mask &= df["Square_Footage"].apply(lambda v: (v is not None) and
                                           (v <= max_sf))

    filtered = df[mask]
    total_matched = int(filtered.shape[0])
    app.logger.info("[Filter-report] %d rows matched filters", total_matched)

    if total_matched == 0:
        return jsonify({"warning":
                        "No units matched the filter criteria."}), 200

    # ---------- 5) Cap to max_rows ----------
    if total_matched > max_rows:
        sliced = filtered.iloc[:max_rows]
        warning = f"Showing first {max_rows} of {total_matched} matching rows."
    else:
        sliced = filtered
        warning = None

    # ---------- 6) Slim to only the preview columns ----------
    work_cols = [
        "Group Key", "Size", "Square_Footage", "Amenities",
        "Current Standard Rate", "Occupancy", "Average Rent",
        "Days Since Last Move-In"
    ]
    available = [c for c in work_cols if c in sliced.columns]
    preview = sliced[available]

    # ---------- 7) Build response ----------
    response = {"rows": preview.to_dict(orient="records")}
    if warning:
        response["warning"] = warning

    app.logger.info("[Filter-report] returning %d rows", len(preview))
    return jsonify(response), 200


@app.route("/upload-report", methods=["POST"])
def upload_report():
    created_by_id = request.form.get("created_by_id")
    file = request.files.get("file")

    if not file:
        return jsonify({"error": "No file uploaded"}), 400

    print("[Upload] Starting upload with retry logic...")
    r = upload_with_retries(file, created_by_id)

    if r is None:
        return jsonify({"error": "Upload failed after retries"}), 500

    return jsonify(r.json()), r.status_code


def decode_group_key(val: str) -> str:
    try:
        return base64.b64decode(val).decode("utf-8")
    except Exception:
        return val  # fallback: return original if decode fails


# --- Require an identity or signal missing ---
def require_user_identity():
    user = get_current_user()  # your existing lookup
    if not user:
        # signal to ChatGPT layer that we need the user set first
        return None
    return user


def convert_types(obj):
    if isinstance(obj, dict):
        return {k: convert_types(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [convert_types(v) for v in obj]
    if isinstance(obj, np.integer):
        return int(obj)
    if isinstance(obj, np.floating):
        return float(obj)
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    return obj


@app.route("/wait-until-ready/<report_id>", methods=["GET"])
def wait_until_ready(report_id):
    success = poll_until_report_ready(report_id)
    if success:
        return jsonify({"status": "complete"})
    else:
        return jsonify({"status": "timeout"}), 504


# --- User identity persistence (single active user) ---
def get_current_user():
    try:
        with open("current_user.txt") as f:
            return f.read().strip()
    except FileNotFoundError:
        return None


@app.route("/set-user", methods=["POST"])
def set_user():
    payload = request.get_json(silent=True) or {}
    user = payload.get("user") or payload.get("user_id")
    if not user:
        return jsonify({"error": "Missing user"}), 400
    user = user.strip()
    with open("current_user.txt", "w") as f:
        f.write(user)
    return jsonify({"status": "ok", "user": user}), 200


@app.route('/gpt-upload-report', methods=['POST'])
def gpt_upload_report():
    data = request.get_json(force=True, silent=True) or {}
    change_source = data.get('change_source')
    csv_data = data.get('csv_data')
    test_mode = data.get('test_mode', False)

    # Require change_source for all uploads
    if not change_source:
        return jsonify({"error": "Missing required field: change_source"}), 400

    # Require CSV for manual uploads (and optionally for bucket if needed)
    if change_source == "manual" or (change_source == "bucket" and csv_data):
        if not csv_data:
            return jsonify({"error": "Missing required field: csv_data"}), 400
        # Base64 validation
        try:
            decoded_csv = base64.b64decode(csv_data, validate=True)
        except (binascii.Error, ValueError):
            return jsonify({"error":
                            "Invalid base64 encoding for csv_data"}), 400
    else:
        decoded_csv = None

    # Require identity before proceeding
    created_by_id = require_user_identity()
    if created_by_id is None:
        return jsonify(convert_types({"error": "MISSING_IDENTITY"})), 428

    try:
        if change_source == "bucket":
            # Pass decoded_csv if your bucket handler uses it, else omit
            return handle_bucket_upload(created_by_id, test_mode)

        elif change_source == "manual":
            return handle_manual_upload(decoded_csv, created_by_id, test_mode)

        else:
            return jsonify({"error": "Invalid change_source"}), 400

    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        return jsonify({
            "error": f"Unhandled error: {e}",
            "traceback": tb
        }), 500


def handle_bucket_upload(created_by_id, test_mode=False):
    if not os.path.exists("bucket_rate_results.json"):
        return jsonify({"error": "Missing bucket results file"}), 400

    patch_data = json.load(open("bucket_rate_results.json"))
    patch_df = pd.DataFrame(patch_data)
    patch_df['ug_key'] = patch_df['ug_key'].astype(str).str.strip()
    patch_df['New Standard Rate'] = patch_df['standard_rate']
    patch_df['New Cross Out Rate'] = (patch_df['standard_rate'] * 1.3).round()

    return finalize_upload(patch_df,
                           created_by_id,
                           test_mode,
                           merge_key="base64",
                           change_source="bucket")


def handle_manual_upload(raw_csv, created_by_id, test_mode=False):
    try:
        try:
            decoded_csv = base64.b64decode(raw_csv).decode("utf-8")
        except Exception:
            decoded_csv = raw_csv  # fallback plain text
        patch_df = pd.read_csv(StringIO(decoded_csv))
    except Exception as e:
        return jsonify({
            "error": "CSV-parse failure",
            "exception": str(e)
        }), 400

    expected_cols = ['Group Key', 'New Standard Rate', 'New Cross Out Rate']
    if not all(col in patch_df.columns for col in expected_cols):
        return jsonify({
            "error": "Missing required columns",
            "columns": patch_df.columns.tolist()
        }), 400

    return finalize_upload(patch_df,
                           created_by_id,
                           test_mode,
                           merge_key="decoded",
                           change_source="manual")


def finalize_upload(patch_df,
                    created_by_id,
                    test_mode=False,
                    merge_key="decoded",
                    change_source="manual"):
    if not os.path.exists("latest_report.json"):
        return jsonify({"error": "Missing report file"}), 404

    with open("latest_report.json", "r") as f:
        report_json = json.load(f)

    report_rows = report_json.get("report_request", {}).get("report", [])
    full_df = pd.DataFrame(report_rows)

    if 'Group Key' not in full_df.columns:
        return jsonify({"error": "Missing Group Key in report"}), 400

    full_df['Group Key Base64'] = full_df['Group Key'].astype(str).str.strip()

    if merge_key == "base64":
        merged = pd.merge(
            full_df,
            patch_df[['ug_key', 'New Standard Rate', 'New Cross Out Rate']],
            left_on='Group Key Base64',
            right_on='ug_key',
            how='left')
        merged['Group Key'] = merged['Group Key Base64']

    else:  # merge_key == "decoded"
        decoded = []
        for key in full_df['Group Key']:
            try:
                decoded.append(base64.b64decode(key).decode('ascii'))
            except Exception:
                decoded.append("")
        full_df['decoded_key'] = decoded
        full_df['Group Key'] = full_df['decoded_key']
        patch_df['Group Key'] = patch_df['Group Key'].astype(str).str.strip()

        merged = pd.merge(
            full_df,
            patch_df[['Group Key', 'New Standard Rate', 'New Cross Out Rate']],
            on='Group Key',
            how='left')

    # Always reassign merged columns after merge (handle _y columns)
    if 'New Standard Rate_y' in merged.columns:
        merged['New Standard Rate'] = merged['New Standard Rate_y']
    if 'New Cross Out Rate_y' in merged.columns:
        merged['New Cross Out Rate'] = merged['New Cross Out Rate_y']

    if not any(col.startswith('New Standard Rate') for col in merged.columns):
        overlap = set(full_df['Group Key Base64']) & set(
            patch_df.get('ug_key', patch_df.get('Group Key', [])))
        return jsonify({
            "error": "Merge failed — 'New Standard Rate' column missing.",
            "merged_columns": merged.columns.tolist(),
            "patch_sample": patch_df.head(3).to_dict(),
            "full_sample": full_df[['Group Key']].head(3).to_dict(),
            "group_key_overlap_count": len(overlap),
            "group_key_overlap_keys": list(overlap)[:5]
        }), 400

    updated_rows = merged['New Standard Rate'].notna().sum()
    print(f"[Upload] Updated rows: {updated_rows}")

    # Compute New Cross Out Rate (if not set, set as 1.3x Standard)
    merged['New Cross Out Rate'] = (merged['New Standard Rate'] * 1.3).round()

    upload_df = merged[[
        'Facility ID', 'Group Key', 'Current Standard Rate',
        'New Standard Rate', 'Current Managed Rate', 'New Managed Rate',
        'New Cross Out Rate'
    ]]

    if test_mode:
        return jsonify({
            "status": "validated",
            "row_count": int(upload_df.shape[0]),
            "csv_preview": upload_df.head(5).to_dict()
        })

    final_csv = upload_df.to_csv(index=False)
    file_stream = BytesIO(final_csv.encode("utf-8"))
    file_stream.name = "final_rate_upload.csv"

    r = upload_with_retries(file_stream, created_by_id)
    if not r:
        return jsonify({"error": "Upload failed after retries"}), 500

    try:
        resp_json = r.json()
    except Exception:
        return jsonify({
            "error": "Upload succeeded but response not JSON",
            "text": r.text
        }), 500

    # Only call the log function once you have resp_json!
    log_rate_changes_to_db(merged,
                           created_by_id,
                           change_source=change_source,
                           batch_id=resp_json.get('event_batch', {}).get('id'))

    return jsonify({
        "status": "uploaded",
        "updated_rows": int(updated_rows),
        "batch_id": resp_json.get('event_batch', {}).get('id'),
        "user": created_by_id
    })


def log_rate_changes_to_db(merged_df, created_by_id, change_source, batch_id):
    try:
        changed = merged_df[merged_df['New Standard Rate'].notna()]
        if changed.empty:
            print("[Logging] No changes to log.")
            return

        if 'Facility Number' in merged_df.columns:
            site_number = str(merged_df['Facility Number'].iloc[0])
        else:
            site_number = None

        with connect_to_db('sE') as conn:
            cur = conn.cursor()
            for _, row in changed.iterrows():
                cur.execute(
                    '''
                    INSERT INTO sE.dbo.rate_change_log
                      (user_id, site_number, group_key,
                       old_standard_rate, new_standard_rate,
                       old_cross_out_rate, new_cross_out_rate,
                       source, batch_id)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ''', (created_by_id, site_number, row['Group Key'],
                          float(row['Current Standard Rate']) if pd.notnull(
                              row['Current Standard Rate']) else None,
                          float(row['New Standard Rate'])
                          if pd.notnull(row['New Standard Rate']) else None,
                          float(row['Current Cross Out Rate']) if pd.notnull(
                              row.get('Current Cross Out Rate')) else None,
                          float(row['New Cross Out Rate']) if pd.notnull(
                              row.get('New Cross Out Rate')) else None,
                          change_source, batch_id))
            conn.commit()
        print(f"[Logging] Logged {len(changed)} rate changes.")

    except Exception as e:
        print(f"[Logging] Failed to log changes: {e}")
        import traceback
        traceback.print_exc()


@app.route("/")
def hello():
    return "Storedge Proxy API is running."


@app.route("/health")
def health():
    return "OK", 200


if __name__ == "__main__":
    app.run(debug=True)
    # app.run(host="0.0.0.0", port=5000, debug=True)
