from flask import Flask, request, jsonify, send_from_directory
from requests_oauthlib import OAuth1
import requests
import os
import time
import json
import pandas as pd
from io import BytesIO, StringIO
from dotenv import load_dotenv
import re
# import pytds
# from pytds import tds_base
from datetime import datetime, timedelta
import numpy as np
import base64
import binascii
import traceback
from uuid import UUID
import string

"""
Direct‑Change Only backend for Storedge Pricing
----------------------------------------------
This version removes ALL bucket/base‑rate functionality.
Supported flow:
  /create-report → /wait-until-ready → /report-data (cache report)
  /filter-report (optional preview subset)
  /preview/auto (DIRECT ONLY)
  /confirm (writes CSV + uploads)
  /gpt-upload-report (manual/direct only)

Notes:
- Group Key handling: accepts Base64 "Group Key" from report, or plain UG_KEY.
- Upload: respects UPLOAD_GROUP_KEY_MODE ("base64" | "plain").
- Identity: /set-user must be called before /confirm or /gpt-upload-report.
"""

load_dotenv()

app = Flask(__name__)

# Configure app for deployment
app.config['JSON_SORT_KEYS'] = False
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True

# Add startup logging
print("Starting Storedge Proxy API...")
print(f"Flask app initialized: {app.name}")
print(f"Base URL configured: {os.getenv('BASE_URL', 'https://api.storedgefms.com')}")

# Add error handlers for deployment
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Not Found", "message": "The requested endpoint was not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal Server Error", "message": "An unexpected error occurred"}), 500

@app.errorhandler(403)
def forbidden(error):
    return jsonify({"error": "Forbidden", "message": "Access denied"}), 403

# === Storedge API Config ===
API_KEY = os.getenv("STOREDGE_API_KEY")
API_SECRET = os.getenv("STOREDGE_API_SECRET")
BASE_URL = "https://api.storedgefms.com"
# Prefer environment COMPANY_ID; fallback to legacy hardcoded (encourage override)
COMPANY_ID = os.getenv("COMPANY_ID", "90df0cad-f32f-4c1f-8d78-9beda9622b34")

# Validate required environment variables for deployment
def validate_environment():
    """Validate that required environment variables are set for deployment."""
    missing_vars = []
    if not API_KEY:
        missing_vars.append("STOREDGE_API_KEY")
    if not API_SECRET:
        missing_vars.append("STOREDGE_API_SECRET")
    
    if missing_vars:
        print(f"WARNING: Missing required environment variables: {', '.join(missing_vars)}")
        print("The application may not function correctly without these variables.")
        # Don't fail startup - just warn
    
# Validate environment on import
validate_environment()

# === Lightweight Bearer gate for GPT Action calls ===
# Set PROXY_BEARER in your Replit Secrets; GPT Action will send Authorization: Bearer <token>
PROXY_BEARER = os.getenv("PROXY_BEARER", "")

def require_bearer(req):
    """Enforce a static bearer secret for sensitive proxy endpoints.
    Returns a (resp, status) tuple if forbidden, else None.
    """
    if not PROXY_BEARER:  # if unset, skip (development convenience)
        return None
    hdr = (req.headers.get("Authorization") or "").strip()
    if not hdr.startswith("Bearer "):
        return jsonify({"error": "FORBIDDEN", "message": "Missing bearer token"}), 403
    token = hdr.split(" ", 1)[1]
    if token != PROXY_BEARER:
        return jsonify({"error": "FORBIDDEN", "message": "Invalid bearer token"}), 403
    return None


# === Caching (in‑process, per dyno) ===
FACILITIES_CACHE_TTL = int(os.getenv("FACILITIES_CACHE_TTL", 300))  # seconds
UNITS_CACHE_TTL = int(os.getenv("UNITS_CACHE_TTL", 120))            # seconds

_CACHE = {
    "facilities_short": {"ts": None, "data": None},
    "units": {}  # facility_id -> {ts: datetime, data: list}
}


def _cache_get(kind: str, facility_id: str | None = None):
    now = datetime.utcnow()
    if kind == "facilities_short":
        entry = _CACHE["facilities_short"]
        if not entry["ts"] or not entry["data"]:
            return None
        age = (now - entry["ts"]).total_seconds()
        if age > FACILITIES_CACHE_TTL:
            return None
        return {"data": entry["data"], "age": age, "ttl": FACILITIES_CACHE_TTL}
    if kind == "units" and facility_id:
        entry = _CACHE["units"].get(facility_id)
        if not entry:
            return None
        age = (now - entry["ts"]).total_seconds()
        if age > UNITS_CACHE_TTL:
            return None
        return {"data": entry["data"], "age": age, "ttl": UNITS_CACHE_TTL}
    return None


def _cache_set(kind: str, data, facility_id: str | None = None):
    now = datetime.utcnow()
    if kind == "facilities_short":
        _CACHE["facilities_short"] = {"ts": now, "data": data}
    elif kind == "units" and facility_id:
        _CACHE["units"][facility_id] = {"ts": now, "data": data}


# === Validation Guards ===
DOOR_TYPES = {"none", "roll_up", "swing"}
ACCESS_TYPES = {"indoor", "outdoor"}

ALLOWED_UPDATE_FIELDS = {
    # core identifier
    "id",
    # typical mutable attributes (extend as needed)
    "door_type", "access_type", "rentable", "unit_type", "unit_number", "size",
    # Add other allowed fields here from Storedge docs if desired
}

ALLOWED_CREATE_FIELDS = {
    "unit_number", "size", "door_type", "access_type", "rentable", "unit_type"
}


def _validate_enum(field, value, allowed, errors):
    if value is None:
        return
    if str(value).lower() not in allowed:
        errors.append({"field": field, "value": value, "allowed": sorted(list(allowed))})


def validate_bulk_update_payload(body: dict):
    errors = []
    cleaned_units = []
    units = body.get("units")
    if not isinstance(units, list) or not units:
        return None, [{"error": "UNITS_REQUIRED", "message": "Provide a non-empty 'units' array."}]
    seen_ids = set()
    for idx, u in enumerate(units):
        if not isinstance(u, dict):
            errors.append({"index": idx, "error": "UNIT_NOT_OBJECT"})
            continue
        uid = u.get("id")
        if not uid:
            errors.append({"index": idx, "error": "MISSING_ID"})
            continue
        if uid in seen_ids:
            errors.append({"index": idx, "error": "DUPLICATE_ID", "id": uid})
            continue
        seen_ids.add(uid)
        # Filter allowed fields
        filtered = {k: v for k, v in u.items() if k in ALLOWED_UPDATE_FIELDS and k != "id"}
        # Enumerations
        if "door_type" in filtered:
            _validate_enum("door_type", filtered["door_type"], DOOR_TYPES, errors)
        if "access_type" in filtered:
            _validate_enum("access_type", filtered["access_type"], ACCESS_TYPES, errors)
        # Remove empty string values (treat as omission rather than blanking)
        filtered = {k: v for k, v in filtered.items() if v not in (None, "")}
        if not filtered:
            errors.append({"index": idx, "error": "NO_CHANGES", "id": uid})
            continue
        cleaned_units.append({"id": uid, **filtered})
    if errors:
        return None, errors
    return {"units": cleaned_units}, None


def validate_bulk_create_payload(body: dict):
    errors = []
    cleaned_units = []
    units = body.get("units")
    if not isinstance(units, list) or not units:
        return None, [{"error": "UNITS_REQUIRED"}]
    seen_numbers = set()
    for idx, u in enumerate(units):
        if not isinstance(u, dict):
            errors.append({"index": idx, "error": "UNIT_NOT_OBJECT"})
            continue
        if "unit_number" not in u or not str(u.get("unit_number")).strip():
            errors.append({"index": idx, "error": "MISSING_UNIT_NUMBER"})
            continue
        un = str(u["unit_number"]).strip()
        if un in seen_numbers:
            errors.append({"index": idx, "error": "DUPLICATE_UNIT_NUMBER", "unit_number": un})
            continue
        seen_numbers.add(un)
        filtered = {k: v for k, v in u.items() if k in ALLOWED_CREATE_FIELDS}
        if "door_type" in filtered:
            _validate_enum("door_type", filtered["door_type"], DOOR_TYPES, errors)
        if "access_type" in filtered:
            _validate_enum("access_type", filtered["access_type"], ACCESS_TYPES, errors)
        cleaned_units.append(filtered)
    if errors:
        return None, errors
    return {"units": cleaned_units}, None


def validate_make_rentable_payload(body: dict):
    errors = []
    cleaned_units = []
    units = body.get("units")
    if not isinstance(units, list) or not units:
        return None, [{"error": "UNITS_REQUIRED"}]
    for idx, u in enumerate(units):
        if not isinstance(u, dict):
            errors.append({"index": idx, "error": "UNIT_NOT_OBJECT"})
            continue
        uid = u.get("id")
        if not uid:
            errors.append({"index": idx, "error": "MISSING_ID"})
            continue
        rentable = u.get("rentable")
        if rentable not in (True, False):
            errors.append({"index": idx, "error": "INVALID_RENTABLE", "id": uid})
            continue
        cleaned_units.append({"id": uid, "rentable": rentable})
    if errors:
        return None, errors
    return {"units": cleaned_units}, None

# === Upload behavior ===
# Some Storedge imports expect the Base64 "Group Key" (exact value from the report).
# If your tenant expects the decoded/plain key, flip this to "plain".
UPLOAD_GROUP_KEY_MODE = os.getenv("UPLOAD_GROUP_KEY_MODE", "base64").lower()  # "base64" | "plain"

# --- Guardrail constants (tune as needed) ---
AGGRESSIVE_PCT = 0.15  # ≥15% → WARN
HIGH_OCC_THRESHOLD = 0.90  # 90%
LOW_OCC_THRESHOLD = 0.90   # 90%
MIN_VACANTS_FOR_DROP = 5

# === Shorthand Mapping and Expansion (used by /filter-report helpers) ===
SHORTHAND_MAP = {
    "cc": "climate controlled",
    "e": "elevator access",
    "du": "drive up",
    "g": "1st floor",
    "locker": "reduced height",
    "econ": "economy"
}


def expand_shorthand(text):
    tokens = re.split(r"[,\s/]+", (text or "").lower())
    expanded = [SHORTHAND_MAP.get(token.strip(), token.strip()) for token in tokens if token]
    return " ".join(expanded)


# === Utilities: key normalization ===
def safe_b64_decode(s: str) -> str | None:
    """Attempt strict base64 decode; return None if unlikely."""
    try:
        if not isinstance(s, str) or not s:
            return None
        raw = base64.b64decode(s, validate=True)
        txt = raw.decode("utf-8", errors="ignore")
        if txt and (sum(ch in string.printable for ch in txt) / max(1, len(txt))) > 0.9:
            return txt
    except Exception:
        pass
    return None


def make_group_key_plain_column(df: pd.DataFrame, report_key_col: str = "Group Key") -> pd.DataFrame:
    """Adds group_key_plain decoded if Base64, else original string."""
    if report_key_col not in df.columns:
        raise ValueError(f"Missing '{report_key_col}' in report DataFrame")
    df = df.copy()
    decoded = df[report_key_col].astype(str).map(safe_b64_decode)
    df["group_key_plain"] = decoded.fillna(df[report_key_col]).astype(str).str.strip()
    return df


def coerce_patch_group_key(patch_df: pd.DataFrame) -> pd.DataFrame:
    """Normalize incoming patch frames to have: group_key_plain column."""
    patch_df = patch_df.copy()
    if "group_key_plain" in patch_df.columns:
        patch_df["group_key_plain"] = patch_df["group_key_plain"].astype(str).str.strip()
        return patch_df
    if "ug_key" in patch_df.columns:
        patch_df["group_key_plain"] = patch_df["ug_key"].astype(str).str.strip()
        return patch_df
    if "Group Key" in patch_df.columns:
        patch_df["Group Key"] = patch_df["Group Key"].astype(str).str.strip()
        decoded = patch_df["Group Key"].map(safe_b64_decode)
        patch_df["group_key_plain"] = decoded.fillna(patch_df["Group Key"]).astype(str).str.strip()
        return patch_df
    raise ValueError("Patch data must include 'ug_key' or 'Group Key' or 'group_key_plain'.")


# === MSSQL Helper: Connect to dynamic database ===
def connect_to_db(db_name):
    try:
        import pytds
        from pytds import tds_base
    except ImportError:
        raise ImportError("pytds not available - database features disabled")
    
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
        tds_version=tds_base.TDS74,  # SQL Server 2012+
    )


# === Helper: Smart Polling for Report Completion ===
def poll_until_report_ready(report_id, timeout=120, interval=10):
    auth = OAuth1(API_KEY, API_SECRET)
    elapsed = 0
    while elapsed < timeout:
        print(f"[Polling] Checking status for report {report_id} at {time.strftime('%X')} (elapsed: {elapsed}s)")
        url = f"{BASE_URL}/v1/companies/{COMPANY_ID}/report_requests/{report_id}"
        try:
            response = requests.get(url, auth=auth, timeout=10)
            if response.status_code != 200:
                print(f"[Polling] Error: status code {response.status_code}")
                return None
            status = response.json().get("report_request", {}).get("status", "unknown")
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
    file.seek(0)
    files = {"unoccupied_revenue_management[file]": (file.name, file.read(), "text/csv")}
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


# === Health + Static ===
@app.route("/ping")
def ping():
    return jsonify(status="ok"), 200


# === Facilities / Units Proxy (GPT Action) ===
@app.get("/facilities/short")
def facilities_short():
    """Return abbreviated facilities list (id + label) via Storedge corporate endpoint.
    Docs: /docs/private/api-v1-corporate-facilities/short.html
    """
    guard = require_bearer(request)
    if guard: return guard
    refresh = request.args.get("refresh") == "1"
    cached = None if refresh else _cache_get("facilities_short")
    if cached:
        return jsonify({"cached": True, **cached}), 200
    url = f"{BASE_URL}/v1/companies/{COMPANY_ID}/facilities/short"
    r = requests.get(url, auth=OAuth1(API_KEY, API_SECRET), timeout=30)
    try:
        data = r.json()
    except Exception:
        return (r.text, r.status_code, {"Content-Type": "application/json"})
    if r.status_code == 200:
        _cache_set("facilities_short", data)
    return jsonify({"cached": False, "data": data}), r.status_code


@app.get("/facilities/<facility_id>/units")
def list_units(facility_id):
    """List units for a facility with pagination and search support.
    
    Query params:
    - page: Page number (default: 1)
    - per_page: Units per page (default: 10, max: 100 to prevent timeouts)
    - search: Search term to filter unit names/numbers
    - name_contains: Filter units where name contains this text
    - unit_number_contains: Filter units where unit_number contains this text
    """
    guard = require_bearer(request)
    if guard: return guard

    # Parse and validate pagination parameters with smaller defaults
    try:
        # Check for limit/offset style first
        limit = request.args.get("limit")
        offset = request.args.get("offset")
        
        if limit is not None or offset is not None:
            # Convert limit/offset to page/per_page with smaller max to prevent timeouts
            limit = max(1, min(100, int(limit or "10")))
            offset = max(0, int(offset or "0"))
            page = (offset // limit) + 1
            per_page = limit
        else:
            # Use page/per_page style with smaller defaults
            page = max(1, int(request.args.get("page", "1")))
            per_page = max(1, min(100, int(request.args.get("per_page", "10"))))
            
    except ValueError as e:
        return jsonify({
            "error": "INVALID_PAGINATION", 
            "message": "Pagination parameters must be positive integers",
            "supported_params": "Use either (page, per_page) or (limit, offset)",
            "details": str(e),
            "note": "Max per_page is 100 to prevent timeouts"
        }), 400
    
    # Get search parameters
    search_term = request.args.get("search", "").strip()
    name_contains = request.args.get("name_contains", "").strip()
    unit_number_contains = request.args.get("unit_number_contains", "").strip()

    # Build Storedge API URL with search parameters
    params = {"page": page, "per_page": per_page}
    
    # Add search filters if provided (Storedge API may support these)
    if search_term:
        params["search"] = search_term
    if name_contains:
        params["name_contains"] = name_contains  
    if unit_number_contains:
        params["unit_number_contains"] = unit_number_contains
    
    url = f"{BASE_URL}/v1/{facility_id}/units"
    
    try:
        r = requests.get(url, params=params, auth=OAuth1(API_KEY, API_SECRET), timeout=60)
        
        if r.status_code != 200:
            return jsonify({
                "error": "STOREDGE_API_ERROR",
                "status_code": r.status_code,
                "response": r.text[:500]
            }), r.status_code
            
        data = r.json()
        
        # Apply client-side filtering if Storedge doesn't support server-side filtering
        units_data = data.get("data", {}).get("units", [])
        if (search_term or name_contains or unit_number_contains) and units_data:
            filtered_units = []
            for unit in units_data:
                unit_name = str(unit.get("name", "")).lower()
                unit_number = str(unit.get("unit_number", "")).lower()
                
                match = True
                if search_term and not (search_term.lower() in unit_name or search_term.lower() in unit_number):
                    match = False
                if name_contains and name_contains.lower() not in unit_name:
                    match = False
                if unit_number_contains and unit_number_contains.lower() not in unit_number:
                    match = False
                    
                if match:
                    filtered_units.append(unit)
            
            # Update the data with filtered results
            data["data"] = filtered_units
            data["filtered_count"] = len(filtered_units)
            data["total_before_filter"] = len(units_data)
        
        # Include pagination metadata in response
        offset = (page - 1) * per_page
        
        response_data = {
            "data": data,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "limit": per_page,
                "offset": offset,
                "requested_facility_id": facility_id,
                "search_applied": bool(search_term or name_contains or unit_number_contains),
                "note": "Supports search, name_contains, unit_number_contains filters"
            }
        }
        
        return jsonify(response_data), r.status_code
        
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "REQUEST_FAILED", "message": str(e)}), 500
    except ValueError:
        # JSON decode error
        return (r.text, r.status_code, {"Content-Type": "application/json"})


@app.put("/facilities/<facility_id>/units/bulk_update")
def bulk_update_units(facility_id):
    """Bulk update unit attributes.
    Docs: /docs/private/api-v1-units/bulk_update.html
    Body shape: {"units": [{"id": "<unit_uuid>", ...fields...}]}
    """
    guard = require_bearer(request)
    if guard: return guard
    raw_body = request.get_json(silent=True) or {}
    cleaned, errors = validate_bulk_update_payload(raw_body)
    if errors:
        return jsonify({"error": "VALIDATION_FAILED", "details": errors}), 400
    url = f"{BASE_URL}/v1/{facility_id}/units/bulk_update"
    r = requests.put(url, json=cleaned, auth=OAuth1(API_KEY, API_SECRET), timeout=60)
    try:
        return jsonify(r.json()), r.status_code
    except Exception:
        return (r.text, r.status_code, {"Content-Type": "application/json"})


@app.post("/facilities/<facility_id>/units/bulk_create")
def bulk_create_units(facility_id):
    """Bulk create units.
    Docs: /docs/private/api-v1-units/bulk_create.html
    Body: {"units": [{"unit_number": "...", "size": "5x10", ...}]}
    """
    guard = require_bearer(request)
    if guard: return guard
    raw_body = request.get_json(silent=True) or {}
    cleaned, errors = validate_bulk_create_payload(raw_body)
    if errors:
        return jsonify({"error": "VALIDATION_FAILED", "details": errors}), 400
    url = f"{BASE_URL}/v1/{facility_id}/units/bulk_create"
    r = requests.post(url, json=cleaned, auth=OAuth1(API_KEY, API_SECRET), timeout=120)
    try:
        return jsonify(r.json()), r.status_code
    except Exception:
        return (r.text, r.status_code, {"Content-Type": "application/json"})


@app.put("/facilities/<facility_id>/units/<unit_id>/make_rentable")
def make_unit_rentable(facility_id, unit_id):
    """Make a single unit rentable or unrentable using direct PUT method.
    Body: {"rentable": true/false} - rentable field required
    Note: reason field is optional for the direct PUT endpoint
    """
    guard = require_bearer(request)
    if guard: return guard
    
    raw_body = request.get_json(silent=True) or {}
    
    # Validate required fields
    validation_errors = []
    
    if "rentable" not in raw_body:
        validation_errors.append({"field": "rentable", "message": "rentable field is required (true or false)"})
    elif raw_body.get("rentable") not in (True, False):
        validation_errors.append({"field": "rentable", "message": "Must be true or false"})
    
    if validation_errors:
        return jsonify({"error": "VALIDATION_FAILED", "details": validation_errors}), 400
    
    rentable = raw_body.get("rentable")
    
    # Use direct PUT to individual unit endpoint
    storedge_body = {
        "unit": {
            "rentable": rentable
        }
    }
    
    url = f"{BASE_URL}/v1/{facility_id}/units/{unit_id}"
    r = requests.put(url, json=storedge_body, auth=OAuth1(API_KEY, API_SECRET), timeout=60)
    
    try:
        response_data = r.json()
        # Return the unit data from the response
        if r.status_code == 200:
            unit_data = response_data.get("unit", response_data.get("data", response_data))
            return jsonify(unit_data), r.status_code
        else:
            return jsonify(response_data), r.status_code
    except Exception:
        return (r.text, r.status_code, {"Content-Type": "application/json"})


@app.post("/facilities/<facility_id>/units/bulk_make_rentable")
def bulk_make_units_rentable(facility_id):
    """Make multiple units rentable/unrentable using individual PUT calls.
    Body: {"units": [{"id": "unit_id", "rentable": true/false}], "reason": "optional"}
    """
    guard = require_bearer(request)
    if guard: return guard
    
    raw_body = request.get_json(silent=True) or {}
    units = raw_body.get("units", [])
    reason = raw_body.get("reason", "").strip()  # Optional for individual PUT calls
    
    validation_errors = []
    
    if not isinstance(units, list) or not units:
        validation_errors.append({"message": "units array is required"})
        
    if validation_errors:
        return jsonify({"error": "VALIDATION_FAILED", "details": validation_errors}), 400
    
    # Validate units
    validated_units = []
    
    for i, unit_data in enumerate(units):
        if not isinstance(unit_data, dict):
            validation_errors.append({"index": i, "error": "Unit data must be an object"})
            continue
            
        unit_id = unit_data.get("id")
        if not unit_id:
            validation_errors.append({"index": i, "error": "Unit ID is required"})
            continue
            
        if "rentable" not in unit_data:
            validation_errors.append({"index": i, "unit_id": unit_id, "error": "rentable field is required"})
            continue
            
        rentable = unit_data.get("rentable")
        if rentable not in (True, False):
            validation_errors.append({"index": i, "unit_id": unit_id, "error": "rentable must be true or false"})
            continue
        
        validated_units.append({
            "id": unit_id,
            "rentable": rentable
        })
    
    if validation_errors:
        return jsonify({"error": "VALIDATION_FAILED", "details": validation_errors}), 400
    
    if not validated_units:
        return jsonify({"error": "VALIDATION_FAILED", "details": [{"message": "No valid units to process"}]}), 400
    
    # Use individual PUT calls to update each unit
    updated_units = []
    failed_units = []
    
    for unit_update in validated_units:
        unit_id = unit_update["id"]
        
        # Use direct PUT to individual unit endpoint
        storedge_body = {
            "unit": {
                "rentable": unit_update["rentable"]
            }
        }
        
        try:
            url = f"{BASE_URL}/v1/{facility_id}/units/{unit_id}"
            r = requests.put(url, json=storedge_body, auth=OAuth1(API_KEY, API_SECRET), timeout=60)
            
            if r.status_code == 200:
                response_json = r.json()
                unit_data = response_json.get("unit", response_json.get("data", response_json))
                updated_units.append({
                    "id": unit_id,
                    "status": "updated",
                    "unit": unit_data
                })
            else:
                failed_units.append({
                    "id": unit_id,
                    "status": "failed",
                    "status_code": r.status_code,
                    "error": r.text[:200]
                })
        except Exception as e:
            failed_units.append({
                "id": unit_id,
                "status": "error",
                "error": str(e)
            })
    
    # Determine overall success
    success_count = len(updated_units)
    total_attempted = len(validated_units)
    overall_success = success_count > 0
    
    response_data = {
        "total_units_requested": len(units),
        "units_attempted": total_attempted,
        "units_updated_successfully": success_count,
        "units_failed": len(failed_units),
        "reason": reason,
        "updated_units": updated_units,
        "failed_units": failed_units
    }
    
    # Return 200 if any units were updated successfully, 207 for partial success, 400 for total failure
    if overall_success:
        status_code = 200 if len(failed_units) == 0 else 207  # 207 = Multi-Status for partial success
    else:
        status_code = 400  # All failed
        
    return jsonify(response_data), status_code


@app.post("/facilities/<facility_id>/units/search_and_update")
def search_and_update_units(facility_id):
    """Search for units by name/number and update their rentable status in one operation.
    
    This is a convenience endpoint that combines search + bulk_make_rentable.
    
    Body: {
        "search_terms": ["Mail2", "Storage Unit 5", "A101"],
        "rentable": true,
        "reason": "Making selected units rentable",
        "exact_match": false,
        "max_pages_per_search": 10
    }
    """
    guard = require_bearer(request)
    if guard: return guard
    
    raw_body = request.get_json(silent=True) or {}
    
    search_terms = raw_body.get("search_terms", [])
    rentable = raw_body.get("rentable")
    reason = raw_body.get("reason", "").strip()
    exact_match = raw_body.get("exact_match", False)
    max_pages = min(50, max(1, int(raw_body.get("max_pages_per_search", 15))))
    
    # Validation
    validation_errors = []
    
    if not isinstance(search_terms, list) or not search_terms:
        validation_errors.append({"field": "search_terms", "message": "Must provide a non-empty array of search terms"})
    
    if rentable not in (True, False):
        validation_errors.append({"field": "rentable", "message": "Must be true or false"})
    
    if not reason:
        validation_errors.append({"field": "reason", "message": "Reason is required"})
    
    if validation_errors:
        return jsonify({"error": "VALIDATION_FAILED", "details": validation_errors}), 400
    
    # Search for all units
    all_matched_units = []
    search_results = {}
    
    try:
        for search_term in search_terms:
            search_term = str(search_term).strip()
            if not search_term:
                continue
                
            matched_units = []
            pages_searched = 0
            
            # Search through pages for this term
            for page in range(1, max_pages + 1):
                pages_searched = page
                
                url = f"{BASE_URL}/v1/{facility_id}/units"
                params = {"page": page, "per_page": 50}
                
                r = requests.get(url, params=params, auth=OAuth1(API_KEY, API_SECRET), timeout=30)
                
                if r.status_code != 200:
                    break
                    
                data = r.json()
                units = data.get("units", [])
                
                if not units:
                    break
                    
                # Search through this page's units
                for unit in units:
                    unit_name = str(unit.get("name", ""))
                    unit_number = str(unit.get("unit_number", ""))
                    
                    match_found = False
                    if exact_match:
                        if (search_term.lower() == unit_name.lower() or 
                            search_term.lower() == unit_number.lower()):
                            match_found = True
                    else:
                        if (search_term.lower() in unit_name.lower() or 
                            search_term.lower() in unit_number.lower()):
                            match_found = True
                    
                    if match_found:
                        unit_info = {
                            "id": unit.get("id"),
                            "name": unit_name,
                            "unit_number": unit_number,
                            "current_rentable": unit.get("rentable"),
                            "status": unit.get("status"),
                            "search_term": search_term
                        }
                        matched_units.append(unit_info)
                        all_matched_units.append(unit_info)
                
                # If exact match and we found something, stop searching pages
                if matched_units and exact_match:
                    break
            
            search_results[search_term] = {
                "matches": len(matched_units),
                "pages_searched": pages_searched,
                "units": matched_units
            }
        
        if not all_matched_units:
            return jsonify({
                "error": "NO_UNITS_FOUND",
                "message": "None of the search terms matched any units",
                "search_results": search_results
            }), 404
        
        # Prepare units for bulk update
        units_to_update = [
            {"id": unit["id"], "rentable": rentable}
            for unit in all_matched_units
            if unit["id"]  # Only include units with valid IDs
        ]
        
        if not units_to_update:
            return jsonify({
                "error": "NO_VALID_UNIT_IDS",
                "message": "Found matching units but none have valid IDs",
                "search_results": search_results
            }), 400
        
        # Perform individual updates using direct PUT method (works around bulk_update 403 issue)
        updated_units = []
        failed_units = []
        
        for unit_update in units_to_update:
            unit_id = unit_update["id"]
            
            # Use direct PUT to individual unit endpoint
            storedge_body = {
                "unit": {
                    "rentable": unit_update["rentable"]
                }
            }
            
            try:
                url = f"{BASE_URL}/v1/{facility_id}/units/{unit_id}"
                r = requests.put(url, json=storedge_body, auth=OAuth1(API_KEY, API_SECRET), timeout=60)
                
                if r.status_code == 200:
                    response_json = r.json()
                    unit_data = response_json.get("unit", response_json.get("data", response_json))
                    updated_units.append({
                        "id": unit_id,
                        "status": "updated",
                        "unit": unit_data
                    })
                else:
                    failed_units.append({
                        "id": unit_id,
                        "status": "failed",
                        "status_code": r.status_code,
                        "error": r.text[:200]
                    })
            except Exception as e:
                failed_units.append({
                    "id": unit_id,
                    "status": "error",
                    "error": str(e)
                })
        
        # Determine overall success
        success_count = len(updated_units)
        total_attempted = len(units_to_update)
        overall_success = success_count > 0
        
        response_data = {
            "search_results": search_results,
            "total_units_found": len(all_matched_units),
            "units_attempted": total_attempted,
            "units_updated_successfully": success_count,
            "units_failed": len(failed_units),
            "rentable_status": rentable,
            "reason": reason,
            "updated_units": updated_units,
            "failed_units": failed_units
        }
        
        # Return 200 if any units were updated successfully, otherwise the appropriate error status
        status_code = 200 if overall_success else (207 if failed_units else 500)
        return jsonify(response_data), status_code
        
    except Exception as e:
        return jsonify({
            "error": "SEARCH_AND_UPDATE_FAILED",
            "message": str(e),
            "search_results": search_results if 'search_results' in locals() else {}
        }), 500


@app.get("/facilities/<facility_id>/units/search")
def search_units(facility_id):
    """Search for units by name or unit number across all pages.
    
    This endpoint will search through multiple pages to find matching units,
    returning just the matching results with their IDs for bulk operations.
    
    Query params:
    - search: Search term to find in unit name or unit_number
    - exact_match: If true, requires exact match (default: false, partial match)
    - max_pages: Maximum pages to search through (default: 10, max: 50)
    """
    guard = require_bearer(request)
    if guard: return guard
    
    search_term = request.args.get("search", "").strip()
    exact_match = request.args.get("exact_match", "false").lower() == "true"
    max_pages = min(50, max(1, int(request.args.get("max_pages", "15"))))
    
    if not search_term:
        return jsonify({
            "error": "MISSING_SEARCH_TERM",
            "message": "Provide a 'search' parameter to find units"
        }), 400
    
    matched_units = []
    pages_searched = 0
    
    try:
        for page in range(1, max_pages + 1):
            pages_searched = page
            
            # Use manageable page size for GPT processing
            url = f"{BASE_URL}/v1/{facility_id}/units"
            params = {"page": page, "per_page": 50}  # Manageable batches
            
            r = requests.get(url, params=params, auth=OAuth1(API_KEY, API_SECRET), timeout=30)
            
            if r.status_code != 200:
                break  # Stop on API error
                
            data = r.json()
            units = data.get("units", [])
            
            if not units:  # No more units
                break
                
            # Search through this page's units
            for unit in units:
                unit_name = str(unit.get("name", ""))
                unit_number = str(unit.get("unit_number", ""))
                
                if exact_match:
                    if (search_term.lower() == unit_name.lower() or 
                        search_term.lower() == unit_number.lower()):
                        matched_units.append({
                            "id": unit.get("id"),
                            "name": unit_name,
                            "unit_number": unit_number,
                            "rentable": unit.get("rentable"),
                            "status": unit.get("status"),
                            "found_on_page": page
                        })
                else:
                    if (search_term.lower() in unit_name.lower() or 
                        search_term.lower() in unit_number.lower()):
                        matched_units.append({
                            "id": unit.get("id"),
                            "name": unit_name,
                            "unit_number": unit_number,
                            "rentable": unit.get("rentable"),
                            "status": unit.get("status"),
                            "found_on_page": page
                        })
            
            # If we found matches and only searching for one, we can stop early
            if matched_units and exact_match:
                break
        
        return jsonify({
            "search_term": search_term,
            "exact_match": exact_match,
            "matches_found": len(matched_units),
            "pages_searched": pages_searched,
            "max_pages": max_pages,
            "units": matched_units,
            "facility_id": facility_id,
            "note": "Use the 'id' field from results for bulk_make_rentable operations"
        }), 200
        
    except Exception as e:
        return jsonify({
            "error": "SEARCH_FAILED",
            "message": str(e),
            "search_term": search_term,
            "pages_searched": pages_searched
        }), 500


# === Universal Endpoints (GPT Actions Optimized for Any Facility) ===
# These endpoints handle natural language requests like "update unit Mail2 at William Warren Group"

def find_facility_by_name(facility_name, exact_match=False):
    """Find a facility by name (partial or exact match)."""
    try:
        # Get all facilities
        url = f"{BASE_URL}/v1/companies/{COMPANY_ID}/facilities/short"
        r = requests.get(url, auth=OAuth1(API_KEY, API_SECRET), timeout=30)
        
        if r.status_code != 200:
            return None
            
        data = r.json()
        facilities = data.get("facilities", [])
        
        # Search for matching facility
        facility_name_lower = facility_name.lower()
        
        for facility in facilities:
            name = facility.get("facility_name", "").lower()
            
            if exact_match:
                if facility_name_lower == name:
                    return facility
            else:
                # Partial match - check if search term is in facility name
                if facility_name_lower in name or name in facility_name_lower:
                    return facility
        
        return None
        
    except Exception as e:
        print(f"Error finding facility: {e}")
        return None

@app.post("/universal/find-and-update-unit")
def find_and_update_unit_universal():
    """Universal endpoint to find and update unit at any facility using natural language."""
    guard = require_bearer(request)
    if guard: return guard
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "MISSING_DATA", "message": "Request body required"}), 400
        
        facility_name = data.get("facility_name", "").strip()
        unit_identifier = data.get("unit_identifier", "").strip()
        rentable = data.get("rentable")
        reason = data.get("reason", "Updated via universal API")
        exact_facility_match = data.get("exact_facility_match", False)
        exact_unit_match = data.get("exact_unit_match", False)
        
        if not facility_name or not unit_identifier or rentable is None:
            return jsonify({
                "error": "MISSING_REQUIRED_FIELDS",
                "message": "facility_name, unit_identifier, and rentable are required"
            }), 400
        
        # Step 1: Find the facility
        facility = find_facility_by_name(facility_name, exact_facility_match)
        
        if not facility:
            return jsonify({
                "success": False,
                "facility_found": False,
                "message": f"No facility found matching '{facility_name}'",
                "errors": [f"Facility '{facility_name}' not found"]
            }), 404
        
        facility_id = facility["id"]
        facility_display_name = facility["facility_name"]
        
        # Step 2: Search for units in that facility
        search_url = f"{BASE_URL}/v1/{facility_id}/units"
        found_units = []
        pages_searched = 0
        
        # Search through multiple pages to find the unit
        for page in range(1, 11):  # Search up to 10 pages
            pages_searched = page
            params = {"page": page, "per_page": 50}
            
            r = requests.get(search_url, params=params, auth=OAuth1(API_KEY, API_SECRET), timeout=30)
            
            if r.status_code != 200:
                break
                
            page_data = r.json()
            units = page_data.get("data", {}).get("units", [])
            
            if not units:  # No more units
                break
            
            # Search this page for matching units
            for unit in units:
                unit_name = str(unit.get("name", ""))
                unit_number = str(unit.get("unit_number", ""))
                
                if exact_unit_match:
                    if (unit_identifier.lower() == unit_name.lower() or 
                        unit_identifier.lower() == unit_number.lower()):
                        found_units.append(unit)
                else:
                    if (unit_identifier.lower() in unit_name.lower() or 
                        unit_identifier.lower() in unit_number.lower()):
                        found_units.append(unit)
        
        if not found_units:
            return jsonify({
                "success": False,
                "facility_found": True,
                "facility_name": facility_display_name,
                "facility_id": facility_id,
                "units_found": 0,
                "message": f"No units found matching '{unit_identifier}' at {facility_display_name}",
                "errors": [f"Unit '{unit_identifier}' not found"]
            }), 404
        
        # Step 3: Update each found unit
        updated_units = []
        errors = []
        
        for unit in found_units:
            unit_id = unit["id"]
            previous_rentable = unit.get("rentable", None)
            
            try:
                # Update the unit
                update_url = f"{BASE_URL}/v1/{facility_id}/units/{unit_id}"
                update_payload = {"unit": {"rentable": rentable}}
                
                r = requests.put(update_url, json=update_payload, 
                               auth=OAuth1(API_KEY, API_SECRET), timeout=30)
                
                if r.status_code == 200:
                    unit_data = r.json()
                    updated_units.append({
                        "id": unit_id,
                        "name": unit.get("name", ""),
                        "unit_number": unit.get("unit_number", ""),
                        "rentable": unit_data.get("rentable"),
                        "previous_rentable": previous_rentable
                    })
                else:
                    errors.append(f"Failed to update unit {unit.get('name', unit_id)}: {r.text}")
                    
            except Exception as e:
                errors.append(f"Error updating unit {unit.get('name', unit_id)}: {str(e)}")
        
        # Return results
        return jsonify({
            "success": len(updated_units) > 0,
            "facility_found": True,
            "facility_name": facility_display_name,
            "facility_id": facility_id,
            "units_found": len(found_units),
            "units_updated": len(updated_units),
            "rentable_status": rentable,
            "updated_units": updated_units,
            "errors": errors,
            "message": f"Updated {len(updated_units)} of {len(found_units)} units at {facility_display_name}"
        }), 200
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": "SERVER_ERROR",
            "message": f"Server error: {str(e)}"
        }), 500

@app.get("/universal/search-units-by-facility-name")
def search_units_by_facility_name():
    """Search for units using facility name instead of facility ID."""
    guard = require_bearer(request)
    if guard: return guard
    
    facility_name = request.args.get("facility_name", "").strip()
    unit_search = request.args.get("unit_search", "").strip()
    exact_facility_match = request.args.get("exact_facility_match", "false").lower() == "true"
    exact_unit_match = request.args.get("exact_unit_match", "false").lower() == "true"
    max_pages = min(20, max(1, int(request.args.get("max_pages", "5"))))
    
    if not facility_name:
        return jsonify({"error": "MISSING_FACILITY_NAME", "message": "facility_name parameter required"}), 400
    
    # Find the facility
    facility = find_facility_by_name(facility_name, exact_facility_match)
    
    if not facility:
        return jsonify({
            "facility_found": False,
            "message": f"No facility found matching '{facility_name}'"
        }), 404
    
    facility_id = facility["id"]
    facility_display_name = facility["facility_name"]
    
    # Search for units
    matching_units = []
    total_units = 0
    
    try:
        for page in range(1, max_pages + 1):
            url = f"{BASE_URL}/v1/{facility_id}/units"
            params = {"page": page, "per_page": 50}
            
            r = requests.get(url, params=params, auth=OAuth1(API_KEY, API_SECRET), timeout=30)
            
            if r.status_code != 200:
                break
                
            data = r.json()
            units = data.get("units", [])
            
            if not units:
                break
                
            total_units += len(units)
            
            # Filter units if search term provided
            if unit_search:
                for unit in units:
                    unit_name = str(unit.get("name", ""))
                    unit_number = str(unit.get("unit_number", ""))
                    
                    if exact_unit_match:
                        if (unit_search.lower() == unit_name.lower() or 
                            unit_search.lower() == unit_number.lower()):
                            matching_units.append(unit)
                    else:
                        if (unit_search.lower() in unit_name.lower() or 
                            unit_search.lower() in unit_number.lower()):
                            matching_units.append(unit)
            else:
                # No search filter - include all units
                matching_units.extend(units)
        
        return jsonify({
            "facility_found": True,
            "facility_name": facility_display_name,
            "facility_id": facility_id,
            "total_units": total_units,
            "matching_units": len(matching_units),
            "units": matching_units[:100]  # Limit to first 100 matches
        }), 200
        
    except Exception as e:
        return jsonify({
            "error": "SEARCH_ERROR",
            "message": f"Error searching units: {str(e)}"
        }), 500

@app.post("/universal/make-unit-unrentable")
def make_unit_unrentable_universal():
    """Simplified endpoint to make units unrentable at any facility."""
    guard = require_bearer(request)
    if guard: return guard
    
    data = request.get_json()
    if not data:
        return jsonify({"error": "MISSING_DATA", "message": "Request body required"}), 400
    
    # Add default values and forward to main universal endpoint
    update_data = {
        "facility_name": data.get("facility_name"),
        "unit_identifier": data.get("unit_identifier"), 
        "rentable": False,
        "reason": data.get("reason", "Made unrentable per user request"),
        "exact_facility_match": False,
        "exact_unit_match": False
    }
    
    # Temporarily store the original request
    original_request_json = request.get_json
    request.get_json = lambda: update_data
    
    try:
        return find_and_update_unit_universal()
    finally:
        request.get_json = original_request_json

@app.post("/universal/make-unit-rentable")  
def make_unit_rentable_universal():
    """Simplified endpoint to make units rentable at any facility."""
    guard = require_bearer(request)
    if guard: return guard
    
    data = request.get_json()
    if not data:
        return jsonify({"error": "MISSING_DATA", "message": "Request body required"}), 400
    
    # Add default values and forward to main universal endpoint
    update_data = {
        "facility_name": data.get("facility_name"),
        "unit_identifier": data.get("unit_identifier"),
        "rentable": True, 
        "reason": data.get("reason", "Made rentable per user request"),
        "exact_facility_match": False,
        "exact_unit_match": False
    }
    
    # Temporarily store the original request
    original_request_json = request.get_json
    request.get_json = lambda: update_data
    
    try:
        return find_and_update_unit_universal()
    finally:
        request.get_json = original_request_json

# === William Warren Group Specific Endpoints (GPT Actions Optimized) ===
# These endpoints are pre-configured with the William Warren Group facility ID
# to make the chatbot integration easier and more reliable.

WILLIAM_WARREN_FACILITY_ID = "701235b0-d7ba-4191-932c-b3d1a182dace"

@app.get("/william-warren/units")
def get_william_warren_units():
    """Get units at William Warren Group facility with search capabilities."""
    guard = require_bearer(request)
    if guard: return guard
    
    # Forward to the existing units endpoint with the correct facility ID
    return list_units(WILLIAM_WARREN_FACILITY_ID)

@app.get("/william-warren/units/search")
def search_william_warren_units():
    """Search for units at William Warren Group facility."""
    guard = require_bearer(request)
    if guard: return guard
    
    # Forward to the existing search endpoint with the correct facility ID
    return search_units(WILLIAM_WARREN_FACILITY_ID)

@app.put("/william-warren/units/<unit_id>/make-rentable")
def make_william_warren_unit_rentable(unit_id):
    """Make a William Warren Group unit rentable/unrentable."""
    guard = require_bearer(request)
    if guard: return guard
    
    # Forward to the existing make_rentable endpoint with the correct facility ID
    return make_unit_rentable(WILLIAM_WARREN_FACILITY_ID, unit_id)

@app.post("/william-warren/units/search-by-name-optimized") 
def search_units_by_name_optimized():
    """Optimized search that finds units efficiently without overwhelming ChatGPT.
    
    For 8.5x11 units like 03A, 11A, etc., this searches the right pages directly.
    """
    guard = require_bearer(request)
    if guard: return guard
    
    body = request.get_json()
    if not body:
        return jsonify({"error": "JSON_REQUIRED"}), 400
    
    unit_names = body.get("unit_names", [])
    if not unit_names:
        return jsonify({"error": "UNIT_NAMES_REQUIRED", "message": "Provide array of unit names to find"}), 400
    
    # Check if these are 8.5x11 units (##A pattern)
    is_eight_five_pattern = all(len(name) == 3 and name.endswith('A') and name[:2].isdigit() for name in unit_names)
    
    found_units = []
    
    if is_eight_five_pattern:
        # These are 8.5x11 units - search pages 7-8 directly
        search_pages = [7, 8]
        print(f"[OPTIMIZED] Detected 8.5x11 pattern, searching pages {search_pages}")
    else:
        # General search - start from page 1
        search_pages = list(range(1, 16))  # Search up to 15 pages
    
    try:
        for page in search_pages:
            url = f"{BASE_URL}/v1/{WILLIAM_WARREN_FACILITY_ID}/units"
            params = {"page": page, "per_page": 50}
            
            r = requests.get(url, params=params, auth=OAuth1(API_KEY, API_SECRET), timeout=30)
            
            if r.status_code != 200:
                continue
                
            data = r.json()
            units = data.get("units", [])
            
            if not units:
                continue
            
            # Search this page for our target units
            for unit in units:
                unit_name = str(unit.get("name", ""))
                
                if unit_name in unit_names:
                    found_units.append({
                        "id": unit.get("id"),
                        "name": unit_name,
                        "unit_number": unit.get("unit_number", ""),
                        "size": unit.get("size", ""),
                        "rentable": unit.get("rentable"),
                        "status": unit.get("status"),
                        "found_on_page": page
                    })
            
            # If we found all units, stop searching
            if len(found_units) >= len(unit_names):
                break
        
        return jsonify({
            "unit_names_requested": unit_names,
            "units_found": len(found_units),
            "units": found_units,
            "optimization_used": "8.5x11_pattern" if is_eight_five_pattern else "general_search"
        })
        
    except Exception as e:
        return jsonify({
            "error": "OPTIMIZED_SEARCH_ERROR",
            "message": str(e)
        }), 500

@app.post("/william-warren/units/search-and-update")
def search_and_update_william_warren_units():
    """Search and update units at William Warren Group facility in one operation."""
    guard = require_bearer(request)
    if guard: return guard
    
    # Forward to the existing search_and_update endpoint with the correct facility ID
    return search_and_update_units(WILLIAM_WARREN_FACILITY_ID)

@app.get("/william-warren/units/search-by-dimensions")
def search_william_warren_units_by_dimensions():
    """Search for units at William Warren Group by dimensions and amenities."""
    guard = require_bearer(request)
    if guard: return guard
    
    # Get search parameters
    width = request.args.get("width", type=float)
    length = request.args.get("length", type=float)
    height = request.args.get("height", type=float)
    description_contains = request.args.get("description_contains", "").strip()
    amenity_names = request.args.get("amenity_names", "").strip()  # comma-separated
    unit_name_starts_with = request.args.get("unit_name_starts_with", "").strip()
    max_pages = min(20, max(1, int(request.args.get("max_pages", "10"))))
    
    matching_units = []
    pages_searched = 0
    
    try:
        for page in range(1, max_pages + 1):
            pages_searched = page
            
            url = f"{BASE_URL}/v1/{WILLIAM_WARREN_FACILITY_ID}/units"
            params = {"page": page, "per_page": 50}
            
            r = requests.get(url, params=params, auth=OAuth1(API_KEY, API_SECRET), timeout=30)
            
            if r.status_code != 200:
                break
                
            data = r.json()
            units = data.get("units", [])
            
            if not units:
                break
                
            # Filter by dimensions and amenities
            for unit in units:
                match = True
                
                # Check dimensions
                if width is not None and unit.get("width") != width:
                    match = False
                if length is not None and unit.get("length") != length:
                    match = False
                if height is not None and unit.get("height") != height:
                    match = False
                
                # Check description
                if description_contains:
                    unit_description = str(unit.get("description", "")).lower()
                    if description_contains.lower() not in unit_description:
                        match = False
                
                # Check amenities
                if amenity_names:
                    required_amenities = [name.strip().lower() for name in amenity_names.split(",")]
                    unit_amenities = unit.get("unit_amenities", [])
                    unit_amenity_names = [amenity.get("name", "").lower() for amenity in unit_amenities]
                    
                    for required in required_amenities:
                        if not any(required in amenity_name for amenity_name in unit_amenity_names):
                            match = False
                            break
                
                # Check unit name prefix
                if unit_name_starts_with:
                    unit_name = str(unit.get("name", "")).lower()
                    unit_number = str(unit.get("unit_number", "")).lower()
                    prefix = unit_name_starts_with.lower()
                    
                    if not (unit_name.startswith(prefix) or unit_number.startswith(prefix)):
                        match = False
                
                if match:
                    matching_units.append({
                        "id": unit.get("id"),
                        "name": unit.get("name"),
                        "unit_number": unit.get("unit_number"),
                        "width": unit.get("width"),
                        "length": unit.get("length"), 
                        "height": unit.get("height"),
                        "size": unit.get("size"),
                        "description": unit.get("description"),
                        "rentable": unit.get("rentable"),
                        "status": unit.get("status"),
                        "unit_amenities": [amenity.get("name") for amenity in unit.get("unit_amenities", [])],
                        "found_on_page": page
                    })
        
        return jsonify({
            "search_criteria": {
                "width": width,
                "length": length,
                "height": height,
                "description_contains": description_contains,
                "amenity_names": amenity_names,
                "unit_name_starts_with": unit_name_starts_with
            },
            "matches_found": len(matching_units),
            "pages_searched": pages_searched,
            "max_pages": max_pages,
            "units": matching_units
        })
        
    except Exception as e:
        return jsonify({
            "error": "SEARCH_ERROR",
            "message": str(e),
            "matches_found": len(matching_units),
            "pages_searched": pages_searched
        }), 500

@app.post("/william-warren/units/search-by-dimensions-and-update")
def search_william_warren_units_by_dimensions_and_update():
    """Search units by dimensions/amenities and update their rentable status."""
    guard = require_bearer(request)
    if guard: return guard
    
    body = request.get_json()
    if not body:
        return jsonify({"error": "JSON_REQUIRED"}), 400
    
    # Search criteria
    width = body.get("width")
    length = body.get("length")
    height = body.get("height")
    description_contains = body.get("description_contains", "")
    amenity_names = body.get("amenity_names", "")  # comma-separated
    unit_name_starts_with = body.get("unit_name_starts_with", "")
    
    # Update criteria  
    rentable = body.get("rentable")
    reason = body.get("reason", "")
    max_pages = min(20, max(1, body.get("max_pages", 10)))
    
    # SAFETY FEATURE: Preview mode (default: true for safety)
    preview_only = body.get("preview_only", True)
    confirmed_unit_ids = body.get("confirmed_unit_ids", [])
    
    # Validation - only required for actual updates, not previews
    if not preview_only:
        if rentable not in (True, False):
            return jsonify({"error": "RENTABLE_REQUIRED", "message": "rentable must be true or false"}), 400
        
        if not reason.strip():
            return jsonify({"error": "REASON_REQUIRED", "message": "reason is required for updates"}), 400
    
    # First, search for matching units
    matching_units = []
    pages_searched = 0
    
    try:
        for page in range(1, max_pages + 1):
            pages_searched = page
            
            url = f"{BASE_URL}/v1/{WILLIAM_WARREN_FACILITY_ID}/units"
            params = {"page": page, "per_page": 50}
            
            r = requests.get(url, params=params, auth=OAuth1(API_KEY, API_SECRET), timeout=30)
            
            if r.status_code != 200:
                break
                
            data = r.json()
            units = data.get("units", [])
            
            if not units:
                break
                
            # Filter by criteria (same logic as search endpoint)
            for unit in units:
                match = True
                
                # Check dimensions
                if width is not None and unit.get("width") != width:
                    match = False
                if length is not None and unit.get("length") != length:
                    match = False  
                if height is not None and unit.get("height") != height:
                    match = False
                
                # Check description
                if description_contains:
                    unit_description = str(unit.get("description", "")).lower()
                    if description_contains.lower() not in unit_description:
                        match = False
                
                # Check amenities
                if amenity_names:
                    required_amenities = [name.strip().lower() for name in amenity_names.split(",")]
                    unit_amenities = unit.get("unit_amenities", [])
                    unit_amenity_names = [amenity.get("name", "").lower() for amenity in unit_amenities]
                    
                    for required in required_amenities:
                        if not any(required in amenity_name for amenity_name in unit_amenity_names):
                            match = False
                            break
                
                # Check unit name prefix
                if unit_name_starts_with:
                    unit_name = str(unit.get("name", "")).lower()
                    unit_number = str(unit.get("unit_number", "")).lower() 
                    prefix = unit_name_starts_with.lower()
                    
                    if not (unit_name.startswith(prefix) or unit_number.startswith(prefix)):
                        match = False
                
                if match:
                    matching_units.append(unit)
        
        # PREVIEW MODE: Just return what would be updated for user confirmation
        if preview_only:
            preview_units = []
            for unit in matching_units:
                preview_units.append({
                    "id": unit.get("id"),
                    "name": unit.get("name"),
                    "unit_number": unit.get("unit_number"),
                    "width": unit.get("width"),
                    "length": unit.get("length"),
                    "height": unit.get("height"),
                    "size": unit.get("size"),
                    "description": unit.get("description"),
                    "current_rentable": unit.get("rentable"),
                    "status": unit.get("status"),
                    "unit_amenities": [amenity.get("name") for amenity in unit.get("unit_amenities", [])]
                })
            
            return jsonify({
                "preview_mode": True,
                "message": "PREVIEW: These units would be updated. Confirm to proceed.",
                "search_criteria": {
                    "width": width,
                    "length": length,
                    "height": height,
                    "description_contains": description_contains,
                    "amenity_names": amenity_names,
                    "unit_name_starts_with": unit_name_starts_with
                },
                "total_units_found": len(matching_units),
                "pages_searched": pages_searched,
                "units_to_update": preview_units,
                "confirmation_required": True,
                "next_step": "Send same request with preview_only: false and confirmed_unit_ids: [list of IDs to update]"
            })
        
        # UPDATE MODE: Filter to only confirmed units if specified
        units_to_update = matching_units
        if confirmed_unit_ids:
            units_to_update = [unit for unit in matching_units if unit.get("id") in confirmed_unit_ids]
        
        # Now update each unit
        updated_units = []
        failed_units = []
        
        for unit in units_to_update:
            try:
                unit_id = unit.get("id")
                unit_name = unit.get("name")
                
                # Use the working PUT endpoint
                update_url = f"{BASE_URL}/v1/{WILLIAM_WARREN_FACILITY_ID}/units/{unit_id}"
                payload = {"unit": {"rentable": rentable}}
                
                update_response = requests.put(update_url, json=payload, auth=OAuth1(API_KEY, API_SECRET), timeout=30)
                
                if update_response.status_code == 200:
                    updated_data = update_response.json()
                    updated_units.append({
                        "id": unit_id,
                        "name": unit_name,
                        "unit_number": unit.get("unit_number", ""),
                        "rentable": rentable,
                        "previous_rentable": unit.get("rentable"),
                        "width": unit.get("width"),
                        "length": unit.get("length"),
                        "height": unit.get("height"),
                        "status": "updated"
                    })
                else:
                    failed_units.append({
                        "id": unit_id,
                        "name": unit_name,
                        "error": f"HTTP {update_response.status_code}: {update_response.text[:100]}"
                    })
                    
            except Exception as e:
                failed_units.append({
                    "id": unit.get("id"),
                    "name": unit.get("name"),
                    "error": str(e)
                })
        
        return jsonify({
            "search_criteria": {
                "width": width,
                "length": length,
                "height": height,
                "description_contains": description_contains,
                "amenity_names": amenity_names,
                "unit_name_starts_with": unit_name_starts_with
            },
            "total_units_found": len(matching_units),
            "units_updated_successfully": len(updated_units),
            "units_failed": len(failed_units),
            "rentable_status": rentable,
            "reason": reason,
            "pages_searched": pages_searched,
            "updated_units": updated_units,
            "failed_units": failed_units
        })
        
    except Exception as e:
        return jsonify({
            "error": "DIMENSION_SEARCH_UPDATE_ERROR",
            "message": str(e)
        }), 500


@app.get("/facilities/<facility_id>/units/count")
def get_units_count(facility_id):
    """Get unit count and pagination info for a facility.
    
    This endpoint makes a request for the first page to get metadata
    about total units available, helping to plan pagination.
    """
    guard = require_bearer(request)
    if guard: return guard
    
    # Request first page with minimal per_page to get metadata quickly
    url = f"{BASE_URL}/v1/{facility_id}/units?page=1&per_page=1"
    
    try:
        r = requests.get(url, auth=OAuth1(API_KEY, API_SECRET), timeout=30)
        
        try:
            data = r.json()
        except ValueError:
            # JSON decode error
            return (r.text, r.status_code, {"Content-Type": "application/json"})
        
        # Extract pagination metadata if available in Storedge response
        # Note: Actual metadata structure depends on Storedge API response format
        response_data = {
            "facility_id": facility_id,
            "sample_response": data,
            "recommended_pagination": {
                "suggested_per_page": 100,
                "note": "Use page and per_page parameters in /facilities/{facility_id}/units endpoint"
            }
        }
        
        return jsonify(response_data), r.status_code
        
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "REQUEST_FAILED", "message": str(e)}), 500


# === Cache Inspection Endpoints (optional for GPT debugging) ===
@app.get("/cache/facilities")
def cache_facilities():
    guard = require_bearer(request)
    if guard: return guard
    c = _cache_get("facilities_short")
    if not c:
        return jsonify({"cached": False, "message": "EMPTY_OR_EXPIRED"}), 404
    return jsonify({"cached": True, **c}), 200


@app.get("/cache/facilities/<facility_id>/units")
def cache_units(facility_id):
    guard = require_bearer(request)
    if guard: return guard
    c = _cache_get("units", facility_id)
    if not c:
        return jsonify({"cached": False, "message": "EMPTY_OR_EXPIRED"}), 404
    return jsonify({"cached": True, **c}), 200


@app.route("/.well-known/ai-plugin.json")
def plugin_manifest():
    return send_from_directory(app.root_path, "ai-plugin.json", mimetype="application/json")


@app.route("/openapi.json")
def openapi_spec():
    return send_from_directory(app.root_path, "openapi.json", mimetype="application/json")


@app.route("/pricing_instructions.json")
def pricing_instructions():
    return send_from_directory(app.root_path, "pricing_instructions.json", mimetype="application/json")


# === Site Keys ===
@app.route('/get_site_keys', methods=['GET'])
def get_site_keys():
    """Lookup sE_ID for a single 4-digit site_number."""
    try:
        site_number = (request.args.get("site_number") or "").strip()
        if not site_number.isdigit() or len(site_number) != 4:
            return jsonify({
                "error": "MISSING_OR_INVALID_SITE_NUMBER",
                "message": "You must provide exactly one 4-digit site_number (e.g., 1089)."
            }), 400
        
        try:
            with connect_to_db("sites") as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT sE_ID, Site_Number, Name
                    FROM sites.dbo.sites
                    WHERE Site_Number = %s
                    """,
                    (site_number,),
                )
                row = cur.fetchone()
        except ImportError:
            return jsonify({
                "error": "DATABASE_UNAVAILABLE",
                "message": "Database functionality not available in this deployment"
            }), 503
        except Exception as db_error:
            return jsonify({
                "error": "DATABASE_ERROR",
                "message": f"Database connection failed: {str(db_error)}"
            }), 503
            
        if not row:
            return jsonify({
                "error": "SITE_NOT_FOUND",
                "message": f"No site found for site_number {site_number}"
            }), 404
        return jsonify({"sE_ID": row[0], "site_number": str(row[1]), "site_name": row[2]}), 200
    except Exception as e:
        return jsonify({"error": "UNHANDLED_EXCEPTION", "message": str(e), "traceback": traceback.format_exc()}), 500


# === Report creation/status/data ===
@app.route("/create-report", methods=["POST"])
def create_report():
    data = request.get_json(silent=True) or {}
    filter_facilities = data.get("filter_facilities")
    if not isinstance(filter_facilities, list) or not filter_facilities:
        return jsonify({"error": "filter_facilities must be a non-empty list of sE_ID(s) (UUIDs)"}), 400
    if not all(is_valid_se_id(f) for f in filter_facilities):
        return jsonify({"error": "Each entry in filter_facilities must be a valid sE_ID (UUID)."}), 400
    payload = {
        "report_request": {
            "report_name": "corporate_unoccupied_revenue_management_controller",
            "report_format": "csv",
            "report_params": {"filter_facilities": filter_facilities}
        }
    }
    url = f"{BASE_URL}/v1/companies/{COMPANY_ID}/report_requests"
    auth = OAuth1(API_KEY, API_SECRET)
    r = requests.post(url, json=payload, auth=auth)
    return jsonify(r.json()), r.status_code


@app.route("/report-status/<report_id>", methods=["GET"])
def report_status(report_id):
    print(f"[Direct Status Check] Received at {time.strftime('%X')}")
    delay = 5
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
    try:
        print("[Report Fetch] Verifying report is ready...")
        status_resp = requests.get(status_url, auth=auth, timeout=10)
        status = status_resp.json().get("report_request", {}).get("status", "")
        print(f"[Report Fetch] Status: {status}")
        if status != "complete":
            print("[Report Fetch] Report is NOT ready — skipping fetch.")
            return jsonify({"error": "Report not ready"}), 202
        r = requests.get(data_url, auth=auth, timeout=10)
        if r.status_code != 200:
            print(f"[Error] Failed to fetch report data for ID {report_id}: {r.status_code}")
            return jsonify({"error": "Failed to fetch report"}), 500
        data = r.json()
        with open("latest_report.json", "w") as f:
            json.dump(data, f)
        with open("latest_report_id.txt", "w") as id_file:
            id_file.write(report_id)
        print(f"[Cache] Cached latest_report.json and report ID: {report_id}")
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
            print(f"[Cache] Saved filtered_unit_summary.csv with {len(filtered_df)} rows")
        except Exception as e:
            print(f"[Cache] Failed to write filtered summary: {e}")
        return jsonify(data), 200
    except Exception as e:
        print(f"[Report Fetch] Error during processing: {e}")
        return jsonify({"error": "Unexpected error while fetching report"}), 500


def load_cached_report(report_id):
    try:
        if os.path.exists("latest_report_id.txt") and os.path.exists("latest_report.json"):
            with open("latest_report_id.txt", "r") as id_file:
                cached_id = id_file.read().strip()
            if cached_id == report_id:
                print(f"[Cache] Using cached latest_report.json for ID: {report_id}")
                with open("latest_report.json", "r") as f:
                    return json.load(f)
    except Exception as e:
        print(f"[Cache] Failed to load cached report: {e}")
    return None


# === Report filter ===
def parse_sqft(size_str: str) -> float | None:
    if not size_str:
        return None
    m = re.match(r'^\s*(\d+(?:\.\d+)?)\s*[xX]\s*(\d+(?:\.\d+)?)\s*$', str(size_str).strip())
    if not m:
        return None
    try:
        return float(m.group(1)) * float(m.group(2))
    except ValueError:
        return None


@app.route("/filter-report", methods=["GET", "POST"])
def filter_report():
    def norm(s: str) -> str:
        return " ".join((s or "").strip().lower().split())
    def get_param(name, default=None):
        if request.method == "POST":
            body = request.get_json(silent=True) or {}
            return body.get(name, default)
        return request.args.get(name, default)

    size_raw = get_param("size", "")
    amenities_raw = get_param("amenities", "")
    unit_type_raw = get_param("unit_type", "")
    min_sf_raw = get_param("min_sf")
    max_sf_raw = get_param("max_sf")
    max_rows_raw = get_param("max_rows", 20)

    size = norm(str(size_raw or ""))
    amenities = norm(str(amenities_raw or ""))
    unit_type = norm(str(unit_type_raw or ""))

    AMENITY_ALIASES = {
        "du": "drive up",
        "drive-up": "drive up",
        "cc": "climate controlled",
        "climate": "climate controlled"
    }
    if amenities in AMENITY_ALIASES:
        amenities = AMENITY_ALIASES[amenities]

    try:
        max_rows = int(max_rows_raw)
    except (TypeError, ValueError):
        max_rows = 20
    max_rows = min(max(max_rows, 1), 100)

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

    if not os.path.exists("latest_report.json"):
        return jsonify({"error": "No cached report found. Please generate a report first."}), 404

    try:
        with open("latest_report.json", "r") as f:
            report_json = json.load(f)
        report_data = report_json.get("report_request", {}).get("report", [])
        df = pd.DataFrame(report_data)
        app.logger.info("[Filter-report] loaded %d total rows", len(df))
    except Exception as e:
        app.logger.exception("[Filter-report] load error: %s", e)
        return jsonify({"error": "Failed to load cached report"}), 500

    if "Size" in df.columns:
        df["Square_Footage"] = df["Size"].apply(parse_sqft)
    else:
        df["Square_Footage"] = None

    def _col(name):
        return df[name].astype(str) if name in df.columns else pd.Series([""] * len(df), index=df.index)
    df["_norm_size"] = _col("Size").map(norm)
    df["_norm_amenities"] = _col("Amenities").map(norm)
    df["_norm_unit_type"] = _col("Unit Type").map(norm)
    df["_norm_size_plus_amen"] = (df["_norm_size"] + " " + df["_norm_amenities"]).str.strip()

    mask = pd.Series(True, index=df.index)

    if size:
        mask &= (df["_norm_size_plus_amen"] == size)
    if amenities:
        mask &= (df["_norm_amenities"] == amenities)
    if unit_type:
        mask &= df["_norm_unit_type"].str.contains(re.escape(unit_type), na=False)

    if min_sf is not None:
        mask &= df["Square_Footage"].apply(lambda v: (v is not None) and (v >= min_sf))
    if max_sf is not None:
        mask &= df["Square_Footage"].apply(lambda v: (v is not None) and (v <= max_sf))

    filtered = df[mask]
    total_matched = int(filtered.shape[0])
    app.logger.info("[Filter-report] %d rows matched filters", total_matched)

    if total_matched == 0:
        return jsonify({"warning": "No units matched the filter criteria."}), 200

    if total_matched > max_rows:
        sliced = filtered.iloc[:max_rows]
        warning = f"Showing first {max_rows} of {total_matched} matching rows."
    else:
        sliced = filtered
        warning = None

    work_cols = [
        "Group Key", "Size", "Square_Footage", "Amenities",
        "Current Standard Rate", "Occupancy", "Average Rent",
        "Days Since Last Move-In"
    ]
    available = [c for c in work_cols if c in sliced.columns]
    preview = sliced[available]

    response = {"rows": preview.to_dict(orient="records"), "warning": warning} if warning else {"rows": preview.to_dict(orient="records")}

    app.logger.info("[Filter-report] returning %d rows", len(preview))
    return jsonify(response), 200


# === Legacy upload endpoint (raw file) ===
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


# === Identity helpers ===
def require_user_identity():
    user = get_current_user()
    if not user:
        return None
    return user


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
    user = str(user).strip()
    with open("current_user.txt", "w") as f:
        f.write(user)
    return jsonify({"status": "ok", "user": user}), 200


@app.route("/wait-until-ready/<report_id>", methods=["GET"])
def wait_until_ready(report_id):
    success = poll_until_report_ready(report_id)
    if success:
        return jsonify({"status": "complete"})
    else:
        return jsonify({"status": "timeout"}), 504


# === DIRECT PREVIEW CORE ===
def normalize_fraction(v):
    try:
        x = float(v)
        return x / 100.0 if x > 1.5 else x  # treat 79.4 → 0.794
    except Exception:
        return None


def assess_change_row(row) -> dict:
    reasons_local = []
    try:
        cur = float(row.get("Current Standard Rate")) if pd.notnull(row.get("Current Standard Rate")) else None
        new = float(row.get("New Standard Rate")) if pd.notnull(row.get("New Standard Rate")) else None
    except Exception:
        return {"pct_change": None, "decision": "WARN", "reasons": ["non-numeric values"]}

    occ = normalize_fraction(row.get("Occupancy"))
    try:
        vac = int(row.get("Available")) if pd.notnull(row.get("Available")) else None
    except Exception:
        vac = None

    if cur is None or new is None or cur == 0:
        return {"pct_change": None, "decision": "WARN", "reasons": ["missing baseline"]}

    pct = (new - cur) / cur
    decision = "OK"

    if abs(pct) >= AGGRESSIVE_PCT:
        decision = "WARN"
        reasons_local.append(f"≥{int(AGGRESSIVE_PCT*100)}% change")

    if occ is not None:
        if pct < 0 and occ >= HIGH_OCC_THRESHOLD and (vac is not None and vac < MIN_VACANTS_FOR_DROP):
            decision = "BLOCK"
            reasons_local.append(f"high occ {occ:.0%} & <{MIN_VACANTS_FOR_DROP} vacants: no drops")
        if pct > 0 and occ < LOW_OCC_THRESHOLD and abs(pct) >= AGGRESSIVE_PCT:
            decision = "WARN"
            reasons_local.append("raising on <90% occupancy")

    return {"pct_change": pct, "decision": decision, "reasons": reasons_local}


def preview_direct_core(report_df: pd.DataFrame, changes: list[dict]):
    # Build patch_df normalized on group_key_plain
    patch_rows = []
    for c in changes:
        gk = str(c.get("group_key", "")).strip()
        if not gk:
            raise ValueError("Each change needs group_key")
        if gk.isdigit() and len(gk) <= 3:
            raise ValueError("LIKELY_BUCKET_ID_PASSED")
        plain = safe_b64_decode(gk) or gk
        row = {"group_key_plain": plain}
        if c.get("new_rate") is not None:
            row["New Standard Rate"] = c["new_rate"]
        elif c.get("pct_delta") is not None:
            row["pct_delta"] = c["pct_delta"]
        else:
            raise ValueError("Each change needs new_rate or pct_delta")
        patch_rows.append(row)
    patch_df = pd.DataFrame(patch_rows)

    df = make_group_key_plain_column(report_df, "Group Key")
    merged = pd.merge(df, patch_df, on="group_key_plain", how="left", suffixes=("", "_p"))

    if "pct_delta" not in merged.columns:
        merged["pct_delta"] = np.nan
    if "New Standard Rate_p" not in merged.columns:
        merged["New Standard Rate_p"] = np.nan

    need_calc = merged["New Standard Rate_p"].isna() & merged["pct_delta"].notna()
    if need_calc.any():
        merged.loc[need_calc, "New Standard Rate_p"] = (
            pd.to_numeric(merged.loc[need_calc, "Current Standard Rate"], errors="coerce") *
            (1 + merged.loc[need_calc, "pct_delta"].astype(float))
        ).round()

    merged["New Standard Rate"] = merged["New Standard Rate_p"]

    matched = merged["New Standard Rate"].notna()
    if not matched.any():
        raise ValueError("NO_KEYS_MATCHED")

    merged = merged.loc[matched].copy()

    assessments = merged.apply(assess_change_row, axis=1)
    merged["pct_change"] = [a["pct_change"] for a in assessments]
    merged["decision"] = [a["decision"] for a in assessments]
    merged["reasons"] = [", ".join(a["reasons"]) for a in assessments]

    pid = f"p_{int(time.time())}"
    proposal = merged[[
        "group_key_plain", "Group Key", "Current Standard Rate", "New Standard Rate",
        "Occupancy", "Available", "pct_change", "decision", "reasons"
    ]].to_dict(orient="records")

    os.makedirs("proposals", exist_ok=True)
    with open(os.path.join("proposals", f"{pid}.json"), "w") as f:
        json.dump(proposal, f)

    summary = {
        "total": int(len(merged)),
        "ok": int((merged["decision"] == "OK").sum()),
        "warn": int((merged["decision"] == "WARN").sum()),
        "block": int((merged["decision"] == "BLOCK").sum()),
    }
    return {"proposal_id": pid, "summary": summary, "rows": proposal, "requires_confirmation": True}


# === Preview (DIRECT ONLY) ===
LAST_PROPOSAL_META: dict[str, object] = {}

def _set_last_proposal(pid):
    LAST_PROPOSAL_META["id"] = pid
    LAST_PROPOSAL_META["ts"] = datetime.utcnow()


def _recent_proposal():
    pid = LAST_PROPOSAL_META.get("id")
    ts = LAST_PROPOSAL_META.get("ts")
    if not pid or not ts:
        return None
    if isinstance(ts, datetime) and datetime.utcnow() - ts > timedelta(minutes=10):
        return None
    return LAST_PROPOSAL_META


@app.post("/preview/auto")
def preview_auto():
    """
    DIRECT form only:
      { "changes": [
          { "group_key": "<Base64 or plain UG_KEY>", "new_rate": 120.0 },
          { "group_key": "<...>", "pct_delta": -0.05 }
        ] }

    Rules:
      - Refuses bucket fields (site_number/proposed_rates).
      - Loads latest_report.json; 404 if missing.
      - Saves LAST_PROPOSAL_META on success for the /confirm step.
    """
    try:
        raw = request.get_json(silent=True) or {}
        payload_candidate = raw.get("params") if isinstance(raw.get("params"), dict) else raw
        payload = payload_candidate if isinstance(payload_candidate, dict) else {}

        # Reject bucket-shaped payloads
        if any(k in payload for k in ("site_number", "proposed_rates", "proposed_base_rates")):
            return jsonify({
                "error": "BUCKET_DISABLED",
                "hint": "This backend is direct-change only. Provide {\"changes\":[{\"group_key\":...,\"new_rate\":...}]} instead."
            }), 400

        if not os.path.exists("latest_report.json"):
            return jsonify({
                "error": "NO_CACHED_REPORT",
                "ask_next": "Please run the report flow first: /create-report → /wait-until-ready → /report-data."
            }), 404

        with open("latest_report.json", "r") as f:
            report_json = json.load(f)
        report_rows = report_json.get("report_request", {}).get("report", [])
        report_df = pd.DataFrame(report_rows)

        if "changes" not in payload:
            return jsonify({"error": "MISSING_CHANGES", "hint": "Provide a non-empty 'changes' array."}), 400
        changes = payload.get("changes") or []
        if not isinstance(changes, list) or not changes:
            return jsonify({"error": "MISSING_CHANGES", "hint": "Provide a non-empty 'changes' array."}), 400

        # Detect if changes look like bucket ids (e.g., {group_key: "3"})
        if all(str(c.get("group_key", "")).isdigit() and len(str(c.get("group_key"))) <= 3 for c in changes):
            return jsonify({
                "error": "LIKELY_BUCKET_ID_PASSED",
                "ask_next": "Bucket workflow is disabled. Provide Base64 Group Key or plain UG_KEY instead."
            }), 400

        # Validate payload
        for i, c in enumerate(changes):
            if "group_key" not in c or not str(c["group_key"]).strip():
                return jsonify({"error": "BAD_CHANGE_ITEM", "hint": f"Change #{i+1} is missing 'group_key'."}), 400
            if ("new_rate" not in c) and ("pct_delta" not in c):
                return jsonify({"error": "BAD_CHANGE_ITEM", "hint": f"Change #{i+1} must have either 'new_rate' or 'pct_delta'."}), 400
            if "new_rate" in c:
                try: float(c["new_rate"])
                except Exception:
                    return jsonify({"error": "BAD_CHANGE_ITEM", "hint": f"Change #{i+1} 'new_rate' must be numeric."}), 400
            if "pct_delta" in c:
                try: float(c["pct_delta"])
                except Exception:
                    return jsonify({"error": "BAD_CHANGE_ITEM", "hint": f"Change #{i+1} 'pct_delta' must be numeric (e.g., -0.05 for -5%)."}), 400

        # Route to direct core
        try:
            result = preview_direct_core(report_df, changes)
        except ValueError as ve:
            msg = str(ve)
            if msg == "LIKELY_BUCKET_ID_PASSED":
                return jsonify({"error": "LIKELY_BUCKET_ID_PASSED", "ask_next": "Provide Base64 Group Key or plain UG_KEY."}), 400
            if msg == "NO_KEYS_MATCHED":
                return jsonify({"error": "NO_KEYS_MATCHED", "hint": "None of the provided group_key values matched the cached report. Use Base64 Group Key or plain UG_KEY, or re-run /filter-report to select."}), 400
            return jsonify({"error": "PREVIEW_DIRECT_FAILED", "message": msg}), 400

        pid = result.get("proposal_id")
        if not pid:
            return jsonify({"error": "PREVIEW_FAILED", "hint": "Direct preview did not return a proposal_id."}), 500
        try:
            _set_last_proposal(pid)
        except Exception:
            pass
        return jsonify(result), 200

    except Exception as e:
        return jsonify({"error": "PREVIEW_AUTO_FAILED", "message": str(e), "traceback": traceback.format_exc()}), 500


# === Confirm + Upload ===
@app.post("/confirm")
def confirm_proposal():
    body = request.get_json(silent=True) or {}
    pid = body.get("proposal_id")
    allow_block = bool(body.get("allow_block", False))
    test_mode = bool(body.get("test_mode", False))

    user = require_user_identity()
    if user is None:
        return jsonify({"error": "MISSING_IDENTITY"}), 428

    if not pid or not isinstance(pid, str):
        return jsonify({"error": "NEED_VALID_PROPOSAL_ID", "hint": "Call /preview/auto first and use the proposal_id it returns."}), 400

    if pid.strip().startswith("{") and pid.strip().endswith("}"):
        return jsonify({"error": "NEED_VALID_PROPOSAL_ID", "hint": "Do not pass the request body as proposal_id. Use the exact proposal_id from /preview/auto."}), 400

    recent = _recent_proposal()
    if not recent:
        return jsonify({"error": "NO_RECENT_PREVIEW", "ask_next": "Please run a preview first with /preview/auto. I need the fresh proposal_id to continue."}), 409

    if pid != recent["id"]:
        return jsonify({"error": "UNKNOWN_PROPOSAL_ID", "hint": f"Expected the most recent proposal_id '{recent['id']}'. Run preview again if unsure."}), 404

    path = os.path.join("proposals", f"{pid}.json")
    if not os.path.exists(path):
        return jsonify({"error": "UNKNOWN_PROPOSAL_ID", "hint": "This proposal_id was not found on the server. Run a fresh preview."}), 404

    rows = json.load(open(path))
    df = pd.DataFrame(rows)
    if not allow_block and "decision" in df:
        df = df[df["decision"] != "BLOCK"]

    patch_df = pd.DataFrame({
        "group_key_plain": df["group_key_plain"],
        "New Standard Rate": df["New Standard Rate"],
    })

    return finalize_upload(patch_df=patch_df, created_by_id=user, test_mode=test_mode, merge_key="decoded", change_source="direct")


@app.get("/ops/last-proposal")
def last_proposal():
    meta = _recent_proposal()
    if not meta:
        return jsonify({"error": "NO_RECENT_PREVIEW"}), 404
    return jsonify(meta), 200


# === GPT-facing upload (DIRECT/MANUAL ONLY) ===
@app.route('/gpt-upload-report', methods=['POST'])
def gpt_upload_report():
    data = request.get_json(force=True, silent=True) or {}
    change_source = (data.get('change_source') or 'manual').lower()  # accept 'direct' as alias
    csv_data = data.get('csv_data')
    test_mode = data.get('test_mode', False)

    if change_source not in {"manual", "direct"}:
        return jsonify({"error": "CHANGE_SOURCE_DISABLED", "hint": "Use change_source 'manual' or 'direct'. Bucket uploads are disabled."}), 400

    if change_source in {"manual", "direct"}:
        if not csv_data:
            return jsonify({"error": "Missing required field: csv_data"}), 400
        created_by_id = require_user_identity()
        if created_by_id is None:
            return jsonify({"error": "MISSING_IDENTITY"}), 428
        try:
            try:
                decoded_csv = base64.b64decode(csv_data, validate=True).decode("utf-8")
            except Exception:
                decoded_csv = csv_data  # fallback plain text
            patch_df = pd.read_csv(StringIO(decoded_csv))
        except Exception as e:
            return jsonify({"error": "CSV-parse failure", "exception": str(e)}), 400
        expected_cols = ['Group Key', 'New Standard Rate', 'New Cross Out Rate']
        if not all(col in patch_df.columns for col in expected_cols):
            return jsonify({"error": "Missing required columns", "columns": patch_df.columns.tolist()}), 400
        return finalize_upload(patch_df=patch_df, created_by_id=created_by_id, test_mode=test_mode, merge_key="decoded", change_source="direct")


# === Finalize Upload ===
def finalize_upload(patch_df, created_by_id, test_mode=False, merge_key="decoded", change_source="direct"):
    if not os.path.exists("latest_report.json"):
        return jsonify({"error": "Missing report file"}), 404

    with open("latest_report.json", "r") as f:
        report_json = json.load(f)
    report_rows = report_json.get("report_request", {}).get("report", [])
    full_df = pd.DataFrame(report_rows)

    if 'Group Key' not in full_df.columns:
        return jsonify({"error": "Missing Group Key in report"}), 400

    # Normalize keys
    full_df = make_group_key_plain_column(full_df, report_key_col="Group Key")

    try:
        if "group_key_plain" not in patch_df.columns:
            patch_df = coerce_patch_group_key(patch_df)
    except ValueError as e:
        return jsonify({"error": str(e), "patch_columns": patch_df.columns.tolist()}), 400

    if "New Standard Rate" in patch_df.columns:
        patch_df["New Standard Rate"] = pd.to_numeric(patch_df["New Standard Rate"], errors="coerce")
        patch_df = patch_df[patch_df["New Standard Rate"].notna()]

    take_cols = []
    if 'New Standard Rate' in patch_df.columns:
        take_cols.append('New Standard Rate')
    if 'New Cross Out Rate' in patch_df.columns:
        take_cols.append('New Cross Out Rate')
    if not take_cols:
        return jsonify({"error": "Patch must include 'New Standard Rate' and/or 'New Cross Out Rate'."}), 400

    merged = pd.merge(full_df, patch_df[['group_key_plain'] + take_cols], on='group_key_plain', how='left', suffixes=('', '_patch'))

    for col in ['New Standard Rate', 'New Cross Out Rate']:
        if f"{col}_patch" in merged.columns:
            merged[col] = merged[f"{col}_patch"]

    updated_rows = merged['New Standard Rate'].notna().sum()
    print(f"[Upload] Updated rows: {updated_rows}")

    # Default Cross Out rate if missing
    if 'New Cross Out Rate' not in merged.columns or merged['New Cross Out Rate'].isna().all():
        merged['New Cross Out Rate'] = (merged['New Standard Rate'] * 1.3).round()

    for col in ['Current Managed Rate', 'New Managed Rate', 'Current Cross Out Rate']:
        if col not in merged.columns:
            merged[col] = np.nan

    # Choose upload key
    if UPLOAD_GROUP_KEY_MODE == "base64":
        upload_key_series = merged['Group Key']  # original from report
    else:
        upload_key_series = merged['group_key_plain']
    merged['Group Key'] = upload_key_series

    needed = [
        'Facility ID', 'Group Key', 'Current Standard Rate', 'New Standard Rate',
        'Current Managed Rate', 'New Managed Rate', 'New Cross Out Rate'
    ]
    missing_needed = [c for c in needed if c not in merged.columns]
    if missing_needed:
        return jsonify({"error": "Missing required upload columns", "missing": missing_needed}), 400

    upload_df = merged[needed]

    if test_mode:
        return jsonify({"status": "validated", "row_count": int(upload_df.shape[0]), "csv_preview": upload_df.head(5).to_dict()})

    final_csv = upload_df.to_csv(index=False)
    file_stream = BytesIO(final_csv.encode("utf-8"))
    file_stream.name = "final_rate_upload.csv"

    r = upload_with_retries(file_stream, created_by_id)
    if not r:
        return jsonify({"error": "Upload failed after retries"}), 500

    try:
        resp_json = r.json()
    except Exception:
        return jsonify({"error": "Upload succeeded but response not JSON", "text": r.text}), 500

    log_rate_changes_to_db(merged, created_by_id, change_source=change_source, batch_id=resp_json.get('event_batch', {}).get('id'))

    return jsonify({
        "status": "uploaded",
        "updated_rows": int(updated_rows),
        "batch_id": resp_json.get('event_batch', {}).get('id'),
        "user": created_by_id
    })


# === Logging ===
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
        
        try:
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
                        ''',
                        (
                            created_by_id,
                            site_number,
                            row['Group Key'],
                            float(row['Current Standard Rate']) if pd.notnull(row['Current Standard Rate']) else None,
                            float(row['New Standard Rate']) if pd.notnull(row['New Standard Rate']) else None,
                            float(row.get('Current Cross Out Rate')) if pd.notnull(row.get('Current Cross Out Rate')) else None,
                            float(row.get('New Cross Out Rate')) if pd.notnull(row.get('New Cross Out Rate')) else None,
                            change_source,
                            batch_id,
                        ),
                    )
                conn.commit()
            print(f"[Logging] Logged {len(changed)} rate changes.")
        except ImportError:
            print("[Logging] Database not available - skipping rate change logging")
        except Exception as db_error:
            print(f"[Logging] Database error: {db_error}")
    except Exception as e:
        print(f"[Logging] Failed to log changes: {e}")
        traceback.print_exc()


# === Misc ===
@app.route("/")
def hello():
    return jsonify({"status": "running", "service": "Storedge Proxy API"}), 200


@app.route("/health")
def health():
    return jsonify({"status": "healthy", "timestamp": datetime.utcnow().isoformat()}), 200


@app.route("/readiness")
def readiness():
    """Readiness check for deployment health checks"""
    checks = {
        "flask_app": True,
        "company_id": bool(COMPANY_ID),
        # Only require API keys if we have at least one (for graceful startup)
        "has_credentials": bool(API_KEY or API_SECRET or PROXY_BEARER)
    }
    
    # Optional checks (don't fail readiness)
    optional_checks = {
        "api_key": bool(API_KEY),
        "api_secret": bool(API_SECRET),
        "proxy_bearer": bool(PROXY_BEARER)
    }
    
    # App is ready if core checks pass
    all_ready = all(checks.values())
    status_code = 200 if all_ready else 503
    
    return jsonify({
        "ready": all_ready,
        "checks": checks,
        "optional_checks": optional_checks,
        "timestamp": datetime.utcnow().isoformat()
    }), status_code


@app.route("/debug/auth-test")
def debug_auth_test():
    """Debug endpoint to test authentication without side effects"""
    guard = require_bearer(request)
    if guard: 
        return guard
    
    return jsonify({
        "message": "Authentication successful!",
        "proxy_bearer_set": bool(PROXY_BEARER),
        "proxy_bearer_length": len(PROXY_BEARER) if PROXY_BEARER else 0,
        "authorization_header": request.headers.get("Authorization", "Not provided")[:50] + "..." if request.headers.get("Authorization") else "Not provided",
        "timestamp": datetime.utcnow().isoformat()
    }), 200


@app.route("/debug/storedge-test/<facility_id>/<unit_id>", methods=["PUT"])
def debug_storedge_test(facility_id, unit_id):
    """Debug endpoint to test the Storedge API call directly"""
    guard = require_bearer(request)
    if guard: return guard
    
    raw_body = request.get_json(silent=True) or {}
    reason = raw_body.get("reason", "Debug test from proxy")
    
    # Test the exact Storedge API call
    storedge_body = {
        "reason": reason,
        "unit": {}
    }
    
    url = f"{BASE_URL}/v1/{facility_id}/units/{unit_id}/make_unit_rentable"
    
    try:
        print(f"[DEBUG] Calling Storedge API: {url}")
        print(f"[DEBUG] Request body: {storedge_body}")
        print(f"[DEBUG] API Key set: {bool(API_KEY)}")
        print(f"[DEBUG] API Secret set: {bool(API_SECRET)}")
        
        r = requests.put(url, json=storedge_body, auth=OAuth1(API_KEY, API_SECRET), timeout=60)
        
        print(f"[DEBUG] Storedge response status: {r.status_code}")
        print(f"[DEBUG] Storedge response headers: {dict(r.headers)}")
        
        response_data = {
            "storedge_url": url,
            "storedge_status": r.status_code,
            "storedge_headers": dict(r.headers),
            "proxy_auth_working": True,
            "api_credentials_set": bool(API_KEY and API_SECRET)
        }
        
        try:
            storedge_response = r.json()
            response_data["storedge_response"] = storedge_response
        except:
            response_data["storedge_response_text"] = r.text[:500]
        
        return jsonify(response_data), 200
        
    except Exception as e:
        return jsonify({
            "error": "STOREDGE_API_ERROR",
            "message": str(e),
            "storedge_url": url,
            "proxy_auth_working": True
        }), 500


@app.route("/debug/sample-units/<facility_id>")
def debug_sample_units(facility_id):
    """Debug endpoint to get sample units from a facility"""
    guard = require_bearer(request)
    if guard: return guard
    
    url = f"{BASE_URL}/v1/{facility_id}/units"
    
    try:
        r = requests.get(url, auth=OAuth1(API_KEY, API_SECRET), params={"limit": 5}, timeout=60)
        
        if r.status_code == 200:
            units_data = r.json()
            return jsonify({
                "facility_id": facility_id,
                "sample_units_count": len(units_data.get("data", [])),
                "sample_units": units_data.get("data", [])[:3],  # First 3 units
                "storedge_status": r.status_code
            }), 200
        else:
            return jsonify({
                "error": "Failed to fetch units",
                "facility_id": facility_id,
                "storedge_status": r.status_code,
                "storedge_response": r.text[:500]
            }), r.status_code
            
    except Exception as e:
        return jsonify({
            "error": "STOREDGE_API_ERROR", 
            "message": str(e),
            "facility_id": facility_id
        }), 500


# === Validators ===
def is_valid_se_id(s):
    try:
        UUID(str(s))
        return True
    except Exception:
        return False


# === SMART UNIT SEARCH ===

@app.post("/units/search-and-update")
def universal_search_and_update():
    """SIMPLE WORKING SEARCH: Find facility by name, find units by name, update them"""
    guard = require_bearer(request)
    if guard: return guard
    
    body = request.get_json(silent=True) or {}
    facility_name = body.get("facility_name", "").strip()
    unit_names = body.get("unit_names", [])
    rentable = body.get("rentable")
    reason = body.get("reason", "").strip()
    
    if not facility_name or not unit_names or rentable is None or not reason:
        return jsonify({"error": "Missing required fields: facility_name, unit_names, rentable, reason"}), 400
    
    try:
        # STEP 1: Find facility by name
        facilities_url = f"{BASE_URL}/v1/companies/{COMPANY_ID}/facilities/short"
        r = requests.get(facilities_url, auth=OAuth1(API_KEY, API_SECRET), timeout=30)
        
        if r.status_code != 200:
            return jsonify({"error": "Failed to get facilities"}), 500
            
        data = r.json()
        facilities = data.get("facilities", [])
        matching_facilities = [f for f in facilities if facility_name.lower() in f.get("facility_name", "").lower()]
        
        if not matching_facilities:
            return jsonify({"error": "FACILITY_NOT_FOUND", "facility_name": facility_name, "available_facilities": [f.get("facility_name") for f in facilities[:10]]}), 404
        
        if len(matching_facilities) > 1:
            return jsonify({"error": "MULTIPLE_FACILITIES_FOUND", "matches": [{"id": f["id"], "name": f["facility_name"]} for f in matching_facilities]}), 400
        
        facility_id = matching_facilities[0]["id"]
        
        # STEP 2: Find units by name within facility
        found_units = []
        not_found = []
        
        for unit_name in unit_names:
            # Search through pages to find the unit
            unit_found = False
            for page in range(1, 21):  # Search 20 pages max
                units_url = f"{BASE_URL}/v1/{facility_id}/units"
                params = {"page": page, "per_page": 50}
                
                r = requests.get(units_url, params=params, auth=OAuth1(API_KEY, API_SECRET), timeout=30)
                if r.status_code != 200:
                    break
                    
                units = r.json().get("units", [])
                if not units:
                    break
                
                # Look for partial matches
                matches = [u for u in units if unit_name.lower() in u.get("name", "").lower() or u.get("name", "").lower() in unit_name.lower()]
                
                if matches:
                    found_units.extend(matches)
                    unit_found = True
                    break
            
            if not unit_found:
                not_found.append(unit_name)
        
        if not found_units:
            return jsonify({
                "error": "NO_UNITS_FOUND", 
                "facility": matching_facilities[0]["name"],
                "searched_for": unit_names,
                "not_found": not_found
            }), 404
        
        # STEP 3: Show matches for confirmation if there are multiple or inexact matches
        if len(found_units) != len(unit_names) or any(u.get("name") not in unit_names for u in found_units):
            return jsonify({
                "confirmation_needed": True,
                "facility": matching_facilities[0]["facility_name"],
                "found_units": [{"id": u["id"], "name": u["name"], "rentable": u.get("rentable")} for u in found_units],
                "searched_for": unit_names,
                "not_found": not_found,
                "message": "Please confirm these are the correct units to update"
            })
        
        # STEP 4: Update the units
        updated_units = []
        failed_units = []
        
        for unit in found_units:
            try:
                update_url = f"{BASE_URL}/v1/{facility_id}/units/{unit['id']}"
                r = requests.put(update_url, json={"unit": {"rentable": rentable}}, auth=OAuth1(API_KEY, API_SECRET), timeout=30)
                
                if r.status_code == 200:
                    updated_units.append({
                        "id": unit["id"], 
                        "name": unit["name"], 
                        "rentable": rentable,
                        "previous_rentable": unit.get("rentable")
                    })
                else:
                    failed_units.append({"id": unit["id"], "name": unit["name"], "error": f"HTTP {r.status_code}"})
            except Exception as e:
                failed_units.append({"id": unit.get("id"), "name": unit.get("name"), "error": str(e)})
        
        return jsonify({
            "facility": matching_facilities[0]["facility_name"],
            "total_found": len(found_units),
            "updated_successfully": len(updated_units), 
            "failed": len(failed_units),
            "rentable": rentable,
            "reason": reason,
            "updated_units": updated_units,
            "failed_units": failed_units
        })
        
    except Exception as e:
        return jsonify({"error": "SEARCH_ERROR", "message": str(e)}), 500


if __name__ == "__main__":
    # For deployment, use environment variables
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    
    app.run(
        host="0.0.0.0", 
        port=port, 
        debug=debug_mode
    )
