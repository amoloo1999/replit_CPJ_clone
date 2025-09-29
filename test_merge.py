import json
import pandas as pd
from io import StringIO

# === Load full report (latest_report.json) ===
with open("latest_report.json") as f:
    report_json = json.load(f)

# Safely navigate to the right part of the JSON
if isinstance(report_json.get("report_request", {}).get("report"), list):
    report_rows = report_json["report_request"]["report"]
elif isinstance(report_json.get("report_request", {}).get("report"), dict):
    report_rows = report_json["report_request"]["report"]["report_request"][
        "report"]
else:
    raise Exception("Unknown report format!")

print("=== TYPE OF report_rows ===", type(report_rows))
print("=== NUM ROWS ===", len(report_rows))
if isinstance(report_rows, list) and report_rows:
    print("=== FIRST ROW ===", report_rows[0])
else:
    print("No rows in report_rows!")

full_df = pd.DataFrame(report_rows)
print("\n=== FULL_DF HEAD ===\n", full_df.head())

# === Patch data as CSV string (as would be received from LLM) ===
patch_csv_data = """Facility ID,Group Key,Current Standard Rate,New Standard Rate,Current Managed Rate,New Managed Rate,New Cross Out Rate\n4ce7ce30-ee9e-430f-9357-d940c06f7056,NXgxMHgwIC0gJDU4LjAwIC0gMjM5MTkyIC0gWzE1Njg0MyAtIDE3MjYzNV0=,58.0,55,,,$72
"""  # <--- replace with your real patch CSV content if needed

patch_df = pd.read_csv(StringIO(patch_csv_data))
print("\n=== PATCH_DF HEAD ===\n", patch_df.head())

# --- Normalize Group Keys on both sides ---
full_df['Group Key'] = full_df['Group Key'].astype(str).str.strip()
patch_df['Group Key'] = patch_df['Group Key'].astype(str).str.strip()

print("\n=== FULL_DF Group Keys ===")
print(full_df['Group Key'].tolist())
print("\n=== PATCH_DF Group Keys ===")
print(patch_df['Group Key'].tolist())

# --- Check for intersections ---
intersect = set(full_df['Group Key']) & set(patch_df['Group Key'])
print("\n=== INTERSECTING KEYS (should NOT be empty!) ===")
print(intersect)

# --- Merge ---
merged = pd.merge(
    full_df,
    patch_df[['Group Key', 'New Standard Rate', 'New Cross Out Rate']],
    on='Group Key',
    how='left',
    suffixes=('', '_patch'))
print("\n=== MERGED HEAD ===\n", merged.head())

# Show rows where a new standard rate will be injected
updated = merged[merged['New Standard Rate'].notna()
                 | merged['New Standard Rate_patch'].notna()]
print(
    "\n=== UPDATED ROWS ({}) ===\n".format(len(updated)), updated[[
        'Group Key', 'Current Standard Rate', 'New Standard Rate_patch',
        'New Cross Out Rate_patch'
    ]])
