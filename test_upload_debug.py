import os
import json
import pandas as pd
import base64
import traceback
from dotenv import load_dotenv
import pytds

# Load environment variables for DB connection
load_dotenv()


def connect_to_db(db_name):
    """
    Return a live pytds connection to the given database using env vars.
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
        tds_version=pytds.tds_base.TDS74,  # SQL Server 2012+
    )


def inspect_report_structure(path):
    """
    Print the JSON structure of the report for debugging.
    """
    print(f"\nLoading report JSON from {path}")
    with open(path, 'r') as f:
        data = json.load(f)

    def walk(obj, prefix=''):
        if isinstance(obj, dict):
            for k, v in obj.items():
                print(f"{prefix}{k}: {type(v).__name__}")
                if isinstance(v, dict):
                    walk(v, prefix + '  ')
        elif isinstance(obj, list):
            print(f"{prefix}[list] length={len(obj)}")

    walk(data)
    return data


def UG_Key(enc_str):
    """
    Normalize a decoded key string into 'dims - unit_type_name - amenities'.
    Handles raw report format of four parts.
    """
    parts = enc_str.split(' - ', 3)
    if len(parts) == 4:
        dims, price, id_part, amenities = parts
        id_str = id_part.strip('[]')
        try:
            ut_id = int(id_str)
            ut_name = ut_df.loc[ut_df['ut_id'] == ut_id, 'ut_name'].iat[0]
        except Exception as e:
            print(f"[UG_Key] Lookup failed for ID {id_str}: {e}")
            ut_name = id_str
        return f"{dims} - {ut_name} - {amenities}"
    # Fallback for unexpected formats
    return enc_str.strip()


def test_decode_and_merge(report_data, patch_path=None):
    try:
        rows = report_data['report_request']['report']['report_request'][
            'report']
        print(f"Extracted {len(rows)} rows.")
    except Exception as e:
        print("Error extracting rows:", e)
        traceback.print_exc()
        return

    df = pd.DataFrame(rows)
    print("Initial columns:", df.columns.tolist())

    # 1) Decode Base64 keys
    decoded = []
    for val in df['Group Key']:
        try:
            decoded.append(base64.b64decode(val).decode('ascii'))
        except Exception as e:
            decoded.append(f"<decode error: {e}>")
    df['decoded_key'] = decoded

    # 2) Normalize report-side keys via UG_Key
    df['Group Key Normalized'] = df['decoded_key'].apply(UG_Key)
    print("Sample normalized latest_json keys:",
          df['Group Key Normalized'].head().tolist())

    if patch_path:
        print(f"\nLoading bucket_json data from {patch_path}")
        with open(patch_path, 'r') as f:
            patch = json.load(f)
        patch_df = pd.DataFrame(patch)
        # Patch values already use decoded ug_key format, no further translation needed
        patch_df['Group Key Normalized'] = patch_df['ug_key'].astype(
            str).str.strip()
        patch_df['New Standard Rate'] = patch_df['standard_rate']
        patch_df['New Cross Out Rate'] = (patch_df['standard_rate'] *
                                          1.3).round()
        print("Sample normalized bucket_json keys:",
              patch_df['Group Key Normalized'].head().tolist())

        # Compare key sets
        report_keys = set(df['Group Key Normalized'])
        patch_keys = set(patch_df['Group Key Normalized'])
        print("Keys in latest_json not in bucket_json:",
              report_keys - patch_keys)
        print("Keys in bucket_json not in latest_json:",
              patch_keys - report_keys)

        # Merge on the unified key
        try:
            merged = pd.merge(df,
                              patch_df[[
                                  'Group Key Normalized', 'New Standard Rate',
                                  'New Cross Out Rate'
                              ]],
                              on='Group Key Normalized',
                              how='left')
            print("Merge successful, result shape:", merged.shape)
        except Exception as e:
            print("Error merging:", e)
            traceback.print_exc()


def main():
    global ut_df
    # Load lookup for unit types
    if os.path.exists('unit_types.csv'):
        print("Loading unit_types from local CSV")
        ut_df = pd.read_csv('unit_types.csv')
    else:
        print("Loading unit_types from SQL Server")
        with connect_to_db('sE') as conn:
            ut_df = pd.read_sql_query(
                'SELECT ut_id, ut_name FROM sE.dbo.unit_types', conn)

    report_data = inspect_report_structure('latest_report.json')
    test_decode_and_merge(report_data, patch_path='bucket_rate_results.json')


if __name__ == '__main__':
    main()
