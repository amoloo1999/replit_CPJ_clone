import os
import time
import json
import pandas as pd
from io import BytesIO, StringIO
from dotenv import load_dotenv
from datetime import datetime
import numpy as np
import base64
import traceback

# SQL connection (pytds)
import pytds
from pytds import tds_base

# Load environment variables
load_dotenv()


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
      tds_version=tds_base.TDS74,  # SQL Server 2012+
  )


# --- Step 1: Prepare Dummy Data ---
dummy_data = pd.DataFrame([{
    "Group Key": "DUMMY123",
    "New Standard Rate": 120.0,
    "New Cross Out Rate": 100.0,
    "Old Standard Rate": 115.0,
    "Old Cross Out Rate": 90.0,
}])

# Replace NaN with None so SQL doesn't get mad
dummy_data = dummy_data.where(pd.notnull(dummy_data), None)


# --- Step 2: Try Logging to SQL ---
def execute_debug(cursor, query, params):
  print(f"\n[SQL EXECUTE] Query:\n{query}")
  print(f"[SQL EXECUTE] Params:\n{params}\n")
  return cursor.execute(query, params)


try:
  with connect_to_db("sE") as conn:
    cur = conn.cursor()
    for _, row in dummy_data.iterrows():
      execute_debug(
          cur, """
                INSERT INTO sE.dbo.rate_change_log
                    (user_id, site_number, group_key,
                     old_standard_rate, new_standard_rate,
                     old_cross_out_rate, new_cross_out_rate,
                     source, batch_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
          ("debug_user", "0000", row["Group Key"], row["Old Standard Rate"],
           row["New Standard Rate"], row["Old Cross Out Rate"],
           row["New Cross Out Rate"], "debug", "debug-batch"))
    conn.commit()
  print("[✅ SUCCESS] Inserted dummy row into rate_change_log")

except Exception:
  print("[🔥 ERROR] Logging failed:")
  traceback.print_exc()
