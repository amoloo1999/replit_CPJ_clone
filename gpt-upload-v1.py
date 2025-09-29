@app.route("/gpt-upload-report", methods=["POST"])
def gpt_upload_report():
  # 1) Ensure user is set
  created_by_id = require_user_identity()
  if created_by_id is None:
    return jsonify(convert_types({"error": "MISSING_IDENTITY"})), 428

  change_source = request.json.get("change_source", "manual")
  raw_csv = request.json.get("csv_data")
  if change_source == "manual" and not raw_csv:
    return jsonify({"error": "Missing CSV data for manual upload"}), 400

  if change_source == "bucket":
    # Optional: validate that bucket_rate_results.json exists
    if not os.path.exists("bucket_rate_results.json"):
      return jsonify({"error": "Missing bucket results file"}), 400
  if raw_csv and "Base64 blob will be generated here" in raw_csv:
    return jsonify({
        "error":
        "Placeholder CSV blob received, GPT may have failed to generate real rate changes."
    }), 400
  try:
    rate_csv = base64.b64decode(raw_csv).decode("utf‑8")
  except Exception:
    # Fallback if someone still sends plain text
    rate_csv = raw_csv

  # 2) -- Pull unit_types lookup --
  with connect_to_db('sE') as conn:
    ut_df = pd.read_sql_query('SELECT ut_id, ut_name FROM sE.dbo.unit_types',
                              conn)

  # 3) Load cached report
  if not os.path.exists("latest_report.json"):
    return jsonify(
        convert_types({
            "error":
            "No stored report found. Please generate a report first via /create-report."
        })), 404

  try:
    # -- Robustly extract report rows --
    with open("latest_report.json", "r") as f:
      report_json = json.load(f)
    report_section = report_json.get("report_request", {}).get("report")

    if isinstance(report_section, list):
      report_rows = report_section
    elif isinstance(report_section, dict):
      report_rows = report_section.get("report_request", {}).get("report", [])
    else:
      return jsonify(convert_types({"error":
                                    "Unable to parse report rows"})), 500

    full_df = pd.DataFrame(report_rows)

    if "Group Key" not in full_df.columns:
      return jsonify(
          convert_types({"error": "'Group Key' missing from report"})), 400

    # 4) Decode Base64 and normalize to “dims – unit_type – amenities”
    decoded = []
    for b64 in full_df['Group Key']:
      try:
        decoded.append(base64.b64decode(b64).decode('ascii'))
      except Exception:
        decoded.append("")  # silently drop bad keys
    full_df['decoded_key'] = decoded
    full_df['Group Key Base64'] = full_df[
        'Group Key']  # <-- preserve the original!

    def normalize_key(enc_str):
      # split into exactly 4 parts: dims, price, id, amenities
      parts = enc_str.split(' - ', 3)
      if len(parts) == 4:
        dims, price, id_part, amenities = parts
        uid = id_part.strip('[]')
        try:
          ut_name = ut_df.loc[ut_df['ut_id'] == int(uid), 'ut_name'].iat[0]
        except Exception:
          ut_name = uid
        return f"{dims} - {ut_name} - {amenities}"
      # fallback: return raw
      return enc_str

    full_df['Group Key'] = full_df['decoded_key'].apply(normalize_key)

    # 5) Load patch DataFrame
    if change_source == 'bucket':
      bucket = json.load(open('bucket_rate_results.json'))
      patch_df = pd.DataFrame(bucket)
      # ug_key already matches our normalized “Group Key”
      patch_df['Group Key'] = patch_df['ug_key'].astype(str).str.strip()
      patch_df['New Standard Rate'] = patch_df['standard_rate']
      patch_df['New Cross Out Rate'] = (patch_df['standard_rate'] *
                                        1.3).round()
      merged = pd.merge(
          full_df,
          patch_df[['Group Key', 'New Standard Rate', 'New Cross Out Rate']],
          on='Group Key',
          how='left')
    else:
      # ---------- 5A. Parse CSV safely ----------
      try:
        patch_df = pd.read_csv(StringIO(rate_csv))
      except Exception as csv_err:
        return jsonify({
            "error": "CSV‑parse failure",
            "exception": str(csv_err),
            "csv_snippet": rate_csv[:300]
        }), 400

      # ---------- 5B. Validate required columns ----------
      required_cols = ['Group Key', 'New Standard Rate', 'New Cross Out Rate']
      missing_cols = [c for c in required_cols if c not in patch_df.columns]
      if missing_cols:
        return jsonify({
            "error":
            "Patch CSV missing required columns",
            "missing_columns":
            missing_cols,
            "patch_cols":
            patch_df.columns.tolist(),
            "patch_head":
            convert_types(patch_df.head(3).astype(str).to_dict())
        }), 400

      # ---------- 5C. Normalise key column & base‑64 guard ----------
      patch_df['Group Key'] = patch_df['Group Key'].astype(str).str.strip()

      if not patch_df['Group Key'].str.match(r'^[A-Za-z0-9+/]+={0,2}$').all():
        return jsonify({
            "error": "CSV Group Key column is not base‑64 as required.",
            "sample_keys": patch_df['Group Key'].head(3).tolist()
        }), 400

      # ---------- 5D. Ensure report has Group Key Base64 ----------
      if 'Group Key Base64' not in full_df.columns:
        return jsonify({
            "error": "Group Key Base64 column missing in report",
            "full_df_cols": full_df.columns.tolist()
        }), 500

      full_df['Group Key Base64'] = full_df['Group Key Base64'].astype(
          str).str.strip()

      # ---------- 5E. Quick overlap check ----------
      overlap = set(patch_df['Group Key']) & set(full_df['Group Key Base64'])
      print(f"[Debug] Overlap count = {len(overlap)} / {len(patch_df)}")

      # ---------- 5F. Merge ----------
      merged = pd.merge(
          full_df,
          patch_df[['Group Key', 'New Standard Rate', 'New Cross Out Rate']],
          left_on='Group Key Base64',
          right_on='Group Key',
          how='left')

      # ---------- 5G. Validate merge success ----------
      expected = ['New Standard Rate_y', 'New Cross Out Rate_y']
      missing_after_merge = [c for c in expected if c not in merged.columns]
      if missing_after_merge:
        return jsonify({
            "error":
            "Merge produced no rate columns (likely key mismatch)",
            "missing_after_merge":
            missing_after_merge,
            "patch_head":
            convert_types(patch_df.head(3).astype(str).to_dict()),
            "full_head":
            convert_types(full_df[['Group Key Base64'
                                   ]].head(3).astype(str).to_dict())
        }), 500

    # 6) Merge updates
    # Count how many rows have new rates to upload
    updated_rows = merged['New Standard Rate_y'].notna().sum()
    print(f"[GPT Upload] Injecting updated rates for {updated_rows} rows")

    # 7) Prepare all required columns for upload
    # Ensure all required columns are present in merged
    for col in [
        'Facility ID', 'Current Standard Rate', 'Current Managed Rate',
        'New Managed Rate'
    ]:
      if col not in merged.columns:
        merged[col] = ''  # fill empty if not present

    # Use the original base64 group key for upload
    merged['Group Key'] = full_df['Group Key Base64'].values

    # ---------- 8)  Build the bullet‑proof upload_df  ----------
    # Map:  base‑64 key  ->  proposed Standard rate
    rate_map = dict(
        zip(
            patch_df['Group Key'],  # already validated as base‑64
            patch_df[
                'New Standard Rate']  # new rate (may be NaN for untouched rows)
        ))

    # Start from the full report so we never lose a column or row
    upload_df = full_df.copy()

    # Inject the proposed rates; untouched rows stay NaN/blank
    upload_df['New Standard Rate'] = upload_df['Group Key Base64'].map(
        rate_map)
    upload_df['New Cross Out Rate'] = (upload_df['New Standard Rate'] *
                                       1.3).round(0)

    # Match Storedge’s expected column order
    upload_df = upload_df[[
        'Facility ID',
        'Group Key Base64',  # rename to Group Key for upload
        'Current Standard Rate',
        'New Standard Rate',
        'Current Managed Rate',
        'New Managed Rate',
        'New Cross Out Rate'
    ]].rename(columns={'Group Key Base64': 'Group Key'})

    # OPTIONAL: keep only changed rows (uncomment if your backend requires it)
    # upload_df = upload_df[upload_df['New Standard Rate'].notna()]

    # 9) Prepare & send to Storedge
    print("UPLOAD_DF HEAD:\n", upload_df.head(10))
    print("UPLOAD_DF NOTNA COUNT:",
          upload_df['New Standard Rate'].notna().sum())
    final_csv = upload_df.to_csv(index=False)
    b64_csv = base64.b64encode(final_csv.encode("utf‑8")).decode("ascii")
    print("FINAL CSV FIRST 500:\n", final_csv[:500])

    file_stream = BytesIO(final_csv.encode('utf-8'))
    file_stream.name = 'final_rate_upload.csv'

    # Optional: Log a preview to your console for extra context
    print("[Upload] CSV first 500 chars:")
    print(final_csv[:500])

    r = upload_with_retries(file_stream, created_by_id)
    if r is None:
      return jsonify(
          convert_types({
              "error":
              "Upload failed after retries",
              "csv_preview":
              final_csv[:500],
              "row_count":
              int(upload_df.shape[0]),  # cast to int!
              "column_count":
              int(upload_df.shape[1]),  # cast to int!
              "upload_df_head":
              upload_df.head(5).astype(str).to_dict()  # cast df to str!
          })), 500

    # Upload succeeded but API might return non-JSON or error code
    try:
      resp_json = r.json()
    except Exception as parse_err:
      return jsonify(
          convert_types({
              "error": "Upload succeeded but response is not JSON",
              "status_code": r.status_code,
              "text": r.text
          })), 500

    batch_id = resp_json.get('event_batch', {}).get('id') if isinstance(
        resp_json, dict) else None

    # 10) Logging changes
    try:
      # Identify changed rows (any new rate, standard or cross out, that is not NA)
      changed_mask = (merged['New Standard Rate_y'].notna()
                      | merged['New Cross Out Rate_y'].notna())

      # Ensure columns exist
      for col in [
          'Current Cross Out Rate', 'Current Standard Rate',
          'New Standard Rate_y', 'New Cross Out Rate_y'
      ]:
        if col not in merged.columns:
          merged[col] = None

      # Prepare changes DataFrame
      changes = merged.loc[changed_mask, [
          'Group Key', 'New Standard Rate_y', 'New Cross Out Rate_y',
          'Current Standard Rate', 'Current Cross Out Rate'
      ]].rename(
          columns={
              'New Standard Rate_y': 'New Standard Rate',
              'New Cross Out Rate_y': 'New Cross Out Rate',
              'Current Standard Rate': 'Old Standard Rate',
              'Current Cross Out Rate': 'Old Cross Out Rate'
          })

      print(f"[Logging] Number of rows to log: {len(changes)}")
      print(f"[Logging] changes DataFrame:\n{changes}")

      # Determine site_number for logging
      site_number = None
      if 'Facility Number' in merged.columns and not merged[
          'Facility Number'].empty:
        site_number = str(merged['Facility Number'].iloc[0])

      print(
          f"[Logging] About to insert {len(changes)} rows (batch_id={batch_id})"
      )

      # Write to DB
      with connect_to_db('sE') as conn:
        cur = conn.cursor()
        for _, row in changes.iterrows():
          cur.execute(
              '''
                        INSERT INTO sE.dbo.rate_change_log
                          (user_id, site_number, group_key,
                           old_standard_rate, new_standard_rate,
                           old_cross_out_rate, new_cross_out_rate,
                           source, batch_id)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        ''',
              (created_by_id, site_number, row['Group Key'],
               float(row['Old Standard Rate'])
               if pd.notnull(row['Old Standard Rate']) else None,
               float(row['New Standard Rate'])
               if pd.notnull(row['New Standard Rate']) else None,
               float(row['Old Cross Out Rate'])
               if pd.notnull(row['Old Cross Out Rate']) else None,
               float(row['New Cross Out Rate'])
               if pd.notnull(row['New Cross Out Rate']) else None,
               change_source, batch_id))
        conn.commit()
      print(f"[Logging] Inserted {len(changes)} rows into rate_change_log")

    except Exception as log_err:
      print(f"[Logging] Failed to record changes: {log_err}")
      import traceback
      traceback.print_exc()

    # 11) Audit snapshot
    audit_path = f"rate_upload_log_{time.strftime('%Y%m%d-%H%M%S')}.csv"
    merged.to_csv(audit_path, index=False)

    # 12) Return success
    response_debug = {
        'status':
        'uploaded',
        'updated_rows':
        updated_rows,
        'batch_id':
        batch_id,
        'user':
        created_by_id,
        'changed_mask_count':
        int(changed_mask.sum()) if 'changed_mask' in locals() else 'N/A',
        'logged_rows':
        int(len(changes)) if 'changes' in locals() else 'N/A',
        'changes_head':
        convert_types(changes.head(5).to_dict())
        if 'changes' in locals() and not changes.empty else [],
        'merged_head':
        convert_types(merged.head(5).to_dict())
        if 'merged' in locals() else [],
        'patch_head':
        convert_types(patch_df.head(5).to_dict())
        if 'patch_df' in locals() else [],
        'columns':
        list(merged.columns) if 'merged' in locals() else [],
        'csv_data_snippet':
        str(rate_csv)[:300] if 'rate_csv' in locals() else None,
    }
    return jsonify(response_debug), r.status_code

  except Exception as e:
    tb = traceback.format_exc()
    debug_info = {
        "error":
        f"Upload processing failed: {e}",
        "traceback":
        tb,
        "patch_columns":
        patch_df.columns.tolist() if 'patch_df' in locals() else 'N/A',
        "patch_head":
        convert_types(patch_df.head(3).astype(str).to_dict())
        if 'patch_df' in locals() else 'N/A',
        "merged_columns":
        merged.columns.tolist() if 'merged' in locals() else 'N/A',
        "merged_head":
        convert_types(merged.head(3).astype(str).to_dict())
        if 'merged' in locals() else 'N/A',
        "len_patch_df":
        int(len(patch_df)) if 'patch_df' in locals() else 'N/A',
        "len_merged":
        int(len(merged)) if 'merged' in locals() else 'N/A',
    }
    return jsonify(convert_types(debug_info)), 500
