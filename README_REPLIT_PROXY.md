# Storedge Units Proxy (Replit)

Adds facilities & units proxy endpoints to existing Flask app so GPT Actions can safely perform unit lookups and modifications.

## New Endpoints

All require `Authorization: Bearer <PROXY_BEARER>` (unless `PROXY_BEARER` env left blank in dev):

- `GET /facilities/short` – list facilities (id + name)
- `GET /facilities/<facility_id>/units` – list units
- `PUT /facilities/<facility_id>/units/bulk_update` – partial fields update
- `POST /facilities/<facility_id>/units/bulk_create` – create units
- `POST /facilities/<facility_id>/units/make_rentable` – mark units rentable/unrentable
 - `GET /cache/facilities` – inspect cached facilities list (bearer-protected)
 - `GET /cache/facilities/<facility_id>/units` – inspect cached units for facility

## Required Secrets (Replit)

Set these in the Secrets tab:

- `STOREDGE_API_KEY`
- `STOREDGE_API_SECRET`
- `COMPANY_ID` (UUID of tenant/company)
- `PROXY_BEARER` (long random string for GPT Action auth)
- (Optional existing) `MSSQL_USER`, `MSSQL_PASSWORD`, `MSSQL_HOST` for legacy endpoints

## Run Command

`.replit` already uses:

```
run = "gunicorn --bind 0.0.0.0:3000 main:app"
```

Swap to 5000 or 8000 if preferred. Example manual run:

```
gunicorn main:app -k gthread -w 1 -b 0.0.0.0:5000
```

## Smoke Tests

Replace placeholders with actual URL and bearer token.

```
# health
curl -s https://<repl>.repl.co/ping

# facilities
curl -s -H "Authorization: Bearer $PROXY_BEARER" https://<repl>.repl.co/facilities/short | jq .

# units
curl -s -H "Authorization: Bearer $PROXY_BEARER" https://<repl>.repl.co/facilities/<FACILITY_ID>/units | jq .

# bulk update
curl -s -X PUT \
  -H "Authorization: Bearer $PROXY_BEARER" \
  -H "Content-Type: application/json" \
  https://<repl>.repl.co/facilities/<FACILITY_ID>/units/bulk_update \
  -d '{"units":[{"id":"<UNIT_ID>","door_type":"roll_up"}]}' | jq .
```

## OpenAPI (GPT Action)

See `openapi_units_proxy.yaml`. Replace `https://YOUR_REPL_URL` with your deployed URL, upload in GPT Builder, and configure Bearer auth with `PROXY_BEARER`.

## Notes / Guardrails

- Omitted fields in bulk_update leave values unchanged.
- Empty array `[]` clears collection fields (amenities, tax_rates, etc.).
- Validate enumerations in the GPT instructions (e.g., door_type: none|roll_up|swing). This layer intentionally keeps logic thin.
- `PROXY_BEARER` left blank disables auth gate (dev only). Always set in production.
- Validation guards run before calling Storedge:
  - Enumerations enforced: `door_type` (none|roll_up|swing), `access_type` (indoor|outdoor)
  - Bulk update: each unit must have an id and at least one changed, allowed field
  - Bulk create: requires unique `unit_number`
  - Make rentable: requires `id` and boolean `rentable`
  - Returns 400 with structured `details` list on validation failure.
- Caching:
  - Facilities list cached up to `FACILITIES_CACHE_TTL` (default 300s)
  - Units list per facility cached up to `UNITS_CACHE_TTL` (default 120s)
  - Force refresh with `?refresh=1` query parameter.

## Future Enhancements

- Add field validation before forwarding to Storedge.
- Cache facility/unit lookups for short TTL to reduce latency.
- Add rate limiting or simple request counter to mitigate abuse.
