# Storedge Units Proxy API

## Overview
This is a Flask-based REST API that acts as a proxy for Storedge FMS (Facility Management System) operations. The application provides endpoints for managing facilities, units, and pricing through the Storedge API.

## Recent Changes
- **2025-09-30**: Initial import and Replit environment setup
  - Installed Python dependencies (Flask, Gunicorn, Pandas, etc.)
  - Configured Flask server to run on port 5000
  - Set up deployment configuration for VM-based hosting
  - Added .gitignore for Python project

## Project Architecture

### Technology Stack
- **Backend**: Python 3.11 with Flask
- **Server**: Gunicorn with sync workers
- **Database**: MSSQL (via python-tds) for logging
- **External API**: Storedge FMS API (OAuth1)
- **Data Processing**: Pandas, NumPy

### Key Components
1. **Facilities/Units Proxy** - GPT Action endpoints for facility and unit management
2. **Pricing Management** - Rate change workflows with validation and guardrails
3. **Report Processing** - Async report generation and caching
4. **Authentication** - Bearer token authentication for proxy endpoints

### Main Endpoints
- `/ping` - Health check
- `/facilities/short` - List facilities (cached)
- `/facilities/<id>/units` - List units for facility (cached)
- `/facilities/<id>/units/bulk_update` - Bulk update units
- `/facilities/<id>/units/bulk_create` - Bulk create units
- `/facilities/<id>/units/make_rentable` - Toggle unit rentability
- `/create-report` - Generate pricing report
- `/preview/auto` - Preview rate changes
- `/confirm` - Confirm and upload rate changes

### Environment Variables Required
- `STOREDGE_API_KEY` - Storedge API key
- `STOREDGE_API_SECRET` - Storedge API secret
- `COMPANY_ID` - UUID of tenant/company
- `PROXY_BEARER` - Bearer token for GPT Action auth
- `MSSQL_USER`, `MSSQL_PASSWORD`, `MSSQL_HOST` - Optional database credentials

### Caching
- Facilities list cached for 300 seconds (configurable via `FACILITIES_CACHE_TTL`)
- Units list per facility cached for 120 seconds (configurable via `UNITS_CACHE_TTL`)
- Force refresh with `?refresh=1` query parameter

## Development Setup
- **Host**: 0.0.0.0 (binds to all interfaces)
- **Port**: 5000 (required for Replit)
- **Server**: Gunicorn with --reuse-port flag
- **Workflow**: Single "Server" workflow running the Gunicorn command

## Deployment
- **Type**: VM (always-running server for stateful operations)
- **Command**: `gunicorn --bind 0.0.0.0:5000 --reuse-port main:app`

## Notes
- This is a backend API application (no frontend UI)
- Bearer authentication can be disabled in dev by leaving `PROXY_BEARER` blank
- Direct pricing changes only (bucket-based workflow disabled)
- Validation guards prevent invalid enumerations and data
