# Deployment Configuration

## Environment Variables Required

Set these environment variables for proper deployment:

### Required for Core Functionality
- `STOREDGE_API_KEY` - Your Storedge API key
- `STOREDGE_API_SECRET` - Your Storedge API secret  
- `COMPANY_ID` - Your company ID (defaults to existing hardcoded value)
- `PROXY_BEARER` - Bearer token for API authentication

### Optional Configuration
- `PORT` - Port to run on (defaults to 5000)
- `FLASK_DEBUG` - Set to "true" for debug mode (defaults to false)
- `FACILITIES_CACHE_TTL` - Facilities cache TTL in seconds (default: 300)
- `UNITS_CACHE_TTL` - Units cache TTL in seconds (default: 120)
- `UPLOAD_GROUP_KEY_MODE` - "base64" or "plain" (default: "base64")

### Database Configuration (Optional)
- `MSSQL_HOST` - SQL Server host
- `MSSQL_USER` - SQL Server username  
- `MSSQL_PASSWORD` - SQL Server password

## Health Check Endpoints

The app provides multiple health check endpoints:

- `GET /health` - Basic health check
- `GET /readiness` - Readiness check with dependency validation
- `GET /` - Service status

## Deployment Notes

1. The app gracefully handles missing optional dependencies (like database connections)
2. Database features will be disabled if `python-tds` is not available
3. All endpoints include proper error handling for deployment environments
4. WSGI configuration is provided in `wsgi.py`
5. Procfile is configured for platforms that use it

## Troubleshooting

If deployment fails:

1. Check that all required environment variables are set
2. Verify the health check endpoints respond correctly
3. Check logs for specific error messages
4. Ensure all dependencies in requirements.txt are available