# Units Pagination Guide

## Problem Solved

Previously, the `/facilities/{facility_id}/units` endpoint would try to fetch all units at once, which failed for facilities with large unit counts like "William Warren Group - Test". The response was too large and the request would fail.

## Solution

The proxy now supports pagination parameters that are properly exposed through the OpenAPI specification, allowing GPT Actions and other clients to paginate through units effectively.

## Updated Endpoints

### 1. List Units with Pagination
```
GET /facilities/{facility_id}/units?page={page}&per_page={per_page}
```

**Parameters:**
- `facility_id` (path, required): The facility UUID
- `page` (query, optional): Page number (default: 1, minimum: 1)
- `per_page` (query, optional): Units per page (default: 100, minimum: 1, maximum: 1000)

**Example Usage:**
```bash
# Get first 5 units
curl -H "Authorization: Bearer YOUR_TOKEN" \
     "https://your-repl-url/facilities/701235b0-d7ba-4191-932c-b3d1a182dace/units?page=1&per_page=5"

# Get second page of 10 units
curl -H "Authorization: Bearer YOUR_TOKEN" \
     "https://your-repl-url/facilities/701235b0-d7ba-4191-932c-b3d1a182dace/units?page=2&per_page=10"
```

**Response Format:**
```json
{
  "data": {
    // Storedge API response data
  },
  "pagination": {
    "page": 1,
    "per_page": 5,
    "requested_facility_id": "701235b0-d7ba-4191-932c-b3d1a182dace"
  }
}
```

### 2. Get Units Count (New)
```
GET /facilities/{facility_id}/units/count
```

This endpoint helps you understand the pagination needs by making a minimal request (first page, 1 unit) to get metadata.

**Example Usage:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
     "https://your-repl-url/facilities/701235b0-d7ba-4191-932c-b3d1a182dace/units/count"
```

## GPT Actions Integration

### Updated OpenAPI Specification

Both `openapi.json` and `openapi_units_proxy.yaml` have been updated to include the pagination parameters. GPT Actions can now:

1. **Discover pagination support**: The parameters are documented in the OpenAPI spec
2. **Use pagination parameters**: Pass `page` and `per_page` as query parameters
3. **Handle large datasets**: Fetch data in manageable chunks

### Recommended GPT Action Flow

```python
# 1. First, check what you're dealing with (optional)
response = requests.get(f"{base_url}/facilities/{facility_id}/units/count", headers=headers)
print("Sample response:", response.json())

# 2. Start with reasonable page size
page = 1
per_page = 100
units = []

while True:
    response = requests.get(
        f"{base_url}/facilities/{facility_id}/units",
        headers=headers,
        params={"page": page, "per_page": per_page}
    )
    
    if response.status_code != 200:
        break
        
    data = response.json()["data"]
    
    # Handle Storedge response structure (adjust based on actual response)
    page_units = data if isinstance(data, list) else data.get("units", [])
    
    if not page_units:
        break  # No more units
        
    units.extend(page_units)
    page += 1
    
    # Optional: limit total requests to avoid timeouts
    if page > 50:  # Adjust based on needs
        break

print(f"Collected {len(units)} units")
```

## Error Handling

The endpoint now provides better error messages for invalid pagination parameters:

- Invalid `page` parameter → 400 error with explanation
- Invalid `per_page` parameter → 400 error with explanation  
- `per_page` is automatically clamped to maximum 1000

## Testing

Run the test script to verify pagination works:

```bash
python test_pagination.py
```

Make sure to update the configuration in the test script:
- Set your Repl URL
- Set your Bearer token
- Verify the facility ID

## Benefits

1. **No more "response too large" errors**: Data is fetched in manageable chunks
2. **Better performance**: Smaller responses are faster to process
3. **Flexible**: Adjust page size based on needs
4. **GPT Action compatible**: Properly documented in OpenAPI spec
5. **Backward compatible**: Default behavior (page=1, per_page=100) works for smaller facilities