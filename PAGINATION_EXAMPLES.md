"""
Updated test examples showing both pagination parameter styles
"""

# === Your proxy now supports BOTH parameter styles: ===

# 1. LIMIT/OFFSET STYLE (what your bot probably expects):
GET /facilities/701235b0-d7ba-4191-932c-b3d1a182dace/units?limit=5&offset=0   # First 5 units
GET /facilities/701235b0-d7ba-4191-932c-b3d1a182dace/units?limit=5&offset=5   # Next 5 units  
GET /facilities/701235b0-d7ba-4191-932c-b3d1a182dace/units?limit=10&offset=20 # 10 units starting from position 20

# 2. PAGE/PER_PAGE STYLE (traditional pagination):
GET /facilities/701235b0-d7ba-4191-932c-b3d1a182dace/units?page=1&per_page=5   # First page, 5 units
GET /facilities/701235b0-d7ba-4181-932c-b3d1a182dace/units?page=2&per_page=5   # Second page, 5 units
GET /facilities/701235b0-d7ba-4191-932c-b3d1a182dace/units?page=3&per_page=10  # Third page, 10 units

# === Response includes both formats for compatibility: ===

{
  "data": { /* Storedge units data */ },
  "pagination": {
    "page": 1,
    "per_page": 5,
    "limit": 5,        # Same as per_page
    "offset": 0,       # Calculated: (page-1) * per_page  
    "requested_facility_id": "701235b0-d7ba-4191-932c-b3d1a182dace",
    "note": "Supports both (page,per_page) and (limit,offset) parameters"
  }
}

# === Your bot should now be able to use: ===
/facilities/701235b0-d7ba-4191-932c-b3d1a182dace/units?limit=5&offset=0