"""
Test script to demonstrate the pagination functionality for the units endpoint.

This script shows how to use the updated proxy with pagination parameters.
"""

import requests
import json
import os

# Configuration
BASE_URL = "https://YOUR_REPL_URL"  # Replace with your actual Repl URL
BEARER_TOKEN = os.getenv("PROXY_BEARER", "your_bearer_token_here")
FACILITY_ID = "701235b0-d7ba-4191-932c-b3d1a182dace"  # William Warren Group - Test

headers = {
    "Authorization": f"Bearer {BEARER_TOKEN}",
    "Content-Type": "application/json"
}

def test_units_count():
    """Test the new units count endpoint."""
    print("=== Testing Units Count Endpoint ===")
    url = f"{BASE_URL}/facilities/{FACILITY_ID}/units/count"
    
    try:
        response = requests.get(url, headers=headers)
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
    except Exception as e:
        print(f"Error: {e}")
    print()

def test_units_pagination():
    """Test the units endpoint with pagination parameters."""
    print("=== Testing Units Pagination ===")
    
    # Test different page sizes
    test_cases = [
        {"page": 1, "per_page": 5},
        {"page": 1, "per_page": 10},
        {"page": 2, "per_page": 5},
    ]
    
    for params in test_cases:
        print(f"Testing with params: {params}")
        url = f"{BASE_URL}/facilities/{FACILITY_ID}/units"
        
        try:
            response = requests.get(url, headers=headers, params=params)
            print(f"Status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                if "pagination" in data:
                    print(f"Pagination info: {data['pagination']}")
                if "data" in data and isinstance(data["data"], list):
                    print(f"Units returned: {len(data['data'])}")
                elif "data" in data and isinstance(data["data"], dict):
                    # If Storedge returns nested structure
                    units = data["data"].get("units", [])
                    if isinstance(units, list):
                        print(f"Units returned: {len(units)}")
                    else:
                        print(f"Response structure: {list(data['data'].keys())}")
            else:
                print(f"Error response: {response.text}")
                
        except Exception as e:
            print(f"Error: {e}")
        print("---")
    print()

def test_invalid_pagination():
    """Test error handling for invalid pagination parameters."""
    print("=== Testing Invalid Pagination Parameters ===")
    
    invalid_cases = [
        {"page": "invalid"},
        {"per_page": "invalid"},
        {"page": -1},
        {"per_page": 0},
    ]
    
    for params in invalid_cases:
        print(f"Testing invalid params: {params}")
        url = f"{BASE_URL}/facilities/{FACILITY_ID}/units"
        
        try:
            response = requests.get(url, headers=headers, params=params)
            print(f"Status: {response.status_code}")
            if response.status_code != 200:
                print(f"Error response: {response.json()}")
                
        except Exception as e:
            print(f"Error: {e}")
        print("---")

if __name__ == "__main__":
    print("Units Pagination Test Script")
    print("=" * 40)
    print()
    
    # Update these values before running
    if BASE_URL == "https://YOUR_REPL_URL":
        print("⚠️  Please update BASE_URL with your actual Repl URL")
    if BEARER_TOKEN == "your_bearer_token_here":
        print("⚠️  Please set PROXY_BEARER environment variable or update BEARER_TOKEN")
    print()
    
    test_units_count()
    test_units_pagination()
    test_invalid_pagination()
    
    print("Test completed!")