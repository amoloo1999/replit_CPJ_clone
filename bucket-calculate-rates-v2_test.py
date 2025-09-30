import requests

url = "https://rate-changer.replit.app/bucket-calculate-rates-v2"
payload = {
    "site_number": "9124",
    "proposed_base_rates": {"3": 45}
}

resp = requests.post(url, json=payload)
print("Status:", resp.status_code)
print("Body:", resp.json())

