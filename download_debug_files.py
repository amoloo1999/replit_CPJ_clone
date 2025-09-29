import requests
import time
import json

BASE_URL = "https://rate-changer.replit.app"

SITE_NUMBER = "9097"
sE_ID = "4ce7ce30-ee9e-430f-9357-d940c06f7056"
PROPOSED_RATES = {"4": 88, "6": 88, "1": 88, "2": 88}


def set_user():
    r = requests.post(f"{BASE_URL}/set-user", json={"user": "debugger"})
    print("User set:", r.status_code, r.text)


def create_report():
    r = requests.post(f"{BASE_URL}/create-report",
                      json={"filter_facilities": [sE_ID]})
    print("Create report raw response:", r.text)

    if r.status_code != 200:
        raise Exception(f"Report request failed: {r.text}")

    try:
        data = r.json()
        report_id = (data.get("report_request", {}).get("id")
                     or data.get("id") or data.get("meta", {}).get(
                         "report_request", {}).get("id"))
        if not report_id:
            raise ValueError(f"Could not extract report ID from: {data}")
        print("Report ID:", report_id)
        return report_id
    except Exception as e:
        raise Exception(f"Error: Could not extract report ID from: {r.text}")


def wait_for_report(report_id, timeout=60):
    for _ in range(timeout):
        r = requests.get(f"{BASE_URL}/report-status/{report_id}")
        data = r.json()
        # Safely extract nested status from within "report_request"
        status = data.get("report_request", {}).get("status")
        print(f"Status: {status} | Raw: {data}")
        if status == "complete":
            print("Report ready.")
            return True
        time.sleep(2)
    raise TimeoutError("Report generation timed out.")


def download_report(report_id):
    r = requests.get(f"{BASE_URL}/report-data/{report_id}")
    if r.status_code != 200:
        raise Exception(f"Failed to download report: {r.text}")
    with open("latest_report.json", "w") as f:
        json.dump({"report_request": {"report": r.json()}}, f, indent=2)
    print("Saved: latest_report.json")


def calculate_bucket_rates():
    payload = {"site_number": SITE_NUMBER, "proposed_rates": PROPOSED_RATES}
    r = requests.post(f"{BASE_URL}/bucket-calculate-rates-v2", json=payload)
    if r.status_code != 200:
        raise Exception(f"Bucket rate calc failed: {r.text}")
    with open("bucket_rate_results.json", "w") as f:
        json.dump(r.json(), f, indent=2)
    print("Saved: bucket_rate_results.json")


if __name__ == "__main__":
    try:
        set_user()
        report_id = create_report()
        wait_for_report(report_id)
        download_report(report_id)
        # calculate_bucket_rates()
    except Exception as e:
        print("Error:", e)
