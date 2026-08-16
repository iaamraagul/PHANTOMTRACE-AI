"""Smoke-test a running PHANTOMTRACE API."""
from __future__ import annotations

import json
import os

import httpx

BASE = os.getenv("API_BASE_URL", "http://localhost:8000")


def main() -> int:
    with httpx.Client(timeout=30.0) as client:
        health = client.get(f"{BASE}/health")
        health.raise_for_status()
        result = client.post(
            f"{BASE}/api/v1/analyze",
            json={"url": "https://example.com/login", "include_threat_intelligence": False},
        )
        result.raise_for_status()
        payload = result.json()
    print(json.dumps({"health": health.json(), "scan_id": payload["scan_id"], "prediction": payload["prediction"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
