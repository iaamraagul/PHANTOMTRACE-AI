"""Validate local phishing datasets and fail loudly on schema-breaking problems."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / "ml/data/raw/phiusiil/phiusiil_raw.csv"
OUT = ROOT / "ml/data/manifests/data_validation_report.json"


def valid_url(value: object) -> bool:
    try:
        parsed = urlsplit(str(value))
        return parsed.scheme in {"http", "https"} and bool(parsed.hostname)
    except Exception:
        return False


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT
    if not path.exists():
        report = {"dataset": "phiusiil", "path": str(path), "status": "FAIL", "errors": ["dataset file not found"]}
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(json.dumps(report, indent=2))
        print(json.dumps(report, indent=2))
        return 1

    df = pd.read_csv(path)
    label = "label" if "label" in df.columns else "Label" if "Label" in df.columns else None
    errors: list[str] = []
    warnings: list[str] = []

    if "URL" not in df.columns:
        errors.append("required URL column missing")
    if label is None:
        errors.append("required label/Label column missing")
    elif not set(df[label].dropna().unique()).issubset({0, 1}):
        errors.append("label values must be exactly 0/1 where 1=legitimate and 0=phishing")

    numeric = df.select_dtypes(include="number")
    infinite_values = int((~np.isfinite(numeric.to_numpy())).sum()) if not numeric.empty else 0
    invalid_urls = int((~df["URL"].map(valid_url)).sum()) if "URL" in df.columns else None
    duplicate_urls = int(df["URL"].astype(str).str.lower().duplicated().sum()) if "URL" in df.columns else None

    if invalid_urls:
        warnings.append(f"{invalid_urls} malformed URLs will be skipped during lexical training")
    if infinite_values:
        errors.append("infinite numeric values detected")

    report = {
        "dataset": "phiusiil",
        "path": str(path),
        "rows": int(len(df)),
        "columns": int(len(df.columns)),
        "missing_values": int(df.isna().sum().sum()),
        "duplicate_rows": int(df.duplicated().sum()),
        "duplicate_urls": duplicate_urls,
        "invalid_urls": invalid_urls,
        "infinite_values": infinite_values,
        "class_distribution": df[label].value_counts().to_dict() if label else {},
        "warnings": warnings,
        "errors": errors,
        "status": "FAIL" if errors else "PASS",
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
