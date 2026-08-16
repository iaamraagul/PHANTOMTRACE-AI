"""Create deterministic processed PhiUSIIL splits for audit/retraining workflows."""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "ml/data/raw/phiusiil/phiusiil_raw.csv"
OUT = ROOT / "ml/data/processed"
SEED = 42


def main() -> int:
    if not RAW.exists():
        raise FileNotFoundError(f"{RAW} not found. Run scripts/download_data.py first.")
    df = pd.read_csv(RAW)
    label = "label" if "label" in df.columns else "Label"
    df = df.drop_duplicates("URL").copy()
    df["normalized_url_key"] = df["URL"].astype(str).str.lower().str.rstrip("/")
    train, temp = train_test_split(df, test_size=0.30, random_state=SEED, stratify=df[label])
    validation, test = train_test_split(temp, test_size=0.50, random_state=SEED, stratify=temp[label])
    OUT.mkdir(parents=True, exist_ok=True)
    train.to_parquet(OUT / "phiusiil_train.parquet", index=False)
    validation.to_parquet(OUT / "phiusiil_validation.parquet", index=False)
    test.to_parquet(OUT / "phiusiil_test.parquet", index=False)
    manifest = {
        "seed": SEED,
        "train_rows": len(train),
        "validation_rows": len(validation),
        "test_rows": len(test),
        "label_semantics": "1=legitimate, 0=phishing",
        "leakage_note": "Duplicate URL strings are removed before stratified splitting.",
    }
    (ROOT / "ml/data/manifests/preprocessing_manifest.json").write_text(json.dumps(manifest, indent=2))
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
