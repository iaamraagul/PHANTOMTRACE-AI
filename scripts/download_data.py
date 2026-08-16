"""Download officially sourced datasets and write provenance manifests.

Large raw datasets are intentionally kept out of Git. This script uses the UCI
repository API for UCI datasets and records configuration instructions for live
intelligence providers that require credentials or terms-aware access.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pandas as pd
from ucimlrepo import fetch_ucirepo

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_DIR = ROOT / "ml/data/manifests"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_uci_dataset(uci_id: int, name: str, slug: str, source: str, label_semantics: str) -> dict[str, object]:
    dataset = fetch_ucirepo(id=uci_id)
    frame = pd.concat([dataset.data.features, dataset.data.targets], axis=1)
    out_dir = ROOT / "ml/data/raw" / slug
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"{slug}_raw.csv"
    frame.to_csv(target, index=False)
    return {
        "dataset": name,
        "uci_id": uci_id,
        "source": source,
        "path": str(target),
        "sha256": sha256(target),
        "rows": len(frame),
        "columns": len(frame.columns),
        "label_semantics": label_semantics,
    }


def main() -> int:
    MANIFEST_DIR.mkdir(parents=True, exist_ok=True)
    manifests = [
        write_uci_dataset(
            967,
            "PhiUSIIL Phishing URL (Website)",
            "phiusiil",
            "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset",
            "1=legitimate, 0=phishing",
        ),
        write_uci_dataset(
            327,
            "UCI Phishing Websites",
            "uci_phishing",
            "https://archive.ics.uci.edu/dataset/327/phishing",
            "classic benchmark labels as provided by UCI; benchmark only, not concatenated into production training",
        ),
    ]
    live_sources = {
        "phishtank": {
            "source": "https://www.phishtank.net/developer_info.php",
            "api_info": "https://www.phishtank.net/api_info.php",
            "env": "PHISHTANK_API_KEY",
            "status": "credential-gated optional enrichment",
        },
        "urlhaus": {
            "source": "https://urlhaus.abuse.ch/",
            "api_info": "https://urlhaus.abuse.ch/api/",
            "env": "URLHAUS_ENABLED",
            "status": "configuration-gated optional enrichment",
        },
    }
    manifest = {"datasets": manifests, "live_intelligence": live_sources}
    (MANIFEST_DIR / "dataset_manifest.json").write_text(json.dumps(manifest, indent=2))
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
