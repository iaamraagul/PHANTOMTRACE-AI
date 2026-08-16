"""Train calibrated phishing URL classifiers from official PhiUSIIL URL labels.

Only deterministic lexical features are used so training and API inference share
the same feature contract. Webpage-derived PhiUSIIL columns are intentionally not
used for the production URL-string scanner.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

try:
    from sklearn.frozen import FrozenEstimator
except ImportError:  # scikit-learn < 1.6
    FrozenEstimator = None

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps/api"))
from app.main import FEATURE_SCHEMA_VERSION, FEATURES, extract_features  # noqa: E402

SEED = 42
RAW = ROOT / "ml/data/raw/phiusiil/phiusiil_raw.csv"


def metric_block(name: str, y_true: list[int], probability: np.ndarray) -> dict[str, object]:
    pred = probability >= 0.5
    tn, fp, fn, tp = confusion_matrix(y_true, pred).ravel()
    return {
        "model": name,
        "accuracy": float(accuracy_score(y_true, pred)),
        "precision": float(precision_score(y_true, pred, zero_division=0)),
        "recall": float(recall_score(y_true, pred, zero_division=0)),
        "f1": float(f1_score(y_true, pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, probability)),
        "pr_auc": float(average_precision_score(y_true, probability)),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "false_positive_rate": float(fp / max(fp + tn, 1)),
        "false_negative_rate": float(fn / max(fn + tp, 1)),
    }


def build_features() -> tuple[list[list[float]], list[int]]:
    if not RAW.exists():
        raise FileNotFoundError(f"{RAW} not found. Run scripts/download_data.py first.")
    df = pd.read_csv(RAW)
    label = "label" if "label" in df.columns else "Label"
    df = df[["URL", label]].dropna().drop_duplicates("URL")
    rows: list[list[float]] = []
    target: list[int] = []
    for url, raw_label in df.itertuples(index=False):
        try:
            _, features = extract_features(str(url))
        except ValueError:
            continue
        rows.append([float(features[name]) for name in FEATURES])
        target.append(1 - int(raw_label))
    return rows, target


def save_plots(y_true: list[int], probability: np.ndarray, metrics: dict[str, object]) -> None:
    plots = ROOT / "ml/reports/plots"
    plots.mkdir(parents=True, exist_ok=True)
    fraction, mean_pred = calibration_curve(y_true, probability, n_bins=10, strategy="quantile")
    plt.figure(figsize=(6, 5))
    plt.plot(mean_pred, fraction, marker="o", label="model")
    plt.plot([0, 1], [0, 1], linestyle="--", color="0.55", label="perfect calibration")
    plt.xlabel("Mean predicted phishing probability")
    plt.ylabel("Observed phishing fraction")
    plt.legend()
    plt.tight_layout()
    plt.savefig(plots / "calibration_curve.png", dpi=160)
    plt.close()

    cm = metrics["confusion_matrix"]
    matrix = np.array([[cm["tn"], cm["fp"]], [cm["fn"], cm["tp"]]])
    plt.figure(figsize=(5, 4))
    plt.imshow(matrix, cmap="copper")
    plt.xticks([0, 1], ["legitimate", "phishing"])
    plt.yticks([0, 1], ["legitimate", "phishing"])
    for row in range(2):
        for col in range(2):
            plt.text(col, row, str(matrix[row, col]), ha="center", va="center", color="white")
    plt.tight_layout()
    plt.savefig(plots / "confusion_matrix.png", dpi=160)
    plt.close()


def main() -> int:
    X, y = build_features()
    X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.30, random_state=SEED, stratify=y)
    X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.50, random_state=SEED, stratify=y_temp)

    candidates = {
        "logistic_regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, class_weight="balanced", random_state=SEED)),
        "random_forest": RandomForestClassifier(n_estimators=220, min_samples_leaf=3, class_weight="balanced_subsample", n_jobs=-1, random_state=SEED),
        "hist_gradient_boosting": HistGradientBoostingClassifier(max_iter=240, learning_rate=0.08, random_state=SEED),
    }

    results: list[dict[str, object]] = []
    fitted: dict[str, object] = {}
    for name, estimator in candidates.items():
        estimator.fit(X_train, y_train)
        probability = estimator.predict_proba(X_val)[:, 1]
        results.append(metric_block(name, y_val, probability))
        fitted[name] = estimator

    best_name = max(results, key=lambda item: (float(item["pr_auc"]), float(item["recall"])))["model"]
    if FrozenEstimator is not None:
        calibrated = CalibratedClassifierCV(FrozenEstimator(fitted[str(best_name)]), method="isotonic")
    else:
        calibrated = CalibratedClassifierCV(fitted[str(best_name)], method="isotonic", cv="prefit")
    calibrated.fit(X_val, y_val)
    test_probability = calibrated.predict_proba(X_test)[:, 1]
    final_metrics = metric_block(f"calibrated_{best_name}", y_test, test_probability)
    final_metrics["candidate_validation_metrics"] = results
    final_metrics["positive_label"] = "phishing"
    final_metrics["source_label_semantics"] = "PhiUSIIL: 1=legitimate, 0=phishing; training converts phishing to positive class 1."
    final_metrics["seed"] = SEED

    prod = ROOT / "ml/models/production"
    metrics_dir = ROOT / "ml/reports/metrics"
    cards = ROOT / "ml/reports/model_cards"
    for path in [prod, metrics_dir, cards]:
        path.mkdir(parents=True, exist_ok=True)

    joblib.dump(calibrated, prod / "model.joblib")
    joblib.dump(np.array(X_train[:80], dtype=float), prod / "shap_background.joblib")
    (prod / "feature_schema.json").write_text(json.dumps({"version": FEATURE_SCHEMA_VERSION, "features": FEATURES}, indent=2))
    metadata = {
        "model_version": f"phiusiil-lexical-{FEATURE_SCHEMA_VERSION}",
        "selected_candidate": best_name,
        "trained_at_utc": pd.Timestamp.utcnow().isoformat(),
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "calibration": "isotonic on validation split",
    }
    (prod / "model_metadata.json").write_text(json.dumps(metadata, indent=2))
    (metrics_dir / "metrics.json").write_text(json.dumps(final_metrics, indent=2))
    save_plots(y_test, test_probability, final_metrics)
    (cards / "phiusiil_lexical_model_card.md").write_text(
        "# PHANTOMTRACE AI PhiUSIIL Lexical Model Card\n\n"
        "This model uses deterministic URL lexical features only. Accuracy alone is insufficient in phishing detection because false negatives can expose users to malicious links and false positives can disrupt legitimate workflows.\n\n"
        f"Selected candidate: {best_name}\n\n"
        f"Test PR-AUC: {final_metrics['pr_auc']:.4f}\n"
        f"Test recall: {final_metrics['recall']:.4f}\n"
        f"Test false-negative rate: {final_metrics['false_negative_rate']:.4f}\n"
    )
    print(json.dumps(final_metrics, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
