# ML Pipeline

The production scanner uses one canonical URL feature extractor shared by training and API inference.

Pipeline:

1. Download official datasets with `python scripts/download_data.py`.
2. Validate schema and labels with `python scripts/validate_data.py`.
3. Build deterministic splits with `python scripts/preprocess_data.py`.
4. Train candidate models with `python scripts/train_model.py`.
5. Save `model.joblib`, `feature_schema.json`, `model_metadata.json`, metrics, plots, and SHAP background under `ml/`.

PhiUSIIL label semantics are preserved: `1=legitimate`, `0=phishing`. Training converts phishing into the positive class.

The current production feature schema is URL lexical only. PhiUSIIL webpage-derived columns are not used in the online scanner because the server must not crawl arbitrary submitted URLs.

Candidate models:

- Logistic Regression baseline
- Random Forest
- HistGradientBoosting

The best model is selected by validation PR-AUC and recall, then calibrated with isotonic calibration on the validation split.

Accuracy alone is not enough for cybersecurity because false negatives can expose users to malicious links, while false positives interrupt legitimate user workflows.

## Current Trained Artifact

The local training run selected `hist_gradient_boosting` and produced `phiusiil-lexical-1`.

Held-out test metrics:

- Accuracy: 0.9701
- Precision: 0.9843
- Recall: 0.9452
- F1: 0.9643
- ROC-AUC: 0.9891
- PR-AUC: 0.9894
- False-positive rate: 0.0113
- False-negative rate: 0.0548

These metrics describe the PhiUSIIL lexical-feature test split. Production risk still applies a separate risk engine because URL-only features can be overconfident outside the training distribution.
