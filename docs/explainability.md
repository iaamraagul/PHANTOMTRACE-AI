# Explainability

Every explanation follows:

Observation -> Model impact -> Human interpretation

Example:

```json
{
  "name": "url_entropy",
  "value": 4.72,
  "impact": 0.18,
  "direction": "positive",
  "observation": "url entropy = 4.72",
  "model_impact": "increased the phishing score",
  "human_interpretation": "Irregular character distribution can signal generated or obfuscated links."
}
```

When `ml/models/production/model.joblib` and `shap_background.joblib` exist, the API uses the real `shap` package for local feature attribution.

Before training, the API labels the method as deterministic baseline explainability. It does not claim fake SHAP values.

Global explainability artifacts are produced by the training workflow under `ml/reports/plots/` and `ml/reports/model_cards/`.
