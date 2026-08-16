# PHANTOMTRACE AI

AI-Powered Phishing Detection & Explainable Threat Intelligence.

PHANTOMTRACE AI is a full-stack URL phishing-analysis workstation. It accepts a URL string, normalizes and validates it, extracts deterministic URL/domain features, runs either the local baseline or a trained calibrated model, returns model probability, separate application risk scoring, explainability, stores scan history, and renders the result through an accessible React + Three.js interface.

The backend never opens submitted URLs, follows redirects, crawls pages, or executes remote JavaScript.

## Stack

- API: FastAPI, Pydantic, SQLite local persistence, SlowAPI rate limiting
- ML: scikit-learn, SHAP, pandas, pyarrow, matplotlib, joblib
- Web: React 19.2, TypeScript, Vite 8.2, Three.js 0.185, React Three Fiber 9.7
- Ops: Docker Compose, Nginx frontend image, GitHub Actions CI

## Quick Start

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r apps/api/requirements.txt
uvicorn app.main:app --app-dir apps/api --reload
```

In another terminal:

```powershell
cd apps/web
npm ci
npm run dev
```

Open `http://localhost:5173`.

## Environment

Copy `.env.example` to `.env` for local use.

Important values:

- `DATABASE_URL`: defaults to local SQLite.
- `SECRET_KEY`: required for production auth token signing.
- `CORS_ORIGINS`: comma-separated frontend origins.
- `PHISHTANK_API_KEY`: optional PhishTank API key.
- `URLHAUS_ENABLED`: enables URLhaus lookup when set to `true`.
- `MODEL_PATH`: production model artifact path.
- `RATE_LIMIT`, `AUTH_RATE_LIMIT`, `BATCH_RATE_LIMIT`: API throttles.
- `VITE_API_URL`: frontend API base URL.

## Data Setup

Official sources are downloaded with:

```powershell
python scripts/download_data.py
python scripts/validate_data.py
python scripts/preprocess_data.py
```

Primary training dataset: UCI PhiUSIIL Phishing URL Dataset. Label semantics are `1=legitimate`, `0=phishing`.

Benchmark dataset: UCI Phishing Websites. It is stored separately for comparison and is not blindly concatenated into production training.

## Training

```powershell
python scripts/train_model.py
```

Training benchmarks Logistic Regression, Random Forest, and HistGradientBoosting, selects by validation PR-AUC and recall, calibrates with isotonic calibration, and writes:

- `ml/models/production/model.joblib`
- `ml/models/production/shap_background.joblib`
- `ml/models/production/feature_schema.json`
- `ml/models/production/model_metadata.json`
- `ml/reports/metrics/metrics.json`
- `ml/reports/plots/calibration_curve.png`
- `ml/reports/plots/confusion_matrix.png`
- `ml/reports/model_cards/phiusiil_lexical_model_card.md`

Until training is run, the app clearly reports `baseline-lexical-1` and does not claim SHAP output.

## API Endpoints

- `GET /health`
- `GET /ready`
- `GET /api/v1/model`
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `POST /api/v1/analyze`
- `POST /api/v1/analyze/batch`
- `GET /api/v1/scans`
- `GET /api/v1/scans/{scan_id}`
- `DELETE /api/v1/scans/{scan_id}`
- `GET /api/v1/statistics`
- `GET /api/v1/threat-intelligence/status`

OpenAPI is available at `/docs`.

## Frontend Routes

The app is a Vite SPA with two internal work modes:

- Scanner: URL input, risk verdict, feature impacts, threat-intel status
- Observatory: saved scan aggregates and data-driven 3D risk map

The WebGL scene is lazy-loaded and has a 2D screen-reader table equivalent.

## Database Schema

SQLite local tables:

- `users(id, email, password_hash, created_at)`
- `scans(id, owner_id, url, url_hash, prediction, probability, risk_score, result_json, created_at)`

Authenticated history is scoped by `owner_id`. Anonymous scans are allowed but not globally browsable.

## Security Controls

- HTTP/HTTPS-only URL validation
- SSRF protection for localhost, private, loopback, reserved, and metadata hosts
- Credential-bearing URL rejection
- Control-character and request-size rejection
- No DNS resolution or URL fetching for submitted targets
- CORS allowlist
- Rate limiting
- Security headers and production HSTS
- Password hashing with PBKDF2
- Signed bearer tokens
- Structured scan audit logs
- No frontend secrets

## Risk Engine

`probability` is the trained model's phishing probability. `risk_score` is the application risk after policy checks, threat-intelligence enrichment, and uncertainty handling.

If the model returns a high phishing probability but the submitted URL has weak structural evidence and no verified threat-intelligence match, PHANTOMTRACE caps the final risk and reports `unknown`. This prevents a URL-only model from overstating certainty on low-evidence or out-of-distribution URLs while keeping the raw model probability visible for analysts.

## PWA and Accessibility

The frontend includes a manifest and service worker for shell caching. Offline mode keeps the scanner shell available, but live API analysis and threat intelligence require the backend.

Accessibility support includes keyboard-focus states, reduced-motion behavior, semantic tables for feature impacts, ARIA live result updates, and a 2D equivalent for WebGL evidence.

## Docker

```powershell
docker compose up --build
```

Frontend: `http://localhost:8080`

API: `http://localhost:8000`

Postgres and Redis are included as deployment-ready services, while the current API persistence defaults to SQLite for simple local operation.

## Deployment

This repository is Vercel-ready for the frontend, but not as a single full-stack Vercel app.

- Vercel target: `apps/web`
- Backend target: a separate host such as Render, Railway, Fly.io, or a VM
- Frontend-to-backend wiring: set `VITE_API_URL` to the backend URL in Vercel environment variables

For the current local one-link setup, the FastAPI backend serves the built frontend from `apps/web/dist` after you run the frontend build. For GitHub and deployment, keep `dist/` treated as a generated build artifact and rebuild it during deployment.

## Verification

```powershell
python -m pytest apps/api/tests -q
cd apps/web
npm run build
```

If PowerShell says `python` is not recognized, use the installed interpreter directly:

```powershell
C:\Users\Raagul\AppData\Local\Programs\Python\Python311\python.exe -m pytest apps/api/tests -q
```

If Windows blocks direct execution from this Codex sandbox, run the same command in your normal PowerShell terminal.

## Known Limitations

- The trained lexical model is URL-string only; it does not inspect page content, certificates, hosting reputation, or DNS records.
- SHAP is real only after `model.joblib` and `shap_background.joblib` exist.
- PhishTank requires `PHISHTANK_API_KEY`; URLhaus is disabled until `URLHAUS_ENABLED=true`.
- The API currently uses SQLite persistence; Postgres is included in Compose but the app does not yet use SQLAlchemy session models.
- Browser matrix testing and Playwright visual checks still need to be run manually on target browsers.

## Manual Steps Needed

1. Set a real `SECRET_KEY` before any production deployment.
2. Run `scripts/download_data.py` and `scripts/train_model.py` to create production model artifacts.
3. Add PhishTank and URLhaus credentials/flags only if you accept their terms.
4. Run browser QA on Chrome, Edge, Firefox, and Safari if this will be shipped publicly.
