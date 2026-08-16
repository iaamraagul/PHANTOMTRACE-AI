# API

Base URL: `http://localhost:8000`

FastAPI exposes OpenAPI at `/docs` and `/openapi.json`.

## Health

- `GET /health`
- `GET /ready`
- `GET /api/v1/model`

## Authentication

- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`

Request:

```json
{"email":"analyst@example.com","password":"minimum-10-chars"}
```

History, statistics, scan lookup, and scan deletion require `Authorization: Bearer <token>`.

## Analysis

- `POST /api/v1/analyze`
- `POST /api/v1/analyze/batch`

Request:

```json
{"url":"https://example.com/login","include_threat_intelligence":true}
```

The server parses the URL string only. It never opens the submitted target.

## History

- `GET /api/v1/scans`
- `GET /api/v1/scans/{scan_id}`
- `DELETE /api/v1/scans/{scan_id}`
- `GET /api/v1/statistics`

History is scoped to the authenticated user.
