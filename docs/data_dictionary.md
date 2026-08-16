# Data Dictionary

## Application Scan

- `id`: UUID scan identifier.
- `owner_id`: authenticated user UUID, nullable for anonymous scans.
- `url`: normalized URL string.
- `url_hash`: SHA-256 hash for audit/search without relying on raw display.
- `prediction`: `legitimate`, `suspicious`, `phishing`, or `unknown`.
- `probability`: model phishing probability.
- `risk_score`: application risk score from 0 to 100.
- `result_json`: full structured API response.
- `created_at`: UTC ISO timestamp.

## Feature Schema

The scanner uses deterministic URL lexical features including URL length, hostname length, path/query lengths, punctuation counts, digit ratio, entropy, suspicious token count, encoded sequence count, IP-host indicator, at-sign indicator, repeated slash indicator, suspicious TLD indicator, punycode indicator, shortener indicator, HTTPS indicator, port indicator, and credential indicator.

No feature is treated as inherently malicious. Features are probabilistic signals.

## Labels

PhiUSIIL source labels:

- `1`: legitimate
- `0`: phishing

Training target:

- `1`: phishing
- `0`: legitimate
