"""PHANTOMTRACE AI API.

The service analyzes URL strings locally. It never opens, crawls, redirects through,
or executes submitted URLs.
"""
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import math
import os
import re
import secrets
import sqlite3
import time
import uuid
from collections import Counter
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Literal
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit

import httpx
import joblib
import numpy as np
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

ROOT = Path(__file__).resolve().parents[3]
DB_PATH = os.getenv("DATABASE_URL", "sqlite:///./phantomtrace.db").replace("sqlite:///", "")
if not Path(DB_PATH).is_absolute():
    DB_PATH = str(ROOT / DB_PATH)

MODEL_FILE = ROOT / os.getenv("MODEL_PATH", "ml/models/production/model.joblib")
SHAP_BACKGROUND_FILE = ROOT / "ml/models/production/shap_background.joblib"
METADATA_FILE = ROOT / "ml/models/production/model_metadata.json"
FRONTEND_DIST = ROOT / "apps/web/dist"
FRONTEND_INDEX = FRONTEND_DIST / "index.html"
SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-me")
TOKEN_TTL_HOURS = int(os.getenv("TOKEN_TTL_HOURS", "24"))
ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()
TOKEN_ISSUER = os.getenv("TOKEN_ISSUER", "phantomtrace-api")
TOKEN_AUDIENCE = os.getenv("TOKEN_AUDIENCE", "phantomtrace-web")
STORE_RAW_URLS = os.getenv("STORE_RAW_URLS", "false").lower() == "true"
ENABLE_SHAP_EXPLANATIONS = os.getenv("ENABLE_SHAP_EXPLANATIONS", "false").lower() == "true"
FEATURE_SCHEMA_VERSION = "2.0"
MAX_URL_LENGTH = int(os.getenv("MAX_URL_LENGTH", "2048"))

KEYWORDS = {
    "login", "signin", "verify", "verification", "secure", "account", "update",
    "password", "wallet", "payment", "billing", "invoice", "support", "bank",
    "confirm", "authentication", "reset", "unlock", "recover", "limited",
    "suspend", "alert", "identity", "kyc", "claim", "airdrop", "seed",
    "recovery", "webscr", "session", "token",
}
REDIRECT_PARAMS = {"url", "u", "uri", "redirect", "redirect_uri", "return", "returnurl", "next", "continue", "target", "dest", "destination", "to", "link"}
SUSPICIOUS_EXTENSIONS = {".exe", ".scr", ".js", ".vbs", ".jar", ".msi", ".bat", ".cmd", ".ps1", ".apk", ".iso", ".img", ".hta", ".zip", ".rar", ".7z"}
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "tiny.cc", "lnkd.in", "s.id", "rb.gy", "shorturl.at",
}
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "gq", "work", "country", "quest", "cam", "icu", "cyou", "rest", "support"}
COMMON_SECOND_LEVEL_SUFFIXES = {"co.uk", "com.au", "co.in", "com.br", "co.jp", "com.sg", "com.my", "com.tr", "co.za", "com.mx"}
HIGH_VALUE_BRANDS = {
    "paypal", "apple", "google", "microsoft", "office", "outlook", "onedrive",
    "amazon", "netflix", "facebook", "instagram", "whatsapp", "linkedin",
    "twitter", "x", "github", "dropbox", "docusign", "adobe", "coinbase",
    "binance", "metamask", "chase", "wellsfargo", "bankofamerica", "hdfc",
    "icici", "sbi", "axis", "phonepe", "paytm", "netbanking",
}
TRUSTED_ROOT_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com", "netflix.com",
    "facebook.com", "instagram.com", "linkedin.com", "github.com", "paypal.com",
    "chatgpt.com", "openai.com", "example.com",
}
LEGACY_FEATURES = [
    "url_length", "hostname_length", "path_length", "query_length", "dots",
    "hyphens", "underscores", "digits", "special_ratio", "path_segments",
    "query_params", "subdomains", "digit_ratio", "hostname_entropy",
    "url_entropy", "suspicious_tokens", "encoded_sequences", "has_ip",
    "has_at", "repeated_slash", "suspicious_tld", "punycode", "shortener",
    "https", "has_port", "has_credentials",
]
FEATURES = LEGACY_FEATURES + [
    "registered_domain_length", "brand_in_hostname", "brand_in_path",
    "brand_as_subdomain", "brand_typosquat", "confusable_hostname",
    "redirect_param_count", "external_url_in_query", "base64_like_tokens",
    "suspicious_extension", "login_path_depth", "many_subdomains",
    "newly_seen_host", "trusted_domain",
]

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("phantomtrace")

_model: Any | None = None
_model_meta: dict[str, Any] | None = None
_shap_explainer: Any | None = None
_model_features: list[str] | None = None


class AnalyzeRequest(BaseModel):
    url: str = Field(min_length=8, max_length=MAX_URL_LENGTH)
    include_threat_intelligence: bool = True

    @field_validator("url")
    @classmethod
    def no_control_chars(cls, value: str) -> str:
        if any(ord(c) < 32 for c in value):
            raise ValueError("URL contains control characters")
        return value.strip()


class BatchAnalyzeRequest(BaseModel):
    urls: list[str] = Field(min_length=1, max_length=25)
    include_threat_intelligence: bool = False


class AuthRequest(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=10, max_length=256)

    @field_validator("password")
    @classmethod
    def strong_enough_password(cls, value: str) -> str:
        if not re.search(r"[A-Za-z]", value) or not re.search(r"\d", value):
            raise ValueError("Password must contain at least one letter and one number")
        return value


class AuthResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_at: str


class FeatureImpact(BaseModel):
    name: str
    value: float | int | bool
    impact: float
    direction: Literal["positive", "negative", "neutral"]
    explanation: str
    observation: str
    model_impact: str
    human_interpretation: str


class AnalyzeResponse(BaseModel):
    scan_id: str
    url: str
    prediction: Literal["legitimate", "suspicious", "phishing", "unknown"]
    probability: float
    risk_score: float
    risk_level: str
    confidence: float
    features: dict[str, float | int | bool]
    explanation: dict[str, Any]
    threat_intelligence: list[dict[str, Any]]
    risk_breakdown: dict[str, Any]
    brand_signals: dict[str, Any]
    reputation_signals: dict[str, Any]
    privacy_mode: str
    feature_version: str
    model_version: str
    created_at: str


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


def init_db() -> None:
    with db() as con:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                owner_id TEXT,
                url TEXT NOT NULL,
                url_hash TEXT NOT NULL,
                prediction TEXT NOT NULL,
                probability REAL NOT NULL,
                risk_score REAL NOT NULL,
                result_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_failures (
                email TEXT PRIMARY KEY,
                failed_count INTEGER NOT NULL,
                locked_until INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        cols = {row["name"] for row in con.execute("PRAGMA table_info(scans)").fetchall()}
        if "owner_id" not in cols:
            con.execute("ALTER TABLE scans ADD COLUMN owner_id TEXT")
        con.execute("CREATE INDEX IF NOT EXISTS scans_owner_created_at ON scans(owner_id, created_at DESC)")
        con.execute("CREATE INDEX IF NOT EXISTS scans_created_at ON scans(created_at DESC)")


def normalize_origin(value: str) -> str:
    return value.strip().rstrip("/")


def configured_cors_origins(default_origins: str) -> list[str]:
    raw_origins = os.getenv("CORS_ORIGINS", default_origins)
    return [origin for origin in (normalize_origin(x) for x in raw_origins.split(",")) if origin]


def validate_runtime_config(origins: list[str]) -> None:
    if ENVIRONMENT != "production":
        return
    if SECRET_KEY in {"dev-only-change-me", "change-this-before-production"} or len(SECRET_KEY) < 32:
        raise RuntimeError("Production SECRET_KEY must be unique and at least 32 characters.")
    unsafe_origins = {"*", "http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:4173", "http://127.0.0.1:4173"}
    if not origins or any(origin in unsafe_origins for origin in origins):
        raise RuntimeError("Production CORS_ORIGINS must contain only explicit production origins.")


def password_hash(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 210_000)
    return f"pbkdf2_sha256${salt}${base64.urlsafe_b64encode(digest).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt, _ = stored.split("$", 2)
    except ValueError:
        return False
    return hmac.compare_digest(password_hash(password, salt), stored)


def sign_token(user_id: str) -> tuple[str, str]:
    exp = datetime.now(timezone.utc) + timedelta(hours=TOKEN_TTL_HOURS)
    now = int(time.time())
    payload = {
        "sub": user_id,
        "iat": now,
        "exp": int(exp.timestamp()),
        "iss": TOKEN_ISSUER,
        "aud": TOKEN_AUDIENCE,
        "jti": secrets.token_urlsafe(12),
    }
    body = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(SECRET_KEY.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}", exp.isoformat()


def parse_token(token: str) -> str:
    try:
        body, sig = token.split(".", 1)
        expected = hmac.new(SECRET_KEY.encode(), body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            raise ValueError
        payload = json.loads(b64url_decode(body).decode())
        now = int(time.time())
        if int(payload["exp"]) < now:
            raise ValueError
        if int(payload.get("iat", now)) > now + 60:
            raise ValueError
        if payload.get("iss") != TOKEN_ISSUER or payload.get("aud") != TOKEN_AUDIENCE:
            raise ValueError
        return str(payload["sub"])
    except Exception as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token") from exc


def login_lock_status(email: str) -> int:
    with db() as con:
        row = con.execute("SELECT locked_until FROM auth_failures WHERE email=?", (email,)).fetchone()
    if not row:
        return 0
    return max(0, int(row["locked_until"]) - int(time.time()))


def record_login_failure(email: str) -> None:
    now = int(time.time())
    with db() as con:
        row = con.execute("SELECT failed_count FROM auth_failures WHERE email=?", (email,)).fetchone()
        failed_count = int(row["failed_count"]) + 1 if row else 1
        locked_until = now + min(900, 30 * max(0, failed_count - 4)) if failed_count >= 5 else 0
        con.execute(
            "INSERT OR REPLACE INTO auth_failures (email, failed_count, locked_until, updated_at) VALUES(?,?,?,?)",
            (email, failed_count, locked_until, utcnow()),
        )


def clear_login_failures(email: str) -> None:
    with db() as con:
        con.execute("DELETE FROM auth_failures WHERE email=?", (email,))


def optional_user(authorization: str | None = Header(default=None)) -> str | None:
    if not authorization:
        return None
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Bearer token required")
    return parse_token(authorization.split(" ", 1)[1])


def required_user(user_id: str | None = Depends(optional_user)) -> str:
    if not user_id:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
    return user_id


def entropy(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    return -sum((count / n) * math.log2(count / n) for count in Counter(text).values())


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def registered_domain(host: str) -> str:
    labels = [label for label in host.lower().strip(".").split(".") if label]
    if len(labels) < 2:
        return host.lower()
    suffix = ".".join(labels[-2:])
    if suffix in COMMON_SECOND_LEVEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return suffix


def root_label(host: str) -> str:
    domain = registered_domain(host)
    return domain.split(".", 1)[0]


def levenshtein_distance(left: str, right: str, max_distance: int = 3) -> int:
    if abs(len(left) - len(right)) > max_distance:
        return max_distance + 1
    previous = list(range(len(right) + 1))
    for i, lc in enumerate(left, 1):
        current = [i]
        smallest = current[0]
        for j, rc in enumerate(right, 1):
            cost = 0 if lc == rc else 1
            value = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            current.append(value)
            smallest = min(smallest, value)
        if smallest > max_distance:
            return max_distance + 1
        previous = current
    return previous[-1]


def looks_base64_like(value: str) -> bool:
    token = value.strip("=-_")
    if len(token) < 18:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", value):
        return False
    return entropy(value) >= 3.5


def has_external_url(value: str) -> bool:
    decoded = unquote(value).lower()
    return "http://" in decoded or "https://" in decoded or decoded.startswith("//")


def mask_url(url: str) -> str:
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    path = parsed.path or "/"
    path_hint = "/" if path == "/" else "/..."
    try:
        parsed_port = parsed.port
    except ValueError:
        parsed_port = None
    port = f":{parsed_port}" if parsed_port else ""
    return urlunsplit((parsed.scheme, host + port, path_hint, "..." if parsed.query else "", ""))


def safe_mask_url(url: str) -> str:
    try:
        if not url.startswith(("http://", "https://")):
            return "[invalid-url]"
        return mask_url(url)
    except Exception:
        return "[invalid-url]"


def url_hash(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()


def seen_host_before(host: str) -> bool:
    try:
        with db() as con:
            row = con.execute("SELECT 1 FROM scans WHERE url_hash LIKE ? LIMIT 1", (f"host:{host}:%",)).fetchone()
        return bool(row)
    except Exception:
        return False


def storage_url_hash(normalized: str) -> str:
    parsed = urlsplit(normalized)
    host = parsed.hostname or ""
    return f"host:{host}:{url_hash(normalized)}"


def normalize_url(value: str) -> tuple[str, Any]:
    if len(value) > MAX_URL_LENGTH:
        raise ValueError(f"URL exceeds maximum length of {MAX_URL_LENGTH} characters")
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only http and https URLs are permitted")
    if not parsed.hostname:
        raise ValueError("URL must include a hostname")
    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Invalid hostname") from exc
    if host in {"localhost", "metadata.google.internal"} or host.endswith(".localhost"):
        raise ValueError("Local and metadata hosts are not permitted")
    try:
        addr = ip_address(host)
        if not addr.is_global:
            raise ValueError("Private, loopback, and reserved IP addresses are not permitted")
    except ValueError as exc:
        if "not permitted" in str(exc):
            raise
    if parsed.username or parsed.password:
        raise ValueError("Credential-bearing URLs are not permitted")
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid URL port") from exc
    port = f":{parsed_port}" if parsed_port else ""
    normalized = urlunsplit((parsed.scheme.lower(), host + port, parsed.path or "/", parsed.query, ""))
    if len(normalized) > MAX_URL_LENGTH:
        raise ValueError(f"URL exceeds maximum length of {MAX_URL_LENGTH} characters")
    return normalized, urlsplit(normalized)


def extract_features(value: str) -> tuple[str, dict[str, float | int | bool]]:
    normalized, parsed = normalize_url(value)
    host = parsed.hostname or ""
    path = unquote(parsed.path)
    lower = normalized.lower()
    special = sum(not c.isalnum() for c in normalized)
    labels = host.split(".")
    tld = labels[-1] if len(labels) > 1 else ""
    tokens = re.findall(r"[a-z]+", lower)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    domain = registered_domain(host)
    root = root_label(host)
    subdomain_labels = labels[: -len(domain.split("."))] if domain and host.endswith(domain) else labels[:-2]
    hostname_tokens = set(re.findall(r"[a-z0-9]+", host.lower()))
    path_tokens = set(re.findall(r"[a-z0-9]+", path.lower()))
    query_values = [value for _, value in query_pairs]
    brand_hits_host = sorted((HIGH_VALUE_BRANDS & hostname_tokens) - {root})
    brand_hits_path = sorted(HIGH_VALUE_BRANDS & path_tokens)
    typosquat_hits = [
        brand for brand in HIGH_VALUE_BRANDS
        if brand != root and 4 <= len(brand) and 0 < levenshtein_distance(root, brand, 2) <= 2
    ]
    redirect_param_count = sum(1 for key, _ in query_pairs if key.lower().replace("-", "_") in REDIRECT_PARAMS)
    external_url_count = sum(1 for value in query_values if has_external_url(value))
    base64_count = sum(1 for token in re.split(r"[/?=&._%-]+", parsed.path + "?" + parsed.query) if looks_base64_like(token))
    suspicious_extension = any(path.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)
    login_path_depth = len([segment for segment in path.lower().split("/") if segment and segment in KEYWORDS])
    trusted_domain = domain in TRUSTED_ROOT_DOMAINS
    features: dict[str, float | int | bool] = {
        "url_length": len(normalized),
        "hostname_length": len(host),
        "path_length": len(path),
        "query_length": len(parsed.query),
        "dots": normalized.count("."),
        "hyphens": normalized.count("-"),
        "underscores": normalized.count("_"),
        "digits": sum(c.isdigit() for c in normalized),
        "special_ratio": round(special / max(len(normalized), 1), 4),
        "path_segments": len([x for x in path.split("/") if x]),
        "query_params": len(parse_qsl(parsed.query, keep_blank_values=True)),
        "subdomains": max(0, len(labels) - 2),
        "digit_ratio": round(sum(c.isdigit() for c in normalized) / max(len(normalized), 1), 4),
        "hostname_entropy": round(entropy(host), 3),
        "url_entropy": round(entropy(normalized), 3),
        "suspicious_tokens": sum(t in KEYWORDS for t in tokens),
        "encoded_sequences": len(re.findall(r"%[0-9a-fA-F]{2}", parsed.path + parsed.query)),
        "has_ip": False,
        "has_at": "@" in normalized,
        "repeated_slash": "//" in parsed.path,
        "suspicious_tld": tld in SUSPICIOUS_TLDS,
        "punycode": "xn--" in host,
        "shortener": host in SHORTENERS,
        "https": parsed.scheme == "https",
        "has_port": parsed.port is not None,
        "has_credentials": False,
        "registered_domain_length": len(domain),
        "brand_in_hostname": len(brand_hits_host),
        "brand_in_path": len(brand_hits_path),
        "brand_as_subdomain": any(label in HIGH_VALUE_BRANDS for label in subdomain_labels),
        "brand_typosquat": len(typosquat_hits),
        "confusable_hostname": bool(re.search(r"[0-9]", root)) and any(char in root for char in "013457"),
        "redirect_param_count": redirect_param_count,
        "external_url_in_query": external_url_count,
        "base64_like_tokens": base64_count,
        "suspicious_extension": suspicious_extension,
        "login_path_depth": login_path_depth,
        "many_subdomains": len(subdomain_labels) >= 3,
        "newly_seen_host": not seen_host_before(host),
        "trusted_domain": trusted_domain,
    }
    try:
        features["has_ip"] = bool(ip_address(host))
    except ValueError:
        pass
    return normalized, features


def load_model() -> Any | None:
    global _model, _model_meta, _model_features
    if not MODEL_FILE.exists():
        return None
    if _model is None:
        _model = joblib.load(MODEL_FILE)
        if METADATA_FILE.exists():
            _model_meta = json.loads(METADATA_FILE.read_text())
        else:
            _model_meta = {"model_version": "phiusiil-lexical-1"}
        schema_file = MODEL_FILE.parent / "feature_schema.json"
        if schema_file.exists():
            schema = json.loads(schema_file.read_text())
            _model_features = list(schema.get("features") or LEGACY_FEATURES)
        else:
            _model_features = LEGACY_FEATURES
    return _model


def active_model_features() -> list[str]:
    if _model_features is not None:
        return _model_features
    if MODEL_FILE.exists() and (MODEL_FILE.parent / "feature_schema.json").exists():
        try:
            schema = json.loads((MODEL_FILE.parent / "feature_schema.json").read_text())
            return list(schema.get("features") or LEGACY_FEATURES)
        except Exception:
            return LEGACY_FEATURES
    return FEATURES


def feature_vector(features: dict[str, float | int | bool]) -> np.ndarray:
    return np.array([[float(features.get(k, 0)) for k in active_model_features()]], dtype=float)


def score(features: dict[str, float | int | bool]) -> float:
    model = load_model()
    if model is not None:
        return float(model.predict_proba(feature_vector(features))[0][1])
    weights = {
        "url_length": .006, "hostname_length": .012, "dots": .035, "hyphens": .045,
        "digits": .025, "special_ratio": .75, "path_segments": .025,
        "query_params": .02, "subdomains": .05, "digit_ratio": .8,
        "hostname_entropy": .055, "url_entropy": .045, "suspicious_tokens": .08,
        "encoded_sequences": .09, "has_ip": .35, "has_at": .35,
        "repeated_slash": .14, "suspicious_tld": .12, "punycode": .14,
        "shortener": .12, "https": -.05, "has_port": .12,
        "brand_in_hostname": .28, "brand_in_path": .08, "brand_as_subdomain": .32,
        "brand_typosquat": .38, "confusable_hostname": .22, "redirect_param_count": .16,
        "external_url_in_query": .28, "base64_like_tokens": .12,
        "suspicious_extension": .3, "login_path_depth": .1, "many_subdomains": .16,
        "newly_seen_host": .04, "trusted_domain": -.45,
    }
    raw = -2.4 + sum(float(features.get(k, 0)) * v for k, v in weights.items())
    return 1 / (1 + math.exp(-max(-20, min(20, raw))))


def structural_signal_score(features: dict[str, float | int | bool]) -> int:
    score_value = 0
    score_value += 2 if not bool(features["https"]) else 0
    score_value += 3 if bool(features["has_ip"]) else 0
    score_value += 3 if bool(features["has_at"]) else 0
    score_value += 2 if bool(features["suspicious_tld"]) else 0
    score_value += 2 if bool(features["punycode"]) else 0
    score_value += 2 if bool(features["shortener"]) else 0
    score_value += 1 if bool(features["has_port"]) else 0
    score_value += 1 if bool(features["repeated_slash"]) else 0
    score_value += 1 if int(features["encoded_sequences"]) > 0 else 0
    score_value += 1 if int(features["digits"]) >= 4 else 0
    score_value += 1 if float(features["digit_ratio"]) >= 0.08 else 0
    score_value += 1 if int(features["hyphens"]) >= 2 else 0
    score_value += 1 if int(features["subdomains"]) >= 3 else 0
    score_value += 1 if int(features["query_params"]) >= 3 else 0
    score_value += 1 if int(features["url_length"]) >= 90 else 0
    score_value += 1 if float(features["hostname_entropy"]) >= 3.8 else 0
    score_value += 1 if int(features["suspicious_tokens"]) >= 2 else 0
    score_value += 3 if int(features.get("brand_typosquat", 0)) > 0 else 0
    score_value += 3 if bool(features.get("brand_as_subdomain")) else 0
    score_value += 2 if int(features.get("brand_in_hostname", 0)) > 0 else 0
    score_value += 2 if int(features.get("external_url_in_query", 0)) > 0 else 0
    score_value += 2 if int(features.get("redirect_param_count", 0)) > 0 else 0
    score_value += 2 if bool(features.get("suspicious_extension")) else 0
    score_value += 1 if int(features.get("base64_like_tokens", 0)) > 0 else 0
    score_value += 1 if bool(features.get("many_subdomains")) else 0
    return score_value


def brand_signal_score(features: dict[str, float | int | bool]) -> float:
    score_value = 0.0
    score_value += 28 if bool(features.get("brand_as_subdomain")) else 0
    score_value += min(22, int(features.get("brand_typosquat", 0)) * 22)
    score_value += min(18, int(features.get("brand_in_hostname", 0)) * 12)
    score_value += min(8, int(features.get("brand_in_path", 0)) * 4)
    if bool(features.get("trusted_domain")):
        score_value = max(0.0, score_value - 24)
    return round(min(100.0, score_value), 1)


def lexical_signal_score(features: dict[str, float | int | bool]) -> float:
    raw = structural_signal_score(features)
    return round(min(100.0, raw * 7.0), 1)


def reputation_signal_score(features: dict[str, float | int | bool], threat_intel: list[dict[str, Any]]) -> float:
    verified_match = any(item.get("matched") and item.get("verified") for item in threat_intel)
    unverified_match = any(item.get("matched") for item in threat_intel)
    score_value = 0.0
    score_value += 100 if verified_match else 65 if unverified_match else 0
    score_value += 12 if bool(features.get("newly_seen_host")) else 0
    score_value += 12 if bool(features.get("shortener")) else 0
    if bool(features.get("trusted_domain")):
        score_value = max(0.0, score_value - 35)
    return round(min(100.0, score_value), 1)


def threat_intel_signal_score(threat_intel: list[dict[str, Any]]) -> float:
    if any(item.get("matched") and item.get("verified") for item in threat_intel):
        return 100.0
    if any(item.get("matched") for item in threat_intel):
        return 70.0
    return 0.0


def risk_engine(probability: float, features: dict[str, float | int | bool], threat_intel: list[dict[str, Any]]) -> dict[str, Any]:
    model_probability = round(probability * 100, 1)
    lexical_risk = lexical_signal_score(features)
    brand_risk = brand_signal_score(features)
    reputation_risk = reputation_signal_score(features, threat_intel)
    ti_risk = threat_intel_signal_score(threat_intel)
    risk = max(
        model_probability * 0.55 + lexical_risk * 0.2 + brand_risk * 0.15 + reputation_risk * 0.1,
        brand_risk,
        ti_risk,
    )
    reasons = ["calibrated model probability" if MODEL_FILE.exists() else "deterministic local baseline"]
    signal_score = structural_signal_score(features)
    verified_match = any(item.get("matched") and item.get("verified") for item in threat_intel)
    capped_for_weak_evidence = False
    if verified_match:
        risk = max(88.0, min(100.0, risk + 15))
        reasons.append("verified threat-intelligence match")
    elif probability >= 0.72 and signal_score <= 1 and not bool(features.get("trusted_domain")):
        risk = min(risk, 35.0)
        capped_for_weak_evidence = True
        reasons.append("model probability capped because structural URL evidence is weak")
    elif bool(features.get("trusted_domain")) and signal_score <= 2:
        risk = min(risk, 18.0)
        reasons.append("known trusted registered domain with weak malicious structure")
    if brand_risk >= 28:
        reasons.append("brand impersonation or typosquatting signal")
    if lexical_risk >= 45:
        reasons.append("multiple suspicious URL-structure signals")
    risk = round(risk, 1)
    if risk >= 80:
        level = "CRITICAL"
    elif risk >= 60:
        level = "HIGH"
    elif risk >= 40:
        level = "SUSPICIOUS"
    elif risk >= 20:
        level = "GUARDED"
    else:
        level = "LOW"
    prediction = "unknown" if capped_for_weak_evidence or abs(probability - 0.5) < 0.06 else "phishing" if risk >= 72 else "suspicious" if risk >= 40 else "legitimate"
    signal_agreement = min(1.0, (lexical_risk + brand_risk + reputation_risk) / 180)
    confidence = round(min(1.0, abs(probability - .5) * 1.4 + signal_agreement * 0.35), 3)
    if "model probability capped because structural URL evidence is weak" in reasons:
        confidence = min(confidence, 0.55)
    return {
        "risk_score": risk,
        "risk_level": level,
        "prediction": prediction,
        "confidence": confidence,
        "reasons": reasons,
        "structural_signal_score": signal_score,
        "uncertainty": round(1 - abs(probability - .5) * 2, 3),
        "risk_breakdown": {
            "model_probability": model_probability,
            "lexical_risk_score": lexical_risk,
            "brand_impersonation_score": brand_risk,
            "reputation_score": reputation_risk,
            "threat_intel_score": ti_risk,
            "final_risk_score": risk,
        },
    }


def baseline_impacts(features: dict[str, float | int | bool]) -> list[dict[str, Any]]:
    baseline = {"url_length": 45, "hostname_entropy": 3.0, "suspicious_tokens": 0, "has_ip": 0, "has_at": 0, "punycode": 0, "https": 1}
    rows: list[dict[str, Any]] = []
    for name in FEATURES:
        value = features[name]
        impact = (float(value) - float(baseline.get(name, 0))) / (120 if name == "url_length" else 8)
        if abs(impact) > .02:
            rows.append(make_impact(name, value, impact))
    return sorted(rows, key=lambda x: abs(x["impact"]), reverse=True)[:8]


def make_impact(name: str, value: float | int | bool, impact: float) -> dict[str, Any]:
    direction = "positive" if impact > 0 else "negative" if impact < 0 else "neutral"
    observation = f"{name.replace('_', ' ')} = {value}"
    model_impact = "increased the phishing score" if direction == "positive" else "reduced the phishing score" if direction == "negative" else "had little effect"
    interpretations = {
        "has_ip": "IP-address hosts are less typical of consumer login flows.",
        "has_at": "An at-sign can obscure the effective destination.",
        "punycode": "Internationalized-domain encoding needs visual review.",
        "brand_typosquat": "The registered-domain label is visually close to a high-value brand.",
        "brand_as_subdomain": "A brand appears as a subdomain while the registered domain is different.",
        "external_url_in_query": "Nested URLs in query parameters are commonly used in redirect chains.",
        "redirect_param_count": "Redirect-like query parameters can hide the final destination.",
        "base64_like_tokens": "Encoded-looking URL sections can hide destination or campaign data.",
        "suspicious_extension": "Downloadable or script-like file extensions increase risk.",
        "suspicious_tokens": "Account and payment wording is one probabilistic URL-structure signal.",
        "url_length": "Long URL structure can indicate tracking, redirection, or obfuscation.",
        "hostname_entropy": "Irregular hostnames differ from many legitimate domains.",
        "url_entropy": "Irregular character distribution can signal generated or obfuscated links.",
        "https": "HTTPS is common for legitimate sites, but does not prove safety.",
    }
    human = interpretations.get(name, f"{name.replace('_', ' ')} is a URL-structure signal used by the model.")
    return {
        "name": name,
        "value": value,
        "impact": round(float(impact), 4),
        "direction": direction,
        "explanation": f"Observation: {observation}. Model impact: {model_impact}. Interpretation: {human}",
        "observation": observation,
        "model_impact": model_impact,
        "human_interpretation": human,
    }


def signal_summary(normalized: str, features: dict[str, float | int | bool], ti: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    host = urlsplit(normalized).hostname or ""
    domain = registered_domain(host)
    root = root_label(host)
    hostname_tokens = set(re.findall(r"[a-z0-9]+", host.lower()))
    path_tokens = set(re.findall(r"[a-z0-9]+", urlsplit(normalized).path.lower()))
    brand_hits_host = sorted((HIGH_VALUE_BRANDS & hostname_tokens) - {root})
    brand_hits_path = sorted(HIGH_VALUE_BRANDS & path_tokens)
    typosquat_hits = sorted(
        brand for brand in HIGH_VALUE_BRANDS
        if brand != root and 4 <= len(brand) and 0 < levenshtein_distance(root, brand, 2) <= 2
    )
    brand_signals = {
        "registered_domain": domain,
        "root_label": root,
        "brand_hits_hostname": brand_hits_host,
        "brand_hits_path": brand_hits_path,
        "brand_as_subdomain": bool(features.get("brand_as_subdomain")),
        "typosquat_candidates": typosquat_hits[:5],
        "score": brand_signal_score(features),
    }
    reputation_signals = {
        "trusted_domain": bool(features.get("trusted_domain")),
        "newly_seen_host": bool(features.get("newly_seen_host")),
        "shortener": bool(features.get("shortener")),
        "threat_intel_matches": [
            item.get("provider") for item in ti if item.get("matched")
        ],
        "score": reputation_signal_score(features, ti),
    }
    return brand_signals, reputation_signals


def shap_impacts(features: dict[str, float | int | bool]) -> tuple[list[dict[str, Any]], str]:
    model = load_model()
    if not ENABLE_SHAP_EXPLANATIONS:
        return baseline_impacts(features), "fast deterministic explanation; set ENABLE_SHAP_EXPLANATIONS=true to use SHAP"
    if model is None or not SHAP_BACKGROUND_FILE.exists():
        return baseline_impacts(features), "deterministic lexical baseline; train the model to enable SHAP"
    global _shap_explainer
    try:
        import shap

        background = joblib.load(SHAP_BACKGROUND_FILE)
        if _shap_explainer is None:
            _shap_explainer = shap.Explainer(lambda data: model.predict_proba(data)[:, 1], background)
        values = _shap_explainer(feature_vector(features))
        shap_values = np.array(values.values[0], dtype=float)
        model_features = active_model_features()
        rows = [make_impact(name, features.get(name, 0), shap_values[i]) for i, name in enumerate(model_features)]
        return sorted(rows, key=lambda x: abs(x["impact"]), reverse=True)[:10], "SHAP local explanation"
    except Exception as exc:
        logger.warning("shap_unavailable error=%s", exc)
        return baseline_impacts(features), "SHAP unavailable for this model artifact; returned deterministic fallback explanation"


class ThreatIntelProvider:
    name = "provider"

    async def lookup(self, url: str) -> dict[str, Any]:
        raise NotImplementedError


class PhishTankProvider(ThreatIntelProvider):
    name = "phishtank"

    async def lookup(self, url: str) -> dict[str, Any]:
        key = os.getenv("PHISHTANK_API_KEY")
        if not key:
            return {"provider": self.name, "matched": False, "status": "unconfigured", "detail": "No PHISHTANK_API_KEY configured."}
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                response = await client.post(
                    "https://checkurl.phishtank.com/checkurl/",
                    data={"url": url, "format": "json", "app_key": key},
                    headers={"User-Agent": "phantomtrace-ai/0.1"},
                )
            if response.status_code >= 400:
                return {"provider": self.name, "matched": False, "status": "unavailable", "detail": f"PhishTank returned HTTP {response.status_code}."}
            data = response.json().get("results", {})
            return {
                "provider": self.name,
                "matched": bool(data.get("in_database")),
                "verified": bool(data.get("verified")),
                "online": bool(data.get("online")),
                "target": data.get("target"),
                "source_timestamp": data.get("verified_at"),
                "raw_reference": data.get("phish_detail_page"),
                "status": "ok",
            }
        except Exception:
            return {"provider": self.name, "matched": False, "status": "timeout_or_error", "detail": "PhishTank lookup degraded gracefully."}


class URLhausProvider(ThreatIntelProvider):
    name = "urlhaus"

    async def lookup(self, url: str) -> dict[str, Any]:
        if os.getenv("URLHAUS_ENABLED", "false").lower() != "true":
            return {"provider": self.name, "matched": False, "status": "disabled", "detail": "URLhaus provider disabled."}
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                response = await client.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url})
            data = response.json()
            matched = data.get("query_status") == "ok"
            return {
                "provider": self.name,
                "matched": matched,
                "verified": matched,
                "online": data.get("url_status") == "online",
                "target": data.get("host"),
                "source_timestamp": data.get("date_added"),
                "raw_reference": data.get("urlhaus_reference"),
                "status": data.get("query_status", "unknown"),
            }
        except Exception:
            return {"provider": self.name, "matched": False, "status": "timeout_or_error", "detail": "URLhaus lookup degraded gracefully."}


async def threat_intel(url: str, enabled: bool) -> list[dict[str, Any]]:
    if not enabled:
        return [{"provider": "all", "matched": False, "status": "disabled", "detail": "Threat intelligence was not requested."}]
    providers: list[ThreatIntelProvider] = [PhishTankProvider(), URLhausProvider()]
    timeout_seconds = float(os.getenv("THREAT_INTEL_TIMEOUT_SECONDS", "2.5"))

    async def guarded_lookup(provider: ThreatIntelProvider) -> dict[str, Any]:
        try:
            return await asyncio.wait_for(provider.lookup(url), timeout=timeout_seconds)
        except Exception:
            return {
                "provider": provider.name,
                "matched": False,
                "status": "timeout_or_error",
                "detail": f"{provider.name} lookup degraded gracefully.",
            }

    return await asyncio.gather(*(guarded_lookup(provider) for provider in providers))


def response_for(normalized: str, features: dict[str, float | int | bool], ti: list[dict[str, Any]]) -> dict[str, Any]:
    probability = score(features)
    risk = risk_engine(probability, features, ti)
    impacts, method = shap_impacts(features)
    brand_signals, reputation_signals = signal_summary(normalized, features, ti)
    scan_id = str(uuid.uuid4())
    trained = MODEL_FILE.exists()
    model_version = (_model_meta or {}).get("model_version", "phiusiil-lexical-1") if trained else "baseline-lexical-1"
    return {
        "scan_id": scan_id,
        "url": normalized,
        "prediction": risk["prediction"],
        "probability": round(probability, 4),
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "confidence": risk["confidence"],
        "features": features,
        "explanation": {
            "summary": f"URL structure produced a {risk['prediction']} assessment with {risk['risk_level'].lower()} application risk.",
            "features": impacts,
            "method": method,
            "risk_engine": {
                "reasons": risk["reasons"],
                "uncertainty": risk["uncertainty"],
                "structural_signal_score": risk["structural_signal_score"],
            },
        },
        "threat_intelligence": ti,
        "risk_breakdown": risk["risk_breakdown"],
        "brand_signals": brand_signals,
        "reputation_signals": reputation_signals,
        "privacy_mode": "raw-url-storage" if STORE_RAW_URLS else "masked-history",
        "feature_version": FEATURE_SCHEMA_VERSION,
        "model_version": model_version,
        "created_at": utcnow(),
    }


def stored_result(result: dict[str, Any]) -> dict[str, Any]:
    if STORE_RAW_URLS:
        return result
    copy = dict(result)
    copy["url"] = mask_url(str(result["url"]))
    copy["privacy_mode"] = "masked-history"
    return copy


init_db()
limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app_instance: FastAPI):
    init_db()
    validate_runtime_config(origins)
    yield


app = FastAPI(title="PHANTOMTRACE AI", version="0.2.0", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, lambda request, exc: JSONResponse({"detail": "Rate limit exceeded"}, status_code=429))
default_origins = ",".join([
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:4173",
    "http://127.0.0.1:4173",
])
origins = configured_cors_origins(default_origins)
validate_runtime_config(origins)
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False, allow_methods=["GET", "POST", "DELETE"], allow_headers=["Content-Type", "Authorization"])
if (FRONTEND_DIST / "assets").exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="frontend-assets")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    if int(request.headers.get("content-length", "0") or "0") > 32_000:
        return JSONResponse({"detail": "Request too large"}, 413)
    response = await call_next(request)
    headers = {
        "X-Request-ID": request_id,
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Cross-Origin-Resource-Policy": "same-site",
        "Cache-Control": "no-store" if request.url.path.startswith("/api/v1/auth/") else "no-cache",
    }
    if ENVIRONMENT == "production":
        headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers.update(headers)
    return response


@app.get("/health")
def health():
    return {"status": "ok", "service": "phantomtrace-api"}


@app.get("/ready")
def ready():
    return {
        "status": "ready",
        "database": "available",
        "model": "trained" if MODEL_FILE.exists() else "deterministic-local-baseline",
        "shap": ENABLE_SHAP_EXPLANATIONS and SHAP_BACKGROUND_FILE.exists() and MODEL_FILE.exists(),
    }


@app.post("/api/v1/auth/register", response_model=AuthResponse)
@limiter.limit(os.getenv("AUTH_RATE_LIMIT", "10/minute"))
def register(request: Request, payload: AuthRequest):
    user_id = str(uuid.uuid4())
    try:
        with db() as con:
            con.execute("INSERT INTO users VALUES(?,?,?,?)", (user_id, payload.email.lower(), password_hash(payload.password), utcnow()))
    except sqlite3.IntegrityError as exc:
        raise HTTPException(409, "User already exists") from exc
    token, expires = sign_token(user_id)
    return {"access_token": token, "expires_at": expires}


@app.post("/api/v1/auth/login", response_model=AuthResponse)
@limiter.limit(os.getenv("AUTH_RATE_LIMIT", "10/minute"))
def login(request: Request, payload: AuthRequest):
    email = payload.email.lower()
    wait_seconds = login_lock_status(email)
    if wait_seconds > 0:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, f"Too many failed login attempts. Try again in {wait_seconds} seconds.")
    with db() as con:
        row = con.execute("SELECT id,password_hash FROM users WHERE email=?", (email,)).fetchone()
    if not row or not verify_password(payload.password, row["password_hash"]):
        record_login_failure(email)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    clear_login_failures(email)
    token, expires = sign_token(row["id"])
    return {"access_token": token, "expires_at": expires}


@app.get("/api/v1/model")
def model():
    meta = json.loads(METADATA_FILE.read_text()) if METADATA_FILE.exists() else {}
    return {
        "version": meta.get("model_version", "phiusiil-lexical-1" if MODEL_FILE.exists() else "baseline-lexical-1"),
        "feature_schema_version": meta.get("feature_schema_version", FEATURE_SCHEMA_VERSION),
        "api_feature_schema_version": FEATURE_SCHEMA_VERSION,
        "features": FEATURES,
        "active_model_features": active_model_features(),
        "trained": MODEL_FILE.exists(),
        "shap_ready": SHAP_BACKGROUND_FILE.exists() and MODEL_FILE.exists(),
        "shap_enabled": ENABLE_SHAP_EXPLANATIONS,
        "training_required": "Run scripts/download_data.py, scripts/validate_data.py, then scripts/train_model.py.",
    }


@app.get("/api/v1/analyze")
def analyze_help():
    raise HTTPException(405, "Use POST /api/v1/analyze with JSON body: {'url': 'https://example.com'}")


@app.post("/api/v1/analyze", response_model=AnalyzeResponse)
@limiter.limit(os.getenv("RATE_LIMIT", "30/minute"))
async def analyze(request: Request, payload: AnalyzeRequest = Body(...), user_id: str | None = Depends(optional_user)):
    try:
        normalized, features = extract_features(payload.url)
    except (ValueError, UnicodeError) as exc:
        raise HTTPException(422, detail=str(exc)) from exc
    ti = await threat_intel(normalized, payload.include_threat_intelligence)
    result = response_for(normalized, features, ti)
    persisted = stored_result(result)
    with db() as con:
        con.execute(
            "INSERT INTO scans (id, owner_id, url, url_hash, prediction, probability, risk_score, result_json, created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                result["scan_id"], user_id, normalized if STORE_RAW_URLS else mask_url(normalized),
                storage_url_hash(normalized),
                result["prediction"], result["probability"], result["risk_score"],
                json.dumps(persisted), result["created_at"],
            ),
        )
    logger.info(
        "scan_complete scan_id=%s user_id=%s model=%s prediction=%s risk=%s",
        result["scan_id"], user_id or "anonymous", result["model_version"], result["prediction"], result["risk_score"],
    )
    return result


@app.post("/api/v1/analyze/batch")
@limiter.limit(os.getenv("BATCH_RATE_LIMIT", "6/minute"))
async def analyze_batch(request: Request, payload: BatchAnalyzeRequest, user_id: str | None = Depends(optional_user)):
    results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for url in payload.urls:
        try:
            normalized, features = extract_features(url)
            ti = await threat_intel(normalized, payload.include_threat_intelligence)
            result = response_for(normalized, features, ti)
            persisted = stored_result(result)
            with db() as con:
                con.execute(
                    "INSERT INTO scans (id, owner_id, url, url_hash, prediction, probability, risk_score, result_json, created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (result["scan_id"], user_id, normalized if STORE_RAW_URLS else mask_url(normalized), storage_url_hash(normalized), result["prediction"], result["probability"], result["risk_score"], json.dumps(persisted), result["created_at"]),
                )
            results.append(result)
        except (ValueError, UnicodeError):
            errors.append({"url": safe_mask_url(url), "detail": "Invalid URL"})
        except Exception:
            errors.append({"url": "[redacted]", "detail": "Analysis failed"})
    return {"items": results, "errors": errors}


@app.get("/api/v1/scans")
def scans(limit: int = 20, offset: int = 0, user_id: str = Depends(required_user)):
    limit = max(1, min(limit, 100))
    offset = max(0, offset)
    with db() as con:
        rows = con.execute(
            "SELECT result_json FROM scans WHERE owner_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (user_id, limit, offset),
        ).fetchall()
    return {"items": [json.loads(r["result_json"]) for r in rows], "limit": limit, "offset": offset}


@app.get("/api/v1/scans/{scan_id}")
def get_scan(scan_id: str, user_id: str = Depends(required_user)):
    with db() as con:
        row = con.execute("SELECT result_json FROM scans WHERE id=? AND owner_id=?", (scan_id, user_id)).fetchone()
    if not row:
        raise HTTPException(404, detail="Scan not found")
    return json.loads(row["result_json"])


@app.delete("/api/v1/scans/{scan_id}", status_code=204)
def delete_scan(scan_id: str, user_id: str = Depends(required_user)):
    with db() as con:
        cur = con.execute("DELETE FROM scans WHERE id=? AND owner_id=?", (scan_id, user_id))
    if not cur.rowcount:
        raise HTTPException(404, detail="Scan not found")


@app.get("/api/v1/statistics")
def statistics(user_id: str = Depends(required_user)):
    with db() as con:
        rows = con.execute(
            "SELECT prediction,COUNT(*) n,AVG(risk_score) risk FROM scans WHERE owner_id=? GROUP BY prediction",
            (user_id,),
        ).fetchall()
    return {"by_prediction": [dict(r) for r in rows]}


@app.get("/api/v1/threat-intelligence/status")
def intelligence_status():
    return {
        "providers": [
            {"provider": "phishtank", "configured": bool(os.getenv("PHISHTANK_API_KEY")), "mode": "official API checkurl"},
            {"provider": "urlhaus", "configured": os.getenv("URLHAUS_ENABLED", "false").lower() == "true", "mode": "official API"},
        ]
    }


def frontend_file(path: str) -> FileResponse:
    if not FRONTEND_INDEX.exists():
        raise HTTPException(
            503,
            "Frontend build not found. Run `npm run build` inside apps/web, then restart the backend.",
        )
    if path:
        candidate = (FRONTEND_DIST / path).resolve()
        dist_root = FRONTEND_DIST.resolve()
        if dist_root == candidate or dist_root in candidate.parents:
            if candidate.is_file():
                return FileResponse(candidate)
    return FileResponse(FRONTEND_INDEX)


@app.get("/", include_in_schema=False)
def frontend_root():
    return frontend_file("")


@app.get("/{path:path}", include_in_schema=False)
def frontend_spa(path: str):
    if path.startswith(("api/", "health", "ready", "docs", "openapi.json", "redoc")):
        raise HTTPException(404, "Not found")
    return frontend_file(path)
