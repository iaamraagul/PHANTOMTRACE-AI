import base64
import hashlib
import hmac
import json
import time

from fastapi.testclient import TestClient

from app.main import TOKEN_AUDIENCE, TOKEN_ISSUER, SECRET_KEY, app
client=TestClient(app)

def test_rejects_ssrf_hosts():
    assert client.post('/api/v1/analyze',json={'url':'http://127.0.0.1/admin'}).status_code==422
    assert client.post('/api/v1/analyze',json={'url':'http://[::1]/admin'}).status_code==422
    assert client.post('/api/v1/analyze',json={'url':'file:///etc/passwd'}).status_code==422
    assert client.post('/api/v1/analyze',json={'url':'https://user:pass@example.com/login'}).status_code==422

def test_accepts_safe_url_without_fetching():
    res=client.post('/api/v1/analyze',json={'url':'https://example.com/login'}); assert res.status_code==200; assert res.json()['scan_id']

def test_serves_frontend_from_backend_root():
    res = client.get('/')
    assert res.status_code == 200
    assert 'text/html' in res.headers['content-type']

def test_get_analyze_explains_post_method():
    res = client.get('/api/v1/analyze')
    assert res.status_code == 405
    assert 'Use POST /api/v1/analyze' in res.json()['detail']

def test_low_evidence_url_is_not_forced_to_critical_risk():
    res = client.post('/api/v1/analyze', json={'url':'https://example.com/login','include_threat_intelligence':False})
    assert res.status_code == 200
    body = res.json()
    assert body['risk_score'] <= 35
    assert body['risk_breakdown']['final_risk_score'] == body['risk_score']
    assert body['feature_version'] == '2.0'

def test_structural_risk_signals_can_remain_high():
    res = client.post('/api/v1/analyze', json={'url':'http://www.f0519141.xsph.ru/login?session=1234','include_threat_intelligence':False})
    assert res.status_code == 200
    assert res.json()['risk_score'] >= 40

def test_brand_impersonation_scores_high():
    res = client.post('/api/v1/analyze', json={'url':'https://paypal.security-check.example-login.com/account/verify?redirect=https%3A%2F%2Fpaypal.com','include_threat_intelligence':False})
    assert res.status_code == 200
    body = res.json()
    assert body['risk_score'] >= 40
    assert body['brand_signals']['brand_as_subdomain'] is True
    assert body['risk_breakdown']['brand_impersonation_score'] > 0

def test_batch_errors_are_sanitized():
    res = client.post('/api/v1/analyze/batch', json={'urls':['file:///etc/passwd'],'include_threat_intelligence':False})
    assert res.status_code == 200
    assert res.json()['errors'][0]['detail'] == 'Invalid URL'
    assert 'etc/passwd' not in json.dumps(res.json()['errors'])

def test_history_requires_authentication():
    assert client.get('/api/v1/scans').status_code == 401

def test_authenticated_scan_history_is_isolated():
    email = 'analyst-security-test@example.com'
    auth = client.post('/api/v1/auth/register', json={'email': email, 'password': 'change-me-12345'})
    if auth.status_code == 409:
        auth = client.post('/api/v1/auth/login', json={'email': email, 'password': 'change-me-12345'})
    assert auth.status_code == 200
    token = auth.json()['access_token']
    scan = client.post(
        '/api/v1/analyze',
        headers={'Authorization': f'Bearer {token}'},
        json={'url': 'https://example.com/account/update', 'include_threat_intelligence': False},
    )
    assert scan.status_code == 200
    history = client.get('/api/v1/scans', headers={'Authorization': f'Bearer {token}'})
    assert history.status_code == 200
    item = next(item for item in history.json()['items'] if item['scan_id'] == scan.json()['scan_id'])
    assert item['privacy_mode'] == 'masked-history'
    assert item['url'] == 'https://example.com/...'

def test_rejects_tampered_and_expired_tokens():
    email = 'analyst-token-test@example.com'
    auth = client.post('/api/v1/auth/register', json={'email': email, 'password': 'change-me-98765'})
    if auth.status_code == 409:
        auth = client.post('/api/v1/auth/login', json={'email': email, 'password': 'change-me-98765'})
    token = auth.json()['access_token']
    assert client.get('/api/v1/scans', headers={'Authorization': f'Bearer {token}x'}).status_code == 401

    payload = {'sub':'someone','iat':int(time.time())-3600,'exp':int(time.time())-1,'iss':TOKEN_ISSUER,'aud':TOKEN_AUDIENCE}
    body = base64.urlsafe_b64encode(json.dumps(payload,separators=(',',':')).encode()).decode().rstrip('=')
    sig = hmac.new(SECRET_KEY.encode(), body.encode(), hashlib.sha256).hexdigest()
    assert client.get('/api/v1/scans', headers={'Authorization': f'Bearer {body}.{sig}'}).status_code == 401
