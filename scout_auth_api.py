"""Google code exchange and private device sessions for Reaper clients.

Google refresh tokens remain server-side. An email address is never a refresh
credential. Existing clients must complete a fresh PKCE Google sign-in once.
"""
import hashlib
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone

import requests
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(title='Reaper Auth Server', version='1.0.0')
app.add_middleware(CORSMiddleware,
    allow_origins=[o.strip() for o in os.getenv('REAPER_AUTH_ORIGINS', 'https://scanner.herdmate.ag').split(',') if o.strip()],
    allow_credentials=False, allow_methods=['POST', 'GET'], allow_headers=['Content-Type', 'Authorization'])
CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID', '284699934813-85gcnvo9l19qki5ul9ckepgpfg067c7e.apps.googleusercontent.com')
CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET', '')
REDIRECT_URI = os.getenv('GOOGLE_REDIRECT_URI', 'https://scanner.herdmate.ag')
DB_PATH = os.getenv('SCOUT_AUTH_DB', './scout_auth.db')
SESSION_SECONDS = 90 * 24 * 60 * 60
GOOGLE_TIMEOUT = 20


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        os.chmod(DB_PATH, 0o600)
        yield conn
    finally:
        conn.close()


def init_db():
    with get_db() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS refresh_tokens (
            email TEXT PRIMARY KEY, refresh_token TEXT NOT NULL,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS device_sessions (
            digest TEXT PRIMARY KEY, email TEXT NOT NULL,
            expires_at INTEGER NOT NULL)''')
        conn.commit()


init_db()


class ExchangeRequest(BaseModel):
    code: str = Field(min_length=1, max_length=4096)
    code_verifier: str = Field(min_length=43, max_length=128)


class RefreshRequest(BaseModel):
    email: str = ''  # compatibility hint only; never used to select credentials


class TokenResponse(BaseModel):
    access_token: str
    expires_in: int
    email: str
    session_token: str | None = None


def google_request(method, url, **kwargs):
    try:
        response = requests.request(method, url, timeout=GOOGLE_TIMEOUT, allow_redirects=False, **kwargs)
    except requests.RequestException:
        raise HTTPException(502, 'Google is temporarily unavailable') from None
    if not response.ok:
        # Never echo Google response bodies, codes, tokens or client secrets.
        raise HTTPException(401, 'Google sign-in is required')
    try:
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("Invalid Google response shape")
        return payload
    except ValueError:
        raise HTTPException(502, 'Google returned an invalid response') from None


def session_identity(authorization):
    scheme, _, token = (authorization or '').partition(' ')
    if scheme.lower() != 'bearer' or not token.strip():
        raise HTTPException(401, 'A private device session is required; sign in again')
    digest = hashlib.sha256(token.strip().encode()).hexdigest()
    with get_db() as conn:
        row = conn.execute('SELECT email FROM device_sessions WHERE digest=? AND expires_at>?',
                           (digest, int(time.time()))).fetchone()
    if not row:
        raise HTTPException(401, 'Device session expired; sign in again')
    return row['email'], digest


@app.post('/scout/auth/exchange', response_model=TokenResponse)
def exchange_code(req: ExchangeRequest):
    if not CLIENT_SECRET:
        raise HTTPException(503, 'Google sign-in is not configured')
    if not re.fullmatch(r'[A-Za-z0-9._~-]{43,128}', req.code_verifier):
        raise HTTPException(400, 'Invalid sign-in verifier')
    data = google_request('POST', 'https://oauth2.googleapis.com/token', data={
        'code': req.code, 'code_verifier': req.code_verifier, 'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET, 'redirect_uri': REDIRECT_URI,
        'grant_type': 'authorization_code'})
    access_token = data.get('access_token')
    if not access_token:
        raise HTTPException(502, 'Google returned no access credential')
    identity = google_request('GET', 'https://openidconnect.googleapis.com/v1/userinfo',
                              headers={'Authorization': 'Bearer ' + access_token})
    email = str(identity.get('email', '')).strip().lower()
    if not email or identity.get('email_verified') is not True or not identity.get('sub'):
        raise HTTPException(403, 'A verified Google identity is required')
    refresh_token = data.get('refresh_token')
    session = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        existing = conn.execute('SELECT refresh_token FROM refresh_tokens WHERE email=?', (email,)).fetchone()
        refresh_token = refresh_token or (existing['refresh_token'] if existing else None)
        if not refresh_token:
            raise HTTPException(400, 'Google offline access is needed; sign in again with consent')
        conn.execute('''INSERT INTO refresh_tokens VALUES(?,?,?,?) ON CONFLICT(email)
            DO UPDATE SET refresh_token=excluded.refresh_token, updated_at=excluded.updated_at''',
                     (email, refresh_token, now, now))
        conn.execute('DELETE FROM device_sessions WHERE expires_at<=?', (int(time.time()),))
        conn.execute('INSERT INTO device_sessions VALUES(?,?,?)',
                     (hashlib.sha256(session.encode()).hexdigest(), email, int(time.time()) + SESSION_SECONDS))
        conn.commit()
    return TokenResponse(access_token=access_token, expires_in=data.get('expires_in', 3600),
                         email=email, session_token=session)


@app.post('/scout/auth/refresh', response_model=TokenResponse, response_model_exclude_none=True)
def refresh_access_token(req: RefreshRequest, authorization: str | None = Header(default=None)):
    email, _ = session_identity(authorization)
    if req.email and req.email.strip().lower() != email:
        raise HTTPException(403, 'Device session belongs to another account')
    if not CLIENT_SECRET:
        raise HTTPException(503, 'Google sign-in is not configured')
    with get_db() as conn:
        row = conn.execute('SELECT refresh_token FROM refresh_tokens WHERE email=?', (email,)).fetchone()
    if not row:
        raise HTTPException(401, 'Google sign-in is required')
    data = google_request('POST', 'https://oauth2.googleapis.com/token', data={
        'refresh_token': row['refresh_token'], 'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET, 'grant_type': 'refresh_token'})
    if not data.get('access_token'):
        raise HTTPException(502, 'Google returned no access credential')
    return TokenResponse(access_token=data['access_token'], expires_in=data.get('expires_in', 3600), email=email)


@app.post('/scout/auth/logout')
def logout(authorization: str | None = Header(default=None)):
    _, digest = session_identity(authorization)
    with get_db() as conn:
        conn.execute('DELETE FROM device_sessions WHERE digest=?', (digest,))
        conn.commit()
    return {'status': 'SIGNED_OUT'}


@app.get('/scout/auth/health')
def health():
    return {'status': 'ok', 'service': 'Scout Auth Server', 'configured': bool(CLIENT_SECRET)}


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=int(os.getenv('PORT', '5012')))
