import hashlib
import importlib
import os
import sqlite3

os.environ['SCOUT_AUTH_DB'] = '/tmp/reaper-auth-test-import.db'
import pytest
import requests
from fastapi.testclient import TestClient
import scout_auth_api as auth


class Reply:
    ok = True
    def __init__(self, data): self.data = data
    def json(self): return self.data


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, 'DB_PATH', str(tmp_path / 'auth.db'))
    monkeypatch.setattr(auth, 'CLIENT_SECRET', 'test-secret')
    auth.init_db()
    calls = []
    def google(method, url, **kwargs):
        calls.append((method, url, kwargs))
        if 'userinfo' in url:
            return Reply({'email': 'owner@example.com', 'email_verified': True, 'sub': 'owner-sub'})
        return Reply({'access_token': 'access-test', 'refresh_token': 'refresh-test', 'expires_in': 3600})
    monkeypatch.setattr(auth.requests, 'request', google)
    return TestClient(auth.app), calls


def exchange(client):
    return client.post('/scout/auth/exchange', json={'code': 'one-use-test-code', 'code_verifier': 'v' * 64})


def test_email_alone_cannot_refresh(client):
    http, calls = client
    exchange(http)
    calls.clear()
    assert http.post('/scout/auth/refresh', json={'email': 'owner@example.com'}).status_code == 401
    assert calls == []


def test_random_device_session_refreshes_only_its_account(client):
    http, calls = client
    response = exchange(http)
    assert response.status_code == 200
    session = response.json()['session_token']
    assert len(session) >= 43
    headers = {'Authorization': 'Bearer ' + session}
    assert http.post('/scout/auth/refresh', json={'email': 'other@example.com'}, headers=headers).status_code == 403
    assert http.post('/scout/auth/refresh', json={}, headers=headers).json()['email'] == 'owner@example.com'
    with auth.get_db() as db:
        assert db.execute('SELECT digest FROM device_sessions').fetchone()['digest'] == hashlib.sha256(session.encode()).hexdigest()
    assert session not in open(auth.DB_PATH, 'rb').read().decode('latin1')


def test_logout_revokes_only_current_device(client):
    http, _ = client
    one, two = exchange(http).json()['session_token'], exchange(http).json()['session_token']
    a = {'Authorization': 'Bearer ' + one}
    b = {'Authorization': 'Bearer ' + two}
    assert http.post('/scout/auth/logout', headers=a).status_code == 200
    assert http.post('/scout/auth/refresh', json={}, headers=a).status_code == 401
    assert http.post('/scout/auth/refresh', json={}, headers=b).status_code == 200


def test_expired_session_fails_before_google(client):
    http, calls = client
    session = exchange(http).json()['session_token']
    with auth.get_db() as db:
        db.execute('UPDATE device_sessions SET expires_at=0')
        db.commit()
    calls.clear()
    assert http.post('/scout/auth/refresh', json={}, headers={'Authorization': 'Bearer ' + session}).status_code == 401
    assert calls == []


def test_pkce_is_required_and_forwarded(client):
    http, calls = client
    assert http.post('/scout/auth/exchange', json={'code': 'test'}).status_code == 422
    assert http.post('/scout/auth/exchange', json={'code': 'test', 'code_verifier': '!' * 64}).status_code == 400
    assert exchange(http).status_code == 200
    assert calls[0][2]['data']['code_verifier'] == 'v' * 64
    assert calls[0][2]['timeout'] == auth.GOOGLE_TIMEOUT


def test_unverified_google_identity_not_stored(client, monkeypatch):
    http, _ = client
    def google(method, url, **kwargs):
        if 'userinfo' in url:
            return Reply({'email': 'owner@example.com', 'email_verified': False, 'sub': 'owner'})
        return Reply({'access_token': 'test', 'refresh_token': 'test'})
    monkeypatch.setattr(auth.requests, 'request', google)
    assert exchange(http).status_code == 403
    with auth.get_db() as db:
        assert db.execute('SELECT count(*) FROM device_sessions').fetchone()[0] == 0


def test_google_timeout_returns_sanitized_error(client, monkeypatch):
    http, _ = client
    def fail(*args, **kwargs): raise requests.Timeout('secret-code-must-not-appear')
    monkeypatch.setattr(auth.requests, 'request', fail)
    response = exchange(http)
    assert response.status_code == 502
    assert 'secret-code' not in response.text


def test_existing_refresh_tokens_survive_schema_upgrade(client):
    http, _ = client
    exchange(http)
    auth.init_db()
    with auth.get_db() as db:
        assert db.execute('SELECT count(*) FROM refresh_tokens').fetchone()[0] == 1
