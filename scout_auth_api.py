#!/usr/bin/env python3
"""
Scout Auth Server — a tiny, dedicated backend whose only job is holding
onto a Google refresh token so Scout never has to ask you to sign in
again after the first time.

This is Scout's OWN server — not Dave's, not Ellis's. Independent, per
the explicit design decision: Scout doesn't depend on anyone else.

WHY THIS EXISTS:
Google will only issue a long-lived "refresh token" to a real backend
server, never to code running directly in a browser (security rule on
Google's side, not something we can configure around). Scout was
signing in entirely in-browser, so it only ever got a short-lived
(~1 hour) access token with nothing to renew it — hence needing to
fully sign in again, over and over.

FLOW:
1. Browser sends Google's one-time "authorization code" here after sign-in
2. This server exchanges that code with Google for an access_token AND
   a refresh_token (using the CLIENT_SECRET, which must NEVER be sent to
   the browser — that's the whole reason this server needs to exist)
3. The refresh_token gets stored here, keyed by the signed-in email
4. From then on, whenever the browser's access token is about to expire,
   it calls /auth/refresh instead of showing a sign-in screen — this
   server uses the stored refresh_token to silently get a new hour of
   access from Google and hands it back

SETUP REQUIRED BEFORE THIS WORKS (one-time, in Google Cloud Console):
1. The existing OAuth client (284699934813-85gcnvo9l19qki5ul9ckepgpfg067c7e...)
   needs a CLIENT_SECRET generated for it, OR a new "Web application" type
   OAuth client needs to be created (the current one may be a "public"
   client type that doesn't support secrets at all — check this first).
2. Add this server's URL as an authorized redirect URI on that client.
3. Set GOOGLE_CLIENT_SECRET below via environment variable — never commit
   it to the repo.
"""

import os
import sqlite3
import requests
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Scout Auth Server", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://scanner.herdmate.ag"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── CONFIG ──
CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "284699934813-85gcnvo9l19qki5ul9ckepgpfg067c7e.apps.googleusercontent.com")
CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")  # MUST be set before this works — see setup notes above
REDIRECT_URI = os.environ.get("GOOGLE_REDIRECT_URI", "https://scanner.herdmate.ag")
DB_PATH = os.environ.get("SCOUT_AUTH_DB", "./scout_auth.db")

if not CLIENT_SECRET:
    print("WARNING: GOOGLE_CLIENT_SECRET is not set. Token exchange will fail "
          "until this is configured in Google Cloud Console and set here.")

# ── DATABASE ──
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            email TEXT PRIMARY KEY,
            refresh_token TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ── MODELS ──
class ExchangeRequest(BaseModel):
    code: str  # the one-time authorization code from Google's sign-in redirect

class RefreshRequest(BaseModel):
    email: str  # whose stored refresh_token to use

class TokenResponse(BaseModel):
    access_token: str
    expires_in: int
    email: str

# ── ENDPOINTS ──

@app.post("/scout/auth/exchange", response_model=TokenResponse)
async def exchange_code(req: ExchangeRequest):
    """
    Called ONCE, right after the browser gets an authorization code from
    Google's sign-in screen. Trades that code for both an access_token
    (handed back to the browser to use immediately) and a refresh_token
    (kept here, never sent to the browser at all).
    """
    if not CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Server not configured — GOOGLE_CLIENT_SECRET missing")

    token_resp = requests.post("https://oauth2.googleapis.com/token", data={
        "code": req.code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
    })
    if not token_resp.ok:
        raise HTTPException(status_code=400, detail=f"Google rejected the code: {token_resp.text[:300]}")

    data = token_resp.json()
    access_token = data.get("access_token")
    refresh_token = data.get("refresh_token")
    expires_in = data.get("expires_in", 3600)

    if not refresh_token:
        # Google only sends a refresh_token the FIRST time a person consents.
        # If they'd already granted access before without this flow existing,
        # they may need to revoke access once at myaccount.google.com and
        # sign in fresh to get a refresh_token issued.
        raise HTTPException(
            status_code=400,
            detail="No refresh_token returned — the person may need to revoke "
                   "prior access at myaccount.google.com/permissions and sign in again"
        )

    # Get their email so we know whose token this is
    userinfo = requests.get(
        "https://www.googleapis.com/oauth2/v3/userinfo",
        headers={"Authorization": f"Bearer {access_token}"}
    ).json()
    email = userinfo.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Could not determine email from Google")

    conn = get_db()
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("""
        INSERT INTO refresh_tokens (email, refresh_token, created_at, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(email) DO UPDATE SET refresh_token=excluded.refresh_token, updated_at=excluded.updated_at
    """, (email, refresh_token, now, now))
    conn.commit()
    conn.close()

    return TokenResponse(access_token=access_token, expires_in=expires_in, email=email)


@app.post("/scout/auth/refresh", response_model=TokenResponse)
async def refresh_access_token(req: RefreshRequest):
    """
    Called silently by Scout whenever its current access token is about
    to expire (or just failed with a 401). No sign-in screen, no human
    involved — this is the whole point.
    """
    if not CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Server not configured — GOOGLE_CLIENT_SECRET missing")

    conn = get_db()
    row = conn.execute("SELECT refresh_token FROM refresh_tokens WHERE email = ?", (req.email,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="No stored refresh token for this email — needs a fresh sign-in")

    token_resp = requests.post("https://oauth2.googleapis.com/token", data={
        "refresh_token": row["refresh_token"],
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "refresh_token",
    })
    if not token_resp.ok:
        # Refresh tokens CAN be revoked (person removed access manually, or
        # Google invalidated it) — if so, they genuinely need to sign in fresh.
        raise HTTPException(status_code=401, detail=f"Refresh failed, sign-in needed again: {token_resp.text[:300]}")

    data = token_resp.json()
    return TokenResponse(
        access_token=data.get("access_token"),
        expires_in=data.get("expires_in", 3600),
        email=req.email,
    )


@app.get("/scout/auth/health")
async def health():
    return {"status": "ok", "service": "Scout Auth Server", "configured": bool(CLIENT_SECRET)}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "5012"))
    uvicorn.run(app, host="0.0.0.0", port=port)
