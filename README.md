# Reaper Google authentication

Implementation candidate for shared Reaper onboarding; not a deployed acceptance
claim. Scout uses this service for authorization-code exchange and private
device-session refresh. Other product clients can reuse the same security
contract when their OAuth origins/redirects are explicitly configured.

## Contract

POST /scout/auth/exchange: JSON code and code_verifier. The client must generate
an S256 PKCE challenge, save a cryptographic OAuth state in sessionStorage and
check the returned state before submitting the code. Google validates the code
verifier. A verified Google email and subject are required. The response includes
an opaque session_token in addition to the short-lived Google access_token.

POST /scout/auth/refresh: Authorization: Bearer <private session_token> and JSON
{} (an optional email hint must match). An email alone never authorizes refresh.
The session selects the stored Google refresh credential. Google refresh tokens
are never returned to clients. POST /scout/auth/logout with the private session
revokes only that device session. A new sign-in creates a separate session.
Sessions expire after 90 days; expired rows are pruned at a successful exchange.

The browser stores its device credential locally; the server stores only its
SHA-256 digest. The server still retains Google refresh tokens in SCOUT_AUTH_DB,
as before. Protect and back up that volume, use encrypted host storage/backups,
and restrict DB access. This is not a zero-retention service. No email-only
compatibility bypass is provided. Revoking Google consent remains the Google
account owner's control; local sign-out does not revoke other devices.

## Deployment

Keep GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET and GOOGLE_REDIRECT_URI; for this
release the redirect remains https://scanner.herdmate.ag. Keep the existing
SCOUT_AUTH_DB file on persistent storage and back it up before deployment. The
schema change is additive and preserves existing refresh tokens. The service
must have access to that directory; no database is bundled into the image.
REAPER_AUTH_ORIGINS is an optional comma-separated explicit origin allowlist;
it defaults to https://scanner.herdmate.ag, with bearer rather than cookie auth.

Coordinate publication with the Gateway and scanner onboarding PRs. Existing
scanner builds do not send a device credential or PKCE verifier: they require
the updated scanner and one fresh Google sign-in. A failed/cancelled OAuth
redirect must be restarted rather than bypassing state verification. Existing
Google project API enablement, consent publishing and test-user restrictions
must be checked in the actual deployment.

## Tests

pip install -r requirements.txt -r requirements-dev.txt
python -m pytest -q

Tests mock Google and use temporary databases. Real Google exchange/consent,
C72 behavior and deployment persistence still require integration/device tests.
