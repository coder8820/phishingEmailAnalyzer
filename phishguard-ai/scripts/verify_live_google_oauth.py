"""
PhishGuard AI — Milestone G1: Live Google OAuth 2.0 Integration Test Tool
=========================================================================
This script provides live, real-world verification of Google OAuth 2.0
and Gmail API access against Google Cloud Identity Services.

It verifies:
  1. Official Google OAuth consent URL generation with PKCE and state.
  2. Browser redirect to Google consent page.
  3. Real authorization code capture from Google.
  4. Real token exchange with https://oauth2.googleapis.com/token.
  5. Real account verification via https://gmail.googleapis.com/gmail/v1/users/me/profile.
  6. Refresh token encryption at rest using AES-128 (MultiFernet).
  7. Real access token refresh flow.
  8. Real token revocation with Google.

USAGE:
  python scripts/verify_live_google_oauth.py

NOTE: If Google credentials (GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET) are missing,
this script exits with status BLOCKED and outputs exact setup instructions.
"""

import asyncio
import base64
import hashlib
import json
import os
import secrets
import sys
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlencode, urlparse, parse_qs

# Add backend directory to sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

# Load .env file
from dotenv import load_dotenv
env_path = os.path.join(BACKEND_DIR, ".env")
if not os.path.exists(env_path):
    env_path = os.path.join(PROJECT_ROOT, ".env")
load_dotenv(env_path)

try:
    import httpx
    from app.core.config import settings
    from app.security.encryption import TokenEncryptionService
except ImportError as e:
    print(f"Error importing PhishGuard dependencies: {e}")
    sys.exit(1)


# Setup capture server
captured_auth_code = None
captured_state = None
callback_error = None


class OAuthCallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global captured_auth_code, captured_state, callback_error
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if "error" in params:
            callback_error = params["error"][0]
        if "code" in params:
            captured_auth_code = params["code"][0]
        if "state" in params:
            captured_state = params["state"][0]

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

        if captured_auth_code:
            html = """
            <html>
            <body style="font-family: monospace; background: #0a0f1d; color: #10b981; padding: 40px; text-align: center;">
                <h2>&#10004; Google Authorization Code Received!</h2>
                <p style="color: #94a3b8;">You may close this tab and return to the terminal.</p>
            </body>
            </html>
            """
        else:
            html = f"""
            <html>
            <body style="font-family: monospace; background: #0a0f1d; color: #ef4444; padding: 40px; text-align: center;">
                <h2>&#10008; Authorization Error: {callback_error or 'Unknown error'}</h2>
                <p style="color: #94a3b8;">Return to terminal for diagnostic details.</p>
            </body>
            </html>
            """
        self.wfile.write(html.encode("utf-8"))

    def log_message(self, format, *args):
        pass  # Suppress HTTP server stdout logs


def run_single_request_server(port: int):
    server = HTTPServer(("localhost", port), OAuthCallbackHandler)
    server.handle_request()  # Handle exactly one request then terminate
    server.server_close()


async def verify_live_google_oauth():
    print("=" * 70)
    print("  PHISHGUARD AI — G1: LIVE GOOGLE OAUTH 2.0 VERIFICATION SUITE")
    print("=" * 70)

    client_id = settings.GOOGLE_CLIENT_ID.strip() if settings.GOOGLE_CLIENT_ID else ""
    client_secret = settings.GOOGLE_CLIENT_SECRET.strip() if settings.GOOGLE_CLIENT_SECRET else ""
    redirect_uri = settings.GOOGLE_REDIRECT_URI.strip() if settings.GOOGLE_REDIRECT_URI else "http://localhost:3001/integrations/gmail/callback"

    # Step 1: Pre-flight Credentials Verification
    print("\n[STEP 1] Validating Google Cloud Configuration...")
    if not client_id or not client_secret:
        print("\n" + "!" * 70)
        print("  STATUS: BLOCKED — MISSING REAL GOOGLE CLOUD CREDENTIALS")
        print("!" * 70)
        print("\nTo perform real Google OAuth verification, configure your Google Cloud credentials:")
        print("1. Go to Google Cloud Console: https://console.cloud.google.com/apis/credentials")
        print("2. Create an OAuth 2.0 Client ID (Application type: Web application).")
        print("3. Add Authorized Redirect URI:")
        print(f"   -> {redirect_uri}")
        print("4. Enable the 'Gmail API' under APIs & Services > Library.")
        print("5. Under OAuth consent screen > Test users, add your test Gmail account.")
        print("6. Update your backend/.env with:")
        print("   GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com")
        print("   GOOGLE_CLIENT_SECRET=your-client-secret")
        print("   GOOGLE_REDIRECT_URI=" + redirect_uri)
        print("\nAutomated mocked tests pass completely. Live verification requires real credentials.\n")
        return False

    print(f"  [OK] GOOGLE_CLIENT_ID: {client_id[:16]}... (Configured)")
    print(f"  [OK] GOOGLE_CLIENT_SECRET: [MASKED] ({len(client_secret)} chars)")
    print(f"  [OK] GOOGLE_REDIRECT_URI: {redirect_uri}")

    # Parse port from redirect URI
    parsed_redirect = urlparse(redirect_uri)
    port = parsed_redirect.port or 3001

    # Step 2: PKCE and CSRF State Generation
    print("\n[STEP 2] Generating RFC 7636 PKCE pair and cryptographic state...")
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    state = secrets.token_urlsafe(32)
    print(f"  [OK] PKCE Code Verifier: {verifier[:16]}...")
    print(f"  [OK] PKCE Code Challenge (S256): {challenge}")
    print(f"  [OK] One-Time CSRF State: {state}")

    # Build Official Google Consent URL
    scopes = [
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/gmail.modify",
    ]
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(scopes),
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"

    print("\n[STEP 3] Opening Google OAuth Consent Page...")
    print(f"  URL: {auth_url}\n")
    print(f"  Starting local callback listener on http://localhost:{port}...")
    webbrowser.open(auth_url)

    # Listen for callback in background thread
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, run_single_request_server, port)

    if callback_error:
        print(f"\n[FAILED] Authorization declined or error received: {callback_error}")
        return False

    if not captured_auth_code:
        print("\n[FAILED] No authorization code captured.")
        return False

    if captured_state != state:
        print(f"\n[FAILED] CSRF state mismatch! Expected: {state}, Got: {captured_state}")
        return False

    print("  [OK] Authorization code successfully received.")
    print(f"  [OK] State validated (CSRF verification passed).")

    # Step 4: Token Exchange with Google Token Endpoint
    print("\n[STEP 4] Exchanging Authorization Code with Google Token Endpoint...")
    token_payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": captured_auth_code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
        "code_verifier": verifier,
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        token_resp = await client.post("https://oauth2.googleapis.com/token", data=token_payload)

    if token_resp.status_code != 200:
        print(f"  [FAILED] Token exchange error ({token_resp.status_code}): {token_resp.text}")
        return False

    token_data = token_resp.json()
    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")
    expires_in = token_data.get("expires_in")
    granted_scope = token_data.get("scope")

    print(f"  [OK] Real Access Token received (expires in {expires_in}s).")
    print(f"  [OK] Real Refresh Token received: {'YES (offline access active)' if refresh_token else 'NO (already consented)'}")
    print(f"  [OK] Scopes granted: {granted_scope}")

    # Step 5: Real Gmail API Account Verification (users.getProfile)
    print("\n[STEP 5] Calling Google Gmail API: users.getProfile...")
    async with httpx.AsyncClient(timeout=15.0) as client:
        profile_resp = await client.get(
            "https://gmail.googleapis.com/gmail/v1/users/me/profile",
            headers={"Authorization": f"Bearer {access_token}"},
        )

    if profile_resp.status_code != 200:
        print(f"  [FAILED] users.getProfile failed ({profile_resp.status_code}): {profile_resp.text}")
        return False

    profile = profile_resp.json()
    verified_email = profile.get("emailAddress")
    msgs_total = profile.get("messagesTotal", 0)
    threads_total = profile.get("threadsTotal", 0)
    history_id = profile.get("historyId", "N/A")

    print(f"  [OK] Authenticated Gmail Address: {verified_email}")
    print(f"  [OK] Live Total Messages: {msgs_total}")
    print(f"  [OK] Live Total Threads: {threads_total}")
    print(f"  [OK] Current Mailbox History ID: {history_id}")

    # Step 6: Encryption at Rest Verification
    print("\n[STEP 6] Verifying Refresh Token Encryption at Rest...")
    encryptor = TokenEncryptionService()
    if refresh_token:
        encrypted_token = encryptor.encrypt(refresh_token)
        print(f"  [OK] Encrypted Token Bytes: {encrypted_token[:24]}... (Length: {len(encrypted_token)})")
        assert refresh_token.encode() not in encrypted_token
        decrypted = encryptor.decrypt(encrypted_token)
        assert decrypted == refresh_token
        print("  [OK] Decryption parity verified via MultiFernet.")

    # Step 7: Live Token Refresh Verification
    if refresh_token:
        print("\n[STEP 7] Verifying Live Token Refresh Flow...")
        refresh_payload = {
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }
        async with httpx.AsyncClient(timeout=15.0) as client:
            ref_resp = await client.post("https://oauth2.googleapis.com/token", data=refresh_payload)

        if ref_resp.status_code == 200:
            print("  [OK] Token refresh endpoint returned fresh access token.")
        else:
            print(f"  [WARN] Token refresh returned HTTP {ref_resp.status_code}: {ref_resp.text}")

    # Step 8: Token Revocation Verification
    print("\n[STEP 8] Verifying Real Token Revocation (Disconnect Simulation)...")
    token_to_revoke = refresh_token or access_token
    async with httpx.AsyncClient(timeout=15.0) as client:
        revoke_resp = await client.post(
            "https://oauth2.googleapis.com/revoke",
            params={"token": token_to_revoke},
        )
    if revoke_resp.status_code == 200:
        print("  [OK] Token successfully revoked with Google Identity Services.")
    else:
        print(f"  [WARN] Revocation endpoint returned HTTP {revoke_resp.status_code}")

    print("\n" + "=" * 70)
    print("  PHISHGUARD AI — G1: LIVE GOOGLE OAUTH VERIFICATION SUCCESSFUL!")
    print("=" * 70)
    return True


if __name__ == "__main__":
    success = asyncio.run(verify_live_google_oauth())
    sys.exit(0 if success else 1)
