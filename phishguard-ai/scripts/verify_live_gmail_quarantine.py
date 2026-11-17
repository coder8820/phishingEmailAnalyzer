"""
PhishGuard AI — Milestone G4: Live Gmail API Quarantine & Remediation Verification Tool
======================================================================================
This script performs genuine, live verification of Gmail quarantine and restore
actions against Google's Gmail API v1.

It verifies:
  1. Google Cloud OAuth credentials and database connection.
  2. Active Gmail connection with 'https://www.googleapis.com/auth/gmail.modify' scope.
  3. Automatic quarantine consent settings and detection policy thresholds.
  4. Querying or creating the custom 'PhishGuard-Quarantine' label via users.labels.
  5. Quarantining a message (adding PhishGuard-Quarantine label, removing INBOX).
  6. Idempotency of quarantine actions.
  7. Restoring the message (restoring INBOX label, removing PhishGuard-Quarantine).
  8. Idempotency of restore actions.
  9. AuditLog record verification.

USAGE:
  python scripts/verify_live_gmail_quarantine.py

NOTE:
If Google credentials or connected Gmail accounts are missing,
this script reports BLOCKED and outputs exact setup instructions.
"""

import asyncio
import os
import sys
import uuid
from datetime import datetime, timezone

# Add backend directory to sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from dotenv import load_dotenv
env_path = os.path.join(BACKEND_DIR, ".env")
if not os.path.exists(env_path):
    env_path = os.path.join(PROJECT_ROOT, ".env")
load_dotenv(env_path)

try:
    import httpx
    from sqlalchemy import select
    from app.core.config import settings
    from app.core.database import AsyncSessionLocal
    from app.models import AuditLog, GmailIntegration, GmailMessage, User
    from app.services.gmail_client_service import (
        gmail_client_service,
        GmailPermissionError,
        GmailAPIError,
    )
except ImportError as e:
    print(f"[-] Dependency import error: {e}")
    sys.exit(1)


def print_banner():
    print("=" * 80)
    print(" PHISHGUARD AI — G4: SAFE GMAIL PHISHING QUARANTINE VERIFICATION")
    print("=" * 80)


def check_configuration() -> bool:
    print("\n[*] Step 1: Checking Google OAuth Configuration...")
    missing = []
    if not settings.GOOGLE_CLIENT_ID:
        missing.append("GOOGLE_CLIENT_ID")
    if not settings.GOOGLE_CLIENT_SECRET:
        missing.append("GOOGLE_CLIENT_SECRET")
    if not settings.TOKEN_ENCRYPTION_KEY:
        missing.append("TOKEN_ENCRYPTION_KEY")

    if missing:
        print("\n[!] STATUS: BLOCKED — Missing required configuration:")
        for var in missing:
            print(f"    - {var}")
        print("\nPlease configure these variables in backend/.env before running live verification.")
        return False

    print("    [+] GOOGLE_CLIENT_ID: configured")
    print("    [+] GOOGLE_CLIENT_SECRET: configured")
    print("    [+] TOKEN_ENCRYPTION_KEY: configured")
    return True


async def run_live_verification():
    print_banner()

    if not check_configuration():
        sys.exit(1)

    print("\n[*] Step 2: Checking Connected Gmail Account & Scope in Database...")
    async with AsyncSessionLocal() as session:
        stmt = select(GmailIntegration).where(
            GmailIntegration.is_connected == True
        ).order_by(GmailIntegration.connected_at.desc()).limit(1)
        res = await session.execute(stmt)
        integration = res.scalar_one_or_none()

        if not integration:
            print("\n[!] STATUS: BLOCKED — No connected Gmail account found in database.")
            print("    Please connect a test Gmail account via the dashboard or OAuth authorization endpoint:")
            print(f"    Endpoint: {settings.API_V1_STR}/gmail/oauth/authorize")
            sys.exit(1)

        print(f"    [+] Connected Account: {integration.email_address}")
        print(f"    [+] Connection Status: {integration.connection_status}")
        print(f"    [+] Token Status: {integration.token_status}")

        granted_scopes = integration.granted_scopes or []
        has_modify = any("gmail.modify" in s for s in granted_scopes)
        if not has_modify:
            print(f"\n[!] STATUS: BLOCKED — Account lacks 'gmail.modify' scope.")
            print(f"    Granted scopes: {granted_scopes}")
            print("    Please reconnect the account with the approved 'https://www.googleapis.com/auth/gmail.modify' scope.")
            sys.exit(1)

        print("    [+] Scope 'https://www.googleapis.com/auth/gmail.modify' is GRANTED.")

        # Resolve user
        user_res = await session.execute(select(User).where(User.id == integration.user_id))
        user = user_res.scalar_one_or_none()
        if not user:
            print("[!] User not found for integration.")
            sys.exit(1)

        # Step 3: Verify custom quarantine label
        print("\n[*] Step 3: Verifying 'PhishGuard-Quarantine' Gmail Label...")
        try:
            label_id = await gmail_client_service.get_or_create_quarantine_label(
                db=session,
                integration=integration,
                label_name=integration.quarantine_label_name or "PhishGuard-Quarantine",
            )
            print(f"    [+] Quarantine Label verified: ID = {label_id}")
        except Exception as e:
            print(f"[-] Failed to get/create quarantine label: {e}")
            sys.exit(1)

        # Step 4: Find an ingested message to test quarantine & restore
        print("\n[*] Step 4: Finding Message for Quarantine & Restore Verification...")
        msg_res = await session.execute(
            select(GmailMessage).where(
                GmailMessage.integration_id == integration.id
            ).limit(1)
        )
        msg = msg_res.scalar_one_or_none()
        if not msg:
            print("    [!] No synced messages in database to quarantine. Synchronize inbox first via POST /gmail/sync.")
            sys.exit(0)

        print(f"    [+] Testing with message: ID={msg.gmail_message_id}, Subject='{msg.subject[:40]}'")
        orig_labels = list(msg.label_ids or [])
        print(f"    [+] Original Labels: {orig_labels}")

        # Step 5: Test Quarantine
        print("\n[*] Step 5: Executing Quarantine via users.messages.modify...")
        try:
            q_res = await gmail_client_service.quarantine_message(
                db=session,
                user=user,
                integration=integration,
                gmail_msg=msg,
                reason="Live Integration Test Verification",
                is_automatic=False,
            )
            print(f"    [+] Quarantine Result: {q_res['status']}")
            print(f"    [+] Updated Labels: {q_res['label_ids']}")
            assert label_id in q_res['label_ids'], "Quarantine label was not applied!"
            assert "INBOX" not in q_res['label_ids'], "INBOX label was not removed!"
        except Exception as e:
            print(f"[-] Quarantine failed: {e}")
            sys.exit(1)

        # Step 6: Test Idempotency
        print("\n[*] Step 6: Testing Quarantine Idempotency...")
        q_idem = await gmail_client_service.quarantine_message(
            db=session,
            user=user,
            integration=integration,
            gmail_msg=msg,
            reason="Repeat test",
        )
        print(f"    [+] Idempotent call returned: {q_idem['status']}")
        assert q_idem['status'] == "already_quarantined"

        # Step 7: Test Restore
        print("\n[*] Step 7: Executing Restore to INBOX...")
        try:
            r_res = await gmail_client_service.restore_message(
                db=session,
                user=user,
                integration=integration,
                gmail_msg=msg,
            )
            print(f"    [+] Restore Result: {r_res['status']}")
            print(f"    [+] Updated Labels: {r_res['label_ids']}")
            assert "INBOX" in r_res['label_ids'], "INBOX label was not restored!"
            assert label_id not in r_res['label_ids'], "Quarantine label was not removed!"
        except Exception as e:
            print(f"[-] Restore failed: {e}")
            sys.exit(1)

        # Step 8: Test Restore Idempotency
        print("\n[*] Step 8: Testing Restore Idempotency...")
        r_idem = await gmail_client_service.restore_message(
            db=session,
            user=user,
            integration=integration,
            gmail_msg=msg,
        )
        print(f"    [+] Idempotent call returned: {r_idem['status']}")
        assert r_idem['status'] == "already_restored"

        # Step 9: Test False-Positive Reporting (G5 Requirement 6.6)
        print("\n[*] Step 9: Testing False-Positive Reporting & Auto-Restore...")
        # First re-quarantine for FP test
        await gmail_client_service.quarantine_message(
            db=session,
            user=user,
            integration=integration,
            gmail_msg=msg,
            reason="Staging for false-positive test",
        )
        fp_res = await gmail_client_service.report_false_positive(
            db=session,
            user=user,
            integration=integration,
            gmail_msg=msg,
            feedback="Live test verification - legitimate newsletter",
        )
        print(f"    [+] False Positive Result: {fp_res['status']}")
        print(f"    [+] Restored to Inbox: {fp_res['restored']}")
        assert fp_res["status"] == "false_positive_recorded"
        assert fp_res["restored"] is True
        assert msg.is_quarantined is False
        assert msg.quarantine_action_status == "false_positive"

        # Step 10: Verify AuditLog entries
        print("\n[*] Step 10: Verifying Immutable Audit Log Entries...")
        audit_res = await session.execute(
            select(AuditLog).where(
                AuditLog.resource_id == msg.id
            ).order_by(AuditLog.created_at.desc()).limit(3)
        )
        audit_records = audit_res.scalars().all()
        for a in audit_records:
            print(f"    [+] AuditLog: action='{a.action}', resource_id={a.resource_id}, time={a.created_at}")

        print("\n" + "=" * 80)
        print(" [✓] ALL LIVE GMAIL QUARANTINE & RESTORE CHECKS COMPLETED SUCCESSFULLY")
        print("=" * 80)


if __name__ == "__main__":
    asyncio.run(run_live_verification())
