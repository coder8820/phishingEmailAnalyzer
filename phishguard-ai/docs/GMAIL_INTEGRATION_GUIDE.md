# PhishGuard AI — Real Gmail Integration & Production Deployment Guide

## 1. Overview & Architecture

PhishGuard AI provides a production-grade, secure, non-destructive integration with Google Workspace and consumer Gmail accounts. The integration monitors user inboxes in real-time for incoming phishing threats, performs automated AI and rule-based multi-stage analysis, isolates high-risk threats into a dedicated quarantine label, and provides SOC analysts and end users with full auditability and one-click restoration.

```
                    ┌────────────────────────┐
                    │      Google Cloud      │
                    │   OAuth 2.0 Endpoint   │
                    └───────────┬────────────┘
                                │ (Authorization Code + PKCE)
                                ▼
┌──────────────┐     ┌────────────────────────┐     ┌────────────────────────┐
│  End User /  ├────►│  PhishGuard AI Backend ├────►│   Gmail REST API v1    │
│  SOC Analyst │     │  (FastAPI / Celery)    │◄────┤ (users.getProfile/MIME)│
└──────────────┘     └───────────▲────────────┘     └────────────────────────┘
                                 │
                                 │ HTTPS Push (JWT / Auth Token)
                                 │
                     ┌───────────┴────────────┐
                     │ Google Cloud Pub/Sub   │
                     │  (gmail-notifications) │
                     └───────────▲────────────┘
                                 │
                     ┌───────────┴────────────┐
                     │  Gmail Push Notification│
                     │  (users.watch / INBOX) │
                     └────────────────────────┘
```

---

## 2. Google Cloud Platform (GCP) Setup

### Step 1: GCP Project & API Activation
1. Sign in to the [Google Cloud Console](https://console.cloud.google.com/).
2. Select or create a dedicated GCP project (e.g., `phishguard-production`).
3. Enable required APIs:
   - **Gmail API**: `console.cloud.google.com/apis/library/gmail.googleapis.com`
   - **Cloud Pub/Sub API**: `console.cloud.google.com/apis/library/pubsub.googleapis.com`

### Step 2: Configure OAuth Consent Screen
1. Go to **APIs & Services > OAuth consent screen**.
2. Select User Type:
   - **Internal**: Recommended for enterprise Google Workspace organizations. Requires no external CASA verification.
   - **External**: Required for public multi-tenant SaaS or personal `@gmail.com` accounts. (Starts in *Testing* mode; requires CASA Tier 2 assessment before public verification).
3. Fill in mandatory application information:
   - App name: `PhishGuard AI`
   - User support email: `security@yourdomain.com`
   - App domain / Privacy Policy URL: `https://yourdomain.com/privacy`
   - Terms of Service URL: `https://yourdomain.com/terms`
4. Define OAuth Scopes:
   - Add `https://www.googleapis.com/auth/gmail.modify` (Restricted Scope).
   - *Security Note*: Never add `https://mail.google.com/` (excessive full-mailbox privilege) or send scopes (`gmail.send`, `gmail.compose`).
5. In *Testing* mode, add authorized test user email addresses under **Test Users**.

### Step 3: Create OAuth 2.0 Client Credentials
1. Go to **APIs & Services > Credentials > Create Credentials > OAuth client ID**.
2. Application type: **Web application**.
3. Name: `PhishGuard AI Web Client`.
4. Authorized JavaScript origins:
   - Development: `http://localhost:3000`, `http://localhost:3001`
   - Production: `https://app.yourdomain.com`
5. Authorized redirect URIs:
   - Development: `http://localhost:8000/api/v1/gmail/callback` (or your local proxy)
   - Production: `https://api.yourdomain.com/api/v1/gmail/callback`
6. Save the generated `Client ID` and `Client Secret`.

---

## 3. Google Cloud Pub/Sub Configuration

PhishGuard AI leverages Google Cloud Pub/Sub for push notifications on new inbox messages.

### Step 1: Create Pub/Sub Topic
```bash
gcloud pubsub topics create phishguard-gmail-notifications \
  --project=<YOUR_GCP_PROJECT_ID>
```
The full topic path will be:
`projects/<YOUR_GCP_PROJECT_ID>/topics/phishguard-gmail-notifications`

### Step 2: Grant Gmail Push Publisher IAM Permissions
The Gmail service account must be granted publisher permissions on the topic:
```bash
gcloud pubsub topics add-iam-policy-binding \
  projects/<YOUR_GCP_PROJECT_ID>/topics/phishguard-gmail-notifications \
  --member="serviceAccount:gmail-api-push@system.gserviceaccount.com" \
  --role="roles/pubsub.publisher"
```

### Step 3: Create Push Subscription
Configure a push subscription pointing to the PhishGuard webhook:
```bash
gcloud pubsub subscriptions create phishguard-gmail-inbox-push \
  --topic=phishguard-gmail-notifications \
  --push-endpoint="https://api.yourdomain.com/api/v1/gmail/pubsub-push?token=<SECURE_WEBHOOK_SECRET>" \
  --ack-deadline=60 \
  --min-retry-delay=10s \
  --max-retry-delay=600s
```

---

## 4. Environment Variables Configuration

Populate the following environment variables in `.env`:

```ini
# Google OAuth 2.0 Credentials
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_REDIRECT_URI=https://api.yourdomain.com/api/v1/gmail/callback

# Pub/Sub Configuration
GMAIL_PUBSUB_TOPIC=projects/your-gcp-project/topics/phishguard-gmail-notifications
GMAIL_PUBSUB_SUBSCRIPTION=projects/your-gcp-project/subscriptions/phishguard-gmail-inbox-push
GMAIL_PUBSUB_VERIFICATION_TOKEN=generate-random-high-entropy-token-here

# Security & Encryption
ENCRYPTION_KEY=generate-fernet-key-with-cryptography-fernet-generate_key
APP_SECRET_KEY=generate-jwt-secret-key

# Data Retention & Privacy Settings (GDPR / Google Limited Use)
GMAIL_RAW_CONTENT_RETENTION_DAYS=30
GMAIL_MESSAGE_METADATA_RETENTION_DAYS=90
GMAIL_AUTO_RESTORE_ON_DELETION=true
```

---

## 5. Security & Privacy Architecture

### Least-Privilege OAuth Scope Justification
- Requested Scope: `https://www.googleapis.com/auth/gmail.modify`
- Purpose: Non-destructive email threat quarantine.
- Justification:
  1. The platform must be able to read message metadata and raw MIME bytes (`users.messages.get`) to analyze headers, authentication records (SPF/DKIM/DMARC), body HTML, URLs, and attachment hashes.
  2. The platform must be able to add the `PhishGuard-Quarantine` label and remove the `INBOX` label (`users.messages.modify`).
  3. The platform strictly avoids `https://mail.google.com/` which grants permanent deletion and email sending privileges.
  4. The platform does not request `gmail.send` or `gmail.compose` under any circumstances.

### Cryptographic Safeguards
1. **PKCE (RFC 7636)**: Authorization code exchanges enforce SHA-256 code challenge and verifier pairs, mitigating authorization code injection.
2. **CSRF State Validation**: OAuth state values are cryptographically random 256-bit nonces with a 10-minute time-to-live and single-use invalidation.
3. **Token Encryption at Rest**: Refresh tokens and sensitive credentials are encrypted using AES-128-CBC with HMAC-SHA256 authenticated encryption (Fernet) before storing in the database.
4. **Immutable Audit Logging**: Every connection, synchronization, quarantine, restore, and disconnection event is recorded in an immutable `audit_logs` table.

### Safe Quarantine Lifecycle
- **Explicit Consent**: Automatic quarantine is `DISABLED` by default and requires explicit user opt-in (`auto_quarantine_enabled=true`).
- **Original Label Preservation**: Before any message modification, original label IDs are captured in `GmailMessage.original_labels` (JSON).
- **Non-Destructive Action**: PhishGuard AI never permanently deletes emails. Messages are simply moved from `INBOX` to `PhishGuard-Quarantine`.
- **API Read Verification**: After applying labels, a subsequent `users.messages.get?format=minimal` call verifies that `PhishGuard-Quarantine` is present and `INBOX` is absent.
- **One-Click Restoration**: Any quarantined message can be restored at any time, returning the message to its pre-quarantine label configuration.
- **Data Erasure Safety**: When a user exercises their GDPR Right-to-Erasure or requests account unlinking, PhishGuard AI automatically restores all quarantined emails to `INBOX` before revoking access and purging data.

---

## 6. Google API Verification & CASA Tier 2 Assessment

When deploying to production with public external users:

1. **Brand Verification**: Verify application domain ownership in Google Search Console.
2. **Privacy Policy Compliance**: Ensure the hosted Privacy Policy explicitly discloses compliance with the [Google API Services User Data Policy](https://developers.google.com/terms/api-services-user-data-policy), including the **Limited Use** requirements:
   - PhishGuard AI uses Gmail data solely to provide cybersecurity threat detection and quarantine services.
   - Gmail data is never used for serving advertisements.
   - Gmail data is never transferred to third parties without explicit user direction.
   - Human agents do not read user emails unless explicit user consent is granted for a specific false positive investigation or required by law.
3. **Cloud App Security Assessment (CASA)**:
   - Applications requesting `gmail.modify` for external users require an annual CASA Tier 2 assessment conducted by an Authorized Lab.
   - CASA validates OWASP ASVS Level 2 security requirements, including secret management, transport encryption, and dependency vulnerability scanning.
   - For internal Google Workspace organizational deployments, CASA assessment is waived.

---

## 7. Operational Runbook & Health Monitoring

### Health & Sync Verification
- View live sync metrics in the **Gmail Defense Hub** dashboard:
  - Last sync timestamp
  - Push watch expiration (renewed automatically every 24 hours)
  - Quarantined threat counts
  - Synchronization and analysis error indicators

### Manual Verification Script
Run the built-in live quarantine verification script:
```bash
python scripts/verify_live_gmail_quarantine.py
```
If GCP credentials are not yet configured, the script will safely output `STATUS: BLOCKED` with specific missing prerequisite keys.
