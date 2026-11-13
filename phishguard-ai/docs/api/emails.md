# Email Ingestion & Analysis API

Endpoints for submitting suspicious emails (via `.eml` file upload or raw RFC-822 text), tracking analysis status, and inspecting findings.

---

## 1. Upload Email File (.eml)

Submit a suspicious `.eml` file for sandboxed inspection and multi-engine analysis.

- **Endpoint**: `POST /emails/upload`
- **Auth**: Bearer token (roles: `analyst`, `security_admin`, `super_admin`)
- **Content-Type**: `multipart/form-data`
- **Max File Size**: 25 MB

### Form Fields

- `file`: The `.eml` file to upload.

### Response (`202 Accepted`)

```json
{
  "success": true,
  "data": {
    "email_id": "33333333-3333-3333-3333-333333333333",
    "status": "queued"
  },
  "error": null
}
```

---

## 2. Submit Raw Email Content

Submit raw RFC-822 email text directly.

- **Endpoint**: `POST /emails/raw`
- **Auth**: Bearer token
- **Content-Type**: `application/json`

### Request Body

```json
{
  "content": "From: security@fake-bank.com\nTo: user@company.com\nSubject: Reset PIN\n\nClick: http://evil-login.xyz",
  "filename": "suspicious_pin_reset.eml"
}
```

### Response (`202 Accepted`)

```json
{
  "success": true,
  "data": {
    "email_id": "33333333-3333-3333-3333-333333333333",
    "status": "queued"
  },
  "error": null
}
```

---

## 3. Get Email Details

Retrieve parsed metadata for a submitted email.

- **Endpoint**: `GET /emails/{email_id}`
- **Auth**: Bearer token

### Response (`200 OK`)

```json
{
  "success": true,
  "data": {
    "id": "33333333-3333-3333-3333-333333333333",
    "subject": "URGENT: PayPal Account Limited",
    "sender_email": "service-security@paypa1-support.com",
    "sender_display_name": "PayPal Account Security",
    "reply_to": "collect-creds@evil-redirect.ru",
    "return_path": "bounce@unverified-mail-relays.net",
    "recipient_to": ["target-analyst@enterprise.local"],
    "source_type": "eml_upload",
    "analysis_status": "complete",
    "created_at": "2026-11-08T14:32:00Z"
  },
  "error": null
}
```

---

## 4. Get Full Threat Analysis

Retrieve the comprehensive risk score, authentication verification (SPF/DKIM/DMARC), extracted indicators, and AI contextual assessment.

- **Endpoint**: `GET /analyses/{email_id}`
- **Auth**: Bearer token

### Response (`200 OK`)

```json
{
  "success": true,
  "data": {
    "email_id": "33333333-3333-3333-3333-333333333333",
    "risk_score": 88,
    "risk_classification": "critical",
    "spf_result": "fail",
    "dkim_result": "fail",
    "dmarc_result": "fail",
    "display_name_spoofing": true,
    "sender_domain_mismatch": true,
    "reply_to_mismatch": true,
    "url_count": 2,
    "malicious_url_count": 1,
    "attachment_count": 0,
    "ioc_count": 5,
    "ai_provider": "mock",
    "ai_phishing_assessment": "phishing",
    "ai_confidence": "high",
    "ai_summary": "High-confidence credential harvesting campaign spoofing PayPal security.",
    "ai_recommended_actions": [
      "Quarantine message across all mailboxes",
      "Block domain paypa1-support.com on secure email gateway",
      "Revoke active sessions for target recipient"
    ],
    "score_breakdown": {
      "auth_failures": 30,
      "spoofing_signals": 25,
      "malicious_urls": 20,
      "ai_risk_weight": 13
    }
  },
  "error": null
}
```

---

## 5. Extracted Components

- **Headers**: `GET /emails/{email_id}/headers`
- **URLs**: `GET /emails/{email_id}/urls`
- **Attachments**: `GET /emails/{email_id}/attachments`
- **Extracted IOCs**: `GET /emails/{email_id}/iocs`
