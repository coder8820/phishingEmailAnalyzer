# PhishGuard AI — REST API Documentation

The PhishGuard AI API is structured around RESTful principles. It accepts JSON-encoded request bodies, returns JSON-encoded responses, and uses standard HTTP response codes and JWT bearer authentication.

## Base URL

- **Direct Backend**: `http://localhost:8000/api/v1`
- **Reverse Proxy**: `http://localhost/api/v1`

Interactive OpenAPI / Swagger documentation is available at `/api/v1/docs` in non-production environments.

---

## Authentication

All protected endpoints require a valid JWT Access Token passed in the `Authorization` header:

```http
Authorization: Bearer <access_token>
```

Access tokens expire after 15 minutes. Use the refresh token endpoint (`POST /auth/refresh`) to obtain a new access token without re-authenticating.

---

## Standard Response Format

All responses follow a consistent JSON envelope structure:

### Success Response (`200 OK`, `201 Created`, `202 Accepted`)

```json
{
  "success": true,
  "data": { ... },
  "error": null,
  "timestamp": "2026-11-09T14:00:00Z"
}
```

### Error Response (`4xx`, `5xx`)

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid email or password",
    "status": 401,
    "details": {}
  },
  "timestamp": "2026-11-09T14:00:00Z"
}
```

---

## Common HTTP Status Codes

| Code | Meaning | Description |
|---|---|---|
| `200` | OK | Request succeeded. |
| `201` | Created | Resource successfully created. |
| `202` | Accepted | Request accepted and queued for asynchronous processing. |
| `400` | Bad Request | Malformed request or validation error. |
| `401` | Unauthorized | Missing, invalid, or expired authentication token. |
| `403` | Forbidden | Insufficient role permissions or cross-tenant access violation. |
| `404` | Not Found | Target resource was not found. |
| `413` | Payload Too Large | File or text exceeds maximum size (25MB). |
| `423` | Locked | Account temporarily locked due to excessive failed logins. |
| `429` | Too Many Requests | Rate limit exceeded. |
| `500` | Internal Error | Server error. |

---

## API Module Guides

1. [Authentication & Users](auth.md) — Sign in, refresh tokens, profile, user administration.
2. [Email Ingestion & Analysis](emails.md) — Upload `.eml`, submit raw text, view score breakdown.
3. [SOC Incidents & Notes](incidents.md) — Incident lifecycle, assignment, investigation notes.
4. [IOCs & Threat Intelligence](intelligence.md) — IOC extraction, reputation lookups, VirusTotal/URLhaus.
5. [Detection Rules & Auditing](rules.md) — Custom heuristic/regex rules and immutable SOC audit logging.
