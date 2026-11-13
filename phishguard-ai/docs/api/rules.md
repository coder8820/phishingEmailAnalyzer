# Detection Rules & Audit Logs API

Endpoints for managing custom organizational detection rules and inspecting immutable SOC audit logs.

---

## 1. List Detection Rules

- **Endpoint**: `GET /rules?page=1&page_size=50`
- **Auth**: Bearer token (roles: `analyst`, `security_admin`, `super_admin`)

### Response (`200 OK`)

```json
{
  "success": true,
  "data": {
    "total": 1,
    "items": [
      {
        "id": "66666666-6666-6666-6666-666666666666",
        "name": "Urgent Financial Action Keyword Trigger",
        "category": "social_engineering",
        "rule_type": "keyword",
        "rule_definition": {
          "keywords": ["wire transfer", "gift card", "immediate payment", "account suspended"]
        },
        "severity": "medium",
        "score_impact": 15,
        "is_enabled": true
      }
    ]
  },
  "error": null
}
```

---

## 2. Create Custom Rule

- **Endpoint**: `POST /rules`
- **Auth**: Bearer token (roles: `security_admin`, `super_admin`)

### Request Body

```json
{
  "name": "Internal Domain Lookalike Detection",
  "category": "spoofing",
  "rule_type": "regex",
  "rule_definition": {
    "pattern": "@.*company-corp\\.com"
  },
  "severity": "high",
  "score_impact": 25,
  "is_enabled": true
}
```

---

## 3. Query Immutable Audit Logs

Retrieve tamper-evident audit records for SOC actions, logins, rule modifications, and email submissions.

- **Endpoint**: `GET /audit?action=auth.login&page=1&page_size=50`
- **Auth**: Bearer token (roles: `security_admin`, `super_admin`)

### Response (`200 OK`)

```json
{
  "success": true,
  "data": {
    "total": 1,
    "items": [
      {
        "id": "77777777-7777-7777-7777-777777777777",
        "action": "auth.login_success",
        "user_id": "11111111-1111-1111-1111-111111111111",
        "ip_address": "192.168.1.100",
        "request_id": "req-98214-abc",
        "severity": "info",
        "created_at": "2026-11-09T08:30:00Z"
      }
    ]
  },
  "error": null
}
```
