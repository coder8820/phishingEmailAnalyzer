# SOC Incidents & Investigation API

Endpoints for tracking, triaging, documenting, and escalating security incidents linked to detected phishing emails.

---

## 1. List Incidents

Retrieve paginated SOC incidents with optional status or severity filters.

- **Endpoint**: `GET /incidents?status=new&severity=high&page=1&page_size=20`
- **Auth**: Bearer token

### Response (`200 OK`)

```json
{
  "success": true,
  "data": {
    "total": 1,
    "page": 1,
    "page_size": 20,
    "items": [
      {
        "id": "44444444-4444-4444-4444-444444444444",
        "incident_number": 1042,
        "title": "Credential harvesting attack via fake PayPal alert",
        "severity": "critical",
        "status": "under_investigation",
        "created_by": "11111111-1111-1111-1111-111111111111",
        "created_at": "2026-11-08T15:00:00Z"
      }
    ]
  },
  "error": null
}
```

---

## 2. Create Incident

Create a new SOC incident (optionally linked to an email and IOCs).

- **Endpoint**: `POST /incidents`
- **Auth**: Bearer token

### Request Body

```json
{
  "title": "Targeted Spear Phishing Campaign - Finance Dept",
  "description": "User reported suspicious invoice request with disguised URL.",
  "severity": "high",
  "email_ids": ["33333333-3333-3333-3333-333333333333"]
}
```

### Response (`201 Created`)

```json
{
  "success": true,
  "data": {
    "id": "44444444-4444-4444-4444-444444444444",
    "incident_number": 1043,
    "title": "Targeted Spear Phishing Campaign - Finance Dept",
    "severity": "high",
    "status": "new"
  },
  "error": null
}
```

---

## 3. Update Incident Status

- **Endpoint**: `PATCH /incidents/{incident_id}`
- **Auth**: Bearer token

### Request Body

```json
{
  "status": "resolved",
  "resolution_notes": "Domain blocked on gateway; user confirmed they did not click the link."
}
```

---

## 4. Add Investigation Note

Add an audit-trailed comment or escalation note to an incident.

- **Endpoint**: `POST /incidents/{incident_id}/notes`
- **Auth**: Bearer token

### Request Body

```json
{
  "content": "Contacted network security to block IP 198.51.100.12 across perimeter firewalls.",
  "note_type": "action"
}
```
