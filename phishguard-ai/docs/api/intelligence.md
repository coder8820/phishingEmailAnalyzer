# IOCs & Threat Intelligence API

Endpoints for querying extracted indicators of compromise (IOCs) and conducting external threat intelligence lookups.

---

## 1. List IOCs

Retrieve all extracted indicators across analyzed emails in the organization.

- **Endpoint**: `GET /iocs?type=domain&risk_level=high&page=1&page_size=50`
- **Auth**: Bearer token

### Filter Query Parameters

- `type`: `ip` | `domain` | `url` | `email` | `hash_sha256`
- `risk_level`: `low` | `suspicious` | `malicious`
- `search`: Substring search on indicator value

### Response (`200 OK`)

```json
{
  "success": true,
  "data": {
    "total": 1,
    "page": 1,
    "page_size": 50,
    "items": [
      {
        "id": "55555555-5555-5555-5555-555555555555",
        "ioc_type": "domain",
        "ioc_value": "paypa1-support.com",
        "risk_level": "malicious",
        "confidence": "high",
        "detection_reason": "Homograph attack and typo-squatting targeting PayPal",
        "reputation_data": {
          "virustotal_positives": 14,
          "virustotal_total": 85,
          "is_demo": true
        },
        "first_seen_at": "2026-11-08T14:32:00Z"
      }
    ]
  },
  "error": null
}
```

---

## 2. Live Threat Intelligence Lookup

Perform a real-time reputation query against integrated intelligence feeds (VirusTotal, URLhaus, AbuseIPDB, or built-in demo feed).

- **Endpoint**: `POST /intelligence/lookup`
- **Auth**: Bearer token

### Request Body

```json
{
  "indicator_type": "domain",
  "indicator_value": "evil-phish-domain.com"
}
```

### Response (`200 OK`)

```json
{
  "success": true,
  "data": {
    "provider": "virustotal",
    "query_value": "evil-phish-domain.com",
    "is_malicious": true,
    "detections": 18,
    "total_engines": 88,
    "confidence": "high",
    "cached": false,
    "is_demo": true
  },
  "error": null
}
```
