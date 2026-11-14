# PhishGuard AI 🛡️
> **Enterprise-Grade AI-Powered Phishing Email Analyzer**  
> A production-oriented cybersecurity platform for SOC analysts to detect, investigate, and document phishing threats.

[![CI/CD](https://github.com/your-org/phishguard-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/phishguard-ai/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![Next.js 14](https://img.shields.io/badge/next.js-14-black.svg)](https://nextjs.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Overview

PhishGuard AI is an enterprise-grade phishing email detection and investigation platform that combines:

- **Rule-based detection** — SPF/DKIM/DMARC authentication analysis, URL pattern detection, attachment security
- **AI-powered analysis** — Contextual threat assessment using LLMs with prompt injection defenses
- **Threat intelligence** — Optional integration with VirusTotal, URLhaus, AbuseIPDB
- **Explainable risk scoring** — Weighted, transparent 0–100 risk score with signal breakdown
- **IOC extraction** — Automatic extraction of IPs, domains, URLs, hashes, emails
- **SOC workflow** — Full incident management, investigation notes, audit logging

> **Important:** This system assists security analysts — it does not replace human judgment. All findings should be reviewed by qualified analysts before taking action.

---

## Architecture

```
phishguard-ai/
├── frontend/          # Next.js 14 + TypeScript + Tailwind CSS
├── backend/           # Python 3.11 + FastAPI + SQLAlchemy 2.0
├── tests/             # Pytest + Playwright test suites
├── infrastructure/    # Nginx + Docker configuration
├── docs/              # Architecture and API documentation
└── docker-compose.yml # Full stack orchestration
```

**Technology Stack:**

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 14, React 18, TypeScript, Tailwind CSS |
| Backend | Python 3.11, FastAPI, Pydantic v2 |
| ORM | SQLAlchemy 2.0 (async), Alembic |
| Database | PostgreSQL 16 |
| Cache/Queue | Redis 7, Celery 5 |
| Proxy | Nginx |
| Container | Docker, Docker Compose |

---

## Quick Start

### Prerequisites

- Docker 24+ and Docker Compose
- 4GB RAM minimum (for local dev)

### 1. Clone & Configure

```bash
git clone https://github.com/your-org/phishguard-ai.git
cd phishguard-ai

# Copy and edit environment configuration
cp .env.example .env
```

**Minimum required edits in `.env`:**
```bash
APP_SECRET_KEY=<generate: openssl rand -hex 32>
POSTGRES_PASSWORD=<strong password>
REDIS_PASSWORD=<strong password>
ENCRYPTION_KEY=<generate: openssl rand -base64 32>
```

### 2. Start All Services

```bash
docker-compose up --build
```

This will:
1. Start PostgreSQL and Redis
2. Run database migrations automatically
3. Start the FastAPI backend (port 8000)
4. Start the Next.js frontend (port 3001)
5. Start Celery workers for async analysis
6. Start Nginx reverse proxy (port 80)

### 3. Access the Application

| Service | URL |
|---------|-----|
| **Application (Nginx Reverse Proxy)** | http://localhost |
| **Application (Direct Frontend)** | http://localhost:3001 |
| **API Docs (Swagger)** | http://localhost:8000/api/v1/docs (or http://localhost/api/v1/docs) |
| **API Health** | http://localhost:8000/api/v1/health |

### 4. Create Initial Admin User

```bash
docker-compose exec backend python scripts/create_admin.py \
  --email admin@example.com \
  --password "SecurePassword123!" \
  --org "My Organization"
```

---

## Demo Mode (No API Keys Required)

PhishGuard AI runs fully in demo mode without any external API keys.

In demo mode:
- **AI Analysis**: Returns clearly labeled simulated AI findings
- **Threat Intelligence**: Returns clearly labeled demo data (not real threat intel)
- **DNS Lookups**: Uses public resolvers (no key needed)
- **URLhaus**: Works without an API key

Demo mode data is always labeled with `"is_demo": true` in API responses and shown with a yellow banner in the UI.

**To enable real threat intelligence:**
1. Navigate to **Integrations** in the sidebar
2. Configure your API keys for VirusTotal, AbuseIPDB
3. Set `TI_DEMO_MODE=false` in your `.env`

---

## Configuration Reference

See [`.env.example`](.env.example) for all configuration options.

### AI Provider Configuration

```bash
# Options: openai | google | mock
AI_PROVIDER=mock

# For OpenAI:
AI_PROVIDER=openai
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o-mini

# For Google Gemini:
AI_PROVIDER=google
GOOGLE_API_KEY=...
GOOGLE_MODEL=gemini-1.5-flash
```

### Threat Intelligence

```bash
# Set to false when using real API keys
TI_DEMO_MODE=true

VIRUSTOTAL_API_KEY=...
VIRUSTOTAL_ENABLED=true

ABUSEIPDB_API_KEY=...
ABUSEIPDB_ENABLED=true
```

---

## User Roles

| Role | Permissions |
|------|------------|
| `super_admin` | Full access including user management and system settings |
| `security_admin` | Manage rules, integrations, view audit logs, all analyst permissions |
| `analyst` | Upload emails, perform analysis, manage incidents, generate reports |
| `viewer` | Read-only access to analyses and dashboard |

Authorization is enforced on the **backend** — frontend role checks are for UX only.

---

## Security Architecture

### Email Processing Security

- **Never execute** uploaded attachments
- **Never fetch** URLs found in emails from the application server
- Filenames sanitized (UUID-based storage paths)
- File size enforced: 25MB maximum
- MIME type validated (magic bytes, not just extension)
- Malformed EML files handled safely

### AI Security

- Email content treated as **untrusted data**, never as instructions
- Structural separation between system prompt and email content
- Output schema validation — malformed AI responses rejected
- Fallback to rule-based analysis if AI is unavailable or returns invalid output
- No tool access from AI engine — cannot call functions or access secrets

### Authentication Security

- Passwords hashed with **Argon2id** (OWASP recommended)
- Short-lived JWT access tokens (15 minutes)
- Refresh token rotation on use
- Account lockout after 5 failed attempts (30 minutes)
- All sensitive events logged to immutable audit log

### Multi-Tenancy

- All database queries filtered by `organization_id` from JWT
- Cross-tenant access prevention tested in security test suite
- API keys encrypted at rest using Fernet symmetric encryption

---

## Running Tests

### Backend Tests

```bash
cd backend

# Unit tests
pytest tests/backend/unit/ -v

# Integration tests (requires running DB)
pytest tests/backend/integration/ -v

# Security tests
pytest tests/security/ -v

# All tests with coverage
pytest tests/backend/ --cov=app --cov-report=html -v

# SAST scan
bandit -r app/ -ll
```

### Frontend Tests

```bash
cd frontend

# Type check
npx tsc --noEmit

# Lint
npm run lint

# E2E tests (requires running application)
npx playwright test
```

---

## API Documentation

Interactive API documentation is available at `/api/v1/docs` in development mode.

API follows RESTful conventions:
- Base URL: `/api/v1/`
- Authentication: `Authorization: Bearer <access_token>`
- Response format: `{"success": true, "data": {...}, "error": null}`
- Pagination: `?page=1&page_size=20`
- Filtering: `?status=complete&risk=high`

See [`docs/api/`](docs/api/) for complete endpoint documentation.

---

## Development

### Local Development (without Docker)

**Backend:**
```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Set environment variables
export APP_ENV=development
export DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/phishguard
# ... other env vars

alembic upgrade head
uvicorn app.main:app --reload
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

**Celery Worker:**
```bash
cd backend
celery -A app.workers.celery_app worker --loglevel=info
```

---

## Known Limitations

1. **AI Analysis**: Demo mode does not perform real AI analysis. Connect an OpenAI or Google API key for production analysis.

2. **Threat Intelligence**: Without API keys, threat intelligence is simulated. Configure real providers for production use.

3. **MSG Format**: .msg (Outlook) file format is not supported in the base implementation. Only .eml and raw email text are accepted.

4. **SSRF Protection**: URL analysis does not visit URLs. Threat intelligence lookups use known-safe API endpoints only.

5. **Attachment Sandbox**: The current implementation performs metadata-only attachment analysis. For full sandbox analysis (dynamic execution), integrate an external service such as Cuckoo Sandbox or Any.run (not included).

6. **Email Sending**: Password reset emails require SMTP configuration. Without SMTP, password resets must be performed by administrators.

7. **Scale**: The current architecture is designed for small-to-medium SOC teams. For high-volume deployments (>10,000 emails/day), additional Celery workers, database read replicas, and Redis clustering should be configured.

---

## Future Improvements

- [ ] SAML/SSO integration
- [ ] Webhook notifications (Slack, PagerDuty, Teams)
- [ ] MITRE ATT&CK technique tagging
- [ ] YARA rule-based attachment analysis
- [ ] Automated quarantine actions (Exchange/Gmail integration)
- [ ] Threat actor attribution
- [ ] Email campaign clustering
- [ ] Mobile-responsive PWA
- [ ] Elasticsearch for log search

---

## License

MIT License — See [LICENSE](LICENSE) for details.

---

## Acknowledgments

Built as a Blue Team / SOC Analyst portfolio project demonstrating:
- Enterprise cybersecurity platform engineering
- AI integration with security controls
- Multi-tenant SaaS architecture
- Full-stack TypeScript + Python development
- DevSecOps practices

---

> **Disclaimer:** This tool is for authorized security analysis only. Never use it to analyze emails you do not have permission to investigate.
