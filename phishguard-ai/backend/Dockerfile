# ============================================================
# Backend Dockerfile — PhishGuard AI
# ============================================================
FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# System deps: libmagic for MIME detection, curl for health checks
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# ---- Dependencies layer ----
FROM base AS dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ---- Production image ----
FROM dependencies AS production
COPY . .

# Non-root user for security
RUN addgroup --system phishguard && adduser --system --group phishguard
RUN mkdir -p /tmp/phishguard_uploads && chown phishguard:phishguard /tmp/phishguard_uploads
USER phishguard

EXPOSE 8000

# ---- Development image (with hot-reload) ----
FROM dependencies AS development
COPY . .
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
