"""
PhishGuard AI — API v1 Router
"""
from fastapi import APIRouter

from app.api.v1.endpoints import (
    auth,
    users,
    emails,
    analyses,
    iocs,
    intelligence,
    incidents,
    dashboard,
    reports,
    rules,
    integrations,
    audit,
    health,
    webhooks,
    feature_approvals,
    gmail,
    chat,
)

api_router = APIRouter()

api_router.include_router(health.router, prefix="/health", tags=["Health"])
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(users.router, prefix="/users", tags=["Users"])
api_router.include_router(emails.router, prefix="/emails", tags=["Email Analysis"])
api_router.include_router(analyses.router, prefix="/analyses", tags=["Analysis Results"])
api_router.include_router(iocs.router, prefix="/iocs", tags=["IOC Management"])
api_router.include_router(intelligence.router, prefix="/intelligence", tags=["Threat Intelligence"])
api_router.include_router(incidents.router, prefix="/incidents", tags=["Incident Management"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["SOC Dashboard"])
api_router.include_router(reports.router, prefix="/reports", tags=["Reports"])
api_router.include_router(rules.router, prefix="/rules", tags=["Detection Rules"])
api_router.include_router(integrations.router, prefix="/integrations", tags=["Integrations"])
api_router.include_router(audit.router, prefix="/audit-logs", tags=["Audit Logs"])
api_router.include_router(webhooks.router, prefix="/webhooks", tags=["Mail Flow Webhooks"])
api_router.include_router(feature_approvals.router, prefix="/feature-approvals", tags=["Feature Approvals & Super Admin"])
api_router.include_router(gmail.router, prefix="/gmail", tags=["Gmail Integration"])
api_router.include_router(chat.router, prefix="/chat", tags=["AI Security Assistant"])

