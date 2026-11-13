"""
Threat Intelligence Manual Lookup API Endpoints for PhishGuard AI.
Enables analysts to query URLs, file hashes, domains, and IPs against
VirusTotal, URLhaus, or demo providers with graceful fallback.
"""
from typing import Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.models import User
from app.security.auth import get_current_user
from app.workers.tasks import get_threat_intel_providers
from app.utils.response import success_response

router = APIRouter()


class URLLookupRequest(BaseModel):
    url: str


class HashLookupRequest(BaseModel):
    sha256: str


class DomainLookupRequest(BaseModel):
    domain: str


class IPLookupRequest(BaseModel):
    ip: str


@router.post("/lookup/url", summary="Query threat intelligence for URL")
async def lookup_url(
    body: URLLookupRequest,
    current_user: User = Depends(get_current_user),
):
    providers = get_threat_intel_providers()
    results = []
    for p in providers:
        try:
            res = await p.lookup_url(body.url)
            results.append({
                "provider": res.provider,
                "query_value": res.query_value,
                "is_malicious": res.is_malicious,
                "confidence": res.confidence,
                "detections": res.detections,
                "total_engines": res.total_engines,
                "tags": res.tags,
                "is_demo": res.is_demo,
                "error": res.error,
            })
        except Exception as e:
            results.append({"provider": p.provider_name, "error": str(e), "is_demo": False})

    return success_response({"url": body.url, "results": results})


@router.post("/lookup/hash", summary="Query threat intelligence for SHA-256 hash")
async def lookup_hash(
    body: HashLookupRequest,
    current_user: User = Depends(get_current_user),
):
    providers = get_threat_intel_providers()
    results = []
    for p in providers:
        try:
            res = await p.lookup_hash(body.sha256)
            results.append({
                "provider": res.provider,
                "query_value": res.query_value,
                "is_malicious": res.is_malicious,
                "confidence": res.confidence,
                "detections": res.detections,
                "total_engines": res.total_engines,
                "tags": res.tags,
                "is_demo": res.is_demo,
                "error": res.error,
            })
        except Exception as e:
            results.append({"provider": p.provider_name, "error": str(e), "is_demo": False})

    return success_response({"sha256": body.sha256, "results": results})


@router.post("/lookup/domain", summary="Query threat intelligence for domain")
async def lookup_domain(
    body: DomainLookupRequest,
    current_user: User = Depends(get_current_user),
):
    providers = get_threat_intel_providers()
    results = []
    for p in providers:
        try:
            res = await p.lookup_domain(body.domain)
            results.append({
                "provider": res.provider,
                "query_value": res.query_value,
                "is_malicious": res.is_malicious,
                "confidence": res.confidence,
                "detections": res.detections,
                "total_engines": res.total_engines,
                "tags": res.tags,
                "is_demo": res.is_demo,
                "error": res.error,
            })
        except Exception as e:
            results.append({"provider": p.provider_name, "error": str(e), "is_demo": False})

    return success_response({"domain": body.domain, "results": results})


@router.post("/lookup/ip", summary="Query threat intelligence for IP address")
async def lookup_ip(
    body: IPLookupRequest,
    current_user: User = Depends(get_current_user),
):
    providers = get_threat_intel_providers()
    results = []
    for p in providers:
        try:
            res = await p.lookup_ip(body.ip)
            results.append({
                "provider": res.provider,
                "query_value": res.query_value,
                "is_malicious": res.is_malicious,
                "confidence": res.confidence,
                "detections": res.detections,
                "total_engines": res.total_engines,
                "tags": res.tags,
                "is_demo": res.is_demo,
                "error": res.error,
            })
        except Exception as e:
            results.append({"provider": p.provider_name, "error": str(e), "is_demo": False})

    return success_response({"ip": body.ip, "results": results})
