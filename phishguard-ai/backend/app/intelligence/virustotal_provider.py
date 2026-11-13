"""
VirusTotal Threat Intelligence Provider for PhishGuard AI.
"""
from __future__ import annotations
import base64
import logging
from typing import Optional
import httpx

from app.intelligence.base_provider import BaseThreatIntelProvider, TIResult
from app.core.config import settings

logger = logging.getLogger(__name__)


class VirusTotalProvider(BaseThreatIntelProvider):
    """
    VirusTotal API v3 integration for URLs, file hashes, domains, and IP lookups.
    """

    def __init__(self, api_key: Optional[str] = None):
        self._api_key = api_key or settings.VIRUSTOTAL_API_KEY
        self._base_url = "https://www.virustotal.com/api/v3"

    @property
    def provider_name(self) -> str:
        return "virustotal"

    @property
    def is_available(self) -> bool:
        return bool(settings.VIRUSTOTAL_ENABLED and self._api_key)

    def _headers(self) -> dict[str, str]:
        return {
            "x-apikey": self._api_key or "",
            "Accept": "application/json",
        }

    async def lookup_url(self, url: str) -> TIResult:
        if not self.is_available:
            return TIResult(
                provider="virustotal",
                query_type="url",
                query_value=url,
                is_malicious=None,
                confidence="unknown",
                detections=None,
                total_engines=None,
                error="VirusTotal provider disabled or missing API key",
            )

        try:
            # URL identifier in VT v3 is base64 without padding
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            async with httpx.AsyncClient(timeout=15.0) as client:
                res = await client.get(
                    f"{self._base_url}/urls/{url_id}",
                    headers=self._headers(),
                )
                if res.status_code == 200:
                    data = res.json()
                    attributes = data.get("data", {}).get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    undetected = stats.get("undetected", 0)
                    harmless = stats.get("harmless", 0)
                    total = malicious + suspicious + undetected + harmless

                    is_mal = malicious > 2 or (malicious + suspicious) > 4
                    conf = "confirmed" if malicious > 3 else ("suspicious" if malicious > 0 else "confirmed")

                    tags = attributes.get("tags", [])
                    return TIResult(
                        provider="virustotal",
                        query_type="url",
                        query_value=url,
                        is_malicious=is_mal,
                        confidence=conf,
                        detections=malicious + suspicious,
                        total_engines=total,
                        tags=tags,
                        raw_data=stats,
                        is_demo=False,
                    )
                else:
                    return TIResult(
                        provider="virustotal",
                        query_type="url",
                        query_value=url,
                        is_malicious=None,
                        confidence="unknown",
                        detections=None,
                        total_engines=None,
                        error=f"VT status code: {res.status_code}",
                    )
        except Exception as e:
            return TIResult(
                provider="virustotal",
                query_type="url",
                query_value=url,
                is_malicious=None,
                confidence="unknown",
                detections=None,
                total_engines=None,
                error=str(e),
            )

    async def lookup_hash(self, sha256: str) -> TIResult:
        if not self.is_available:
            return TIResult(
                provider="virustotal",
                query_type="hash",
                query_value=sha256,
                is_malicious=None,
                confidence="unknown",
                detections=None,
                total_engines=None,
                error="VirusTotal provider disabled or missing API key",
            )

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                res = await client.get(
                    f"{self._base_url}/files/{sha256}",
                    headers=self._headers(),
                )
                if res.status_code == 200:
                    data = res.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total = sum(stats.values())
                    is_mal = malicious > 2
                    conf = "confirmed" if malicious > 3 else ("suspicious" if malicious > 0 else "confirmed")
                    return TIResult(
                        provider="virustotal",
                        query_type="hash",
                        query_value=sha256,
                        is_malicious=is_mal,
                        confidence=conf,
                        detections=malicious,
                        total_engines=total,
                        tags=[],
                        raw_data=stats,
                        is_demo=False,
                    )
                else:
                    return TIResult(
                        provider="virustotal",
                        query_type="hash",
                        query_value=sha256,
                        is_malicious=None,
                        confidence="unknown",
                        detections=None,
                        total_engines=None,
                        error=f"VT status: {res.status_code}",
                    )
        except Exception as e:
            return TIResult(
                provider="virustotal",
                query_type="hash",
                query_value=sha256,
                is_malicious=None,
                confidence="unknown",
                detections=None,
                total_engines=None,
                error=str(e),
            )

    async def lookup_domain(self, domain: str) -> TIResult:
        if not self.is_available:
            return TIResult(
                provider="virustotal",
                query_type="domain",
                query_value=domain,
                is_malicious=None,
                confidence="unknown",
                detections=None,
                total_engines=None,
                error="VirusTotal provider disabled",
            )
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                res = await client.get(f"{self._base_url}/domains/{domain}", headers=self._headers())
                if res.status_code == 200:
                    stats = res.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    return TIResult(
                        provider="virustotal",
                        query_type="domain",
                        query_value=domain,
                        is_malicious=malicious > 2,
                        confidence="confirmed" if malicious > 2 else "unknown",
                        detections=malicious,
                        total_engines=sum(stats.values()),
                        raw_data=stats,
                        is_demo=False,
                    )
                return TIResult(
                    provider="virustotal",
                    query_type="domain",
                    query_value=domain,
                    is_malicious=None,
                    confidence="unknown",
                    detections=None,
                    total_engines=None,
                    error=f"VT status: {res.status_code}",
                )
        except Exception as e:
            return TIResult(provider="virustotal", query_type="domain", query_value=domain, is_malicious=None, confidence="unknown", detections=None, total_engines=None, error=str(e))

    async def lookup_ip(self, ip: str) -> TIResult:
        if not self.is_available:
            return TIResult(
                provider="virustotal",
                query_type="ip",
                query_value=ip,
                is_malicious=None,
                confidence="unknown",
                detections=None,
                total_engines=None,
                error="VirusTotal provider disabled",
            )
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                res = await client.get(f"{self._base_url}/ip_addresses/{ip}", headers=self._headers())
                if res.status_code == 200:
                    stats = res.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    return TIResult(
                        provider="virustotal",
                        query_type="ip",
                        query_value=ip,
                        is_malicious=malicious > 2,
                        confidence="confirmed" if malicious > 2 else "unknown",
                        detections=malicious,
                        total_engines=sum(stats.values()),
                        raw_data=stats,
                        is_demo=False,
                    )
                return TIResult(
                    provider="virustotal",
                    query_type="ip",
                    query_value=ip,
                    is_malicious=None,
                    confidence="unknown",
                    detections=None,
                    total_engines=None,
                    error=f"VT status: {res.status_code}",
                )
        except Exception as e:
            return TIResult(provider="virustotal", query_type="ip", query_value=ip, is_malicious=None, confidence="unknown", detections=None, total_engines=None, error=str(e))
