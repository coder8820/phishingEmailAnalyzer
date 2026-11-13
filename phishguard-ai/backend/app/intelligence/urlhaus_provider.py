"""
URLhaus Threat Intelligence Provider for PhishGuard AI.
Uses the abuse.ch URLhaus public API.
"""
from __future__ import annotations
import logging
from typing import Optional
import httpx

from app.intelligence.base_provider import BaseThreatIntelProvider, TIResult
from app.core.config import settings

logger = logging.getLogger(__name__)


class URLhausProvider(BaseThreatIntelProvider):
    """
    URLhaus API provider for detecting malicious and malware distribution URLs.
    Does not require an API key for queries.
    """

    def __init__(self, base_url: Optional[str] = None):
        self._base_url = (base_url or settings.URLHAUS_BASE_URL).rstrip("/")
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def provider_name(self) -> str:
        return "urlhaus"

    @property
    def is_available(self) -> bool:
        return bool(settings.URLHAUS_ENABLED)

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=10.0)
        return self._client

    async def lookup_url(self, url: str) -> TIResult:
        if not self.is_available:
            return TIResult(
                provider="urlhaus",
                query_type="url",
                query_value=url,
                is_malicious=None,
                confidence="unknown",
                detections=None,
                total_engines=None,
                error="URLhaus provider disabled",
            )

        try:
            client = await self._get_client()
            endpoint = f"{self._base_url}/url/"
            response = await client.post(endpoint, data={"url": url})

            if response.status_code == 200:
                data = response.json()
                query_status = data.get("query_status")

                if query_status == "ok":
                    url_status = data.get("url_status")
                    threat = data.get("threat")
                    tags = data.get("tags") or []
                    if threat and threat not in tags:
                        tags.append(threat)

                    return TIResult(
                        provider="urlhaus",
                        query_type="url",
                        query_value=url,
                        is_malicious=True,
                        confidence="confirmed",
                        detections=1,
                        total_engines=1,
                        tags=tags,
                        raw_data=data,
                        is_demo=False,
                    )
                elif query_status == "no_results":
                    return TIResult(
                        provider="urlhaus",
                        query_type="url",
                        query_value=url,
                        is_malicious=False,
                        confidence="confirmed",
                        detections=0,
                        total_engines=1,
                        tags=[],
                        raw_data=data,
                        is_demo=False,
                    )
                else:
                    return TIResult(
                        provider="urlhaus",
                        query_type="url",
                        query_value=url,
                        is_malicious=None,
                        confidence="unknown",
                        detections=None,
                        total_engines=None,
                        error=f"URLhaus query status: {query_status}",
                    )
            else:
                return TIResult(
                    provider="urlhaus",
                    query_type="url",
                    query_value=url,
                    is_malicious=None,
                    confidence="unknown",
                    detections=None,
                    total_engines=None,
                    error=f"HTTP {response.status_code}",
                )
        except Exception as e:
            logger.warning("urlhaus_lookup_failed", url=url, error=str(e))
            return TIResult(
                provider="urlhaus",
                query_type="url",
                query_value=url,
                is_malicious=None,
                confidence="unknown",
                detections=None,
                total_engines=None,
                error=str(e),
            )

    async def lookup_hash(self, sha256: str) -> TIResult:
        # Not supported directly on URLhaus URL endpoint
        return TIResult(
            provider="urlhaus",
            query_type="hash",
            query_value=sha256,
            is_malicious=None,
            confidence="unknown",
            detections=None,
            total_engines=None,
            error="Hash lookup not implemented for URLhaus provider",
        )

    async def lookup_domain(self, domain: str) -> TIResult:
        return TIResult(
            provider="urlhaus",
            query_type="domain",
            query_value=domain,
            is_malicious=None,
            confidence="unknown",
            detections=None,
            total_engines=None,
            error="Domain lookup not implemented for URLhaus provider",
        )

    async def lookup_ip(self, ip: str) -> TIResult:
        return TIResult(
            provider="urlhaus",
            query_type="ip",
            query_value=ip,
            is_malicious=None,
            confidence="unknown",
            detections=None,
            total_engines=None,
            error="IP lookup not implemented for URLhaus provider",
        )
