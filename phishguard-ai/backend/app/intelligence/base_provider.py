"""
Abstract base class for Threat Intelligence providers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TIResult:
    """
    Standardised result returned by every TI provider.

    is_malicious = None means the provider could not determine maliciousness.
    is_demo = True signals that the data is synthetic and not real intelligence.
    """

    provider: str
    query_type: str            # url | hash | domain | ip
    query_value: str
    is_malicious: Optional[bool]  # None = unknown
    confidence: str            # confirmed | suspicious | unknown
    detections: Optional[int]
    total_engines: Optional[int]
    tags: list[str] = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)
    is_demo: bool = False
    error: Optional[str] = None


class BaseThreatIntelProvider(ABC):
    """
    Abstract contract for all threat-intelligence backend providers.

    Every concrete provider must implement each lookup method and expose
    ``provider_name`` and ``is_available`` properties.
    """

    @abstractmethod
    async def lookup_url(self, url: str) -> TIResult:
        """Look up a URL in the threat-intel backend."""
        ...

    @abstractmethod
    async def lookup_hash(self, sha256: str) -> TIResult:
        """Look up a file hash (SHA-256) in the threat-intel backend."""
        ...

    @abstractmethod
    async def lookup_domain(self, domain: str) -> TIResult:
        """Look up a domain name in the threat-intel backend."""
        ...

    @abstractmethod
    async def lookup_ip(self, ip: str) -> TIResult:
        """Look up an IP address in the threat-intel backend."""
        ...

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Human-readable name for this provider."""
        ...

    @property
    @abstractmethod
    def is_available(self) -> bool:
        """
        Return True when the provider is reachable and configured.
        Returns False when an API key is missing or the service is down.
        """
        ...
