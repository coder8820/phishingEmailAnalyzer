"""
Mock Threat Intelligence Provider for PhishGuard AI.
Used for local demonstration, offline testing, and demo mode.
Returns clearly labeled synthetic data.
"""
from __future__ import annotations
import hashlib
from typing import Optional

from app.intelligence.base_provider import BaseThreatIntelProvider, TIResult


class MockThreatIntelProvider(BaseThreatIntelProvider):
    """
    Mock threat intelligence provider for testing and demo environments.
    All results are explicitly marked with `is_demo=True`.
    """

    def __init__(self, simulate_detections: bool = False):
        self._simulate_detections = simulate_detections

    @property
    def provider_name(self) -> str:
        return "mock_intel_provider"

    @property
    def is_available(self) -> bool:
        return True

    async def lookup_url(self, url: str) -> TIResult:
        is_malicious = False
        confidence = "unknown"
        detections = 0
        total_engines = 75
        tags = ["demo", "mock"]

        # Known mock triggers
        lower_url = url.lower()
        if any(bad in lower_url for bad in ["malicious", "phish", "evil", "steal", "fake-paypal", "paypa1", "bit.ly/fake"]):
            is_malicious = True
            confidence = "confirmed"
            detections = 14
            tags.extend(["phishing", "credential_harvesting"])
        elif any(sus in lower_url for sus in ["suspicious", "verify", "update-security"]):
            is_malicious = None
            confidence = "suspicious"
            detections = 2
            tags.append("suspicious")

        return TIResult(
            provider="mock",
            query_type="url",
            query_value=url,
            is_malicious=is_malicious,
            confidence=confidence,
            detections=detections,
            total_engines=total_engines,
            tags=tags,
            raw_data={"source": "MockThreatIntel", "simulated": True},
            is_demo=True,
        )

    async def lookup_hash(self, sha256: str) -> TIResult:
        is_malicious = False
        confidence = "unknown"
        detections = 0
        total_engines = 70
        tags = ["demo", "mock"]

        # Mock malicious hashes or trigger on particular test hashes
        if sha256.startswith("bad") or sha256.startswith("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"): # dummy
            is_malicious = True
            confidence = "confirmed"
            detections = 48
            tags.extend(["trojan", "stealer"])

        return TIResult(
            provider="mock",
            query_type="hash",
            query_value=sha256,
            is_malicious=is_malicious,
            confidence=confidence,
            detections=detections,
            total_engines=total_engines,
            tags=tags,
            raw_data={"source": "MockThreatIntel", "simulated": True},
            is_demo=True,
        )

    async def lookup_domain(self, domain: str) -> TIResult:
        is_malicious = False
        confidence = "unknown"
        detections = 0
        total_engines = 85
        tags = ["demo"]

        lower_domain = domain.lower()
        if any(bad in lower_domain for bad in ["paypa1", "evil", "phish", "account-verify-login", "micros0ft"]):
            is_malicious = True
            confidence = "confirmed"
            detections = 23
            tags.extend(["typosquatting", "phishing_domain"])

        return TIResult(
            provider="mock",
            query_type="domain",
            query_value=domain,
            is_malicious=is_malicious,
            confidence=confidence,
            detections=detections,
            total_engines=total_engines,
            tags=tags,
            raw_data={"source": "MockThreatIntel", "simulated": True},
            is_demo=True,
        )

    async def lookup_ip(self, ip: str) -> TIResult:
        is_malicious = False
        confidence = "unknown"
        detections = 0
        total_engines = 60
        tags = ["demo"]

        if ip.startswith("198.51.100.") or ip.startswith("203.0.113."):
            is_malicious = True
            confidence = "suspicious"
            detections = 8
            tags.append("tor_exit_node")

        return TIResult(
            provider="mock",
            query_type="ip",
            query_value=ip,
            is_malicious=is_malicious,
            confidence=confidence,
            detections=detections,
            total_engines=total_engines,
            tags=tags,
            raw_data={"source": "MockThreatIntel", "simulated": True},
            is_demo=True,
        )
