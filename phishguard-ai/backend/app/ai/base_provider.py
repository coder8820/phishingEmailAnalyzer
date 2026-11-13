"""
Abstract Base Class for AI Phishing Detection Providers in PhishGuard AI.
Enforces strict schema validation, prompt injection defense, and structured outputs.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class AIFinding:
    category: str  # urgency | credential_harvesting | impersonation | financial | suspicious_link | generic_phishing
    description: str
    severity: str  # critical | high | medium | low
    confidence: str  # high | medium | low
    evidence_quotes: list[str] = field(default_factory=list)


@dataclass
class AIAnalysisResult:
    provider: str
    model: str
    is_available: bool
    phishing_assessment: str  # phishing | suspicious | legitimate | unknown
    confidence: str  # high | medium | low
    summary: str
    findings: list[AIFinding] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    is_demo: bool = False
    error: Optional[str] = None
    raw_response: Optional[str] = None


class BaseAIProvider(ABC):
    """
    Contract for AI phishing detection providers.
    All implementations must treat email content as untrusted input
    and follow prompt injection isolation principles.
    """

    @abstractmethod
    async def analyze_email(
        self,
        subject: str,
        sender: str,
        body_text: str,
        header_findings: list[dict[str, Any]],
        url_findings: list[dict[str, Any]],
    ) -> AIAnalysisResult:
        """Execute AI analysis and return structured assessment."""
        ...

    @property
    @abstractmethod
    def provider_name(self) -> str:
        ...

    @property
    @abstractmethod
    def is_available(self) -> bool:
        ...
