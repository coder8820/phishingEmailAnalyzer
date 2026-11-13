"""
Mock AI Phishing Detection Provider for PhishGuard AI.
Returns simulated, explainable AI assessments without requiring external API keys.
"""
from __future__ import annotations
import re
from typing import Any
from app.ai.base_provider import BaseAIProvider, AIAnalysisResult, AIFinding


class MockAIProvider(BaseAIProvider):
    """
    Simulated AI provider that checks for common heuristic markers
    and generates structured analysis mimicking an LLM output.
    """

    @property
    def provider_name(self) -> str:
        return "mock_ai"

    @property
    def is_available(self) -> bool:
        return True

    async def analyze_email(
        self,
        subject: str,
        sender: str,
        body_text: str,
        header_findings: list[dict[str, Any]],
        url_findings: list[dict[str, Any]],
    ) -> AIAnalysisResult:
        full_text = f"{subject}\n{body_text}".lower()

        findings: list[AIFinding] = []
        recommended_actions: list[str] = []

        # 1. Urgency / Psychological pressure
        urgency_terms = ["urgent", "immediately", "account suspended", "24 hours", "action required", "unauthorized access", "limited access"]
        matched_urgency = [term for term in urgency_terms if term in full_text]
        if matched_urgency:
            findings.append(
                AIFinding(
                    category="urgency",
                    description=f"Email exerts artificial psychological urgency: detected phrases '{', '.join(matched_urgency)}'.",
                    severity="high",
                    confidence="high",
                    evidence_quotes=[f"Matches urgency triggers: {matched_urgency[:3]}"],
                )
            )

        # 2. Credential harvesting / Login links
        login_terms = ["verify your account", "update your password", "confirm your identity", "log in to verify", "click here to unlock"]
        matched_login = [term for term in login_terms if term in full_text]
        if matched_login:
            findings.append(
                AIFinding(
                    category="credential_harvesting",
                    description="Content solicits account re-authentication or credential verification through email links.",
                    severity="critical",
                    confidence="high",
                    evidence_quotes=[f"Matches credential verification prompts: {matched_login[:2]}"],
                )
            )

        # 3. Financial / Payment lures
        finance_terms = ["invoice", "wire transfer", "payment overdue", "bitcoin", "cryptocurrency", "gift card", "payroll"]
        matched_finance = [term for term in finance_terms if term in full_text]
        if matched_finance:
            findings.append(
                AIFinding(
                    category="financial",
                    description="Email discusses high-risk financial transactions, invoices, or unusual payment methods.",
                    severity="medium",
                    confidence="medium",
                    evidence_quotes=[f"Financial keywords: {matched_finance[:2]}"],
                )
            )

        # 4. Impersonation of well-known brands
        brands = ["paypal", "microsoft", "google", "apple", "amazon", "dhl", "fedex", "bank of america", "chase"]
        matched_brands = [b for b in brands if b in full_text]
        if matched_brands and not any(f"@{b}.com" in sender.lower() for b in matched_brands):
            findings.append(
                AIFinding(
                    category="impersonation",
                    description=f"Probable brand impersonation of '{', '.join(matched_brands).title()}' from an unverified sender address: {sender}.",
                    severity="high",
                    confidence="high",
                    evidence_quotes=[f"Sender: {sender}", f"Referenced brand: {matched_brands[0]}"],
                )
            )

        # Determine overall assessment
        if any(f.severity in ("critical", "high") for f in findings):
            assessment = "phishing"
            confidence = "high"
            summary = (
                "The email exhibits prominent indicators of a social engineering or phishing attack. "
                "Urgent coercive language, impersonation of corporate entities, or credential harvesting triggers were observed."
            )
            recommended_actions = [
                "Do not click any embedded links or provide credentials.",
                "Block sender domain and blacklist all extracted URLs at email perimeter.",
                "Notify SOC Incident Response team and check authentication logs for compromised accounts.",
            ]
        elif findings:
            assessment = "suspicious"
            confidence = "medium"
            summary = (
                "The email displays anomalous characteristics or financial terminology that warrant closer manual inspection."
            )
            recommended_actions = [
                "Verify sender authenticity via an out-of-band communication channel.",
                "Inspect URL destination domains in an isolated threat intelligence environment.",
            ]
        else:
            assessment = "legitimate"
            confidence = "high"
            summary = (
                "No overt linguistic manipulation, brand impersonation, or credential harvesting indicators were identified by the AI engine."
            )
            recommended_actions = [
                "Standard operational delivery. Continue standard logging and endpoint monitoring.",
            ]

        return AIAnalysisResult(
            provider="mock_ai",
            model="simulated-gpt4-guard",
            is_available=True,
            phishing_assessment=assessment,
            confidence=confidence,
            summary=summary,
            findings=findings,
            recommended_actions=recommended_actions,
            is_demo=True,
            raw_response="{\"simulated\": true, \"mode\": \"heuristic_mock\"}",
        )
