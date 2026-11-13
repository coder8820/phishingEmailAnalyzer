"""
Risk scoring engine for PhishGuard AI.

Aggregates signals from all analyzers into a single 0-100 risk score.
Each signal has a configurable weight; the final score is capped at 100.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Signal weights (configurable via settings or override at init)
# ---------------------------------------------------------------------------

SIGNAL_WEIGHTS: dict[str, int] = {
    "spf_fail": 15,
    "dkim_fail": 10,
    "dmarc_fail": 12,
    "display_name_spoofing": 20,
    "sender_domain_mismatch": 15,
    "reply_to_mismatch": 8,
    "suspicious_routing": 5,
    "malicious_url_confirmed": 25,
    "suspicious_url_heuristic": 10,
    "url_shortener": 5,
    "ip_based_url": 8,
    "dangerous_attachment_confirmed": 25,
    "dangerous_attachment_heuristic": 15,
    "macro_attachment": 12,
    "ai_phishing_high_confidence": 15,
    "ai_phishing_medium_confidence": 8,
    "brand_impersonation": 20,
    "domain_newly_registered": 10,
}

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class ScoreSignal:
    """A single scored signal contributing to the total risk score."""

    name: str
    weight: int
    raw_score: int      # 0 or weight (applied fully) or partial
    applied_score: int  # actual contribution after confidence discount
    confidence: str     # confirmed | suspicious | heuristic
    reason: str


@dataclass
class RiskScoreResult:
    """Final output of the risk scoring engine."""

    score: int                           # 0–100
    classification: str                  # low | suspicious | medium | high | critical
    breakdown: list[ScoreSignal] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    explanation: str = ""


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------


class RiskScorer:
    """
    Computes a composite risk score from all analyzer outputs.

    Signals are deduped (same underlying IOC counts once).
    Score is capped at 100.
    Missing evidence is recorded without adding score.
    """

    def __init__(self, weights: Optional[dict[str, int]] = None) -> None:
        self._weights = weights or dict(SIGNAL_WEIGHTS)

    def compute(
        self,
        header_result: Any,
        url_result: Any,
        attachment_result: Any,
        ai_result: Any,
        domain_intel: Optional[dict] = None,
    ) -> RiskScoreResult:
        """
        Compute the final risk score.

        Args:
            header_result: HeaderAnalysisResult (or dict).
            url_result: URLAnalysisResult (or dict).
            attachment_result: AttachmentAnalysisResult (or dict).
            ai_result: AIAnalysisResult (or dict).
            domain_intel: Optional dict with TI lookup results.

        Returns:
            RiskScoreResult with score, classification, breakdown, and explanation.
        """
        result = RiskScoreResult(score=0, classification="low")
        signals: list[ScoreSignal] = []
        missing: list[str] = []
        triggered_iocs: set[str] = set()  # deduplication key

        # ------- Header signals -------
        self._header_signals(header_result, signals, missing, triggered_iocs)

        # ------- URL signals -------
        self._url_signals(url_result, signals, triggered_iocs)

        # ------- Attachment signals -------
        self._attachment_signals(attachment_result, signals, triggered_iocs)

        # ------- AI signals -------
        self._ai_signals(ai_result, signals)

        # ------- Domain intel signals -------
        if domain_intel:
            self._domain_intel_signals(domain_intel, signals, triggered_iocs)

        # ------- Compute total -------
        total = min(100, sum(s.applied_score for s in signals))
        result.score = total
        result.breakdown = signals
        result.missing_evidence = missing
        result.classification = self._classify(total)
        result.explanation = self._explain(result)
        return result

    # ------------------------------------------------------------------
    # Header signals
    # ------------------------------------------------------------------

    def _header_signals(
        self,
        header_result: Any,
        signals: list[ScoreSignal],
        missing: list[str],
        triggered_iocs: set[str],
    ) -> None:
        spf = _ga(header_result, "spf_result", "unknown")
        dkim = _ga(header_result, "dkim_result", "unknown")
        dmarc = _ga(header_result, "dmarc_result", "unknown")

        if spf == "none":
            missing.append("SPF record absent — cannot verify sender")
        elif spf in ("fail", "hardfail"):
            self._add_signal(signals, "spf_fail", "confirmed", "SPF check failed", triggered_iocs)
        elif spf == "softfail":
            self._add_signal(signals, "spf_fail", "suspicious", "SPF softfail", triggered_iocs, discount=0.5)

        if dkim == "none":
            missing.append("DKIM signature absent")
        elif dkim == "fail":
            self._add_signal(signals, "dkim_fail", "confirmed", "DKIM check failed", triggered_iocs)

        if dmarc == "none":
            missing.append("DMARC policy absent")
        elif dmarc == "fail":
            self._add_signal(signals, "dmarc_fail", "confirmed", "DMARC check failed", triggered_iocs)

        if _ga(header_result, "display_name_spoofing", False):
            self._add_signal(
                signals, "display_name_spoofing", "confirmed",
                "Display-name spoofing detected", triggered_iocs,
            )

        if _ga(header_result, "sender_domain_mismatch", False):
            self._add_signal(
                signals, "sender_domain_mismatch", "confirmed",
                "Sender domain does not match envelope domain", triggered_iocs,
            )

        if _ga(header_result, "reply_to_mismatch", False):
            self._add_signal(
                signals, "reply_to_mismatch", "suspicious",
                "Reply-To domain differs from From domain", triggered_iocs,
            )

        if _ga(header_result, "suspicious_routing", False):
            self._add_signal(
                signals, "suspicious_routing", "heuristic",
                f"Suspicious routing ({_ga(header_result, 'routing_hops', '?')} hops)",
                triggered_iocs,
            )

    # ------------------------------------------------------------------
    # URL signals
    # ------------------------------------------------------------------

    def _url_signals(
        self,
        url_result: Any,
        signals: list[ScoreSignal],
        triggered_iocs: set[str],
    ) -> None:
        findings = _ga(url_result, "findings", [])
        shortener_added = False
        ip_added = False

        for uf in findings:
            url_val = _ga(uf, "url_normalized") or _ga(uf, "url_raw", "")
            risk = _ga(uf, "risk_level", "low")

            ioc_key = f"url:{url_val}"
            if ioc_key in triggered_iocs:
                continue

            if risk == "critical":
                self._add_signal(
                    signals, "malicious_url_confirmed", "confirmed",
                    f"Malicious URL detected: {url_val[:80]}", triggered_iocs,
                    ioc_key=ioc_key,
                )
            elif risk in ("high", "medium"):
                self._add_signal(
                    signals, "suspicious_url_heuristic", "heuristic",
                    f"Suspicious URL: {url_val[:80]}", triggered_iocs,
                    ioc_key=ioc_key,
                )

            if _ga(uf, "is_shortener", False) and not shortener_added:
                self._add_signal(
                    signals, "url_shortener", "heuristic",
                    "URL shortener service used", triggered_iocs,
                )
                shortener_added = True

            if _ga(uf, "is_ip_based", False) and not ip_added:
                self._add_signal(
                    signals, "ip_based_url", "suspicious",
                    "URL uses IP address instead of hostname", triggered_iocs,
                )
                ip_added = True

    # ------------------------------------------------------------------
    # Attachment signals
    # ------------------------------------------------------------------

    def _attachment_signals(
        self,
        attachment_result: Any,
        signals: list[ScoreSignal],
        triggered_iocs: set[str],
    ) -> None:
        findings = _ga(attachment_result, "findings", [])

        for af in findings:
            sha256 = _ga(af, "sha256_hash", "")
            risk = _ga(af, "risk_level", "low")
            ioc_key = f"hash:{sha256}"

            if ioc_key in triggered_iocs and sha256:
                continue

            if risk == "critical":
                self._add_signal(
                    signals, "dangerous_attachment_confirmed", "confirmed",
                    f"Dangerous attachment: {_ga(af, 'filename_original', '?')}",
                    triggered_iocs, ioc_key=ioc_key if sha256 else None,
                )
            elif risk == "high":
                self._add_signal(
                    signals, "dangerous_attachment_heuristic", "heuristic",
                    f"High-risk attachment: {_ga(af, 'filename_original', '?')}",
                    triggered_iocs, ioc_key=ioc_key if sha256 else None,
                )

            if _ga(af, "has_macro_indicator", False):
                macro_key = f"macro:{sha256}"
                if macro_key not in triggered_iocs:
                    self._add_signal(
                        signals, "macro_attachment", "suspicious",
                        f"Office macro-enabled file: {_ga(af, 'filename_original', '?')}",
                        triggered_iocs, ioc_key=macro_key,
                    )

    # ------------------------------------------------------------------
    # AI signals
    # ------------------------------------------------------------------

    def _ai_signals(self, ai_result: Any, signals: list[ScoreSignal]) -> None:
        if ai_result is None:
            return

        assessment = _ga(ai_result, "phishing_assessment", "unknown")
        confidence = _ga(ai_result, "confidence", "low")

        if assessment == "phishing":
            if confidence == "high":
                self._add_signal_direct(
                    signals, "ai_phishing_high_confidence", "confirmed",
                    "AI analysis: high-confidence phishing",
                )
            else:
                self._add_signal_direct(
                    signals, "ai_phishing_medium_confidence", "suspicious",
                    "AI analysis: phishing (medium confidence)",
                )
        elif assessment == "suspicious":
            self._add_signal_direct(
                signals, "ai_phishing_medium_confidence", "heuristic",
                "AI analysis: suspicious email",
            )

        # Brand impersonation from AI findings
        ai_findings = _ga(ai_result, "findings", [])
        for f in ai_findings:
            cat = _ga(f, "category", "")
            if cat == "impersonation":
                self._add_signal_direct(
                    signals, "brand_impersonation", "suspicious",
                    f"AI detected impersonation: {_ga(f, 'description', '')[:80]}",
                )
                break

    # ------------------------------------------------------------------
    # Domain intel signals
    # ------------------------------------------------------------------

    def _domain_intel_signals(
        self,
        domain_intel: dict,
        signals: list[ScoreSignal],
        triggered_iocs: set[str],
    ) -> None:
        if domain_intel.get("newly_registered"):
            domain = domain_intel.get("domain", "unknown")
            ioc_key = f"domain:{domain}"
            self._add_signal(
                signals, "domain_newly_registered", "confirmed",
                f"Domain '{domain}' was recently registered (< 30 days)",
                triggered_iocs, ioc_key=ioc_key,
            )

    # ------------------------------------------------------------------
    # Signal helpers
    # ------------------------------------------------------------------

    def _add_signal(
        self,
        signals: list[ScoreSignal],
        name: str,
        confidence: str,
        reason: str,
        triggered_iocs: set[str],
        discount: float = 1.0,
        ioc_key: Optional[str] = None,
    ) -> None:
        """Add a signal if it hasn't been triggered by the same IOC key."""
        if ioc_key:
            if ioc_key in triggered_iocs:
                return
            triggered_iocs.add(ioc_key)

        self._add_signal_direct(signals, name, confidence, reason, discount)

    def _add_signal_direct(
        self,
        signals: list[ScoreSignal],
        name: str,
        confidence: str,
        reason: str,
        discount: float = 1.0,
    ) -> None:
        weight = self._weights.get(name, 0)
        confidence_multiplier = {"confirmed": 1.0, "suspicious": 0.75, "heuristic": 0.5}.get(
            confidence, 0.5
        )
        applied = int(weight * confidence_multiplier * discount)
        signals.append(
            ScoreSignal(
                name=name,
                weight=weight,
                raw_score=weight,
                applied_score=applied,
                confidence=confidence,
                reason=reason,
            )
        )

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    @staticmethod
    def _classify(score: int) -> str:
        if score < 20:
            return "low"
        if score < 40:
            return "suspicious"
        if score < 70:
            return "medium"
        if score < 90:
            return "high"
        return "critical"

    # ------------------------------------------------------------------
    # Explanation
    # ------------------------------------------------------------------

    @staticmethod
    def _explain(result: RiskScoreResult) -> str:
        """Generate a human-readable explanation paragraph."""
        cls = result.classification.upper()
        score = result.score
        num_signals = len(result.breakdown)
        signal_names = ", ".join(s.name for s in result.breakdown[:5])
        more = f" (and {num_signals - 5} more)" if num_signals > 5 else ""

        explanation = (
            f"This email received a risk score of {score}/100, classified as {cls}. "
        )

        if num_signals == 0:
            explanation += "No significant threat signals were detected."
        else:
            explanation += (
                f"The score was driven by {num_signals} signal(s) including: "
                f"{signal_names}{more}. "
            )

        if result.missing_evidence:
            evidence_str = "; ".join(result.missing_evidence)
            explanation += (
                f"Note: Some evidence was unavailable ({evidence_str}), "
                "which may understate the actual risk."
            )

        return explanation


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------


def _ga(obj: Any, attr: str, default: Any = None) -> Any:
    """Get attribute from object or dict."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(attr, default)
    return getattr(obj, attr, default)
