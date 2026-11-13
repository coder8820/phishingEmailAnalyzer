"""
PhishGuard AI — Intelligent SOC Chat Assistant Service
Provides comprehensive, expert-level explanations of PhishGuard AI,
cybersecurity concepts (SPF, DKIM, DMARC, IOCs, heuristics),
SOC workflows, and curated verified resources for external security platforms.
Supports English, Urdu, and Roman Urdu seamlessly.
"""
from __future__ import annotations

import json
import re
from typing import Any, List, Optional
import structlog
import httpx

from app.core.config import settings

logger = structlog.get_logger(__name__)

# ============================================================
# VERIFIED EXTERNAL CYBERSECURITY & THREAT INTEL PLATFORMS
# ============================================================
CYBER_RESOURCES: list[dict[str, Any]] = [
    {
        "id": "virustotal",
        "title": "VirusTotal",
        "url": "https://www.virustotal.com/gui/home/upload",
        "category": "Threat Intelligence & Malware Analysis",
        "badge": "Threat Intel",
        "description": "Analyze suspicious files, domains, IPs, and URLs across 70+ antivirus scanners and threat feeds.",
        "tags": ["virustotal", "file hash", "url scan", "ip reputation", "antivirus", "malware"],
    },
    {
        "id": "abuseipdb",
        "title": "AbuseIPDB",
        "url": "https://www.abuseipdb.com/",
        "category": "IP Reputation & Abuse Reporting",
        "badge": "IP Intel",
        "description": "Check if an IP address has been reported for malicious activity, spam, brute force, or hacking attempts.",
        "tags": ["abuseipdb", "ip lookup", "ip reputation", "blacklist", "spam ip", "attacker ip"],
    },
    {
        "id": "urlhaus",
        "title": "URLhaus (abuse.ch)",
        "url": "https://urlhaus.abuse.ch/",
        "category": "Malicious URL Feed",
        "badge": "Malware URLs",
        "description": "Community-driven database sharing malicious URLs used for malware distribution and phishing payloads.",
        "tags": ["urlhaus", "malicious url", "payloads", "malware download", "abuse.ch"],
    },
    {
        "id": "mxtoolbox",
        "title": "MXToolbox Email Health & SuperTool",
        "url": "https://mxtoolbox.com/emailhealth/",
        "category": "Email Deliverability & DNS Inspection",
        "badge": "DNS & Headers",
        "description": "Test and verify MX records, SPF syntax, DKIM selectors, DMARC compliance, and email blacklists.",
        "tags": ["mxtoolbox", "mx record", "spf check", "dkim check", "dmarc check", "dns lookup"],
    },
    {
        "id": "google-messageheader",
        "title": "Google Admin Toolbox Messageheader",
        "url": "https://toolbox.googleapps.com/apps/messageheader/",
        "category": "Email Header Analyzer",
        "badge": "Header Inspector",
        "description": "Paste raw email headers to analyze delivery delays, routing hops, SPF, DKIM, and authentication results.",
        "tags": ["google message header", "header analysis", "delivery delay", "hops", "authentication results"],
    },
    {
        "id": "dmarcian",
        "title": "dmarcian DMARC Inspector",
        "url": "https://dmarcian.com/dmarc-inspector/",
        "category": "DMARC & Email Security",
        "badge": "DMARC",
        "description": "Inspect and troubleshoot DMARC records, alignment policies (p=reject, quarantine), and reporting URIs.",
        "tags": ["dmarcian", "dmarc", "alignment", "quarantine", "reject policy"],
    },
    {
        "id": "phishtank",
        "title": "PhishTank",
        "url": "https://phishtank.org/",
        "category": "Phishing Database",
        "badge": "Phish Feed",
        "description": "A collaborative clearinghouse for data and information about phishing on the internet with community verification.",
        "tags": ["phishtank", "phishing list", "verified phishing", "suspicious links"],
    },
    {
        "id": "openphish",
        "title": "OpenPhish Global Phishing Feed",
        "url": "https://openphish.com/",
        "category": "Zero-Day Phishing Intel",
        "badge": "Phish Intel",
        "description": "Real-time automated phishing threat intelligence feed detecting zero-day phishing sites globally.",
        "tags": ["openphish", "zero day", "feed", "phishing detection"],
    },
    {
        "id": "google-safe-browsing",
        "title": "Google Safe Browsing Transparency",
        "url": "https://transparencyreport.google.com/safe-browsing/search",
        "category": "Domain Reputation",
        "badge": "Safe Browsing",
        "description": "Check if a domain or URL is flagged by Google for hosting malware, unwanted software, or social engineering attacks.",
        "tags": ["google safe browsing", "safe search", "deceptive site"],
    },
    {
        "id": "anyrun",
        "title": "ANY.RUN Interactive Sandbox",
        "url": "https://any.run/",
        "category": "Interactive Malware Sandbox",
        "badge": "Sandbox",
        "description": "Interactive malware analysis sandbox for safely opening suspicious email attachments, PDFs, and phishing links in a live VM.",
        "tags": ["anyrun", "any.run", "sandbox", "malware analysis", "interactive detonation"],
    },
    {
        "id": "hybrid-analysis",
        "title": "Hybrid Analysis",
        "url": "https://www.hybrid-analysis.com/",
        "category": "Automated Sandbox Analysis",
        "badge": "Falcon Sandbox",
        "description": "Free malware analysis service powered by Falcon Sandbox and CrowdStrike intelligence to examine suspicious files.",
        "tags": ["hybrid analysis", "crowdstrike", "static analysis", "dynamic analysis"],
    },
    {
        "id": "cisco-talos",
        "title": "Cisco Talos Intelligence Network",
        "url": "https://talosintelligence.com/",
        "category": "Commercial Threat Intelligence",
        "badge": "Talos",
        "description": "Comprehensive IP, domain, and file reputation lookup backed by one of the largest commercial threat detection networks.",
        "tags": ["talos", "cisco", "reputation", "threat data"],
    },
    {
        "id": "alienvault-otx",
        "title": "AlienVault OTX (Open Threat Exchange)",
        "url": "https://otx.alienvault.com/",
        "category": "Community Threat Exchange",
        "badge": "OTX Pulses",
        "description": "Community-generated threat intelligence pulses containing Indicators of Compromise (IOCs) for targeted campaigns.",
        "tags": ["alienvault", "otx", "pulses", "ioc sharing"],
    },
    {
        "id": "mitre-attack",
        "title": "MITRE ATT&CK: Phishing (T1566)",
        "url": "https://attack.mitre.org/techniques/T1566/",
        "category": "SOC Framework & Adversary Tactics",
        "badge": "MITRE ATT&CK",
        "description": "Detailed breakdown of adversary tactics for spearphishing attachments, links, and third-party services.",
        "tags": ["mitre", "attack", "t1566", "spearphishing", "adversary"],
    },
    {
        "id": "cisa-phishing",
        "title": "CISA Phishing Guidance & Defense",
        "url": "https://www.cisa.gov/stopransomware/phishing",
        "category": "Government Security Standard",
        "badge": "CISA Best Practice",
        "description": "Official Cybersecurity and Infrastructure Security Agency guidelines on recognizing and countering phishing threats.",
        "tags": ["cisa", "guidance", "government", "incident response", "security standard"],
    },
    {
        "id": "rfc7208",
        "title": "IETF RFC 7208: Sender Policy Framework (SPF)",
        "url": "https://datatracker.ietf.org/doc/html/rfc7208",
        "category": "RFC Specification",
        "badge": "RFC 7208",
        "description": "Official Internet standard specification for authorizing sending mail transfer agents using SPF DNS records.",
        "tags": ["rfc 7208", "spf standard", "rfc", "email protocol"],
    },
    {
        "id": "rfc6376",
        "title": "IETF RFC 6376: DomainKeys Identified Mail (DKIM)",
        "url": "https://datatracker.ietf.org/doc/html/rfc6376",
        "category": "RFC Specification",
        "badge": "RFC 6376",
        "description": "Official technical standard for cryptographic signing of email messages to guarantee integrity and authenticity.",
        "tags": ["rfc 6376", "dkim standard", "digital signature"],
    },
    {
        "id": "rfc7489",
        "title": "IETF RFC 7489: DMARC Specification",
        "url": "https://datatracker.ietf.org/doc/html/rfc7489",
        "category": "RFC Specification",
        "badge": "RFC 7489",
        "description": "Official standard defining how domain owners specify handling policies for emails that fail SPF or DKIM.",
        "tags": ["rfc 7489", "dmarc standard", "domain policy"],
    },
]


def find_matching_resources(query: str, limit: int = 5) -> list[dict[str, Any]]:
    """Match resources from catalog based on query keywords."""
    q = query.lower()
    scored: list[tuple[int, dict[str, Any]]] = []

    # If general request for external platforms/tools/sources
    general_external_keywords = [
        "source", "tool", "platform", "website", "link", "external",
        "dusre", "dusri", "resources", "site", "online", "free", "kaha se",
        "check karu", "check karein", "explore", "recommend"
    ]
    is_general_request = any(k in q for k in general_external_keywords)

    for item in CYBER_RESOURCES:
        score = 0
        # Direct title match
        if item["title"].lower() in q or item["id"] in q:
            score += 10
        # Tag matches
        for tag in item["tags"]:
            if tag in q:
                score += 4
        # Category matches
        if item["category"].lower() in q:
            score += 3

        if is_general_request and score == 0:
            # Add diverse core platforms if user generally asked for tools/resources
            if item["id"] in ["virustotal", "abuseipdb", "mxtoolbox", "urlhaus", "anyrun", "mitre-attack"]:
                score += 1

        if score > 0:
            scored.append((score, item))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [item for _, item in scored[:limit]]


# ============================================================
# SYSTEM PROMPT & KNOWLEDGE BASE
# ============================================================
KNOWLEDGE_BASE = """
You are the official AI Security Assistant for **PhishGuard AI** (Enterprise AI-Powered Phishing Email Analyzer).
You are an expert SOC Level 2/Level 3 Analyst and cybersecurity specialist.
You must assist users with:
1. Deep explanations of how PhishGuard AI works, its architecture, and its detection engine.
2. Step-by-step guidance on analyzing suspicious emails, interpreting risk scores, and handling incidents.
3. Detailed breakdown of email authentication: SPF (Sender Policy Framework), DKIM (DomainKeys Identified Mail), and DMARC (Domain-based Message Authentication Reporting and Conformance).
4. Explaining heuristic rules: urgency cues, brand impersonation, typosquatting domains, lookalike characters (homograph attacks), hidden zero-width text, malicious attachment types, and credential harvesting forms.
5. Providing accurate, working external tools and platforms whenever users ask for outside verification, lookup sites, or resources (e.g. VirusTotal, MXToolbox, AbuseIPDB, URLhaus, ANY.RUN, PhishTank, MITRE ATT&CK, CISA).
6. Responding fluently in English, Urdu, or Roman Urdu according to the user's language.

### Key Details of PhishGuard AI:
- **Stack**: Next.js 14 (TypeScript, Tailwind CSS), FastAPI (Python 3.11), SQLAlchemy 2.0 (async), SQLite (local dev) / PostgreSQL 16 (production), Celery & Redis (async analysis queue).
- **Core Workflow**:
  1. **Ingestion**: Upload .EML/.MSG, raw headers & body text, or automated sync via connected Gmail accounts.
  2. **Parsing**: RFC 5322 parsing of headers, MIME multiparts, decoded body text (HTML & plain), attachment hashing (SHA-256), and URL extraction.
  3. **Header Authentication**: Validates SPF records, DKIM cryptographic signatures, and DMARC alignment (p=reject/quarantine/none).
  4. **URL & Domain Analysis**: Extracts URLs, canonicalizes domains, checks against URLhaus blacklist, flags IP-based URLs, punycode/homoglyphs, and detects domain typosquatting.
  5. **Attachment Inspection**: Scans double extensions (e.g., invoice.pdf.exe), dangerous executable types (.iso, .scr, .vbs, .hta, .docm), evaluates MIME vs extension mismatch.
  6. **AI Assessment**: Contextual analysis using LLM (Gemini / OpenAI / Mock) with strict prompt injection containment to detect psychological manipulation and urgency.
  7. **Threat Intelligence**: Real-time integration with VirusTotal, URLhaus, and AbuseIPDB.
  8. **Explainable Risk Score (0-100)**:
     - 0-29: Clean / Legitimate
     - 30-59: Low / Suspicious (User review advised)
     - 60-84: High / Malicious (Quarantine / Block)
     - 85-100: Critical Threat (Immediate Incident Escalation)
  9. **IOC Management**: Automatically defangs and catalogs malicious IPs (`192[.]168[.]1[.]1`), domains (`paypa1[.]com`), and hashes.
  10. **SOC Workflow**: Incident creation, assignment, investigation notes, and downloadable PDF forensic reports.
"""


def generate_session_title(first_message: str) -> str:
    """Generate a clean, concise 3-6 word title for a chat session."""
    clean = re.sub(r"[^\w\s]", "", first_message).strip()
    words = clean.split()
    if not words:
        return "New Investigation"
    
    # Check known themes
    lower = first_message.lower()
    if "spf" in lower or "dkim" in lower or "dmarc" in lower:
        return "Email Auth (SPF/DKIM/DMARC)"
    if "risk" in lower or "score" in lower or "scoring" in lower:
        return "Risk Scoring Breakdown"
    if "source" in lower or "tool" in lower or "platform" in lower or "external" in lower:
        return "External Security Tools"
    if "work" in lower or "kaam" in lower or "flow" in lower or "architecture" in lower:
        return "PhishGuard Architecture"
    if "gmail" in lower:
        return "Gmail Integration Guide"
    if "ioc" in lower or "indicator" in lower:
        return "IOC Extraction Guide"
    
    title_words = words[:5]
    title = " ".join(title_words).capitalize()
    return title[:45]


class ChatAssistantService:
    """Chat service handling prompt processing, external tool recommendation, and AI execution."""

    @classmethod
    async def answer_query(
        cls,
        user_message: str,
        conversation_history: list[dict[str, str]],
    ) -> tuple[str, list[dict[str, Any]]]:
        """
        Process the user query.
        Returns: (assistant_response_markdown, matched_sources)
        """
        msg_lower = user_message.lower()
        matched_sources = find_matching_resources(user_message, limit=5)

        # Check if we should call external LLM (Gemini or OpenAI)
        if settings.AI_PROVIDER == "google" and settings.GOOGLE_API_KEY:
            try:
                response_text = await cls._call_gemini(user_message, conversation_history, matched_sources)
                if response_text:
                    return response_text, matched_sources
            except Exception as e:
                logger.warning("gemini_chat_failed_fallback_to_expert_engine", error=str(e))

        elif settings.AI_PROVIDER == "openai" and settings.OPENAI_API_KEY:
            try:
                response_text = await cls._call_openai(user_message, conversation_history, matched_sources)
                if response_text:
                    return response_text, matched_sources
            except Exception as e:
                logger.warning("openai_chat_failed_fallback_to_expert_engine", error=str(e))

        # Built-in High-Accuracy Expert Engine (works completely offline / without external API key)
        response_text = cls._generate_expert_response(user_message, matched_sources)
        return response_text, matched_sources

    @classmethod
    async def _call_gemini(
        cls,
        user_message: str,
        conversation_history: list[dict[str, str]],
        matched_sources: list[dict[str, Any]],
    ) -> str:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{settings.GOOGLE_MODEL}:generateContent?key={settings.GOOGLE_API_KEY}"
        contents = []

        # System instructions
        contents.append({
            "role": "user",
            "parts": [{"text": KNOWLEDGE_BASE}],
        })
        contents.append({
            "role": "model",
            "parts": [{"text": "Understood. I am the PhishGuard AI Security Assistant. I will provide comprehensive, expert SOC insights, explain the project thoroughly, and supply valid verified resource links."}],
        })

        # History (limit to last 6 messages)
        for msg in conversation_history[-6:]:
            role = "user" if msg["sender"] == "user" else "model"
            contents.append({"role": role, "parts": [{"text": msg["content"]}]})

        # Latest query + context
        prompt_with_sources = user_message
        if matched_sources:
            sources_summary = "\n".join([f"- [{s['title']}]({s['url']}): {s['description']}" for s in matched_sources])
            prompt_with_sources += f"\n\n[System Note: User may find these verified external platforms relevant. You can reference them where appropriate:\n{sources_summary}]"

        contents.append({"role": "user", "parts": [{"text": prompt_with_sources}]})

        async with httpx.AsyncClient(timeout=35.0) as client:
            resp = await client.post(url, json={"contents": contents})
            if resp.status_code == 200:
                data = resp.json()
                return data["candidates"][0]["content"]["parts"][0]["text"]
            else:
                raise RuntimeError(f"Gemini API returned status {resp.status_code}: {resp.text}")

    @classmethod
    async def _call_openai(
        cls,
        user_message: str,
        conversation_history: list[dict[str, str]],
        matched_sources: list[dict[str, Any]],
    ) -> str:
        url = "https://api.openai.com/v1/chat/completions"
        messages = [{"role": "system", "content": KNOWLEDGE_BASE}]

        for msg in conversation_history[-6:]:
            role = "user" if msg["sender"] == "user" else "assistant"
            messages.append({"role": role, "content": msg["content"]})

        prompt_with_sources = user_message
        if matched_sources:
            sources_summary = "\n".join([f"- [{s['title']}]({s['url']}): {s['description']}" for s in matched_sources])
            prompt_with_sources += f"\n\n[System Reference: Include or reference these verified external platforms if helpful: {sources_summary}]"

        messages.append({"role": "user", "content": prompt_with_sources})

        headers = {
            "Authorization": f"Bearer {settings.OPENAI_API_KEY}",
            "Content-Type": "application/json",
        }
        async with httpx.AsyncClient(timeout=35.0) as client:
            resp = await client.post(
                url,
                headers=headers,
                json={"model": settings.OPENAI_MODEL, "messages": messages, "temperature": 0.4},
            )
            if resp.status_code == 200:
                data = resp.json()
                return data["choices"][0]["message"]["content"]
            else:
                raise RuntimeError(f"OpenAI API returned status {resp.status_code}: {resp.text}")

    @classmethod
    def _generate_expert_response(cls, user_message: str, matched_sources: list[dict[str, Any]]) -> str:
        """
        Expert Rule Engine that provides in-depth, production-grade responses
        covering working mechanisms, architecture, email authentication,
        risk scores, SOC workflow, and external platform resources.
        """
        q = user_message.lower().strip()

        # Check Roman Urdu or Urdu language cues
        is_roman_urdu = any(word in q for word in [
            "kaisy", "kaise", "btao", "kya", "kia", "karta", "krta", "hai", "hy",
            "karo", "kren", "kisi", "dusre", "dusri", "smjhao", "samjhao", "tarika",
            "tareeqa", "cheez", "mera", "mere", "ye", "yeh", "konsa", "kab"
        ])

        # 1. External Platforms & Sources Query
        if any(w in q for w in ["source", "sources", "platform", "platforms", "external tool", "bahar k", "dusre tools", "other tool", "website", "links", "resource"]):
            return cls._build_sources_response(is_roman_urdu, matched_sources)

        # 2. How PhishGuard Works / Workflow / Architecture
        if any(w in q for w in ["work", "working", "flow", "architecture", "kaam", "process", "kaise kaam", "kaisy kaam", "overview", "kya hai", "kia hy", "what is"]):
            return cls._build_working_response(is_roman_urdu)

        # 3. SPF / DKIM / DMARC Header Authentication
        if any(w in q for w in ["spf", "dkim", "dmarc", "header", "authentication", "align", "spoof", "spoofing"]):
            return cls._build_auth_response(is_roman_urdu)

        # 4. Risk Score Calculation (0-100)
        if any(w in q for w in ["risk score", "score", "scoring", "calculate", "formula", "weights", "classification", "severity"]):
            return cls._build_risk_score_response(is_roman_urdu)

        # 5. IOC (Indicators of Compromise) & Defanging
        if any(w in q for w in ["ioc", "indicator", "defang", "hash", "sha256", "ip", "domain extraction"]):
            return cls._build_ioc_response(is_roman_urdu)

        # 6. Incident Management & SOC Workflow
        if any(w in q for w in ["incident", "soc", "triage", "investigation", "analyst", "report", "workflow", "audit"]):
            return cls._build_incident_response(is_roman_urdu)

        # 7. Threat Intelligence (VirusTotal, URLhaus, AbuseIPDB)
        if any(w in q for w in ["threat intel", "intelligence", "virustotal", "urlhaus", "abuseipdb", "reputation"]):
            return cls._build_threat_intel_response(is_roman_urdu)

        # 8. Gmail Integration & Auto Sync
        if any(w in q for w in ["gmail", "sync", "oauth", "mailbox", "inbox", "auto analyze"]):
            return cls._build_gmail_response(is_roman_urdu)

        # Default Comprehensive Guide & Help
        return cls._build_general_response(is_roman_urdu, user_message, matched_sources)

    # -------------------------------------------------------------------------
    # RESPONSE BUILDERS (Structured, Professional, SOC-Oriented)
    # -------------------------------------------------------------------------
    @classmethod
    def _build_sources_response(cls, is_urdu: bool, matched_sources: list[dict[str, Any]]) -> str:
        intro = (
            "Agar aap **PhishGuard AI** k elawa third-party verification ya deep threat intelligence k lea external platforms use krna chahte hain, to yahan verified aur standard tools ki list mojood hy:"
            if is_urdu else
            "Here are the top industry-standard external platforms, threat feeds, and analysis sandboxes recommended by SOC teams to verify phishing emails, domains, and IOCs:"
        )

        table_rows = []
        for s in CYBER_RESOURCES[:8]:
            table_rows.append(f"| **[{s['title']}]({s['url']})** | `{s['badge']}` | {s['description']} |")

        table_md = "\n".join(table_rows)

        advice = (
            "\n\n### 🛡️ Analyst Pro-Tip:\n"
            "- **URLs:** Pehle URL ko defang karen (`hxxps[:]//example[.]com`), phir **VirusTotal** aur **URLhaus** par check karen.\n"
            "- **Headers:** Agar SPF/DKIM fail lag raha ho to **Google Admin Toolbox Messageheader** ya **MXToolbox** par raw headers paste kr k hop-by-hop latency aur DKIM signature verify karen.\n"
            "- **Attachments:** Kisi b anjaan attachment ko host system par open mat karen — **ANY.RUN** ya **Hybrid Analysis** sandbox ma detonate karen."
            if is_urdu else
            "\n\n### 🛡️ SOC Best Practices When Using External Platforms:\n"
            "- **Never visit raw phishing URLs directly** — Always defang them (`hxxps[:]//domain[.]com`) and submit them to **VirusTotal** and **URLhaus**.\n"
            "- **Header Verification** — Inspect hop routing, DKIM selectors, and SPF records using **Google Admin Messageheader** and **MXToolbox**.\n"
            "- **Dynamic Detonation** — Execute suspicious PDFs, Office documents, or macro files in an interactive sandbox like **ANY.RUN** to observe behavioral evasion."
        )

        return f"{intro}\n\n| Platform | Category | Purpose & Capability |\n|---|---|---|\n{table_md}{advice}"

    @classmethod
    def _build_working_response(cls, is_urdu: bool) -> str:
        if is_urdu:
            return """### 🛡️ PhishGuard AI kaisy kaam karta hy (Full Working Architecture)

PhishGuard AI ek **Enterprise-Grade SOC Defense Platform** hy jo 6-Layer Multi-Stage Pipeline k zarye emails ko analyze krta hy:

```
[Email Ingestion (.EML/Raw/Gmail)] 
       ⬇
[Layer 1: Email Parser] ➔ Headers, MIME parts, Body, Attachments, URLs alag krta hy
       ⬇
[Layer 2: Authentication Engine] ➔ SPF, DKIM, DMARC alignment check
       ⬇
[Layer 3: Heuristic & Rule Engine] ➔ Urgency words, Typosquatting, Bad extensions (.exe, .iso)
       ⬇
[Layer 4: AI Contextual Threat Engine] ➔ Social engineering & Prompt Injection defense
       ⬇
[Layer 5: Threat Intelligence] ➔ VirusTotal, URLhaus, AbuseIPDB reputation check
       ⬇
[Layer 6: Explainable Risk Scoring (0–100)] ➔ Clean, Suspicious, Malicious, Critical
       ⬇
[SOC Incident & IOC Extraction] ➔ Defanged IOCs, Case triage, PDF Forensic Report
```

#### 🔍 Step-by-Step Working:
1. **Email Submission**:
   - Analyst `.eml` ya `.msg` file upload krta hy, ya seedha raw headers/body paste krta hy.
   - Connected **Gmail** account se automatically unread emails sync aur scan hoti hain.
2. **Parsing & Normalization**:
   - System standard RFC 5322 k mutabiq `From`, `To`, `Subject`, `Return-Path`, `Authentication-Results` aur `Received` hops extract krta hy.
   - HTML body se text aur hidden zero-font characters clean kr k URLs nikale jate hain.
3. **Authentication Verification**:
   - **SPF Check**: Dekhta hy k sender IP domain k DNS record se authorized hy ya nahi.
   - **DKIM Check**: Cryptographic signature verify krta hy k email raste ma modify to nahi hui.
   - **DMARC Alignment**: Confirm krta hy k `From` header domain SPF/DKIM k sath match krta hy.
4. **URL & Domain Heuristics**:
   - IP-based URLs (e.g. `http://192.168.1.1/login`), Punycode (homograph attack e.g. `pаypal.com`), suspicious TLDs (`.tk`, `.top`), aur URL shorteners identify hotay hain.
5. **AI Threat Intelligence**:
   - AI model email k context ko analyze krta hy (e.g., account suspension fake threats, fake password reset, executive spoofing).
   - Prompt injection defense email body ko isolated rakhta hy ta k koi attacker LLM ko hijack na kr saky.
6. **Composite Risk Score (0-100)**:
   - Sabhi signals k weighted score se final risk number nikalta hy aur breakdown explainable format ma analyst ko milta hy."""
        else:
            return """### 🛡️ PhishGuard AI End-to-End Architecture & Operational Workflow

PhishGuard AI operates as an automated SOC tier-1 & tier-2 phishing defense pipeline built on a **multi-signal, explainable defense architecture**:

```
[Email Submission (EML/MSG/Raw/Gmail)]
       │
       ▼
┌──────────────────────────────────────────────┐
│ 1. Ingestion & RFC 5322 Parsing Engine       │
│    Extracts Hops, Authentication-Results,    │
│    MIME Parts, URLs, and Attachment Hashes   │
└──────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────┐
│ 2. Tri-Factor Authentication Analysis        │
│    • SPF (RFC 7208) DNS Sender Validation    │
│    • DKIM (RFC 6376) Cryptographic Verify    │
│    • DMARC (RFC 7489) Policy Alignment       │
└──────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────┐
│ 3. Deep Heuristics & Static Rule Engine      │
│    • URL Canonicalization & Punycode Check   │
│    • Typosquatting / Lookalike Brand Domain  │
│    • Dangerous Attachments (.exe/.iso/.vbs)  │
└──────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────┐
│ 4. AI Threat Analysis & Prompt Defense       │
│    • Contextual Urgency & Intent Evaluation  │
│    • Strict System-User Boundary Isolation   │
└──────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────┐
│ 5. Multi-Source Threat Intelligence Lookup   │
│    • VirusTotal IP/Domain/Hash Check         │
│    • URLhaus Real-time Malware Payload DB    │
│    • AbuseIPDB Host Abuse Confidence Score   │
└──────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────┐
│ 6. Explainable 0-100 Composite Risk Scoring  │
│    Safe (0-29) | Suspicious | Malicious (60+)│
└──────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────┐
│ 7. SOC Incident Triage & Automated Reporting │
│    • Auto-defanged IOCs (`1.1.1[.]1`)        │
│    • Analyst Investigation Notes & Audit Trail│
│    • Executive & Technical PDF Exports       │
└──────────────────────────────────────────────┘
```

#### Key Technical Capabilities:
- **Frontend**: Next.js 14, Tailwind CSS, Recharts for threat telemetry.
- **Backend**: FastAPI (Python 3.11) with asynchronous SQLAlchemy 2.0.
- **Safety**: Safe handling of payloads — URLs are never directly fetched by the server; attachments are never executed."""

    @classmethod
    def _build_auth_response(cls, is_urdu: bool) -> str:
        if is_urdu:
            return """### 📧 Email Authentication k 3 Pillars: SPF, DKIM, aur DMARC

Email spoofing se bachne k lea PhishGuard in 3 protocols ko gehrai se check krta hy:

| Protocol | Full Form | Kia Check Krta Hy? | Failure Par PhishGuard Ka Action |
|---|---|---|---|
| **SPF** | Sender Policy Framework | Sender IP domain k DNS SPF TXT record ma allowed hy ya nahi. | Agar `fail` ya `softfail` ho to score +20-30 points barhata hy. |
| **DKIM** | DomainKeys Identified Mail | Email k content aur headers par cryptographic digital signature verify krta hy. | Signature mismatch par tampering detect kr k alert deta hy. |
| **DMARC** | Domain-based Message Authentication | Ye check krta hy k `From` header SPF aur DKIM domains k sath align krta hy ya nahi. | DMARC fail hone par spoofing flag hoti hy aur `p=reject` enforce hota hy. |

#### ⚠️ Spoofing Example:
Agar koi email `security@paypal.com` show kr rahi ho lekin uska sending IP kisi unverified server ka ho, to **SPF Fail** hoga aur **DMARC Alignment Fail** hogi. PhishGuard isko foran **High/Critical Phishing** detect kr leta hy!

> **External Verification Tools:**
> - [MXToolbox SuperTool](https://mxtoolbox.com/emailhealth/) — SPF aur DMARC record syntax test krne k lea.
> - [Google Admin Messageheader](https://toolbox.googleapps.com/apps/messageheader/) — Header hops aur authentication results dekhne k lea."""
        else:
            return """### 📧 The Triad of Email Authentication: SPF, DKIM, and DMARC

PhishGuard AI analyzes the three standard authentication protocols to detect identity spoofing:

#### 1. SPF (Sender Policy Framework — RFC 7208)
- **Mechanism**: The receiving mail server extracts the sender's IP address and queries the DNS `TXT` record of the domain in the `Return-Path` (envelope sender).
- **PhishGuard Logic**: Checks whether the sending IP is listed in the domain's SPF record. Results can be `Pass`, `SoftFail` (~all), `Fail` (-all), or `Neutral`.

#### 2. DKIM (DomainKeys Identified Mail — RFC 6376)
- **Mechanism**: The sending mail server computes a hash of the email body and selected headers, signs it with its private RSA/Ed25519 key, and embeds it in the `DKIM-Signature` header.
- **PhishGuard Logic**: Retrieves the public key from the sender's DNS selector record and validates the cryptographic signature to confirm no transit tampering occurred.

#### 3. DMARC (RFC 7489)
- **Mechanism**: Ties SPF and DKIM together by enforcing **Domain Alignment** with the human-visible `From:` header.
- **PhishGuard Logic**:
  - Requires **Identifier Alignment**: The domain in the `From:` header must match the SPF-authenticated domain or the DKIM `d=` domain.
  - Inspects the published DMARC policy: `p=none` (monitoring), `p=quarantine` (deliver to spam), or `p=reject` (drop message).

#### Recommended External Diagnostics:
- [Google Admin Messageheader](https://toolbox.googleapps.com/apps/messageheader/)
- [MXToolbox Email Health](https://mxtoolbox.com/emailhealth/)
- [dmarcian DMARC Inspector](https://dmarcian.com/dmarc-inspector/)"""

    @classmethod
    def _build_risk_score_response(cls, is_urdu: bool) -> str:
        if is_urdu:
            return """### 📊 PhishGuard AI ka Risk Score (0–100) kaisy calculate hota hy?

PhishGuard AI kisi ek factor par faisla nahi krta, balkay **Composite Weighted Scoring Algorithm** use krta hy:

| Signal Category | Weight | Kya Check Hota Hy? |
|---|---|---|
| **Header Authentication** | **30%** | SPF, DKIM, DMARC alignment, Return-Path mismatch |
| **URL & Domain Reputation** | **25%** | Typosquatting, punycode, IP-based links, URLhaus matches |
| **Attachment Safety** | **20%** | Double extensions (`.pdf.exe`), `.iso`, `.vbs`, dangerous MIME types |
| **AI Content Intent** | **15%** | False urgency, credential harvest triggers, impersonation cues |
| **Keyword & Urgency Rules** | **10%** | "Verify within 24 hours", "Account suspended", financial fraud keywords |

#### 🎯 Risk Tiers & Severity:
- **0 – 29 [Clean / Safe]** 🟢: Sabhi checks pass, koi suspicious indicator nahi.
- **30 – 59 [Suspicious / Medium]** 🟡: Partial authentication mismatch ya mild urgency cues. SOC analyst review required.
- **60 – 84 [Malicious / High]** 🟠: Verified credential harvesting links ya SPF/DMARC spoofing.
- **85 – 100 [Critical Threat]** 🔴: Multi-vector attack (Known malware attachment + spoofed domain + phishing landing page). Foran incident create hota hy."""
        else:
            return """### 📊 PhishGuard AI Risk Score Calculation & Weighting Matrix

PhishGuard AI produces an **explainable 0–100 risk score** by evaluating weighted signals across five discrete analysis engines:

$$\\text{Risk Score} = \\sum (\\text{Signal Score}_i \\times \\text{Weight}_i)$$

| Dimension | Default Weight | Key Risk Indicators Evaluated |
|---|---|---|
| **Authentication Engine** | **30%** | Hard SPF Fail, DKIM signature invalid, DMARC alignment failure, spoofed display name. |
| **URL & Link Engine** | **25%** | IP addresses as hostnames, punycode/homoglyphs, URLhaus matches, redirector chains. |
| **Attachment Engine** | **20%** | High-risk executable extensions (.exe, .scr, .vbs, .hta, .iso), double extensions, MIME type discrepancy. |
| **AI Semantic Intent** | **15%** | Credential phishing intent, coercive urgency, executive impersonation, prompt injection attempts. |
| **Heuristic Content** | **10%** | Threat phrases ("suspend your account", "wire transfer", "unauthorized login detected"). |

#### 🚦 SOC Severity Thresholds:
- **0–29 (Safe)**: Legitimate commercial or personal communication.
- **30–59 (Suspicious)**: Ambiguous signals; recommended for manual analyst triage.
- **60–84 (Malicious)**: Phishing or scam campaign detected; automatic quarantine recommended.
- **85–100 (Critical)**: Active zero-day attack or targeted spearphishing with high weaponization."""

    @classmethod
    def _build_ioc_response(cls, is_urdu: bool) -> str:
        if is_urdu:
            return """### 🎯 IOCs (Indicators of Compromise) Extraction aur Defanging

Jab koi email analyze hoti hy, PhishGuard automatically tamam technical indicators extract aur **Defang** krta hy ta k SOC analyst ghalti se un par click na kare:

#### 1. Indicators Extracted:
- **IP Addresses**: Sending mail relay IPs, URL target IPs.
- **Domains & Hostnames**: Spoofed brands, redirectors, C2 domains.
- **URLs**: Complete query paths, phishing login pages.
- **File Hashes**: Attachments k **SHA-256**, **MD5**, aur **SHA-1** hashes.
- **Email Addresses**: Sender, reply-to, aur return-path addresses.

#### 2. Defanging Example (Security Protection):
- `http://evil-phish.com/login` ➔ `hxxp://evil-phish[.]com/login`
- `198.51.100.42` ➔ `198.51.100[.]42`

In IOCs ko aap copy kr k foran **VirusTotal**, **AbuseIPDB**, ya apne organization k SIEM/Firewall ma blocklist kr saktay hain!"""
        else:
            return """### 🎯 Automated IOC Extraction & Safe Defanging

PhishGuard AI extracts and neutralizes all forensic artifacts (Indicators of Compromise) from analyzed emails to empower rapid SOC response:

#### 1. Extracted Artifacts:
- **Network IOCs**: Originating IP addresses, SMTP relay hops, and autonomous system numbers (ASN).
- **Host & Web IOCs**: Full request URLs, destination domains, and canonical hostnames.
- **Payload Hashes**: SHA-256 and MD5 cryptographic hashes of all extracted attachments.
- **Identity IOCs**: Visible `From`, header `Reply-To`, and SMTP `MAIL FROM` envelopes.

#### 2. Standard Defanging Format:
To prevent accidental clicks or automatic system link resolution, all IOCs are rendered in defanged format:
- `http://malicious-login.com` $\\rightarrow$ `hxxp://malicious-login[.]com`
- `192.0.2.1` $\\rightarrow$ `192.0.2[.]1`

#### Recommended Lookup Platforms:
- [VirusTotal File & Hash Search](https://www.virustotal.com/gui/home/upload)
- [AbuseIPDB IP Lookup](https://www.abuseipdb.com/)
- [AlienVault OTX Community Pulses](https://otx.alienvault.com/)"""

    @classmethod
    def _build_incident_response(cls, is_urdu: bool) -> str:
        if is_urdu:
            return """### 🚨 SOC Incident Management & Analyst Workflow

PhishGuard AI analyst k workflow ko streamline krta hy:

1. **Auto-Escalation**: Agar email ka score **60+** ho to foran Incident generate krne ki recommendation aati hy.
2. **Case Triage**: Incident ko status di ja sakti hy: `New`, `Investigating`, `Contained`, `Resolved`, ya `False Positive`.
3. **Analyst Notes**: Har investigation k sath notes add hotay hain jo audit trail ma log hotay hain.
4. **Forensic Report**: Ek click par Executive Summary aur Technical Details wali PDF report generate hoti hy.
5. **Audit Logs**: Kis user ne kab email scan ki, kab rule update kia — har action timestamp k sath log hota hy."""
        else:
            return """### 🚨 SOC Incident Response & Investigation Lifecycle

PhishGuard AI bridges automated email analysis with enterprise SOC incident management:

1. **Automated Incident Escalation**: Analyzed emails with high or critical risk can be converted into an active SOC incident with one click.
2. **Investigation Tracking**: Assign incidents to analysts, set priority tiers (Low, Medium, High, Critical), and track lifecycle statuses:
   - `New` $\\rightarrow$ `Under Investigation` $\\rightarrow$ `Contained` $\\rightarrow$ `Closed` (or `False Positive`).
3. **Forensic Notes & Timeline**: Keep timestamped analyst notes, link related IOCs, and document remediation actions (e.g. mailbox purge, firewall domain block).
4. **PDF Case Reporting**: Generates clean forensic reports suitable for management briefings or regulatory compliance.
5. **Immutable Audit Trail**: All user actions, rule modifications, and status changes are permanently recorded in the Audit Log."""

    @classmethod
    def _build_threat_intel_response(cls, is_urdu: bool) -> str:
        if is_urdu:
            return """### 🌐 Threat Intelligence Integrations in PhishGuard AI

PhishGuard AI 3 primary Threat Intelligence feeds k sath integrate hota hy:

1. **VirusTotal**:
   - Suspicious files k SHA-256 hashes aur URLs ko 70+ security vendors k against query krta hy.
2. **URLhaus (abuse.ch)**:
   - Known malware distribution aur phishing sites ka real-time database hy (bina API key k b chalta hy).
3. **AbuseIPDB**:
   - Sending IP address ka abuse confidence score check krta hy (e.g. 100% abusive IPs foran flag hoti hain).

Aap **Settings > Integrations** ma ja kr apni personal API keys configure kr saktay hain ya demo mode ma test kr saktay hain!"""
        else:
            return """### 🌐 Threat Intelligence Engine & API Integrations

PhishGuard AI enriches raw email findings by cross-referencing extracted IOCs with global threat intelligence feeds:

1. **VirusTotal (Files, URLs, Domains)**:
   - Queries multi-engine detection telemetry to confirm whether an attachment or destination domain is recognized by enterprise AV vendors.
2. **URLhaus by abuse.ch (Malware Distribution)**:
   - Real-time community intelligence identifying URLs actively delivering trojans, ransomware, and malicious loaders.
3. **AbuseIPDB (IP Reputation)**:
   - Queries historical abuse reports and IP reputation scores for SMTP relay hosts.

You can configure your real API keys in the **Integrations** tab in the sidebar or run in seamless demo mode."""

    @classmethod
    def _build_gmail_response(cls, is_urdu: bool) -> str:
        if is_urdu:
            return """### 📬 Gmail Live Integration & Auto-Analysis

PhishGuard AI ma Gmail account connect kr k emails ko live monitor kia ja sakta hy:

1. **OAuth 2.0 / App Password Setup**:
   - **Settings** ya **Email Analyzer** ma ja kr apna Gmail connect karen.
2. **Automatic Synchronization**:
   - Ingested messages automatically inbox se sync hoti hain.
3. **Auto-Analyze Pipeline**:
   - Nayi aane wali emails automatically analyze hoti hain aur dashboard par risk alert generate hota hy."""
        else:
            return """### 📬 Gmail Integration & Automated Inbox Protection

PhishGuard AI features native Gmail integration for automated inbound mail defense:

1. **Connection Modes**: Connect using OAuth 2.0 or secure App Passwords.
2. **Automated Polling**: Ingests incoming emails into the pipeline without requiring manual `.eml` exports.
3. **Continuous Background Analysis**: Triggers the tri-factor authentication, heuristic checks, and threat intel lookup automatically as new messages arrive."""

    @classmethod
    def _build_general_response(cls, is_urdu: bool, user_message: str, matched_sources: list[dict[str, Any]]) -> str:
        if is_urdu:
            return f"""Main **PhishGuard AI** ka specialized cybersecurity assistant hoon! 🛡️

Aap mujh se is project k baray ma kuch b pooch saktay hain:
- **Working & Architecture:** Project kaisy kaam krta hy aur kon konsi technologies use hui hain?
- **Email Authentication:** SPF, DKIM, aur DMARC checks kaisy hotay hain?
- **Risk Score Breakdown:** 0–100 ka risk score kaisy calculate hota hy?
- **External Tools & Platforms:** VirusTotal, MXToolbox, AbuseIPDB, ANY.RUN jaisi external websites k verified links aur use cases.
- **SOC Workflow:** Phishing incident report kaisy create aur resolve hoti hy?

Aap Roman Urdu ya English kisi ma b apna sawaal likh saktay hain!"""
        else:
            return f"""I am the **PhishGuard AI SOC Security Assistant**! 🛡️

I can provide in-depth technical details on:
- **System Architecture & Workflow**: How emails are ingested, parsed, analyzed, and scored.
- **Email Authentication Protocols**: Detailed mechanics of SPF (RFC 7208), DKIM (RFC 6376), and DMARC (RFC 7489).
- **Risk Scoring Algorithm**: How the composite 0–100 score and severity tiers are calculated.
- **External Platforms & Threat Feeds**: Verified links and guides for VirusTotal, MXToolbox, AbuseIPDB, ANY.RUN, URLhaus, and MITRE ATT&CK.
- **Incident Response & IOCs**: Extracting, defanging, and documenting indicators for SOC investigations.

How can I assist your investigation or answer your question today?"""
