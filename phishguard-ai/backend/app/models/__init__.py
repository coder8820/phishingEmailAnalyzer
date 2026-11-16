"""
PhishGuard AI — SQLAlchemy Models
All models enforce tenant isolation via organization_id.
"""
import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import (
    Boolean, Column, Date, DateTime, Float, ForeignKey,
    Index, Integer, String, Text, func, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, BYTEA, INET, JSONB, UUID
from sqlalchemy.orm import relationship, Mapped, mapped_column

from app.core.database import Base


def uuid_pk():
    return Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


def now_utc():
    return Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


# ============================================================
# ORGANIZATIONS
# ============================================================
class Organization(Base):
    __tablename__ = "organizations"

    id = uuid_pk()
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False)
    plan = Column(String(50), default="free")
    is_active = Column(Boolean, default=True)
    settings = Column(JSONB, default=dict)
    created_at = now_utc()
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    deleted_at = Column(DateTime(timezone=True), nullable=True)

    users = relationship("User", back_populates="organization")
    emails = relationship("Email", back_populates="organization")
    incidents = relationship("Incident", back_populates="organization")


# ============================================================
# USERS
# ============================================================
class User(Base):
    __tablename__ = "users"

    id = uuid_pk()
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=False)
    display_name = Column(String(255))
    hashed_password = Column(String(255), nullable=False)  # Argon2id
    role = Column(String(50), nullable=False, default="analyst")
    # roles: super_admin | security_admin | analyst | viewer
    is_active = Column(Boolean, default=True)
    is_email_verified = Column(Boolean, default=False)
    failed_login_count = Column(Integer, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    password_changed_at = Column(DateTime(timezone=True), server_default=func.now())
    created_at = now_utc()
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    deleted_at = Column(DateTime(timezone=True), nullable=True)

    organization = relationship("Organization", back_populates="users")
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")
    submitted_emails = relationship("Email", back_populates="submitted_by_user")
    audit_logs = relationship("AuditLog", back_populates="user")

    __table_args__ = (
        Index("idx_users_org_active", "organization_id", postgresql_where=Column("deleted_at").is_(None)),
    )


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = uuid_pk()
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(String(255), unique=True, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    ip_address = Column(INET)
    user_agent = Column(Text)
    created_at = now_utc()

    user = relationship("User", back_populates="refresh_tokens")


# ============================================================
# EMAILS
# ============================================================
class Email(Base):
    __tablename__ = "emails"

    id = uuid_pk()
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    submitted_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    message_id = Column(String(512))
    subject = Column(Text)
    sender_raw = Column(Text)
    sender_email = Column(String(255), index=True)
    sender_display_name = Column(Text)
    reply_to = Column(Text)
    return_path = Column(Text)
    recipient_to = Column(ARRAY(Text))
    recipient_cc = Column(ARRAY(Text))
    received_at = Column(DateTime(timezone=True))
    source_type = Column(String(20), nullable=False)  # eml_upload | raw_input
    raw_content = Column(Text)  # sanitized storage only
    file_hash_sha256 = Column(String(64))
    file_size_bytes = Column(Integer)
    original_filename = Column(String(255))  # sanitized
    analysis_status = Column(String(30), default="pending", index=True)
    # pending | queued | processing | complete | failed
    created_at = now_utc()
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    deleted_at = Column(DateTime(timezone=True), nullable=True)

    organization = relationship("Organization", back_populates="emails")
    submitted_by_user = relationship("User", back_populates="submitted_emails")
    headers = relationship("EmailHeader", back_populates="email", cascade="all, delete-orphan")
    attachments = relationship("Attachment", back_populates="email", cascade="all, delete-orphan")
    urls = relationship("ExtractedURL", back_populates="email", cascade="all, delete-orphan")
    analysis = relationship("EmailAnalysis", back_populates="email", uselist=False)
    iocs = relationship("IOC", back_populates="email")

    __table_args__ = (
        Index("idx_emails_created_desc", "created_at"),
    )


class EmailHeader(Base):
    __tablename__ = "email_headers"

    id = uuid_pk()
    email_id = Column(UUID(as_uuid=True), ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    value = Column(Text, nullable=False)
    position = Column(Integer, nullable=False)
    created_at = now_utc()

    email = relationship("Email", back_populates="headers")


# ============================================================
# ATTACHMENTS
# ============================================================
class Attachment(Base):
    __tablename__ = "attachments"

    id = uuid_pk()
    email_id = Column(UUID(as_uuid=True), ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    filename_original = Column(String(512))
    filename_sanitized = Column(String(512))
    mime_type_declared = Column(String(255))
    mime_type_detected = Column(String(255))
    extension = Column(String(50))
    file_size_bytes = Column(Integer)
    sha256_hash = Column(String(64), nullable=False, index=True)
    is_executable = Column(Boolean, default=False)
    is_archive = Column(Boolean, default=False)
    has_macro_indicator = Column(Boolean, default=False)
    has_double_extension = Column(Boolean, default=False)
    mime_type_mismatch = Column(Boolean, default=False)
    risk_level = Column(String(20), default="unknown")
    storage_path = Column(String(1024))  # sandboxed, never executed
    created_at = now_utc()

    email = relationship("Email", back_populates="attachments")


# ============================================================
# URLS
# ============================================================
class ExtractedURL(Base):
    __tablename__ = "extracted_urls"

    id = uuid_pk()
    email_id = Column(UUID(as_uuid=True), ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    url_raw = Column(Text, nullable=False)
    url_normalized = Column(Text)
    domain = Column(String(255), index=True)
    scheme = Column(String(20))
    is_shortener = Column(Boolean, default=False)
    is_ip_based = Column(Boolean, default=False)
    is_punycode = Column(Boolean, default=False)
    is_homograph_suspect = Column(Boolean, default=False)
    has_suspicious_params = Column(Boolean, default=False)
    redirect_chain = Column(JSONB, default=list)
    reputation_score = Column(Float)
    reputation_source = Column(String(100))
    is_malicious = Column(Boolean)  # None = unknown
    malicious_confidence = Column(String(20))  # confirmed | suspicious | heuristic
    detection_reasons = Column(ARRAY(Text))
    source_location = Column(String(50))  # body_html | body_text | header
    created_at = now_utc()

    email = relationship("Email", back_populates="urls")


# ============================================================
# DOMAIN INTELLIGENCE
# ============================================================
class DomainIntelligence(Base):
    __tablename__ = "domain_intelligence"

    id = uuid_pk()
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    domain = Column(String(255), nullable=False)
    spf_record = Column(Text)
    spf_valid = Column(Boolean)
    dkim_selector = Column(String(255))
    dmarc_record = Column(Text)
    dmarc_policy = Column(String(50))
    mx_records = Column(ARRAY(Text))
    a_records = Column(ARRAY(Text))
    ns_records = Column(ARRAY(Text))
    whois_registrar = Column(Text)
    domain_created_at = Column(Date)
    is_newly_registered = Column(Boolean)
    brand_impersonation_target = Column(String(255))
    similarity_score = Column(Float)
    reputation_score = Column(Float)
    reputation_source = Column(String(100))
    is_known_malicious = Column(Boolean)
    data_sources = Column(ARRAY(Text))
    cached_at = Column(DateTime(timezone=True))
    cache_ttl_seconds = Column(Integer, default=3600)
    created_at = now_utc()
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint("organization_id", "domain", name="uq_org_domain"),
    )


# ============================================================
# ANALYSIS
# ============================================================
class EmailAnalysis(Base):
    __tablename__ = "email_analyses"

    id = uuid_pk()
    email_id = Column(UUID(as_uuid=True), ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, unique=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    analyzed_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))

    # Risk Score
    risk_score = Column(Integer, nullable=False, default=0)
    risk_classification = Column(String(30), nullable=False)
    # low | suspicious | medium | high | critical

    # Authentication Summary
    spf_result = Column(String(20))
    dkim_result = Column(String(20))
    dmarc_result = Column(String(20))
    auth_alignment = Column(String(20))

    # Spoofing
    display_name_spoofing = Column(Boolean, default=False)
    sender_domain_mismatch = Column(Boolean, default=False)
    reply_to_mismatch = Column(Boolean, default=False)

    # Counts
    url_count = Column(Integer, default=0)
    malicious_url_count = Column(Integer, default=0)
    suspicious_url_count = Column(Integer, default=0)
    attachment_count = Column(Integer, default=0)
    malicious_attachment_count = Column(Integer, default=0)
    ioc_count = Column(Integer, default=0)

    # AI
    ai_provider = Column(String(100))
    ai_model = Column(String(100))
    ai_analysis_available = Column(Boolean, default=False)
    ai_phishing_assessment = Column(String(50))
    ai_confidence = Column(String(20))
    ai_summary = Column(Text)
    ai_findings = Column(JSONB, default=list)
    ai_recommended_actions = Column(ARRAY(Text))

    # Scoring
    score_breakdown = Column(JSONB, default=dict)

    # Metadata
    analysis_duration_ms = Column(Integer)
    analysis_version = Column(String(20), default="1.0")
    missing_evidence = Column(ARRAY(Text))
    errors = Column(JSONB, default=list)

    created_at = now_utc()
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    email = relationship("Email", back_populates="analysis")
    findings = relationship("DetectionFinding", back_populates="analysis", cascade="all, delete-orphan")
    iocs = relationship("IOC", back_populates="analysis")

    __table_args__ = (
        Index("idx_analyses_risk_desc", "risk_score"),
        Index("idx_analyses_created_desc", "created_at"),
    )


class DetectionFinding(Base):
    __tablename__ = "detection_findings"

    id = uuid_pk()
    analysis_id = Column(UUID(as_uuid=True), ForeignKey("email_analyses.id", ondelete="CASCADE"), nullable=False, index=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    category = Column(String(100), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    severity = Column(String(20), nullable=False)
    confidence = Column(String(20), nullable=False)
    evidence = Column(JSONB, default=dict)
    score_impact = Column(Integer, default=0)
    rule_id = Column(UUID(as_uuid=True), ForeignKey("detection_rules.id"), nullable=True)
    created_at = now_utc()

    analysis = relationship("EmailAnalysis", back_populates="findings")


# ============================================================
# IOCs
# ============================================================
class IOC(Base):
    __tablename__ = "iocs"

    id = uuid_pk()
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    email_id = Column(UUID(as_uuid=True), ForeignKey("emails.id"), nullable=True)
    analysis_id = Column(UUID(as_uuid=True), ForeignKey("email_analyses.id"), nullable=True, index=True)
    ioc_type = Column(String(50), nullable=False)
    # ip | domain | url | email | hash_sha256 | filename
    ioc_value = Column(Text, nullable=False)
    source_location = Column(String(100))
    risk_level = Column(String(20))
    confidence = Column(String(20))
    detection_reason = Column(Text)
    reputation_data = Column(JSONB, default=dict)
    is_false_positive = Column(Boolean, default=False)
    tags = Column(ARRAY(Text))
    first_seen_at = Column(DateTime(timezone=True), server_default=func.now())
    last_seen_at = Column(DateTime(timezone=True), server_default=func.now())
    created_at = now_utc()

    email = relationship("Email", back_populates="iocs")
    analysis = relationship("EmailAnalysis", back_populates="iocs")

    __table_args__ = (
        Index("idx_iocs_type_value", "ioc_type", "ioc_value"),
    )


# ============================================================
# THREAT INTELLIGENCE
# ============================================================
class ThreatIntelligenceResult(Base):
    __tablename__ = "threat_intelligence_results"

    id = uuid_pk()
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    provider = Column(String(100), nullable=False)
    query_type = Column(String(50), nullable=False)
    query_value = Column(Text, nullable=False)
    raw_response = Column(JSONB)
    is_malicious = Column(Boolean)
    confidence = Column(String(20))
    detections = Column(Integer)
    total_engines = Column(Integer)
    tags = Column(ARRAY(Text))
    cached = Column(Boolean, default=False)
    queried_at = Column(DateTime(timezone=True), server_default=func.now())
    cache_expires_at = Column(DateTime(timezone=True))

    __table_args__ = (
        Index("idx_ti_provider_query", "provider", "query_type", "query_value"),
    )


# ============================================================
# INCIDENTS
# ============================================================
class Incident(Base):
    __tablename__ = "incidents"

    id = uuid_pk()
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(String(20), nullable=False)
    status = Column(String(50), nullable=False, default="new", index=True)
    # new | under_investigation | escalated | resolved | false_positive
    incident_number = Column(Integer)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    resolved_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolution_notes = Column(Text)
    tags = Column(ARRAY(Text))
    created_at = now_utc()
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    deleted_at = Column(DateTime(timezone=True), nullable=True)

    organization = relationship("Organization", back_populates="incidents")
    creator = relationship("User", foreign_keys=[created_by])
    assignments = relationship("IncidentAssignment", back_populates="incident", cascade="all, delete-orphan")
    notes = relationship("InvestigationNote", back_populates="incident", cascade="all, delete-orphan")
    email_links = relationship("IncidentEmail", back_populates="incident", cascade="all, delete-orphan")
    ioc_links = relationship("IncidentIOC", back_populates="incident", cascade="all, delete-orphan")


class IncidentEmail(Base):
    __tablename__ = "incident_emails"

    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True)
    email_id = Column(UUID(as_uuid=True), ForeignKey("emails.id", ondelete="CASCADE"), primary_key=True)
    added_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    added_at = Column(DateTime(timezone=True), server_default=func.now())

    incident = relationship("Incident", back_populates="email_links")


class IncidentIOC(Base):
    __tablename__ = "incident_iocs"

    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True)
    ioc_id = Column(UUID(as_uuid=True), ForeignKey("iocs.id", ondelete="CASCADE"), primary_key=True)
    added_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    added_at = Column(DateTime(timezone=True), server_default=func.now())

    incident = relationship("Incident", back_populates="ioc_links")


class IncidentAssignment(Base):
    __tablename__ = "incident_assignments"

    id = uuid_pk()
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    assigned_to = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    assigned_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    is_active = Column(Boolean, default=True)
    assigned_at = Column(DateTime(timezone=True), server_default=func.now())

    incident = relationship("Incident", back_populates="assignments")
    assignee = relationship("User", foreign_keys=[assigned_to])


class InvestigationNote(Base):
    __tablename__ = "investigation_notes"

    id = uuid_pk()
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    author_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    content = Column(Text, nullable=False)
    note_type = Column(String(50), default="note")
    # note | action | escalation | resolution
    is_internal = Column(Boolean, default=True)
    created_at = now_utc()
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    incident = relationship("Incident", back_populates="notes")
    author = relationship("User")


# ============================================================
# AUDIT LOG (Immutable)
# ============================================================
class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = uuid_pk()
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    action = Column(String(255), nullable=False, index=True)
    resource_type = Column(String(100))
    resource_id = Column(UUID(as_uuid=True))
    ip_address = Column(INET)
    user_agent = Column(Text)
    request_id = Column(String(100))
    details = Column(JSONB, default=dict)
    severity = Column(String(20), default="info")
    created_at = now_utc()
    # NO updated_at — audit logs are immutable

    organization = relationship("Organization")
    user = relationship("User", back_populates="audit_logs")

    __table_args__ = (
        Index("idx_audit_org_created", "organization_id", "created_at"),
        Index("idx_audit_user_created", "user_id", "created_at"),
    )


# ============================================================
# DETECTION RULES
# ============================================================
class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id = uuid_pk()
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    category = Column(String(100), nullable=False)
    rule_type = Column(String(50), nullable=False)  # regex | keyword | heuristic | yara
    rule_definition = Column(JSONB, nullable=False)
    severity = Column(String(20), nullable=False)
    score_impact = Column(Integer, default=0)
    is_enabled = Column(Boolean, default=True)
    is_global = Column(Boolean, default=False)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at = now_utc()
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


# ============================================================
# API INTEGRATIONS
# ============================================================
class APIIntegration(Base):
    __tablename__ = "api_integrations"

    id = uuid_pk()
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    provider = Column(String(100), nullable=False)
    is_enabled = Column(Boolean, default=False)
    api_key_encrypted = Column(BYTEA)  # encrypted at rest
    config = Column(JSONB, default=dict)
    last_used_at = Column(DateTime(timezone=True))
    request_count = Column(Integer, default=0)
    error_count = Column(Integer, default=0)
    created_at = now_utc()
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint("organization_id", "provider", name="uq_org_provider"),
    )


# ============================================================
# FEATURE ACCESS REQUESTS & APPROVALS
# ============================================================
class FeatureRequest(Base):
    __tablename__ = "feature_requests"

    id = uuid_pk()
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    user_email = Column(String(255), nullable=False)
    user_name = Column(String(255), nullable=False)
    feature_key = Column(String(100), nullable=False)
    feature_name = Column(String(255), nullable=False)
    justification = Column(Text, nullable=False)
    status = Column(String(50), nullable=False, default="pending")  # pending | approved | rejected
    admin_notes = Column(Text, nullable=True)
    reviewed_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = now_utc()
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    user = relationship("User", foreign_keys=[user_id])
    reviewer = relationship("User", foreign_keys=[reviewed_by])


# ============================================================
# CONTACT SUPER ADMIN MESSAGES & EMAIL DISPATCH
# ============================================================
class AdminMessage(Base):
    __tablename__ = "admin_messages"

    id = uuid_pk()
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    user_email = Column(String(255), nullable=False)
    user_name = Column(String(255), nullable=False)
    subject = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    status = Column(String(50), nullable=False, default="unread")  # unread | read | replied
    admin_reply = Column(Text, nullable=True)
    replied_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    replied_at = Column(DateTime(timezone=True), nullable=True)
    created_at = now_utc()
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    user = relationship("User", foreign_keys=[user_id])
    replier = relationship("User", foreign_keys=[replied_by])


# ============================================================
# GMAIL INTEGRATION & AUTO-ANALYZE HUB
# ============================================================
class GmailIntegration(Base):
    __tablename__ = "gmail_integrations"

    id = uuid_pk()
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    email_address = Column(String(255), nullable=False)
    is_connected = Column(Boolean, default=True, nullable=False)
    connection_status = Column(String(50), default="connected", nullable=False)  # connected | disconnected | error | revoked
    token_status = Column(String(50), default="valid", nullable=False)            # valid | expired | revoked | invalid
    refresh_token_encrypted = Column(BYTEA, nullable=True)                       # AES-128/Fernet encrypted at rest
    access_token_encrypted = Column(BYTEA, nullable=True)                        # AES-128/Fernet encrypted at rest
    token_expires_at = Column(DateTime(timezone=True), nullable=True)
    granted_scopes = Column(JSONB, nullable=True, default=list)
    auto_analyze_enabled = Column(Boolean, default=True, nullable=False)
    auth_type = Column(String(50), default="oauth2", nullable=False)             # oauth2 | app_password | live_sync
    connected_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_verified_at = Column(DateTime(timezone=True), nullable=True)
    last_synced_at = Column(DateTime(timezone=True), nullable=True)
    last_history_id = Column(String(64), nullable=True)
    quarantine_label_id = Column(String(100), nullable=True)
    watch_expiration = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(Text, nullable=True)

    # Deprecated plaintext columns retained for backward migration compatibility
    access_token = Column(Text, nullable=True)
    refresh_token = Column(Text, nullable=True)

    created_at = now_utc()
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    user = relationship("User", foreign_keys=[user_id])
    messages = relationship("GmailMessage", back_populates="integration", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_gmail_org_user", "organization_id", "user_id"),
        Index("idx_gmail_email", "email_address"),
        UniqueConstraint("organization_id", "email_address", name="uq_gmail_org_email"),
    )


class OAuthState(Base):
    __tablename__ = "oauth_states"

    id = uuid_pk()
    state = Column(String(128), unique=True, nullable=False, index=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    code_verifier = Column(String(128), nullable=True)
    redirect_uri = Column(String(512), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = now_utc()

    __table_args__ = (
        Index("idx_oauth_state_lookup", "state"),
    )


class GmailMessage(Base):
    __tablename__ = "gmail_messages"

    id = uuid_pk()
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    integration_id = Column(UUID(as_uuid=True), ForeignKey("gmail_integrations.id", ondelete="CASCADE"), nullable=False)
    
    gmail_message_id = Column(String(255), nullable=False)
    thread_id = Column(String(255), nullable=True)
    label_ids = Column(JSONB, nullable=True, default=list)
    internal_date = Column(DateTime(timezone=True), nullable=True)
    subject = Column(String(500), nullable=False)
    sender = Column(String(255), nullable=False)
    snippet = Column(Text, nullable=True)
    body_text = Column(Text, nullable=True)
    raw_eml = Column(Text, nullable=True)
    received_at = Column(DateTime(timezone=True), nullable=True)

    is_analyzed = Column(Boolean, default=False, nullable=False)
    analysis_status = Column(String(50), default="pending", nullable=False)  # pending | processing | analyzed | failed
    risk_score = Column(Float, nullable=True)
    risk_classification = Column(String(50), nullable=True)  # Safe | Suspicious | Malicious | Critical
    email_id = Column(UUID(as_uuid=True), ForeignKey("emails.id", ondelete="SET NULL"), nullable=True)
    error_message = Column(Text, nullable=True)

    created_at = now_utc()
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    integration = relationship("GmailIntegration", back_populates="messages")
    analyzed_email = relationship("Email", foreign_keys=[email_id])

    __table_args__ = (
        Index("idx_gmail_msg_org", "organization_id", "user_id"),
        Index("idx_gmail_msg_unique", "integration_id", "gmail_message_id", unique=True),
        UniqueConstraint("integration_id", "gmail_message_id", name="uq_gmail_integration_msg"),
    )


# ============================================================
# AI ASSISTANT CHAT MODELS
# ============================================================
class ChatSession(Base):
    __tablename__ = "chat_sessions"

    id = uuid_pk()
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    title = Column(String(255), nullable=False, default="New Conversation")
    created_at = now_utc()
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    user = relationship("User", foreign_keys=[user_id])
    messages = relationship("ChatMessage", back_populates="session", cascade="all, delete-orphan", order_by="ChatMessage.created_at")

    __table_args__ = (
        Index("idx_chat_session_org_user", "organization_id", "user_id"),
    )


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id = uuid_pk()
    session_id = Column(UUID(as_uuid=True), ForeignKey("chat_sessions.id", ondelete="CASCADE"), nullable=False)
    sender = Column(String(50), nullable=False)  # user | assistant
    content = Column(Text, nullable=False)
    sources = Column(JSONB, nullable=True, default=list)  # list of { title, url, description, category }
    created_at = now_utc()

    session = relationship("ChatSession", back_populates="messages")

    __table_args__ = (
        Index("idx_chat_message_session", "session_id"),
    )



