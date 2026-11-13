"""initial schema

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-11-09 14:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. organizations
    op.create_table(
        'organizations',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('slug', sa.String(length=100), nullable=False, unique=True),
        sa.Column('plan', sa.String(length=50), server_default='free'),
        sa.Column('is_active', sa.Boolean(), server_default='true'),
        sa.Column('settings', postgresql.JSONB(), server_default='{}'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.func.now()),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
    )

    # 2. users
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False, unique=True),
        sa.Column('username', sa.String(length=100), nullable=False, unique=True),
        sa.Column('display_name', sa.String(length=255), nullable=True),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('role', sa.String(length=50), server_default='analyst', nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default='true'),
        sa.Column('is_email_verified', sa.Boolean(), server_default='false'),
        sa.Column('failed_login_count', sa.Integer(), server_default='0'),
        sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('password_changed_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.func.now()),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_users_email', 'users', ['email'])
    op.create_index('idx_users_org_active', 'users', ['organization_id'])

    # 3. refresh_tokens
    op.create_table(
        'refresh_tokens',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('token_hash', sa.String(length=255), nullable=False, unique=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('ip_address', postgresql.INET(), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_refresh_tokens_token_hash', 'refresh_tokens', ['token_hash'])

    # 4. emails
    op.create_table(
        'emails',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('submitted_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('message_id', sa.String(length=512), nullable=True),
        sa.Column('subject', sa.Text(), nullable=True),
        sa.Column('sender_raw', sa.Text(), nullable=True),
        sa.Column('sender_email', sa.String(length=255), nullable=True),
        sa.Column('sender_display_name', sa.Text(), nullable=True),
        sa.Column('reply_to', sa.Text(), nullable=True),
        sa.Column('return_path', sa.Text(), nullable=True),
        sa.Column('recipient_to', postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column('recipient_cc', postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column('received_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('source_type', sa.String(length=20), nullable=False),
        sa.Column('raw_content', sa.Text(), nullable=True),
        sa.Column('file_hash_sha256', sa.String(length=64), nullable=True),
        sa.Column('file_size_bytes', sa.Integer(), nullable=True),
        sa.Column('original_filename', sa.String(length=255), nullable=True),
        sa.Column('analysis_status', sa.String(length=30), server_default='pending'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.func.now()),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_emails_organization_id', 'emails', ['organization_id'])
    op.create_index('ix_emails_sender_email', 'emails', ['sender_email'])
    op.create_index('ix_emails_analysis_status', 'emails', ['analysis_status'])
    op.create_index('idx_emails_created_desc', 'emails', ['created_at'])

    # 5. email_headers
    op.create_table(
        'email_headers',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('email_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('emails.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('value', sa.Text(), nullable=False),
        sa.Column('position', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_email_headers_email_id', 'email_headers', ['email_id'])

    # 6. attachments
    op.create_table(
        'attachments',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('email_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('emails.id', ondelete='CASCADE'), nullable=False),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('filename_original', sa.String(length=512), nullable=True),
        sa.Column('filename_sanitized', sa.String(length=512), nullable=True),
        sa.Column('mime_type_declared', sa.String(length=255), nullable=True),
        sa.Column('mime_type_detected', sa.String(length=255), nullable=True),
        sa.Column('extension', sa.String(length=50), nullable=True),
        sa.Column('file_size_bytes', sa.Integer(), nullable=True),
        sa.Column('sha256_hash', sa.String(length=64), nullable=False),
        sa.Column('is_executable', sa.Boolean(), server_default='false'),
        sa.Column('is_archive', sa.Boolean(), server_default='false'),
        sa.Column('has_macro_indicator', sa.Boolean(), server_default='false'),
        sa.Column('has_double_extension', sa.Boolean(), server_default='false'),
        sa.Column('mime_type_mismatch', sa.Boolean(), server_default='false'),
        sa.Column('risk_level', sa.String(length=20), server_default='unknown'),
        sa.Column('storage_path', sa.String(length=1024), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_attachments_email_id', 'attachments', ['email_id'])
    op.create_index('ix_attachments_sha256_hash', 'attachments', ['sha256_hash'])

    # 7. extracted_urls
    op.create_table(
        'extracted_urls',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('email_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('emails.id', ondelete='CASCADE'), nullable=False),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('url_raw', sa.Text(), nullable=False),
        sa.Column('url_normalized', sa.Text(), nullable=True),
        sa.Column('domain', sa.String(length=255), nullable=True),
        sa.Column('scheme', sa.String(length=20), nullable=True),
        sa.Column('is_shortener', sa.Boolean(), server_default='false'),
        sa.Column('is_ip_based', sa.Boolean(), server_default='false'),
        sa.Column('is_punycode', sa.Boolean(), server_default='false'),
        sa.Column('is_homograph_suspect', sa.Boolean(), server_default='false'),
        sa.Column('has_suspicious_params', sa.Boolean(), server_default='false'),
        sa.Column('redirect_chain', postgresql.JSONB(), server_default='[]'),
        sa.Column('reputation_score', sa.Float(), nullable=True),
        sa.Column('reputation_source', sa.String(length=100), nullable=True),
        sa.Column('is_malicious', sa.Boolean(), nullable=True),
        sa.Column('malicious_confidence', sa.String(length=20), nullable=True),
        sa.Column('detection_reasons', postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column('source_location', sa.String(length=50), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_extracted_urls_email_id', 'extracted_urls', ['email_id'])
    op.create_index('ix_extracted_urls_domain', 'extracted_urls', ['domain'])

    # 8. domain_intelligence
    op.create_table(
        'domain_intelligence',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('domain', sa.String(length=255), nullable=False),
        sa.Column('spf_record', sa.Text(), nullable=True),
        sa.Column('spf_valid', sa.Boolean(), nullable=True),
        sa.Column('dkim_selector', sa.String(length=255), nullable=True),
        sa.Column('dmarc_record', sa.Text(), nullable=True),
        sa.Column('dmarc_policy', sa.String(length=50), nullable=True),
        sa.Column('mx_records', postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column('a_records', postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column('ns_records', postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column('whois_registrar', sa.Text(), nullable=True),
        sa.Column('domain_created_at', sa.Date(), nullable=True),
        sa.Column('is_newly_registered', sa.Boolean(), nullable=True),
        sa.Column('brand_impersonation_target', sa.String(length=255), nullable=True),
        sa.Column('similarity_score', sa.Float(), nullable=True),
        sa.Column('reputation_score', sa.Float(), nullable=True),
        sa.Column('reputation_source', sa.String(length=100), nullable=True),
        sa.Column('is_known_malicious', sa.Boolean(), nullable=True),
        sa.Column('data_sources', postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column('cached_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('cache_ttl_seconds', sa.Integer(), server_default='3600'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.func.now()),
        sa.UniqueConstraint('organization_id', 'domain', name='uq_org_domain'),
    )

    # 9. email_analyses
    op.create_table(
        'email_analyses',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('email_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('emails.id', ondelete='CASCADE'), nullable=False, unique=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('analyzed_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('risk_score', sa.Integer(), server_default='0', nullable=False),
        sa.Column('risk_classification', sa.String(length=30), nullable=False),
        sa.Column('spf_result', sa.String(length=20), nullable=True),
        sa.Column('dkim_result', sa.String(length=20), nullable=True),
        sa.Column('dmarc_result', sa.String(length=20), nullable=True),
        sa.Column('auth_alignment', sa.String(length=20), nullable=True),
        sa.Column('display_name_spoofing', sa.Boolean(), server_default='false'),
        sa.Column('sender_domain_mismatch', sa.Boolean(), server_default='false'),
        sa.Column('reply_to_mismatch', sa.Boolean(), server_default='false'),
        sa.Column('url_count', sa.Integer(), server_default='0'),
        sa.Column('malicious_url_count', sa.Integer(), server_default='0'),
        sa.Column('suspicious_url_count', sa.Integer(), server_default='0'),
        sa.Column('attachment_count', sa.Integer(), server_default='0'),
        sa.Column('malicious_attachment_count', sa.Integer(), server_default='0'),
        sa.Column('ioc_count', sa.Integer(), server_default='0'),
        sa.Column('ai_provider', sa.String(length=100), nullable=True),
        sa.Column('ai_model', sa.String(length=100), nullable=True),
        sa.Column('ai_analysis_available', sa.Boolean(), server_default='false'),
        sa.Column('ai_phishing_assessment', sa.String(length=50), nullable=True),
        sa.Column('ai_confidence', sa.String(length=20), nullable=True),
        sa.Column('ai_summary', sa.Text(), nullable=True),
        sa.Column('ai_findings', postgresql.JSONB(), server_default='[]'),
        sa.Column('ai_recommended_actions', postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column('score_breakdown', postgresql.JSONB(), server_default='{}'),
        sa.Column('analysis_duration_ms', sa.Integer(), nullable=True),
        sa.Column('analysis_version', sa.String(length=20), server_default='1.0'),
        sa.Column('missing_evidence', postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column('errors', postgresql.JSONB(), server_default='[]'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.func.now()),
    )
    op.create_index('ix_email_analyses_organization_id', 'email_analyses', ['organization_id'])
    op.create_index('idx_analyses_risk_desc', 'email_analyses', ['risk_score'])
    op.create_index('idx_analyses_created_desc', 'email_analyses', ['created_at'])

    # 10. detection_findings
    op.create_table(
        'detection_findings',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('analysis_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('email_analyses.id', ondelete='CASCADE'), nullable=False),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('category', sa.String(length=100), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('confidence', sa.String(length=20), nullable=False),
        sa.Column('evidence', postgresql.JSONB(), server_default='{}'),
        sa.Column('score_impact', sa.Integer(), server_default='0'),
        sa.Column('rule_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_detection_findings_analysis_id', 'detection_findings', ['analysis_id'])

    # 11. iocs
    op.create_table(
        'iocs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('email_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('emails.id'), nullable=True),
        sa.Column('analysis_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('email_analyses.id'), nullable=True),
        sa.Column('ioc_type', sa.String(length=50), nullable=False),
        sa.Column('ioc_value', sa.Text(), nullable=False),
        sa.Column('source_location', sa.String(length=100), nullable=True),
        sa.Column('risk_level', sa.String(length=20), nullable=True),
        sa.Column('confidence', sa.String(length=20), nullable=True),
        sa.Column('detection_reason', sa.Text(), nullable=True),
        sa.Column('reputation_data', postgresql.JSONB(), server_default='{}'),
        sa.Column('is_false_positive', sa.Boolean(), server_default='false'),
        sa.Column('tags', postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_iocs_organization_id', 'iocs', ['organization_id'])
    op.create_index('ix_iocs_analysis_id', 'iocs', ['analysis_id'])
    op.create_index('idx_iocs_type_value', 'iocs', ['ioc_type', 'ioc_value'])

    # 12. threat_intelligence_results
    op.create_table(
        'threat_intelligence_results',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('provider', sa.String(length=100), nullable=False),
        sa.Column('query_type', sa.String(length=50), nullable=False),
        sa.Column('query_value', sa.Text(), nullable=False),
        sa.Column('raw_response', postgresql.JSONB(), nullable=True),
        sa.Column('is_malicious', sa.Boolean(), nullable=True),
        sa.Column('confidence', sa.String(length=20), nullable=True),
        sa.Column('detections', sa.Integer(), nullable=True),
        sa.Column('total_engines', sa.Integer(), nullable=True),
        sa.Column('tags', postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column('cached', sa.Boolean(), server_default='false'),
        sa.Column('queried_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('cache_expires_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_threat_intel_org_id', 'threat_intelligence_results', ['organization_id'])
    op.create_index('idx_ti_provider_query', 'threat_intelligence_results', ['provider', 'query_type', 'query_value'])

    # 13. incidents
    op.create_table(
        'incidents',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('title', sa.String(length=500), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('status', sa.String(length=50), server_default='new', nullable=False),
        sa.Column('incident_number', sa.Integer(), autoincrement=True),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('resolved_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolution_notes', sa.Text(), nullable=True),
        sa.Column('tags', postgresql.ARRAY(sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.func.now()),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_incidents_organization_id', 'incidents', ['organization_id'])
    op.create_index('ix_incidents_status', 'incidents', ['status'])

    # 14. incident_emails
    op.create_table(
        'incident_emails',
        sa.Column('incident_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('incidents.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('email_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('emails.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('added_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('added_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # 15. incident_iocs
    op.create_table(
        'incident_iocs',
        sa.Column('incident_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('incidents.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('ioc_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('iocs.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('added_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('added_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # 16. incident_assignments
    op.create_table(
        'incident_assignments',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('incident_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('incidents.id', ondelete='CASCADE'), nullable=False),
        sa.Column('assigned_to', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('assigned_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default='true'),
        sa.Column('assigned_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # 17. investigation_notes
    op.create_table(
        'investigation_notes',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('incident_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('incidents.id', ondelete='CASCADE'), nullable=False),
        sa.Column('author_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('note_type', sa.String(length=50), server_default='note'),
        sa.Column('is_internal', sa.Boolean(), server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.func.now()),
    )
    op.create_index('ix_investigation_notes_incident_id', 'investigation_notes', ['incident_id'])

    # 18. audit_logs
    op.create_table(
        'audit_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('action', sa.String(length=255), nullable=False),
        sa.Column('resource_type', sa.String(length=100), nullable=True),
        sa.Column('resource_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('ip_address', postgresql.INET(), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('request_id', sa.String(length=100), nullable=True),
        sa.Column('details', postgresql.JSONB(), server_default='{}'),
        sa.Column('severity', sa.String(length=20), server_default='info'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index('ix_audit_logs_action', 'audit_logs', ['action'])
    op.create_index('idx_audit_org_created', 'audit_logs', ['organization_id', 'created_at'])
    op.create_index('idx_audit_user_created', 'audit_logs', ['user_id', 'created_at'])

    # 19. detection_rules
    op.create_table(
        'detection_rules',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('category', sa.String(length=100), nullable=False),
        sa.Column('rule_type', sa.String(length=50), nullable=False),
        sa.Column('rule_definition', postgresql.JSONB(), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('score_impact', sa.Integer(), server_default='0'),
        sa.Column('is_enabled', sa.Boolean(), server_default='true'),
        sa.Column('is_global', sa.Boolean(), server_default='false'),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.func.now()),
    )

    # 20. api_integrations
    op.create_table(
        'api_integrations',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('provider', sa.String(length=100), nullable=False),
        sa.Column('is_enabled', sa.Boolean(), server_default='false'),
        sa.Column('api_key_encrypted', postgresql.BYTEA(), nullable=True),
        sa.Column('config', postgresql.JSONB(), server_default='{}'),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('request_count', sa.Integer(), server_default='0'),
        sa.Column('error_count', sa.Integer(), server_default='0'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.func.now()),
        sa.UniqueConstraint('organization_id', 'provider', name='uq_org_provider'),
    )


def downgrade() -> None:
    op.drop_table('api_integrations')
    op.drop_table('detection_rules')
    op.drop_table('audit_logs')
    op.drop_table('investigation_notes')
    op.drop_table('incident_assignments')
    op.drop_table('incident_iocs')
    op.drop_table('incident_emails')
    op.drop_table('incidents')
    op.drop_table('threat_intelligence_results')
    op.drop_table('iocs')
    op.drop_table('detection_findings')
    op.drop_table('email_analyses')
    op.drop_table('domain_intelligence')
    op.drop_table('extracted_urls')
    op.drop_table('attachments')
    op.drop_table('email_headers')
    op.drop_table('emails')
    op.drop_table('refresh_tokens')
    op.drop_table('users')
    op.drop_table('organizations')
