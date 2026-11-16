"""google oauth2 integration and secure token storage

Revision ID: 002_google_oauth2_integration
Revises: 001_initial_schema
Create Date: 2026-11-16 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '002_google_oauth2_integration'
down_revision: Union[str, None] = '001_initial_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create oauth_states table
    op.create_table(
        'oauth_states',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('state', sa.String(length=128), nullable=False, unique=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('code_verifier', sa.String(length=128), nullable=True),
        sa.Column('redirect_uri', sa.String(length=512), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )
    op.create_index('idx_oauth_state_lookup', 'oauth_states', ['state'])

    # 2. Add columns to gmail_integrations if table exists, or create table
    # Check if gmail_integrations exists
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = inspector.get_table_names()

    if 'gmail_integrations' in tables:
        columns = [c['name'] for c in inspector.get_columns('gmail_integrations')]
        if 'connection_status' not in columns:
            op.add_column('gmail_integrations', sa.Column('connection_status', sa.String(length=50), server_default='connected', nullable=False))
        if 'token_status' not in columns:
            op.add_column('gmail_integrations', sa.Column('token_status', sa.String(length=50), server_default='valid', nullable=False))
        if 'refresh_token_encrypted' not in columns:
            op.add_column('gmail_integrations', sa.Column('refresh_token_encrypted', postgresql.BYTEA(), nullable=True))
        if 'access_token_encrypted' not in columns:
            op.add_column('gmail_integrations', sa.Column('access_token_encrypted', postgresql.BYTEA(), nullable=True))
        if 'token_expires_at' not in columns:
            op.add_column('gmail_integrations', sa.Column('token_expires_at', sa.DateTime(timezone=True), nullable=True))
        if 'granted_scopes' not in columns:
            op.add_column('gmail_integrations', sa.Column('granted_scopes', postgresql.JSONB(), server_default='[]', nullable=True))
        if 'connected_at' not in columns:
            op.add_column('gmail_integrations', sa.Column('connected_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True))
        if 'last_verified_at' not in columns:
            op.add_column('gmail_integrations', sa.Column('last_verified_at', sa.DateTime(timezone=True), nullable=True))
        if 'last_history_id' not in columns:
            op.add_column('gmail_integrations', sa.Column('last_history_id', sa.String(length=64), nullable=True))
        if 'quarantine_label_id' not in columns:
            op.add_column('gmail_integrations', sa.Column('quarantine_label_id', sa.String(length=100), nullable=True))
        if 'watch_expiration' not in columns:
            op.add_column('gmail_integrations', sa.Column('watch_expiration', sa.DateTime(timezone=True), nullable=True))
        if 'last_error' not in columns:
            op.add_column('gmail_integrations', sa.Column('last_error', sa.Text(), nullable=True))
    else:
        op.create_table(
            'gmail_integrations',
            sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column('organization_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=False),
            sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
            sa.Column('email_address', sa.String(length=255), nullable=False),
            sa.Column('is_connected', sa.Boolean(), server_default='true', nullable=False),
            sa.Column('connection_status', sa.String(length=50), server_default='connected', nullable=False),
            sa.Column('token_status', sa.String(length=50), server_default='valid', nullable=False),
            sa.Column('refresh_token_encrypted', postgresql.BYTEA(), nullable=True),
            sa.Column('access_token_encrypted', postgresql.BYTEA(), nullable=True),
            sa.Column('token_expires_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('granted_scopes', postgresql.JSONB(), server_default='[]', nullable=True),
            sa.Column('auto_analyze_enabled', sa.Boolean(), server_default='true', nullable=False),
            sa.Column('auth_type', sa.String(length=50), server_default='oauth2', nullable=False),
            sa.Column('connected_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
            sa.Column('last_verified_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('last_synced_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('last_history_id', sa.String(length=64), nullable=True),
            sa.Column('quarantine_label_id', sa.String(length=100), nullable=True),
            sa.Column('watch_expiration', sa.DateTime(timezone=True), nullable=True),
            sa.Column('last_error', sa.Text(), nullable=True),
            sa.Column('access_token', sa.Text(), nullable=True),
            sa.Column('refresh_token', sa.Text(), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint('organization_id', 'email_address', name='uq_gmail_org_email'),
        )
        op.create_index('idx_gmail_org_user', 'gmail_integrations', ['organization_id', 'user_id'])
        op.create_index('idx_gmail_email', 'gmail_integrations', ['email_address'])


def downgrade() -> None:
    op.drop_table('oauth_states')
